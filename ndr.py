#!/usr/bin/env python3
"""OPENNDR - sensor NDR pasivo basado en IsolationForest.

Escucha en una interfaz (idealmente un puerto espejo/SPAN), agrupa los paquetes
en flujos bidireccionales y puntua cada flujo contra un modelo no supervisado
entrenado con el trafico normal de la propia red.

    python ndr.py ifaces
    python ndr.py capture --iface Ethernet --duration 3600
    python ndr.py train
    python ndr.py detect --iface Ethernet
    python ndr.py eval

No modifica la red: no hace ARP spoofing ni reenvia paquetes.
"""
import argparse
import os
import threading
import time
from collections import deque
from ipaddress import ip_address

import numpy as np
import pandas as pd

DATA, MODEL = "network_data.csv", "network_model.pkl"
COLS = ['timestamp', 'src_ip', 'dst_ip', 'proto', 'sport', 'dport', 'length', 'payload_len']
PROTOS = [1, 6, 17]  # ICMP, TCP, UDP
# Ventana de agregacion. Tiene que abarcar varios intervalos del beacon que
# quieras ver: con 300 s, uno que llame cada 30 s deja 10 muestras y su
# regularidad es medible. Mas ventana = mejor senal pero mas latencia de alerta,
# porque detect puntua una vez por ventana.
WINDOW = 300.0


# --------------------------------------------------------------------------- flujos

def _is_global(ip):
    """Enrutable en internet. is_global y no `not is_private` porque los rangos
    reservados (TEST-NET, benchmarking, CGNAT) no son ni lo uno ni lo otro, y
    sin excluir multicast el mDNS de la propia LAN (224.0.0.251) contaba como
    salida a internet."""
    try:
        a = ip_address(ip)
        return a.is_global and not a.is_multicast
    except ValueError:
        return False


def parse_time(s):
    """Epoch float (capturas nuevas) o texto (CSV antiguo, resolucion de 1 s)."""
    return pd.to_datetime(s, unit='s') if pd.api.types.is_numeric_dtype(s) else pd.to_datetime(s)


def flows_from_packets(df, window=WINDOW):
    """Paquetes -> flujos bidireccionales, troceados por ventana temporal.

    Un flujo = misma pareja de extremos y mismo protocolo dentro de la misma
    ventana de `window` segundos. Deliberadamente NO se parte por inactividad:
    un beacon C2 que llama cada 30 s tiene que quedar en un unico flujo para que
    su regularidad (iat_std bajo) sea visible. Partirlo por huecos destruiria
    justo la senal que lo delata.

    La ventana acota el flujo por arriba, asi que una descarga de una hora no se
    convierte en un solo registro imposible de puntuar. Va en rejilla global (no
    desde el primer paquete de cada flujo), que es mas simple y hace el troceado
    reproducible; a cambio, un flujo que cae sobre un borde sale partido en dos.
    """
    t = parse_time(df['timestamp'])
    df = df.assign(_t=t).sort_values('_t', kind='stable')

    a = df['src_ip'] + ':' + df['sport'].astype(str)
    b = df['dst_ip'] + ':' + df['dport'].astype(str)
    lo, hi = np.minimum(a, b), np.maximum(a, b)
    # total_seconds() en vez de astype('int64'): el entero crudo va en la unidad
    # del dtype, que pandas 3 deja en segundos y antes era siempre nanosegundos.
    secs = (df['_t'] - pd.Timestamp(0)).dt.total_seconds()
    bucket = (secs // window).astype('int64').astype(str)
    df['_key'] = lo + '|' + hi + '|' + df['proto'].astype(str) + '|' + bucket

    # Direccion: el extremo con el puerto alto es el cliente (puerto efimero), asi
    # que fwd = cliente -> servidor. fwd_ratio alto = mucho subiendo (exfiltracion).
    df['_fwd'] = df['sport'] > df['dport']
    df['_fwd_len'] = df['length'].where(df['_fwd'], 0)
    df['_iat'] = df.groupby('_key', sort=False)['_t'].diff().dt.total_seconds()

    fl = df.groupby('_key', sort=False).agg(
        t0=('_t', 'min'), t1=('_t', 'max'),
        n_pkts=('length', 'size'), n_bytes=('length', 'sum'),
        len_mean=('length', 'mean'), len_std=('length', 'std'),
        iat_mean=('_iat', 'mean'), iat_std=('_iat', 'std'),
        proto=('proto', 'first'), sport=('sport', 'first'), dport=('dport', 'first'),
        src_ip=('src_ip', 'first'), dst_ip=('dst_ip', 'first'),
        fwd_bytes=('_fwd_len', 'sum'),
    )
    fl['duration'] = (fl['t1'] - fl['t0']).dt.total_seconds()
    # Puerto de servicio: el bajo de los dos (443 frente a 51000 efimero).
    fl['service_port'] = np.minimum(fl['sport'], fl['dport'])
    glob = {ip: _is_global(ip) for ip in pd.concat([fl['src_ip'], fl['dst_ip']]).unique()}
    fl['external'] = (fl['src_ip'].map(glob) | fl['dst_ip'].map(glob)).astype(int)
    return fl


FLOW_FEATURES = ['hour_sin', 'hour_cos', 'duration', 'n_pkts', 'n_bytes', 'len_mean',
                 'len_std', 'iat_mean', 'iat_std', 'iat_cv', 'fwd_ratio', 'pps',
                 'service_port', 'external'] + [f'proto_{p}' for p in PROTOS]


def featurize_flows(fl):
    """Unico sitio donde se definen las features. train y detect pasan por aqui."""
    h = fl['t0'].dt.hour
    f = pd.DataFrame(index=fl.index)
    f['hour_sin'] = np.sin(2 * np.pi * h / 24)
    f['hour_cos'] = np.cos(2 * np.pi * h / 24)
    f['duration'] = fl['duration']
    f['n_pkts'] = fl['n_pkts']
    f['n_bytes'] = fl['n_bytes']
    f['len_mean'] = fl['len_mean']
    f['len_std'] = fl['len_std'].fillna(0)      # un solo paquete -> sin dispersion
    f['iat_mean'] = fl['iat_mean'].fillna(0)
    f['iat_std'] = fl['iat_std'].fillna(0)
    # Regularidad normalizada: ~0 = reloj (beacon), >=1 = trafico humano. Hace
    # falta separarla de iat_std porque un flujo de 1-2 paquetes tambien tiene
    # std 0, y al ser tan comunes hacian que "std 0" pareciese lo normal y el
    # beacon se perdiese entre ellos. Sin intervalos suficientes -> 1, que es
    # "no hay evidencia de regularidad", no "es regular".
    cv = fl['iat_std'] / fl['iat_mean'].replace(0, np.nan)
    f['iat_cv'] = cv.where(fl['n_pkts'] >= 3, 1.0).fillna(1.0)
    f['fwd_ratio'] = fl['fwd_bytes'] / fl['n_bytes'].replace(0, 1)
    f['pps'] = fl['n_pkts'] / fl['duration'].clip(lower=0.001)
    f['service_port'] = fl['service_port']
    f['external'] = fl['external']
    for p in PROTOS:
        f[f'proto_{p}'] = (fl['proto'] == p).astype(int)
    return f[FLOW_FEATURES]


def beacon_rule(F, cv=0.1, min_pkts=5):
    """Flujo periodico y de poco volumen hacia internet: un implante llamando a casa.

    Va aparte del modelo a proposito. IsolationForest busca lo raro y ruidoso, y
    un beacon esta disenado para ser silencioso y aburrido: medido sobre 24,5 min
    de trafico real se queda en el percentil 95 de anomalia, nunca en el 1% que
    cruza el umbral. Esta regla lo coge por su firma (intervalos de reloj) en vez
    de por rareza estadistica.
    """
    return (F['iat_cv'] < cv) & (F['n_pkts'] >= min_pkts) & (F['external'] == 1)


def row_from_pkt(pkt):
    """Paquete -> fila con el mismo esquema que el CSV, para reusar flows_from_packets()."""
    from scapy.all import IP, TCP, UDP
    ip = pkt[IP]
    l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
    return dict(zip(COLS, (
        # Epoch con decimales: con la resolucion de 1 s del formato anterior los
        # inter-arrival de una rafaga salian todos 0 y iat_std no valia nada.
        time.time(), ip.src, ip.dst, int(ip.proto),
        # sport/dport viven en la capa 4, no en IP: leerlos de pkt[IP] lanzaba
        # AttributeError en cada paquete y el filtro de puertos nunca se aplico.
        int(l4.sport) if l4 else 0, int(l4.dport) if l4 else 0,
        len(pkt), len(l4.payload) if l4 else len(ip.payload))))


def severity(score, ref):
    """Percentil inverso dentro de los scores de entrenamiento (0-100)."""
    return round(100 * (1 - np.searchsorted(ref, score) / len(ref)), 1)


# --------------------------------------------------------------------------- comandos

def cmd_ifaces(args):
    """Interfaces con IP utilizable. --all incluye las que no la tienen."""
    from scapy.all import conf
    rows = []
    for i in conf.ifaces.values():
        ip = getattr(i, 'ip', None) or ''
        # 0.0.0.0 = sin configurar, 169.254.x = APIPA (sin conectividad real)
        usable = ip and not ip.startswith(('0.', '169.254.'))
        if usable or args.all:
            rows.append((' *' if i == conf.iface else '  ',
                         ip or '-', i.description or i.name, i.name))
    for mark, ip, desc, name in sorted(rows, key=lambda r: r[1], reverse=True):
        print(f"{mark} {ip:<16} {desc}")
        if args.verbose:
            print(f"     {name}")
    print("\n  * = interfaz por defecto (la de la ruta por defecto)")
    if not args.all:
        print("  --all para ver tambien las que no tienen IP utilizable")


def cmd_capture(args):
    from scapy.all import sniff, IP
    buf = deque(maxlen=500_000)
    stop = threading.Event()

    def handle(pkt):
        if IP in pkt:
            buf.append(row_from_pkt(pkt))

    def flush():
        # popleft() es atomico, asi que vaciamos sin lock y sin perder los
        # paquetes que lleguen durante el volcado (el clear() original si los perdia).
        rows = [buf.popleft() for _ in range(len(buf))]
        if rows:
            pd.DataFrame(rows, columns=COLS).to_csv(
                args.out, mode='a', index=False, header=not os.path.exists(args.out))
            print(f"[+] {len(rows)} paquetes -> {args.out}", flush=True)

    def saver():
        while not stop.wait(args.interval):
            flush()

    threading.Thread(target=saver, daemon=True).start()
    print(f"[+] Capturando en {args.iface or 'interfaz por defecto'} "
          f"({args.duration or 'sin limite'} s). Ctrl-C para parar.", flush=True)
    try:
        sniff(prn=handle, store=0, iface=args.iface, filter="ip", timeout=args.duration or None)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        flush()  # volcado final: el original perdia el ultimo buffer al salir


def cmd_train(args):
    import joblib
    from sklearn.ensemble import IsolationForest

    df = pd.read_csv(args.data).dropna(subset=['proto', 'src_ip', 'dst_ip', 'length'])
    fl = flows_from_packets(df, args.window)
    # Los flujos de 1-2 paquetes (ACKs sueltos, restos de ventana) son el 63% del
    # total y no son conversaciones. Dejarlos dentro hace que el bosque gaste sus
    # cortes separandolos, y todo lo demas queda indistinguible: medido, pasar de
    # min_packets 1 a 5 baja los falsos positivos de 279 a 46 por hora.
    fl = fl[fl['n_pkts'] >= args.min_packets]
    X = featurize_flows(fl)
    if len(X) < 500:
        print(f"[!] Solo {len(X)} flujos. Un modelo util necesita horas de baseline,")
        print("    no minutos: con tan pocos flujos el umbral no significa nada.")

    model = IsolationForest(n_estimators=args.trees, contamination=args.contamination,
                            random_state=42, n_jobs=-1).fit(X)
    scores = model.score_samples(X)
    rng = np.random.default_rng(0)
    ref = np.sort(rng.choice(scores, min(10_000, len(scores)), replace=False))
    threshold = float(np.quantile(scores, args.contamination))

    joblib.dump({'model': model, 'features': list(X.columns), 'score_ref': ref,
                 'threshold': threshold, 'samples': len(X), 'packets': len(df),
                 'window': args.window, 'min_packets': args.min_packets,
                 'trained': pd.Timestamp.now().isoformat(timespec='seconds')}, args.model)
    print(f"[+] {len(df)} paquetes -> {len(X)} flujos (ventana {args.window:g} s, "
          f"min {args.min_packets} paquetes)")
    print(f"[+] umbral p{args.contamination * 100:g} = {threshold:.4f} -> {args.model}")


def cmd_detect(args):
    import joblib
    from scapy.all import sniff, IP

    b = joblib.load(args.model)
    model, feats, ref = b['model'], b['features'], b['score_ref']
    thr = args.threshold if args.threshold is not None else b['threshold']
    window = b.get('window', WINDOW)  # la misma que al entrenar, o los flujos no comparan
    min_pkts = b.get('min_packets', 1)
    white, seen = set(args.whitelist), {}
    pending, last = [], time.time()

    print(f"[+] {args.model}: {b.get('samples', '?')} flujos, ventana {window:g} s, "
          f"umbral {thr:.4f}")
    print(f"[+] Escucha pasiva en {args.iface or 'interfaz por defecto'}. Ctrl-C para parar.",
          flush=True)

    def flush():
        """Agrupa la ventana acumulada y puntua los flujos de golpe.

        Micro-lotes en vez de estado de flujo incremental: asi detect llama a la
        MISMA flows_from_packets() que train, y no pueden divergir.
        """
        nonlocal last
        last = time.time()
        if not pending:
            return
        df = pd.DataFrame(pending, columns=COLS)
        pending.clear()
        fl = flows_from_packets(df, window)
        fl = fl[fl['n_pkts'] >= min_pkts]
        if fl.empty:
            return
        F = featurize_flows(fl)
        scores = model.score_samples(F[feats])
        beacons = beacon_rule(F).values
        for (_, f), s, es_beacon in zip(fl.iterrows(), scores, beacons):
            motivo = 'BEACON' if es_beacon else 'anomalia' if s < thr else None
            if motivo is None:
                continue
            key = f"{f.src_ip}:{f.sport} <-> {f.dst_ip}:{f.dport}"
            now = time.time()
            if now - seen.get(key, 0) < args.cooldown:
                continue
            seen[key] = now
            print(f"\n[!] {motivo}  {f.t0:%H:%M:%S}  score {s:.4f}  "
                  f"severidad {severity(s, ref)}%")
            print(f"    {key}  proto {f.proto}")
            print(f"    {f.n_pkts} paquetes / {f.n_bytes} B en {f.duration:.1f} s"
                  f"  |  intervalo {f.iat_mean or 0:.2f}s +-{f.iat_std or 0:.2f}", flush=True)

    def handle(pkt):
        if IP not in pkt:
            return
        row = row_from_pkt(pkt)
        if row['sport'] in white or row['dport'] in white or row['length'] < args.min_length:
            return
        pending.append(row)
        if time.time() - last >= window:
            flush()

    try:
        sniff(prn=handle, store=0, iface=args.iface, filter="ip", timeout=args.duration or None)
    except KeyboardInterrupt:
        pass
    finally:
        flush()


def _synthetic_beacon(t0, interval, count, dst='93.184.216.34', size=220):
    """Flujo regular hacia fuera: lo que hace un implante al llamar a casa."""
    return [dict(zip(COLS, (t0 + i * interval, '192.168.1.254', dst, 6,
                            51820, 443, size, size - 54))) for i in range(count)]


def cmd_validate(args):
    """Holdout temporal: entrena con el principio del CSV y mide sobre el final.

    Responde las dos preguntas que `eval` no puede: cuantos falsos positivos
    saldran por hora, y si el modelo veria un beacon que no estaba en el baseline.
    """
    from sklearn.ensemble import IsolationForest

    df = pd.read_csv(args.data).dropna(subset=['proto', 'src_ip', 'dst_ip', 'length'])
    fl = flows_from_packets(df, args.window).sort_values('t0')
    fl = fl[fl['n_pkts'] >= args.min_packets]
    if len(fl) < 50:
        print(f"[!] Solo {len(fl)} flujos: la medida no sera fiable. Captura mas tiempo.")
    cut = int(len(fl) * args.split)
    tr, te = fl.iloc[:cut], fl.iloc[cut:]
    Xtr = featurize_flows(tr)
    m = IsolationForest(n_estimators=args.trees, contamination=args.contamination,
                        random_state=42, n_jobs=-1).fit(Xtr)
    thr = float(np.quantile(m.score_samples(Xtr), args.contamination))
    ste = m.score_samples(featurize_flows(te))

    horas = max((te['t1'].max() - te['t0'].min()).total_seconds() / 3600, 1e-9)
    Xte = featurize_flows(te)
    n_anom = int((ste < thr).sum())
    n_regla = int(beacon_rule(Xte).sum())
    print(f"  entreno {len(tr)} flujos  |  test {len(te)} flujos no vistos ({horas:.2f} h)")
    print(f"  umbral  {thr:.4f}\n")
    print(f"  falsos positivos del modelo : {100 * (ste < thr).mean():5.2f}%  "
          f"= {n_anom / horas:.0f} alertas/hora")
    print(f"  disparos de la regla beacon : {100 * n_regla / len(te):5.2f}%  "
          f"= {n_regla / horas:.0f} alertas/hora")
    if n_regla:
        print("    (revisalos: suelen ser servicios periodicos legitimos, y una vez"
              "\n     identificados se filtran con --whitelist)")

    # Beacon sintetico dentro de la ventana de test: ni el modelo ni el baseline
    # lo han visto nunca. Si no lo marca, el sensor no sirve para lo que importa.
    # Alineado a la rejilla para que caiga entero en una ventana: la particion
    # por borde es un efecto conocido y aqui estorbaria a la medida.
    t0 = (te['t0'].min().timestamp() // args.window + 1) * args.window
    ref = np.sort(m.score_samples(Xtr))
    print(f"\n  beacon sintetico (220 B, hacia una IP publica):")
    for iv in (10, 30, 60):
        rows = _synthetic_beacon(t0, iv, max(5, int(args.window / iv)))
        B = featurize_flows(flows_from_packets(pd.DataFrame(rows, columns=COLS), args.window))
        s = float(m.score_samples(B[list(Xtr.columns)])[0])
        por_modelo, por_regla = s < thr, bool(beacon_rule(B).iloc[0])
        visto = 'regla' if por_regla else 'modelo' if por_modelo else 'NO DETECTADO'
        print(f"    cada {iv:>2}s ({int(B.n_pkts.iloc[0]):>2} pkts): score {s:.4f} "
              f"severidad {severity(s, ref):>5.1f}%  ->  {visto}")


def cmd_eval(args):
    import joblib
    import matplotlib
    if args.save:
        matplotlib.use('Agg')  # sin ventana: para servidores sin escritorio
    import matplotlib.pyplot as plt

    b = joblib.load(args.model)
    ref, thr = b['score_ref'], b['threshold']
    print(f"  flujos     {b.get('samples', '?')}  (de {b.get('packets', '?')} paquetes)")
    print(f"  ventana    {b.get('window', WINDOW):g} s")
    print(f"  features   {', '.join(b['features'])}")
    print(f"  umbral     {thr:.4f}")
    for p in (0.5, 1, 5, 50, 95):
        print(f"  p{p:<4g}      {np.percentile(ref, p):.4f}")
    # Si el grueso de los scores cae pegado al umbral, el corte es arbitrario:
    # separa flujos casi identicos y el baseline no da para discriminar.
    near = float((np.abs(ref - thr) < 0.005).mean())
    if near > 0.005:
        print(f"\n  [!] {near * 100:.1f}% de las muestras caen a menos de 0.005 del umbral.")
        print("      El corte separa flujos casi identicos: baseline poco representativo.")

    plt.hist(ref, bins=80, color='steelblue')
    plt.axvline(thr, color='crimson', ls='--', label=f"umbral {thr:.4f}")
    plt.xlabel('score de anomalia')
    plt.ylabel('flujos')
    plt.title(f"Distribucion de scores ({b.get('samples', '?')} flujos)")
    plt.legend()
    plt.tight_layout()
    if args.save:
        plt.savefig(args.save, dpi=120)
        print(f"\n  -> {args.save}")
    else:
        plt.show()


# --------------------------------------------------------------------------- cli

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)

    i = sub.add_parser('ifaces', help='lista interfaces')
    i.add_argument('--all', action='store_true', help='incluye las que no tienen IP utilizable')
    i.add_argument('-v', '--verbose', action='store_true', help='muestra el nombre interno')
    i.set_defaults(func=cmd_ifaces)

    c = sub.add_parser('capture', help='captura pasiva a CSV')
    c.add_argument('--iface')
    c.add_argument('--out', default=DATA)
    c.add_argument('--duration', type=int, default=0, help='segundos (0 = sin limite)')
    c.add_argument('--interval', type=int, default=10, help='segundos entre volcados')
    c.set_defaults(func=cmd_capture)

    t = sub.add_parser('train', help='entrena el modelo')
    t.add_argument('--data', default=DATA)
    t.add_argument('--model', default=MODEL)
    t.add_argument('--trees', type=int, default=150)
    t.add_argument('--contamination', type=float, default=0.01)
    t.add_argument('--window', type=float, default=WINDOW, help='segundos por flujo')
    t.add_argument('--min-packets', type=int, default=3,
                   help='descarta flujos mas cortos (ACKs sueltos, restos de ventana)')
    t.set_defaults(func=cmd_train)

    d = sub.add_parser('detect', help='puntua flujos en vivo')
    d.add_argument('--iface')
    d.add_argument('--model', default=MODEL)
    d.add_argument('--threshold', type=float, help='por defecto, el guardado al entrenar')
    d.add_argument('--duration', type=int, default=0)
    d.add_argument('--cooldown', type=int, default=300, help='segundos entre alertas iguales')
    d.add_argument('--min-length', type=int, default=0,
                   help='ignora paquetes menores (el default 128 original ocultaba ICMP y escaneos)')
    d.add_argument('--whitelist', type=int, nargs='*', default=[],
                   help='puertos a ignorar, p.ej. --whitelist 80 443 53')
    d.set_defaults(func=cmd_detect)

    v = sub.add_parser('validate', help='falsos positivos por hora y deteccion de beacon')
    v.add_argument('--data', default=DATA)
    v.add_argument('--window', type=float, default=WINDOW)
    v.add_argument('--trees', type=int, default=150)
    v.add_argument('--contamination', type=float, default=0.01)
    v.add_argument('--split', type=float, default=0.8, help='fraccion para entrenar')
    v.add_argument('--min-packets', type=int, default=3)
    v.set_defaults(func=cmd_validate)

    e = sub.add_parser('eval', help='distribucion de scores y umbral')
    e.add_argument('--model', default=MODEL)
    e.add_argument('--save', metavar='PNG', help='guarda el grafico en vez de abrir ventana')
    e.set_defaults(func=cmd_eval)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
