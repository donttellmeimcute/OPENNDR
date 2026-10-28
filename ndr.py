#!/usr/bin/env python3
"""OPENNDR - sensor NDR pasivo basado en IsolationForest.

Escucha en una interfaz (idealmente un puerto espejo/SPAN), extrae features por
paquete y puntua cada uno contra un modelo no supervisado entrenado con el
trafico normal de la propia red.

    python ndr.py ifaces
    python ndr.py capture --iface Ethernet --duration 600
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


# --------------------------------------------------------------------------- features

def _is_private(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def featurize(df):
    """Unico sitio donde se definen las features.

    Entrenamiento e inferencia llaman aqui con el mismo esquema de fila, asi que
    no pueden divergir (el bug original: payload_ratio salia 0.0 al entrenar y
    real al detectar).
    """
    h = pd.to_datetime(df['timestamp']).dt.hour
    f = pd.DataFrame(index=df.index)
    # Hora ciclica: con 'hour' crudo, las 23:00 y las 00:00 quedaban a 23 de distancia.
    f['hour_sin'] = np.sin(2 * np.pi * h / 24)
    f['hour_cos'] = np.cos(2 * np.pi * h / 24)
    for c in ('sport', 'dport', 'length'):
        f[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
    priv = {ip: _is_private(ip) for ip in df['src_ip'].unique()}
    f['local_ip'] = df['src_ip'].map(priv).astype(int)
    proto = pd.to_numeric(df['proto'], errors='coerce')
    for p in PROTOS:
        f[f'proto_{p}'] = (proto == p).astype(int)
    if 'payload_len' in df.columns:
        f['payload_ratio'] = (pd.to_numeric(df['payload_len'], errors='coerce').fillna(0)
                              / f['length'].replace(0, 1))
    return f


def row_from_pkt(pkt):
    """Paquete -> fila con el mismo esquema que el CSV, para reusar featurize()."""
    from scapy.all import IP, TCP, UDP
    ip = pkt[IP]
    l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
    return dict(zip(COLS, (
        time.strftime('%Y-%m-%d %H:%M:%S'), ip.src, ip.dst, int(ip.proto),
        # sport/dport viven en la capa 4, no en IP: leerlos de pkt[IP] lanzaba
        # AttributeError en cada paquete y el filtro de puertos nunca se aplicaba.
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
    buf = deque(maxlen=200_000)
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
            print(f"[+] {len(rows)} paquetes -> {args.out}")

    def saver():
        while not stop.wait(args.interval):
            flush()

    threading.Thread(target=saver, daemon=True).start()
    print(f"[+] Capturando en {args.iface or 'interfaz por defecto'} "
          f"({args.duration or 'sin limite'} s). Ctrl-C para parar.")
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
    # Sin drop_duplicates(): los paquetes repetidos son la senal de volumen, y
    # deduplicarlos hacia que el modelo viera una distribucion que no existe en vivo.
    X = featurize(df)
    model = IsolationForest(n_estimators=args.trees, contamination=args.contamination,
                            random_state=42, n_jobs=-1).fit(X)

    scores = model.score_samples(X)
    rng = np.random.default_rng(0)
    ref = np.sort(rng.choice(scores, min(10_000, len(scores)), replace=False))
    threshold = float(np.quantile(scores, args.contamination))

    joblib.dump({'model': model, 'features': list(X.columns), 'score_ref': ref,
                 'threshold': threshold, 'samples': len(df),
                 'trained': pd.Timestamp.now().isoformat(timespec='seconds')}, args.model)
    print(f"[+] {len(df)} muestras, features: {', '.join(X.columns)}")
    print(f"[+] umbral p{args.contamination * 100:g} = {threshold:.4f} -> {args.model}")


def cmd_detect(args):
    import joblib
    from scapy.all import sniff, IP

    b = joblib.load(args.model)
    model, feats, ref = b['model'], b['features'], b['score_ref']
    thr = args.threshold if args.threshold is not None else b['threshold']
    white, seen = set(args.whitelist), {}

    print(f"[+] {args.model}: {b.get('samples', '?')} muestras, umbral {thr:.4f}")
    print(f"[+] Escucha pasiva en {args.iface or 'interfaz por defecto'}. Ctrl-C para parar.")

    # Puntuar paquete a paquete cuesta ~4 ms (techo ~250 pkt/s, por debajo de una
    # Wi-Fi domestica). En lote son ~2 us/paquete: el coste es montar el DataFrame
    # y entrar al modelo, no el arbol. De ahi el buffer.
    pending, last = [], time.time()

    def score_batch(rows):
        X = featurize(pd.DataFrame(rows))[feats]
        for row, s in zip(rows, model.score_samples(X)):
            if s >= thr:
                continue
            key = f"{row['src_ip']}:{row['sport']} > {row['dst_ip']}:{row['dport']}"
            now = time.time()
            if now - seen.get(key, 0) < args.cooldown:
                continue
            seen[key] = now
            print(f"\n[!] {row['timestamp']}  score {s:.4f}  severidad {severity(s, ref)}%")
            print(f"    {key}  proto {row['proto']}  {row['length']} B "
                  f"(payload {row['payload_len']} B)")

    def flush():
        nonlocal last
        if pending:
            rows, last = pending.copy(), time.time()
            pending.clear()
            score_batch(rows)

    def handle(pkt):
        if IP not in pkt:
            return
        row = row_from_pkt(pkt)
        if row['sport'] in white or row['dport'] in white or row['length'] < args.min_length:
            return
        pending.append(row)
        if len(pending) >= args.batch or time.time() - last >= args.max_delay:
            flush()

    try:
        sniff(prn=handle, store=0, iface=args.iface, filter="ip", timeout=args.duration or None)
    except KeyboardInterrupt:
        pass
    finally:
        flush()


def cmd_eval(args):
    import joblib
    import matplotlib
    if args.save:
        matplotlib.use('Agg')  # sin ventana: para servidores sin escritorio
    import matplotlib.pyplot as plt

    b = joblib.load(args.model)
    ref, thr = b['score_ref'], b['threshold']
    print(f"  muestras   {b.get('samples', '?')}")
    print(f"  features   {', '.join(b['features'])}")
    print(f"  umbral     {thr:.4f}")
    for p in (0.5, 1, 5, 50, 95):
        print(f"  p{p:<4g}      {np.percentile(ref, p):.4f}")
    # Si el grueso de los scores cae pegado al umbral, el corte es arbitrario:
    # separa paquetes casi identicos y el baseline no da para discriminar.
    near = float((np.abs(ref - thr) < 0.005).mean())
    if near > 0.005:
        print(f"\n  [!] {near * 100:.1f}% de las muestras caen a menos de 0.005 del umbral.")
        print("      El corte separa paquetes casi identicos: baseline poco representativo.")

    plt.hist(ref, bins=80, color='steelblue')
    plt.axvline(thr, color='crimson', ls='--', label=f"umbral {thr:.4f}")
    plt.xlabel('score de anomalia')
    plt.ylabel('muestras')
    plt.title(f"Distribucion de scores ({b.get('samples', '?')} muestras)")
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
    t.set_defaults(func=cmd_train)

    d = sub.add_parser('detect', help='puntua trafico en vivo')
    d.add_argument('--iface')
    d.add_argument('--model', default=MODEL)
    d.add_argument('--threshold', type=float, help='por defecto, el guardado al entrenar')
    d.add_argument('--duration', type=int, default=0)
    d.add_argument('--cooldown', type=int, default=30, help='segundos entre alertas iguales')
    d.add_argument('--min-length', type=int, default=0,
                   help='ignora paquetes menores (el default 128 original ocultaba ICMP y escaneos)')
    d.add_argument('--whitelist', type=int, nargs='*', default=[],
                   help='puertos a ignorar, p.ej. --whitelist 80 443 53')
    d.add_argument('--batch', type=int, default=256, help='paquetes por lote a puntuar')
    d.add_argument('--max-delay', type=float, default=2.0,
                   help='segundos maximos que un paquete espera en el lote')
    d.set_defaults(func=cmd_detect)

    e = sub.add_parser('eval', help='distribucion de scores y umbral')
    e.add_argument('--model', default=MODEL)
    e.add_argument('--save', metavar='PNG', help='guarda el grafico en vez de abrir ventana')
    e.set_defaults(func=cmd_eval)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
