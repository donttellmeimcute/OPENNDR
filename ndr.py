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
    from scapy.all import get_if_list, get_if_addr
    for name in get_if_list():
        try:
            addr = get_if_addr(name)
        except Exception:
            addr = '?'
        print(f"  {name}  {addr}")


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

    def handle(pkt):
        if IP not in pkt:
            return
        row = row_from_pkt(pkt)
        if row['sport'] in white or row['dport'] in white or row['length'] < args.min_length:
            return
        # ponytail: un score_samples por paquete (~1 ms). Si satura, acumular en
        # lotes de N paquetes y puntuar el lote de golpe.
        s = float(model.score_samples(featurize(pd.DataFrame([row]))[feats])[0])
        if s >= thr:
            return
        key = f"{row['src_ip']}:{row['sport']} > {row['dst_ip']}:{row['dport']}"
        now = time.time()
        if now - seen.get(key, 0) < args.cooldown:
            return
        seen[key] = now
        print(f"\n[!] {row['timestamp']}  score {s:.4f}  severidad {severity(s, ref)}%")
        print(f"    {key}  proto {row['proto']}  {row['length']} B "
              f"(payload {row['payload_len']} B)")

    sniff(prn=handle, store=0, iface=args.iface, filter="ip", timeout=args.duration or None)


def cmd_eval(args):
    import joblib
    import matplotlib.pyplot as plt

    b = joblib.load(args.model)
    plt.hist(b['score_ref'], bins=80, color='steelblue')
    plt.axvline(b['threshold'], color='crimson', ls='--', label=f"umbral {b['threshold']:.4f}")
    plt.xlabel('score de anomalia')
    plt.ylabel('muestras')
    plt.title(f"Distribucion de scores ({b.get('samples', '?')} muestras)")
    plt.legend()
    plt.tight_layout()
    plt.show()


# --------------------------------------------------------------------------- cli

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)

    sub.add_parser('ifaces', help='lista interfaces').set_defaults(func=cmd_ifaces)

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
    d.set_defaults(func=cmd_detect)

    e = sub.add_parser('eval', help='distribucion de scores y umbral')
    e.add_argument('--model', default=MODEL)
    e.set_defaults(func=cmd_eval)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
