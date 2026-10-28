"""Check minimo: lo que se rompe si featurize() se desincroniza.

    python test_ndr.py
"""
import numpy as np
import pandas as pd

from ndr import COLS, featurize, severity

ROW = dict(zip(COLS, ('2025-01-29 23:30:00', '192.168.1.10', '8.8.8.8', 6, 51000, 443, 1500, 1448)))


def test_parity():
    """La fila de un paquete en vivo y la de un CSV dan exactamente las mismas features."""
    live = featurize(pd.DataFrame([ROW]))
    csv = featurize(pd.read_csv(pd.io.common.StringIO(
        ','.join(COLS) + '\n' + ','.join(str(ROW[c]) for c in COLS) + '\n')))
    assert list(live.columns) == list(csv.columns), (list(live.columns), list(csv.columns))
    assert np.allclose(live.values, csv.values), (live.values, csv.values)


def test_hour_is_cyclic():
    """23:00 y 00:00 deben quedar contiguas, no a 23 de distancia."""
    f = featurize(pd.DataFrame([{**ROW, 'timestamp': '2025-01-29 23:00:00'},
                                {**ROW, 'timestamp': '2025-01-30 00:00:00'},
                                {**ROW, 'timestamp': '2025-01-30 12:00:00'}]))
    d = lambda a, b: np.hypot(*(f.iloc[a][['hour_sin', 'hour_cos']].values
                                - f.iloc[b][['hour_sin', 'hour_cos']].values))
    assert d(0, 1) < d(0, 2), (d(0, 1), d(0, 2))


def test_payload_ratio_only_when_available():
    """Sin payload_len no se inventa la feature (antes entrenaba a 0.0 y detectaba real)."""
    assert 'payload_ratio' in featurize(pd.DataFrame([ROW]))
    assert 'payload_ratio' not in featurize(pd.DataFrame([{k: v for k, v in ROW.items()
                                                           if k != 'payload_len'}]))


def test_l4_ports_and_protos():
    f = featurize(pd.DataFrame([ROW])).iloc[0]
    assert (f['sport'], f['dport']) == (51000, 443)
    assert (f['proto_6'], f['proto_17'], f['proto_1']) == (1, 0, 0)
    assert f['local_ip'] == 1 and abs(f['payload_ratio'] - 1448 / 1500) < 1e-9


def test_severity_is_a_percentile():
    ref = np.sort(np.linspace(-0.6, 0.1, 1000))
    assert severity(ref[0] - 1, ref) == 100.0   # mas raro que todo lo visto
    assert severity(ref[-1] + 1, ref) == 0.0    # perfectamente normal
    assert 40 < severity(np.median(ref), ref) < 60


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_'):
            fn()
            print(f"ok  {name}")
    print("\nTodo correcto.")
