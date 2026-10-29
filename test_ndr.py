"""Check minimo: lo que se rompe si la agregacion de flujos se desincroniza.

    python test_ndr.py
"""
import numpy as np
import pandas as pd

from ndr import COLS, FLOW_FEATURES, featurize_flows, flows_from_packets, severity

# Epoch fijo (para no depender de la hora) y multiplo de 300 y de 900: las
# ventanas van en rejilla global, no desde el primer paquete del flujo.
T0 = 1_761_599_700.0


def p(t, src, dst, sport, dport, length=1000, proto=6):
    """Un paquete, en el mismo orden que COLS."""
    return (T0 + t, src, dst, proto, sport, dport, length, max(0, length - 54))


def flujo(rows, window=300.0):
    return flows_from_packets(pd.DataFrame([dict(zip(COLS, r)) for r in rows],
                                           columns=COLS), window)


def test_bidireccional_es_un_solo_flujo():
    """A->B y B->A son la misma conversacion, no dos flujos."""
    fl = flujo([p(0, '10.0.0.5', '1.1.1.1', 51000, 443),
                p(1, '1.1.1.1', '10.0.0.5', 443, 51000)])
    assert len(fl) == 1, fl
    assert fl.iloc[0].n_pkts == 2


def test_beacon_tiene_iat_std_bajo():
    """La senal que el modelo por paquetes no podia ver."""
    beacon = flujo([p(30 * i, '10.0.0.5', '1.1.1.1', 51000, 443, 200) for i in range(10)])
    rafaga = flujo([p(t, '10.0.0.5', '2.2.2.2', 51001, 443, 200)
                    for t in (0, 1, 2, 3, 60, 61, 120, 200, 201, 290)])
    b, r = featurize_flows(beacon).iloc[0], featurize_flows(rafaga).iloc[0]
    assert b.iat_std < 0.001, b.iat_std            # intervalos identicos
    assert r.iat_std > 10 * max(b.iat_std, 1e-6)   # irregular
    assert abs(b.iat_mean - 30) < 0.001, b.iat_mean


def test_la_ventana_trocea_flujos_largos():
    """Una descarga larga no puede ser un unico registro."""
    largo = [p(t, '10.0.0.5', '1.1.1.1', 51000, 443) for t in range(0, 900, 10)]
    assert len(flujo(largo, window=300.0)) == 3
    assert len(flujo(largo, window=900.0)) == 1


def test_sin_nan_ni_columnas_de_mas():
    """Un flujo de un solo paquete no puede colar NaN en el modelo."""
    f = featurize_flows(flujo([p(0, '10.0.0.5', '8.8.8.8', 0, 0, 74, proto=1)]))
    assert list(f.columns) == FLOW_FEATURES, list(f.columns)
    assert not f.isna().any().any(), f
    assert f.iloc[0].proto_1 == 1 and f.iloc[0].n_pkts == 1


def test_direccion_y_exfiltracion():
    """fwd = puerto alto (cliente): fwd_ratio alto significa mucho subiendo."""
    subida = featurize_flows(flujo(
        [p(i, '10.0.0.5', '1.1.1.1', 51000, 443, 1400) for i in range(10)] +
        [p(i, '1.1.1.1', '10.0.0.5', 443, 51000, 60) for i in range(10)])).iloc[0]
    assert subida.fwd_ratio > 0.9, subida.fwd_ratio
    assert subida.external == 1
    assert subida.service_port == 443


def test_external_solo_con_ip_enrutable():
    interno = featurize_flows(flujo([p(0, '192.168.1.10', '192.168.1.20', 51000, 445)])).iloc[0]
    fuera = featurize_flows(flujo([p(0, '192.168.1.10', '93.184.216.34', 51000, 443)])).iloc[0]
    # TEST-NET y CGNAT no son enrutables: no cuentan como salida a internet
    reservada = featurize_flows(flujo([p(0, '192.168.1.10', '203.0.113.7', 51000, 443)])).iloc[0]
    assert interno.external == 0
    assert fuera.external == 1
    assert reservada.external == 0


def test_epoch_y_texto_dan_lo_mismo():
    """El CSV antiguo (texto) y las capturas nuevas (epoch) deben coincidir."""
    rows = [p(0, '10.0.0.5', '1.1.1.1', 51000, 443),
            p(7, '1.1.1.1', '10.0.0.5', 443, 51000)]
    epoch = pd.DataFrame([dict(zip(COLS, r)) for r in rows], columns=COLS)
    texto = epoch.assign(timestamp=pd.to_datetime(epoch.timestamp, unit='s')
                         .dt.strftime('%Y-%m-%d %H:%M:%S'))
    a = featurize_flows(flows_from_packets(epoch))
    b = featurize_flows(flows_from_packets(texto))
    assert list(a.columns) == list(b.columns)
    assert np.allclose(a.values, b.values), (a.values, b.values)


def test_severidad_es_un_percentil():
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
