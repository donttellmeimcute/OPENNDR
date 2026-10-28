# OPENNDR

Sensor NDR pasivo. Aprende cómo es el tráfico normal de tu red con un
IsolationForest y avisa cuando algo se sale de esa distribución.

Un solo archivo: [`ndr.py`](ndr.py).

```bash
pip install -r requirements.txt

python ndr.py ifaces                              # ver interfaces
python ndr.py capture --iface Ethernet --duration 3600   # 1 h de tráfico normal
python ndr.py train                               # entrena y calibra el umbral
python ndr.py eval                                # distribución de scores
python ndr.py detect --iface Ethernet             # detección en vivo
```

Capturar requiere privilegios (root / Administrador) y Npcap en Windows.

## Dónde ponerlo

El sensor solo escucha: **no modifica la red**. Para ver tráfico que no sea el
de la propia máquina, conéctalo a un **puerto espejo (SPAN/mirror)** del switch
o a un TAP. Es como se despliega un NDR de verdad, y a diferencia de interceptar
con ARP spoofing no degrada la red, no rompe TLS ni es un único punto de fallo
para todo el tráfico.

## Entrenamiento

El modelo es **no supervisado**: asume que lo que capturas al entrenar es
mayoritariamente normal. Captura con la red en un día tranquilo. El umbral sale
del percentil `--contamination` (por defecto 1%) de los scores de entrenamiento,
así que es el dial para ajustar falsos positivos:

```bash
python ndr.py train --contamination 0.005   # menos alertas, más estricto
python ndr.py detect --threshold -0.8       # o fíjalo a mano
```

`eval` dibuja la distribución real de scores con el umbral marcado: es la forma
honesta de elegirlo.

## Features

Las define `featurize()`, y es el **único** sitio donde se definen — entrenamiento
y detección pasan por la misma función, así que no pueden divergir. El modelo
guarda su propia lista de features y la detección se ciñe a ella.

`hour_sin`/`hour_cos` (hora cíclica), `sport`, `dport`, `length`, `local_ip`,
`proto_1`/`proto_6`/`proto_17` (ICMP/TCP/UDP) y `payload_ratio` cuando el CSV
trae `payload_len`.

## Limitaciones

Medido sobre una Wi-Fi doméstica (136.918 paquetes en 5 min, ~450 pkt/s),
entrenando con 4 minutos y midiendo sobre el minuto siguiente no visto:

| | |
|---|---|
| Alertas sobre tráfico normal no visto | 0,67 % |
| En términos operativos | **181 alertas en 60 s = 3 por segundo** |
| Concentración | 6,83 % del TCP, 0,00 % del UDP |

**Esa es la limitación de fondo: puntúa paquetes sueltos, no flujos.** Un 0,67 %
suena bien hasta que lo multiplicas por el volumen de paquetes — son ~10.000
falsos positivos por hora, todos tráfico HTTPS corriente. Y al revés, un beacon
C2 regular o un escaneo lento pasan desapercibidos, porque cada paquete suyo es
individualmente normal.

Agregar por flujo (bytes totales, duración, nº de paquetes, periodicidad) antes
de puntuar es **la mejora que hace falta para que esto sea usable**, no un extra.

Otras:

- El modelo tiende a aprender "el protocolo mayoritario es lo normal". Con un
  baseline de 60 s que era 91 % QUIC, marcaba el 11,6 % de todo el TCP. Con 5 min
  y 76/24 bajó al 6,8 %. Hacen falta **horas** de baseline cubriendo el ciclo
  diario, no minutos.
- `eval` avisa cuando el grueso de los scores cae pegado al umbral: ahí el corte
  separa paquetes casi idénticos y el baseline no da para discriminar.
- `--min-length` y `--whitelist` vienen vacíos a propósito. Los valores del código
  original (128 bytes, puertos 80/443/53) escondían justo lo que interesa:
  ICMP, escaneos y el grueso del tráfico real.
- Captura en Windows necesita Npcap. No hace falta ser administrador si Npcap se
  instaló sin la restricción a administradores.

## Qué se quitó

La versión anterior hacía **ARP spoofing** contra todos los hosts de la LAN para
verlos desde una máquina cualquiera, y reenviaba los paquetes interceptados.
Eso es un MITM: convierte al sensor en el cuello de botella de toda la red, y
cualquier fallo suyo deja a los hosts sin conectividad. Un puerto espejo da la
misma visibilidad sin tocar nada.

También se eliminó `xpected.py`, que pintaba una curva ROC con números inventados
a mano (`fpr`/`tpr` escritos en el código) bajo el título de resultados del
sistema. `python ndr.py eval` lo sustituye por la distribución real del modelo.
