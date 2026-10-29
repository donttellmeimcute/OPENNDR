# OPENNDR

Sensor NDR pasivo. Agrupa el tráfico en flujos, aprende cómo son los normales en
tu red con un IsolationForest y avisa cuando aparece uno que no encaja.

Un solo archivo: [`ndr.py`](ndr.py).

```bash
pip install -r requirements.txt

python ndr.py ifaces                                     # ver interfaces
python ndr.py capture --iface Ethernet --duration 86400  # 24 h de tráfico normal
python ndr.py train                                      # entrena y calibra el umbral
python ndr.py validate                                   # ¿cuántos falsos positivos?
python ndr.py eval                                       # distribución de scores
python ndr.py detect --iface Ethernet                    # detección en vivo
```

Capturar requiere Npcap en Windows. No hace falta ser administrador si Npcap se
instaló sin la restricción a administradores.

## Dónde ponerlo

El sensor solo escucha: **no modifica la red**. Para ver tráfico que no sea el
de la propia máquina, conéctalo a un **puerto espejo (SPAN/mirror)** del switch
o a un TAP. Es como se despliega un NDR de verdad, y a diferencia de interceptar
con ARP spoofing no degrada la red, no rompe TLS ni es un único punto de fallo
para todo el tráfico.

## Flujos, no paquetes

El modelo puntúa **flujos**, no paquetes sueltos. Un flujo es una conversación
entre dos extremos (bidireccional: A→B y B→A son el mismo flujo) dentro de una
ventana de `--window` segundos, 300 por defecto.

Esto importa por dos motivos:

- **Volumen.** 257.266 paquetes se convierten en 875 flujos: un factor de 294.
  Puntuando paquetes, un 0,67 % de falsos positivos eran 3 alertas por segundo.
- **Lo que se puede ver.** Un beacon C2 que llama a casa cada 30 s es invisible
  paquete a paquete — cada uno suyo es HTTPS normal. Como flujo tiene una firma
  clarísima: intervalos idénticos (`iat_cv` ≈ 0), paquetes del mismo tamaño,
  poco volumen y mucha duración.

Por eso los flujos **no se parten por inactividad**, solo por la ventana: partir
un beacon de 30 s por sus huecos destruiría justo la señal que lo delata. La
ventana va en rejilla global, así que un flujo que cae sobre un borde sale
partido en dos.

Elige `--window` para que abarque varios intervalos del beacon que te preocupe:
con 300 s, uno que llame cada 30 s deja 10 muestras. Más ventana = mejor señal,
pero más latencia, porque `detect` puntúa una vez por ventana.

### Features

Las define `featurize_flows()`, y es el **único** sitio donde se definen —
entrenamiento y detección pasan por la misma función, así que no pueden
divergir. El modelo guarda su propia lista y `detect` se ciñe a ella.

| | |
|---|---|
| `duration`, `n_pkts`, `n_bytes`, `pps` | tamaño y ritmo |
| `len_mean`, `len_std` | tamaño de paquete y su dispersión |
| `iat_mean`, `iat_std`, `iat_cv` | **regularidad** — `iat_cv` ≈ 0 es un reloj |
| `fwd_ratio` | fracción de bytes que **sale**; alto = exfiltración |
| `service_port`, `external`, `proto_*` | qué servicio, y si sale a internet |
| `hour_sin`, `hour_cos` | hora cíclica (23:00 y 00:00 contiguas) |

`iat_cv` va aparte de `iat_std` a propósito: un flujo de uno o dos paquetes
también tiene desviación 0, y como son muy comunes hacían que "std 0" pareciese
lo normal y el beacon se perdiera entre ellos. Sin intervalos suficientes,
`iat_cv` vale 1 — *no hay evidencia de regularidad*, que no es lo mismo que
*es regular*.

## El baseline es el 90 % del trabajo

El modelo es **no supervisado**: asume que lo que capturas al entrenar es
mayoritariamente normal. Dos reglas:

1. **Captura horas, no minutos.** Con 60 s de baseline que era 91 % QUIC, el
   modelo marcaba el 11,6 % de todo el TCP: había aprendido "UDP es normal". Con
   5 min y 76/24 bajó al 6,8 %. Hace falta cubrir el ciclo diario entero.
2. **Mide antes de desplegar.** `python ndr.py validate` entrena con el principio
   del CSV, mide sobre el final que no ha visto y te da los falsos positivos por
   hora. Además inyecta un beacon sintético y te dice si lo vería.

El umbral sale del percentil `--contamination` (1 % por defecto) de los scores de
entrenamiento. Es el dial para ajustar falsos positivos:

```bash
python ndr.py train --contamination 0.005   # más estricto, menos alertas
python ndr.py detect --threshold -0.8       # o fíjalo a mano
```

`eval` dibuja la distribución real y avisa si el grueso de los scores cae pegado
al umbral — señal de que el baseline no da para discriminar.

## Dos detectores, no uno

`detect` aplica dos cosas a cada flujo, y la alerta dice cuál saltó:

- **`anomalia`** — el IsolationForest. Encuentra lo raro y ruidoso: transferencias
  enormes, puertos insólitos, ritmos imposibles.
- **`BEACON`** — una regla fija: `iat_cv < 0.1` y ≥ 5 paquetes y hacia una IP
  pública. Un flujo con intervalos de reloj saliendo a internet.

La regla existe porque **el modelo no sirve para esto, y está medido**. Un beacon
está diseñado para ser silencioso y aburrido; el detector de anomalías busca lo
contrario. Sobre 24,5 min de tráfico real, un beacon sintético se quedó en
severidad 88-93 %: anómalo, pero nunca en el 1 % que cruza el umbral. Para
cogerlo con el modelo habría que subir el umbral hasta 873 alertas/hora.

Medido sobre esos mismos datos (2.087.752 paquetes, 2.918 flujos):

| | |
|---|---|
| Falsos positivos del modelo | 1,54 % = **97 alertas/hora** |
| Falsos positivos de la regla | **0** |
| Beacon a 10 s / 30 s / 60 s | detectado por la regla, los tres |
| En vivo, 6 min | 3 alertas (la mayor: una transferencia de 67 MB) |

Esto es cómo funciona un NDR de verdad: anomalías para lo que no sabes nombrar,
reglas dirigidas para los comportamientos que sí. Ninguno de los dos basta solo.

## Limitaciones

- **Timestamps.** Las capturas nuevas guardan epoch con decimales. El CSV antiguo
  del repo tiene resolución de 1 s, y ahí la regularidad es inmedible: el 55 % de
  sus flujos salen con `iat_std = 0` porque todos los paquetes del segundo
  comparten marca de tiempo. Sirve para probar el pipeline, no para entrenar.
- **Sin seguimiento de estado TCP.** No mira FIN/RST ni reensambla sesiones; la
  ventana es lo único que acota un flujo.
- **Los flujos de 1-2 paquetes se descartan** (`--min-packets`, 3 por defecto).
  Son el 63 % del total y no son conversaciones: dejarlos dentro hacía que el
  bosque gastara sus cortes separándolos y todo lo demás quedaba indistinguible.
  Medido: pasar de 1 a 5 baja los falsos positivos de 279 a 46 por hora. El
  precio es que la detección de escaneos, que vive justo en esos flujos de un
  paquete, necesitaría su propia regla (destinos distintos por origen).
- **97 falsos positivos/hora con 20 min de baseline.** Es la cifra honesta de una
  línea base corta, no el techo del método. Captura 24 h y vuelve a medir con
  `validate` antes de concluir nada.
- `--min-length` y `--whitelist` vienen vacíos a propósito. Los valores del
  código original (128 bytes, puertos 80/443/53) escondían justo lo que interesa.
- Un host solo ve su propio tráfico. Sin puerto espejo esto no es un NDR de red,
  es un monitor de una máquina.

## Qué se quitó

La versión anterior hacía **ARP spoofing** contra todos los hosts de la LAN para
verlos desde una máquina cualquiera, y reenviaba los paquetes interceptados.
Eso es un MITM: convierte al sensor en el cuello de botella de toda la red, y
cualquier fallo suyo deja a los hosts sin conectividad. Un puerto espejo da la
misma visibilidad sin tocar nada.

También se eliminó `xpected.py`, que pintaba una curva ROC con números inventados
a mano (`fpr`/`tpr` escritos en el código) bajo el título de resultados del
sistema. `ndr.py eval` y `ndr.py validate` lo sustituyen con medidas reales.
