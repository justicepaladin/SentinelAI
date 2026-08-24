# SentinelAI - Demo Nivel 1 (Replay del Dataset CIC-IDS2017)

## Propósito de la demo

Esta rama contiene un escenario reproducible para demostrar el pipeline completo
de SentinelAI sin depender de una captura de red en vivo. El cliente
`SentinelAI-Edge/demo_replay.py` toma una muestra controlada de flujos
CIC-IDS2017 con sus características ya extraídas, la envía flujo por flujo al
backend y muestra el resultado de la inferencia en tiempo real.

La demostración recorre el circuito end-to-end:

```text
CIC-IDS2017 (Wednesday)
          │  80 flujos benignos + 20 ataques, mezclados
          ▼
     demo_replay.py
          │  POST /ingest
          ▼
       API FastAPI
          │  MinMaxScaler + Autoencoder
          ▼
 cálculo de MSE y comparación con TAU
          ├──────────────► clasificación en consola
          └── anomalía ──► tabla alerts en PostgreSQL
```

El backend normaliza las 78 características esperadas por el modelo, reconstruye
el flujo con el Autoencoder y calcula el error cuadrático medio (MSE):

$$
\operatorname{MSE}(x, \hat{x}) = \frac{1}{n}\sum_{i=1}^{n}(x_i-\hat{x}_i)^2
$$

Un flujo se clasifica como anómalo cuando su MSE supera el umbral configurado
(`TAU = 0.000308`). Las anomalías se guardan en PostgreSQL; los flujos
clasificados como normales no se persisten.

## Valor técnico

La Demo Nivel 1 desacopla la validación del modelo de las variables propias de la
captura en vivo, como el tráfico disponible, la interfaz de red, los permisos del
sensor o el tiempo necesario para observar un ataque. Al utilizar una selección
repetible (`random_state=42`), permite comparar la etiqueta real de los mismos 80
flujos benignos y 20 ataques con la decisión del Autoencoder. El orden de envío
se mezcla de nuevo en cada ejecución, pero la composición de la muestra se
mantiene.

Cada línea de la consola presenta la etiqueta real, la clasificación producida
por SentinelAI y el MSE. Esa comparación hace visibles los verdaderos positivos,
falsos positivos, verdaderos negativos y falsos negativos que sustentan la
validación empírica de las métricas de *Precision* y *Recall*:

$$
\operatorname{Precision} = \frac{TP}{TP+FP}
\qquad
\operatorname{Recall} = \frac{TP}{TP+FN}
$$

`demo_replay.py` no calcula automáticamente el resumen agregado de estas
métricas; muestra la evidencia flujo por flujo para contrastar el comportamiento
del modelo con las métricas obtenidas durante su evaluación.

## Componentes involucrados

| Componente | Función en la demo |
| --- | --- |
| `SentinelAI-Edge/demo_replay.py` | Selecciona 80 flujos benignos y 20 ataques, los mezcla y los inyecta secuencialmente. |
| `SentinelAI-Backend/main.py` | Expone `POST /ingest`, ejecuta la inferencia y devuelve el MSE y la clasificación. |
| `SentinelAI-Backend/database.py` | Crea la tabla `alerts` y administra la persistencia mediante SQLAlchemy. |
| `SentinelAI-Model/models/sentinel_scaler.save` | Aplica la misma normalización utilizada durante el entrenamiento. |
| `SentinelAI-Model/models/sentinel_model.h5` | Autoencoder entrenado para reconstruir tráfico benigno. |
| `sentinel-postgres` | Contenedor PostgreSQL que almacena las alertas detectadas. |

## Requisitos previos

- Linux con Docker en ejecución.
- Python 3.10 o superior y soporte para entornos virtuales (`venv`).
- Rama `demo50` activa.
- Dataset de los miércoles de CIC-IDS2017 en
  `SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv`.
- Modelo entrenado en `SentinelAI-Model/models/sentinel_model.h5`.
- Scaler en `SentinelAI-Model/models/sentinel_scaler.save`.
- Puerto `5432` disponible para PostgreSQL y puerto `8000` disponible para la
  API.

El dataset y el archivo `.h5` se distribuyen por separado y están ignorados por
Git. Esta rama tampoco utiliza `docker-compose.yml`: PostgreSQL se inicia
directamente con Docker.

## Guía de Ejecución Paso a Paso

Todos los comandos siguientes parten desde la raíz del repositorio, es decir, el
directorio que contiene `SentinelAI-Backend`, `SentinelAI-Edge` y
`SentinelAI-Model`.

### 1. Seleccionar la rama de la demo

```bash
git switch demo50
```

### 2. Levantar PostgreSQL

El siguiente comando inicia `sentinel-postgres` si ya existe; si es la primera
ejecución, crea el contenedor con la imagen PostgreSQL 16 y las credenciales de
la demo:

```bash
docker start sentinel-postgres 2>/dev/null || docker run \
  --name sentinel-postgres \
  -e POSTGRES_USER=sentinel_user \
  -e POSTGRES_PASSWORD=sentinel_password \
  -e POSTGRES_DB=sentinel_db \
  -p 5432:5432 \
  -d postgres:16
```

Comprobar que PostgreSQL acepta conexiones:

```bash
docker exec sentinel-postgres pg_isready \
  -U sentinel_user \
  -d sentinel_db
```

La salida esperada contiene `accepting connections`. Si el contenedor acaba de
crearse y todavía está inicializándose, esperar unos segundos y repetir la
comprobación.

### 3. Preparar y activar el entorno virtual

Entrar al backend y crear el entorno solamente si todavía no existe:

```bash
cd SentinelAI-Backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r ../SentinelAI-Edge/requirements.txt
```

En ejecuciones posteriores basta con:

```bash
cd SentinelAI-Backend
source .venv/bin/activate
```

### 4. Verificar los artefactos requeridos

Desde `SentinelAI-Backend`, ejecutar:

```bash
test -f ../SentinelAI-Model/models/sentinel_model.h5 && \
  test -f ../SentinelAI-Model/models/sentinel_scaler.save && \
  test -f ../SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv && \
  echo 'Artefactos y dataset disponibles.'
```

Si aparece el mensaje de confirmación, los tres archivos están en las rutas
esperadas. Si no aparece, comprobar individualmente las rutas para identificar el
archivo que falta.

### 5. Iniciar el backend localmente

Mantener abierta esta primera terminal, con el entorno virtual activo, y ejecutar:

```bash
export DATABASE_URL='postgresql://sentinel_user:sentinel_password@localhost:5432/sentinel_db'
uvicorn main:app --host 0.0.0.0 --port 8000
```

Uvicorn debe informar que la aplicación completó el arranque y está disponible
en `http://0.0.0.0:8000`. La documentación interactiva de la API queda en
`http://localhost:8000/docs`.

### 6. Abrir una terminal paralela y ejecutar el replay

Sin cerrar la terminal del backend, abrir una segunda terminal. Volver a la raíz
del repositorio y ejecutar:

```bash
cd SentinelAI-Backend
source .venv/bin/activate
curl http://127.0.0.1:8000/health
cd ../SentinelAI-Edge
python demo_replay.py
```

Es importante iniciar `demo_replay.py` desde `SentinelAI-Edge`, porque el script
resuelve desde allí la ruta relativa al dataset de los miércoles.

### 7. Interpretar la salida en pantalla

El replay anuncia primero la preparación de 100 flujos y luego imprime una línea
por inferencia. Por ejemplo:

```text
[*] Cargando dataset para el Replay (Nivel 1)...
[+] Dataset preparado. Iniciando inyección de 100 flujos...
[001] REAL: BENIGN          | IA: 🟢 NORMAL             | MSE: 0.000012
[002] REAL: DoS Hulk        | IA: 🚨 ANOMALÍA DETECTADA | MSE: 0.001234
```

La muestra contiene una selección reproducible de 80 etiquetas reales benignas y
20 etiquetas reales de ataque, mezcladas en un orden aleatorio en cada ejecución.
La cantidad de predicciones `NORMAL` y `ANOMALÍA DETECTADA` no tiene por qué
coincidir con esa división: las diferencias representan falsos positivos o falsos
negativos y son precisamente las que afectan a *Precision* y *Recall*.

### 8. Verificar la persistencia de anomalías

En la segunda terminal, una vez finalizado el replay, consultar las alertas más
recientes:

```bash
docker exec -it sentinel-postgres \
  psql -U sentinel_user -d sentinel_db \
  -c 'SELECT id, timestamp, source_ip, destination_ip, destination_port, mse_score FROM alerts ORDER BY id DESC LIMIT 20;'
```

La tabla acumula resultados entre ejecuciones mientras se conserve el contenedor.
Solo aparecerán los flujos que el backend clasificó como anómalos.

### 9. Finalizar la demo

Presionar `Ctrl+C` en la primera terminal para detener Uvicorn. PostgreSQL puede
quedar activo para otra ejecución o detenerse con:

```bash
docker stop sentinel-postgres
```

## Problemas frecuentes

### El dataset no se encuentra

Confirmar que el nombre respeta mayúsculas y minúsculas:

```text
SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv
```

### El endpoint `/health` devuelve estado degradado

Revisar la terminal de Uvicorn. Las causas habituales son la ausencia de
`sentinel_model.h5`, una incompatibilidad entre modelo y scaler o PostgreSQL aún
no disponible durante el arranque.

### PostgreSQL rechaza las credenciales

Verificar que `DATABASE_URL` se haya exportado en la misma terminal donde se
inicia Uvicorn. Si `sentinel-postgres` fue creado anteriormente con otras
credenciales, se debe usar la configuración de ese contenedor o recrearlo de
forma consciente; no borrar el contenedor si sus datos deben conservarse.

### El puerto ya está ocupado

Comprobar qué contenedores y procesos están usando los puertos de la demo:

```bash
docker ps
ss -ltnp | grep -E ':(5432|8000)\b'
```

Las credenciales incluidas en esta guía son exclusivamente para un entorno local
de demostración y no deben reutilizarse en producción.
