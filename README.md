# SentinelAI

SentinelAI es un sistema de detección de anomalías en tráfico de red desarrollado
como proyecto de tesis. El modelo aprende el comportamiento del tráfico benigno
de CIC-IDS2017 y marca como anómalos los flujos cuyo error de reconstrucción
supera el umbral configurado.

El repositorio reúne el ciclo completo: preparación de datos, entrenamiento del
autoencoder, inferencia mediante una API y envío de flujos desde un nodo Edge.

## Arquitectura

```text
CIC-IDS2017 / sensor de red
            │ CSV
            ▼
SentinelAI-Edge/integracion_sensor.py
            │ POST /ingest
            ▼
SentinelAI-Backend (FastAPI)
            ├── MinMaxScaler + autoencoder
            └── PostgreSQL (solo anomalías)
```

El flujo de inferencia sigue estos pasos:

1. El cliente Edge lee cada fila de `flujos_capturados.csv`.
2. La API ordena las 78 características según el scaler entrenado y aplica la
   misma normalización utilizada durante el entrenamiento.
3. El autoencoder reconstruye el flujo y la API calcula su error cuadrático medio
   (MSE).
4. Si el MSE supera `0.000308`, la anomalía se guarda en la tabla `alerts` de
   PostgreSQL.

## Estructura del repositorio

| Ruta | Contenido |
| --- | --- |
| `SentinelAI-Model/` | Notebook de exploración, limpieza, entrenamiento y validación. |
| `SentinelAI-Model/models/` | Scaler versionado y modelo entrenado local. |
| `SentinelAI-Backend/` | API FastAPI, carga de artefactos y persistencia de alertas. |
| `SentinelAI-Edge/` | Cliente que reproduce un CSV como una secuencia de flujos. |
| `start_demo.sh` | Orquestador de PostgreSQL, backend y cliente Edge. |

Los datasets, capturas, modelos Keras y archivos de log se mantienen fuera de Git
por su tamaño o porque se generan durante la ejecución.

## Requisitos

- Python 3.10 o superior.
- Docker, para iniciar PostgreSQL con el orquestador.
- Los archivos `sentinel_scaler.save` y `sentinel_model.h5` en
  `SentinelAI-Model/models/`.
- Un CSV compatible con CIC-IDS2017 en
  `SentinelAI-Edge/flujos_capturados.csv`.
- GPU NVIDIA y NVIDIA Container Toolkit únicamente si se quiere entrenar con
  aceleración CUDA.

## Preparación del entorno

Desde la raíz del repositorio:

```bash
python -m venv SentinelAI-Backend/.venv
source SentinelAI-Backend/.venv/bin/activate
pip install -r SentinelAI-Backend/requirements.txt
pip install -r SentinelAI-Edge/requirements.txt
cp SentinelAI-Backend/.env.example SentinelAI-Backend/.env
```

El script de demostración define su propia `DATABASE_URL`. Para ejecutar el
backend de forma manual, exportá la variable antes de iniciar Uvicorn o cargá el
archivo `.env` con la herramienta que uses habitualmente.

## Dataset

Los CSV originales de CIC-IDS2017 no se versionan. Descargalos desde su fuente y
guardalos en `SentinelAI-Model/data/` para trabajar con el notebook.

Para la demostración end-to-end, copiá el archivo que quieras reproducir:

```bash
cp SentinelAI-Model/data/Monday-WorkingHours.pcap_ISCX.csv \
  SentinelAI-Edge/flujos_capturados.csv
```

El cliente admite las columnas numéricas del dataset y usa valores locales por
defecto para las direcciones IP cuando el CSV no incluye `Src IP` o `Dst IP`.

## Demostración end-to-end

Con Docker activo, el entorno virtual preparado, los artefactos del modelo y el
CSV en sus rutas:

```bash
./start_demo.sh
```

El orquestador:

1. inicia o crea el contenedor `sentinel-postgres`;
2. levanta la API en `http://localhost:8000`;
3. valida el dataset inyectado en el módulo Edge;
4. envía los flujos de forma secuencial y detiene el backend al terminar.

PostgreSQL queda en ejecución para conservar las alertas entre demostraciones.
Se puede detener manualmente con `docker stop sentinel-postgres`.

## Ejecución manual

### Backend

```bash
source SentinelAI-Backend/.venv/bin/activate
export DATABASE_URL='postgresql://sentinel_user:sentinel_password@localhost:5432/sentinel_db'
cd SentinelAI-Backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

La documentación interactiva queda disponible en
`http://localhost:8000/docs`.

| Método | Endpoint | Uso |
| --- | --- | --- |
| `GET` | `/health` | Informa si el modelo y la base estaban disponibles al iniciar. |
| `POST` | `/ingest` | Analiza un flujo y persiste la alerta cuando corresponde. |

El cuerpo de `/ingest` tiene esta forma:

```json
{
  "source_ip": "192.168.1.25",
  "destination_ip": "10.0.0.8",
  "destination_port": 443,
  "features": [0.0, 0.0, 0.0]
}
```

`features` puede ser una lista plana de 78 valores, una fila de 79 valores con
`Label` al final o un objeto con los nombres de las características. El ejemplo
abreviado de arriba solo muestra el formato; una solicitud real debe incluir las
78 entradas esperadas.

### Cliente Edge

```bash
source SentinelAI-Backend/.venv/bin/activate
cd SentinelAI-Edge
python integracion_sensor.py
```

La URL de la API y la ruta del dataset se pueden cambiar con `SENTINEL_API_URL` y
`SENTINEL_CSV_FILE`, respectivamente.

## Entrenamiento del modelo

Desde la raíz, Jupyter se puede iniciar con soporte para GPU:

```bash
docker run -it --rm --runtime=nvidia --gpus all \
  -v "$(pwd)/SentinelAI-Model:/tf/notebooks" \
  -p 8888:8888 \
  tensorflow/tensorflow:latest-gpu-jupyter
```

Sin una GPU NVIDIA, usá `tensorflow/tensorflow:latest-jupyter` y quitá los flags
`--runtime=nvidia --gpus all`.

El notebook entrena el autoencoder exclusivamente con tráfico benigno. La regla
de detección es:

$$L(x, \hat{x}) = \lVert x - \hat{x} \rVert^2 > \tau$$

El scaler usado para entrenar debe conservarse junto al modelo: ambos tienen que
esperar las mismas 78 características y en el mismo orden.
