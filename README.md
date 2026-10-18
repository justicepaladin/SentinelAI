# SentinelAI

SentinelAI es un prototipo de IDPS distribuido. Sensores Edge autenticados envían flujos a una API FastAPI; un autoencoder de TensorFlow compartido calcula el error de reconstrucción. Cada sitio configura su umbral MSE, inventario de dispositivos y política de respuesta con `iptables` y Telegram.

La rama `75` parte de `new-fix-50` y añade alertas filtrables, telemetría, modo informativo, suspensión por enlace degradado, inventario por sitio y reversión manual auditada. Los flujos se registran en `.log` rotativos; PostgreSQL mantiene alertas, estado operacional e historial inmutable de mitigación. Se incluyen un benchmark de latencia/resiliencia y una comparación estadística de umbrales sobre CIC-IDS2017.

La [documentación completa](docs/README.md) incluye arquitectura, instalación, API, rotación y archivado, cron, evaluación del modelo, resultados y límites conocidos.

## Componentes

- [`SentinelAI-Backend/`](SentinelAI-Backend/): API, inferencia, respuesta activa, estado y logging.
- [`SentinelAI-Backend/provision_sensor.py`](SentinelAI-Backend/provision_sensor.py): registra un sitio y sensor, y entrega una vez su token Bearer; la base guarda sólo SHA-256.
- [`SentinelAI-Edge/`](SentinelAI-Edge/): envía flujos desde un generador en memoria; los CSV son una fuente opcional de replay.
- [`SentinelAI-Model/`](SentinelAI-Model/): notebook, modelo/scaler compartidos y evaluación fuera de muestra.
- [`scripts/archive_logs.py`](scripts/archive_logs.py): archivado seguro de logs antiguos.
- [`scripts/benchmark_rnf.py`](scripts/benchmark_rnf.py): medición local de inferencia y `/ingest` con pruebas RNF-05/06.
- [`SentinelAI-Model/threshold_analysis.py`](SentinelAI-Model/threshold_analysis.py): normalidad y FPR/F1 para cuatro alternativas de umbral.
- [`start_demo.sh`](start_demo.sh): inicia PostgreSQL, abre Backend/Edge/firewall y ofrece una consola para recorrer las funciones del 75 %.
- [`docker-compose.yml`](docker-compose.yml): cliente y víctima de la demo de nivel 2.

Los CSV y el archivo `sentinel_model.h5` se mantienen fuera de Git; deben estar disponibles localmente para repetir inferencia y evaluación.

Una instalación con tablas de `new-fix-50` debe respaldar PostgreSQL y ejecutar [migrate_75.py](SentinelAI-Backend/migrate_75.py). Si parte de `fix-50%`, ejecutar antes [migrate_multisite.py](SentinelAI-Backend/migrate_multisite.py). `create_all()` no cambia las columnas ni restricciones previas; la [guía de migración](docs/README.md#migración-de-una-base-existente) describe el procedimiento.

Con el entorno, la base y los tokens preparados, la demo completa se inicia desde la raíz con:

```bash
export SENTINEL_SENSOR_TOKEN='<token del sensor>'
export TOKEN_ADMIN='<token administrador sin hashear>'
./start_demo.sh --site-id 1 --sensor-id 1
```

El procedimiento inicial, el contenido de cada terminal y el recorrido sugerido están en la [guía completa](docs/README.md).

### Obtención de Datasets (Validación y Replay)
Para reproducir las simulaciones y las evaluaciones de generalización (OOD), el sistema requiere los archivos CSV originales. Por cuestiones de tamaño y licencias, no están incluidos en este repositorio.

Deberás descargarlos desde el portal oficial del Instituto Canadiense de Ciberseguridad (CIC - UNB) y colocarlos en `SentinelAI-Model/data/`:

1. **CIC-IDS2017 (Dataset Principal de Entrenamiento/Test):**
   - **Enlace:** [Intrusion Detection Evaluation Dataset (CIC-IDS2017)](https://www.unb.ca/cic/datasets/ids-2017.html)
   - *Nota:* Descargar la versión "MachineLearningCSV" generada con CICFlowMeter.
2. **CIC-UNSW-NB15 (Dataset Externo para Validación OOD):**
   - **Enlace:** [Re-extracted UNSW-NB15 Dataset (CIC-UNSW-NB15)](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html)
   - *Nota:* Utilizar esta versión re-extraída con CICFlowMeter para garantizar la total compatibilidad del vector de 78 características con el Autoencoder de SentinelAI.