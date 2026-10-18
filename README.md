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
- [`docker-compose.yml`](docker-compose.yml): cliente y víctima de la demo de nivel 2.

Los CSV y el archivo `sentinel_model.h5` se mantienen fuera de Git; deben estar disponibles localmente para repetir inferencia y evaluación.

Una instalación con tablas de `new-fix-50` debe respaldar PostgreSQL y ejecutar [migrate_75.py](SentinelAI-Backend/migrate_75.py). Si parte de `fix-50%`, ejecutar antes [migrate_multisite.py](SentinelAI-Backend/migrate_multisite.py). `create_all()` no cambia las columnas ni restricciones previas; la [guía de migración](docs/README.md#migración-de-una-base-existente) describe el procedimiento.
