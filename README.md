# SentinelAI

SentinelAI es un prototipo de IDPS distribuido. Sensores Edge autenticados envían flujos a una API FastAPI; un autoencoder de TensorFlow compartido calcula el error de reconstrucción. Cada sitio configura su umbral MSE y si habilita la respuesta activa con `iptables` y Telegram.

Esta rama `new-fix-50` continúa la corrección de la entrega del 50 %. Reúne la demo con Telegram y el escenario de cliente/víctima de `demo50lv2`. Los flujos y detecciones se registran en archivos `.log` rotativos; PostgreSQL mantiene estado operacional por sitio y un historial inmutable de eventos de mitigación. La evaluación por día de CIC-IDS2017 permite medir el comportamiento del modelo compartido fuera de la muestra de la demo.

La [documentación completa](docs/README.md) incluye arquitectura, instalación, API, rotación y archivado, cron, evaluación del modelo, resultados y límites conocidos.

## Componentes

- [`SentinelAI-Backend/`](SentinelAI-Backend/): API, inferencia, respuesta activa, estado y logging.
- [`SentinelAI-Backend/provision_sensor.py`](SentinelAI-Backend/provision_sensor.py): registra un sitio y sensor, y entrega una vez su token Bearer; la base guarda sólo SHA-256.
- [`SentinelAI-Edge/`](SentinelAI-Edge/): envía flujos desde un generador en memoria; los CSV son una fuente opcional de replay.
- [`SentinelAI-Model/`](SentinelAI-Model/): notebook, modelo/scaler compartidos y evaluación fuera de muestra.
- [`scripts/archive_logs.py`](scripts/archive_logs.py): archivado seguro de logs antiguos.
- [`docker-compose.yml`](docker-compose.yml): cliente y víctima de la demo de nivel 2.

Los CSV y el archivo `sentinel_model.h5` se mantienen fuera de Git; deben estar disponibles localmente para repetir inferencia y evaluación.

Una instalación con tablas de `fix-50%` debe respaldar PostgreSQL y ejecutar [migrate_multisite.py](SentinelAI-Backend/migrate_multisite.py) antes de iniciar esta versión. `create_all()` no cambia el esquema anterior; la [guía de migración](docs/README.md#migración-de-una-base-existente) describe el procedimiento.
