# SentinelAI

SentinelAI es un prototipo de IDPS distribuido. El componente Edge envía flujos a una API FastAPI; un autoencoder de TensorFlow calcula el error de reconstrucción, y el backend puede aislar IPs con `iptables` y avisar por Telegram.

Esta rama `fix-50%` reúne la demo con Telegram y el escenario de cliente/víctima de `demo50lv2`. La corrección de la entrega separa el historial de tráfico del estado operacional: los flujos y detecciones se registran en archivos `.log` rotativos, mientras PostgreSQL mantiene cuarentenas activas y alertas críticas recientes. También incorpora una evaluación por día de CIC-IDS2017 y una interfaz para datos externos con características equivalentes.

La [documentación completa](docs/README.md) incluye arquitectura, instalación, API, rotación y archivado, cron, evaluación del modelo, resultados y límites conocidos.

## Componentes

- [`SentinelAI-Backend/`](SentinelAI-Backend/): API, inferencia, respuesta activa, estado y logging.
- [`SentinelAI-Edge/`](SentinelAI-Edge/): sensor CSV y replay de la demo.
- [`SentinelAI-Model/`](SentinelAI-Model/): notebook, artefactos y evaluación fuera de muestra.
- [`scripts/archive_logs.py`](scripts/archive_logs.py): archivado seguro de logs antiguos.
- [`docker-compose.yml`](docker-compose.yml): cliente y víctima de la demo de nivel 2.

Los CSV y el archivo `sentinel_model.h5` se mantienen fuera de Git; deben estar disponibles localmente para repetir inferencia y evaluación.
