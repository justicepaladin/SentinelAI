# SentinelAI Backend

API FastAPI para inferencia IDS con el autoencoder de `../SentinelAI-Model`.
Cada flujo analizado se registra en archivos locales rotativos; PostgreSQL conserva
únicamente cuarentenas activas y una alerta crítica reciente por IP.

## Ejecución

```bash
cd SentinelAI-Backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp -n .env.example .env
# Completá las credenciales de Telegram dentro de .env antes de iniciar la API.
uvicorn main:app --host 0.0.0.0 --port 8000
```

La documentación interactiva queda disponible en `http://localhost:8000/docs`.

`GET /health` indica si están listos el modelo, PostgreSQL al arrancar y el
registro local. `GET /dashboard/state` expone cuarentenas y alertas críticas
vigentes. `POST /ingest` sigue devolviendo MSE y clasificación, y añade
`dashboard_state_persisted` cuando hubo que actualizar PostgreSQL. Un fallo de
PostgreSQL no impide analizar ni registrar el flujo localmente.

## Persistencia y archivado

Por defecto, `traffic_logging.py` crea segmentos JSON Lines `traffic-*.log` y
`detection-*.log` en `logs/`. Rota al cambiar el día UTC o antes de superar
50 MiB. `SENTINEL_LOG_DIR` y `SENTINEL_LOG_MAX_BYTES` permiten cambiar estos
valores. El historial de flujo completo ya no se inserta en la tabla heredada
`alerts`.

El cron diario puede ejecutar, desde la raíz del repositorio:

```bash
python3 scripts/archive_logs.py --log-dir SentinelAI-Backend/logs --months 6
```

Sólo los segmentos cerrados con más de seis meses calendario se comprimen y
verifican antes de borrar el `.log`. Los `.tar.gz` quedan en `logs/archive/`.
Usá rutas absolutas al instalar el cron. Las variables `SENTINEL_CRITICAL_MSE`,
`SENTINEL_QUARANTINE_SECONDS`, `SENTINEL_ALERT_TTL_HOURS` y
`SENTINEL_ALERT_UPDATE_SECONDS` están ejemplificadas en `.env.example`.

La guía completa y la validación OOD del modelo están en [`../docs/README.md`](../docs/README.md).

El scaler y el modelo incluidos esperan 78 entradas numéricas. Los CSV originales
de CIC-IDS2017 tienen 79 columnas porque agregan `Label`; por eso el endpoint acepta
78 entradas de inferencia o una fila de 79 valores y descarta el último valor
(`Label`). Para diccionarios con nombres, las columnas se ordenan usando
`scaler.feature_names_in_`.
