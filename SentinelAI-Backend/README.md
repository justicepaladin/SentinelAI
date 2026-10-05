# SentinelAI Backend

API FastAPI de inferencia IDS. Los sensores Edge se registran en PostgreSQL y se autentican con un token Bearer. El token determina el sitio: el cliente no elige `site_id` en el payload. El backend comparte un autoencoder y un scaler entre sitios; cada sitio puede definir su umbral MSE y habilitar o deshabilitar la respuesta activa.

## Preparación

Desde la raíz del repositorio:

```bash
cd SentinelAI-Backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp -n .env.example .env
```

Editar `DATABASE_URL` en `.env`. Los archivos `../SentinelAI-Model/models/sentinel_model.h5` y `sentinel_scaler.save` deben existir y pertenecer al mismo entrenamiento. El `.h5` no está versionado. En una base nueva, aprovisionar un sensor antes del primer envío:

```bash
python provision_sensor.py \
  --site-slug demo \
  --site-name Demo \
  --sensor-name replay \
  --threshold 0.000308
```

`provision_sensor.py` muestra `SENTINEL_SENSOR_TOKEN=...` una sola vez. Guardar ese valor en un lugar seguro; la tabla `sensors` conserva únicamente el hash SHA-256. Un segundo sensor puede registrarse con otro nombre en el mismo sitio. Omitir `--threshold` utiliza el umbral base `0.000308`. La respuesta activa está **deshabilitada por defecto**; añadir `--active-response` sólo en un sitio preparado para aplicar reglas `iptables`. El token se configura en Edge como `SENTINEL_SENSOR_TOKEN`, nunca en el `.env` del backend.

Iniciar la API desde `SentinelAI-Backend` con el entorno virtual activo:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

La documentación interactiva está en `http://localhost:8000/docs`. Para la demo actual se recomienda un solo worker: `iptables`, el control temporal de escrituras y la liberación programada todavía dependen de estado local del proceso.

## Contrato HTTP

| Endpoint | Autenticación | Resultado |
| --- | --- | --- |
| `POST /ingest` | Bearer del sensor | MSE, decisión, mensaje y `dashboard_state_persisted`. |
| `GET /dashboard/state` | Bearer del sensor | Cuarentenas y alertas críticas vigentes del **mismo sitio**. |
| `GET /health` | Ninguna | Disponibilidad de ML, PostgreSQL al arranque y logger local. |
| `GET /metrics` | Ninguna | Contadores y último MSE para Prometheus. |
| `GET /docs` | Ninguna | OpenAPI interactivo. |

El Edge envía `Authorization: Bearer <token>`. Si falta o no corresponde a un sensor y sitio activos, la API devuelve HTTP 401; si PostgreSQL no permite autenticar, devuelve 503. El payload de `/ingest` contiene `source_ip`, `destination_ip`, `destination_port` y `features`. El scaler espera 78 características numéricas: un diccionario se alinea con `scaler.feature_names_in_`; una lista plana de 79 elementos puede incluir `Label` al final, que se descarta antes de inferir. La etiqueta real no participa de la predicción.

Bearer no cifra el canal. `http://localhost` es sólo para la demo; un despliegue distribuido requiere HTTPS/TLS y restringir `/metrics` y `/docs` según la red y el proxy usados.

Ejemplo para consultar el dashboard con un token ya exportado en la terminal:

```bash
curl -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
  http://127.0.0.1:8000/dashboard/state
```

El MSE se compara con `site_configs.custom_mse_threshold` si existe; de lo contrario se usa `TAU = 0.000308`. La alerta crítica usa el mayor entre `SENTINEL_CRITICAL_MSE` y tres veces el umbral del sitio. Si `active_response_enabled` está deshabilitado, la anomalía se registra pero no se instala una regla `iptables` ni se envía el aviso de bloqueo. Si PostgreSQL falla después de autenticar, el flujo y la decisión siguen en los logs locales y `/ingest` puede responder 200 con `dashboard_state_persisted=false`.

## Persistencia

`traffic_logging.py` escribe JSON Lines `traffic-*.log` para todos los flujos analizados y `detection-*.log` para anomalías y cambios de mitigación. Incluye identificadores de sitio y sensor, pero nunca el token. Los archivos rotan por día UTC o tamaño, 50 MiB por defecto. `SENTINEL_LOG_DIR` y `SENTINEL_LOG_MAX_BYTES` controlan la ubicación y el tamaño. `scripts/archive_logs.py` comprime segmentos cerrados con más de seis meses calendario, verifica el archivo y luego elimina el `.log` original. La guía del cron está en [docs](../docs/README.md).

PostgreSQL guarda `sites`, `sensors` y `site_configs`; las proyecciones actuales `active_quarantines` y `critical_alerts` se identifican por `(site_id, source_ip)`. La tabla `mitigation_events` guarda eventos `APPLY` y `REVERSION`. Una reversión referencia su aplicación original y PostgreSQL impide actualizar, borrar o truncar eventos. Estos eventos documentan acciones del firewall; la historia completa de flujos y detecciones está en los archivos locales.

### Bases creadas antes de `new-fix-50`

El esquema anterior tenía claves por IP sin sitio. `Base.metadata.create_all()` **no** transforma columnas, claves primarias ni filas existentes. Esta versión verifica el esquema y rechaza una base antigua hasta que se ejecute la migración explícita. Hacer un respaldo de PostgreSQL antes de migrar; ver el procedimiento y el tratamiento de cuarentenas previas en la [guía de migración](../docs/README.md#migración-de-una-base-existente).

Con la API detenida y después del respaldo, desde `SentinelAI-Backend`:

```bash
python migrate_multisite.py --site-slug legacy --site-name 'Sitio heredado'
```

La migración preserva las proyecciones previas en el sitio `legacy`, crea eventos `APPLY` importados para cuarentenas activas y deja la respuesta activa deshabilitada. Luego registrar un sensor en ese sitio con `provision_sensor.py`. La tabla histórica `alerts` no se modifica.

El modelo compartido se evaluó con los siete CSV de CIC-IDS2017 no usados para entrenar. El resultado y la limitación de UNSW-NB15 están en la [documentación del proyecto](../docs/README.md#resultado-medido-en-los-csv-locales-completos).
