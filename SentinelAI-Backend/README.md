# SentinelAI Backend

API FastAPI de inferencia IDS. Los sensores Edge se registran en PostgreSQL y se autentican con un token Bearer. El token determina el sitio: el cliente no elige `site_id` en el payload. El backend comparte un autoencoder y un scaler entre sitios; cada sitio puede definir su umbral MSE, inventario de IP/subredes y política de respuesta.

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

`provision_sensor.py` muestra `SENTINEL_SENSOR_TOKEN=...` una sola vez. Guardar ese valor en un lugar seguro; la tabla `sensors` conserva únicamente el hash SHA-256. Un segundo sensor puede registrarse con otro nombre en el mismo sitio. Omitir `--threshold` utiliza el umbral base `0.000308`. La respuesta activa está **deshabilitada por defecto** y el modo informativo está **habilitado por defecto**. Para una demo con firewall, usar `--active-response --disable-informative-only` en un sitio preparado para ejecutar `iptables`. El token se configura en Edge como `SENTINEL_SENSOR_TOKEN`, nunca en el `.env` del backend.

Las operaciones administrativas requieren un token distinto del token del sensor. Generar un valor aleatorio de al menos 32 caracteres, guardar su SHA-256 hexadecimal en `SENTINEL_ADMIN_TOKEN_SHA256` dentro del `.env` del backend y conservar el token original fuera del repositorio. El backend compara los hashes en tiempo constante. Si no se configura, `PUT /sites/{site_id}/config` y la reversión manual responden 503. Un ejemplo para preparar el valor en una terminal local es `python -c 'import secrets; print(secrets.token_urlsafe(48))'` y luego `printf '%s' "$TOKEN_ADMIN" | sha256sum`.

Iniciar la API desde `SentinelAI-Backend` con el entorno virtual activo:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

La documentación interactiva está en `http://localhost:8000/docs`. Para la demo actual se recomienda un solo worker: `iptables`, el control temporal de escrituras y la liberación programada todavía dependen de estado local del proceso.

Para la presentación completa, [start_demo.sh](../start_demo.sh) realiza los chequeos previos, inicia PostgreSQL y abre terminales separadas para Uvicorn, Edge, el monitor de `iptables` y una consola de las funciones del 75 %. Requiere exportar previamente `SENTINEL_SENSOR_TOKEN` y el token administrador sin hashear como `TOKEN_ADMIN`. El procedimiento está en la [documentación principal](../docs/README.md).

## Contrato HTTP

| Endpoint | Autenticación | Resultado |
| --- | --- | --- |
| `POST /ingest` | Bearer del sensor | MSE, decisión, dispositivo desconocido, mitigación, suspensión y persistencia. |
| `GET /dashboard/state` | Bearer del sensor | Cuarentenas y alertas críticas vigentes del **mismo sitio**. |
| `GET /alerts` | Bearer admin o sensor | Alertas recientes; filtros `site_id`, `sensor_id`, `source_ip`, `severity` (`warning`, `high`, `critical`), `since`, `until`, `unrecognized_device`, `before_id` y `limit`. El sensor sólo ve su sitio. Detalle en la [guía de la API](../docs/README.md#api-y-observabilidad). |
| `GET /alerts/{alert_id}` | Bearer admin o sensor | Una alerta; 404 si no existe o es de otro sitio para un sensor. |
| `GET /sites` | Bearer admin o sensor | Sitios con su configuración; el sensor sólo ve el suyo. |
| `GET /sites/{site_id}/sensors` | Bearer admin o sensor del sitio | Sensores del sitio con nombre y telemetría. |
| `GET /mitigation-events` | Bearer admin o sensor | Eventos de firewall, más recientes primero; filtros `site_id`, `source_ip` y `limit` (1–1000). |
| `GET /quarantines` | Bearer admin o sensor | Cuarentenas vigentes con `site_id`; filtro opcional `site_id`. El sensor sólo ve su sitio. |
| `GET /sensors/{sensor_id}/telemetry` | Bearer admin o ese sensor | Último heartbeat/ingesta, total de flujos, estado activo y último estado del enlace. |
| `POST /sensors/{sensor_id}/heartbeat` | Bearer de ese sensor | Registra un heartbeat con `link_degraded`; no incrementa el contador de flujos. |
| `GET /sites/{site_id}/config` | Bearer admin o sensor del sitio | Umbral, modos de respuesta e inventario conocido. |
| `PUT /sites/{site_id}/config` | Bearer admin | Actualiza parcialmente esos campos. |
| `POST /quarantines/{source_ip}/revert` | Bearer admin | Quita la regla antes del TTL y agrega `MANUAL_REVERSION` a la auditoría inmutable. Acepta `?site_id=` cuando corresponde. |
| `GET /health` | Ninguna | Disponibilidad de ML, PostgreSQL al arranque y logger local. |
| `GET /metrics` | Ninguna | Contadores y último MSE para Prometheus. |
| `GET /docs` | Ninguna | OpenAPI interactivo. |

El Edge envía `Authorization: Bearer <token>`. Si falta o no corresponde a un sensor y sitio activos, la API devuelve HTTP 401; si PostgreSQL no permite autenticar, devuelve 503. El payload de `/ingest` contiene `source_ip`, `destination_ip`, `destination_port`, `features` y opcionalmente `link_degraded: true`. El scaler espera 78 características numéricas: un diccionario se alinea con `scaler.feature_names_in_`; una lista plana de 79 elementos puede incluir `Label` al final, que se descarta antes de inferir. La etiqueta real no participa de la predicción.

Una detección anómala siempre se registra. `iptables` sólo se invoca si `active_response_enabled=true`, `informative_only_mode=false` y el enlace está sano. `link_degraded=true` en un flujo suspende la respuesta; si el campo se omite, se usa el último reporte explícito del sensor durante `SENTINEL_LINK_STATE_TTL_SECONDS` (120 segundos por defecto). Un heartbeat con enlace degradado también suspende las ingestas posteriores durante esa vigencia; `link_degraded=false` comunica la recuperación. La detección y el registro siguen activos. El inventario `known_devices` acepta IPs o CIDR y se normaliza a CIDR; una fuente RFC1918 o ULA fuera del inventario se marca como `unrecognized_device`, aun si su MSE no supera el umbral. Un inventario vacío trata toda fuente interna como desconocida. Las IPs de documentación y las públicas no se clasifican como dispositivos internos.

Ejemplo de configuración, con `TOKEN_ADMIN` disponible sólo en la terminal operativa:

```bash
curl -X PUT -H "Authorization: Bearer ${TOKEN_ADMIN}" \
  -H 'Content-Type: application/json' \
  -d '{"custom_mse_threshold":0.000308,"active_response_enabled":true,"informative_only_mode":false,"known_devices":["192.168.1.0/24","10.0.0.8"]}' \
  http://127.0.0.1:8000/sites/1/config
```

Bearer no cifra el canal. `http://localhost` es sólo para la demo; un despliegue distribuido requiere HTTPS/TLS y restringir `/metrics` y `/docs` según la red y el proxy usados.

Ejemplo para consultar el dashboard con un token ya exportado en la terminal:

```bash
curl -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
  http://127.0.0.1:8000/dashboard/state
```

El MSE se compara con `site_configs.custom_mse_threshold` si existe; de lo contrario se usa `TAU = 0.000308`. La alerta crítica usa el mayor entre `SENTINEL_CRITICAL_MSE` y tres veces el umbral del sitio. Si PostgreSQL falla después de autenticar, el flujo y la decisión siguen en los logs locales y `/ingest` puede responder 200 con `dashboard_state_persisted=false`.

## Persistencia

`traffic_logging.py` escribe JSON Lines `traffic-*.log` para todos los flujos analizados y `detection-*.log` para anomalías y cambios de mitigación. Incluye identificadores de sitio y sensor, pero nunca el token. Los archivos rotan por día UTC o tamaño, 50 MiB por defecto. `SENTINEL_LOG_DIR` y `SENTINEL_LOG_MAX_BYTES` controlan la ubicación y el tamaño. `scripts/archive_logs.py` comprime segmentos cerrados con más de seis meses calendario, verifica el archivo y luego elimina el `.log` original. La guía del cron está en [docs](../docs/README.md).

PostgreSQL guarda `sites`, `sensors`, `site_configs`, `sensor_telemetry` y `detection_alerts`; las proyecciones actuales `active_quarantines` y `critical_alerts` se identifican por `(site_id, source_ip)`. `detection_alerts` guarda una fila por anomalía, dispositivo desconocido o advertencia de enlace. La tabla `mitigation_events` guarda eventos `APPLY`, `REVERSION` y `MANUAL_REVERSION`. Una reversión referencia su aplicación original y PostgreSQL impide actualizar, borrar o truncar eventos. La historia completa de flujos permanece en los archivos locales.

### Bases creadas antes de `new-fix-50`

El esquema anterior tenía claves por IP sin sitio. `Base.metadata.create_all()` **no** transforma columnas, claves primarias ni filas existentes. Esta versión verifica el esquema y rechaza una base antigua hasta que se ejecute la migración explícita. Hacer un respaldo de PostgreSQL antes de migrar; ver el procedimiento y el tratamiento de cuarentenas previas en la [guía de migración](../docs/README.md#migración-de-una-base-existente).

Con la API detenida y después del respaldo, desde `SentinelAI-Backend`:

```bash
python migrate_multisite.py --site-slug legacy --site-name 'Sitio heredado'
```

La migración preserva las proyecciones previas en el sitio `legacy`, crea eventos `APPLY` importados para cuarentenas activas y deja la respuesta activa deshabilitada. Luego registrar un sensor en ese sitio con `provision_sensor.py`. La tabla histórica `alerts` no se modifica.

### Bases creadas con `new-fix-50`

Con la API detenida y una copia de seguridad de PostgreSQL, ejecutar `python migrate_75.py` desde `SentinelAI-Backend`. La migración agrega el modo informativo y el inventario a `site_configs`, crea alertas y telemetría, y permite el evento inmutable `MANUAL_REVERSION`. Las cuarentenas y eventos existentes se preservan. El inicio de la API rechaza el esquema anterior con un mensaje que indica esta migración. No se inventan alertas históricas: `GET /alerts` muestra detecciones generadas desde el 75 %.

Para verificar: `../SentinelAI-Backend/.venv/bin/python -m unittest discover -s ../tests -v` desde `SentinelAI-Backend`, o ejecutar `SentinelAI-Backend/.venv/bin/python -m unittest discover -s tests -v` desde la raíz.

El modelo compartido se evaluó con los siete CSV de CIC-IDS2017 no usados para entrenar. El resultado y la limitación de UNSW-NB15 están en la [documentación del proyecto](../docs/README.md#resultado-medido-en-los-csv-locales-completos).
