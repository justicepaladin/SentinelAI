# SentinelAI: arquitectura, operación y validación

Documento de referencia para continuar el proyecto después de la entrega del 50 %. Describe el código de esta rama, los artefactos que necesita y la forma de comprobar los cambios de persistencia y validación del modelo. Los ejemplos parten de la raíz del repositorio.

La rama `new-fix-50` continúa el trabajo de `fix-50%` y reúne la demo con notificaciones de Telegram y `demo50lv2`, que aportó el laboratorio de contenedores cliente/víctima.

## 1. Qué hace el proyecto

SentinelAI es un prototipo de IDPS distribuido. Cada proceso *Edge* envía características numéricas de flujos de red a una API FastAPI con el token de un sensor registrado. El backend identifica su sitio, aplica el `MinMaxScaler` y el autoencoder de TensorFlow compartidos, calcula el error cuadrático medio de reconstrucción (MSE) y compara el resultado con el umbral configurado para ese sitio (`0.000308` si no hay override). La respuesta activa con `iptables` se habilita por sitio; cuando está activa, la demo puede aislar la IP temporalmente y avisar por Telegram. Prometheus puede consultar métricas de inferencia.

```text
Extractor o CSV → Edge con token → POST /ingest → autenticar sensor y sitio
                                              → validar 78 características
                                              → scaler y autoencoder compartidos
                                              → MSE > umbral del sitio
                                              ├─ registro local rotativo
                                              ├─ estado y eventos por sitio en PostgreSQL
                                              └─ respuesta activa habilitada → iptables/Telegram
```

El replay usa datos ya procesados de CIC-IDS2017. No captura paquetes de red en vivo. Las direcciones IP de la demo se construyen para mostrar el bloqueo, y no provienen del CSV de características.

## 2. Mapa del repositorio

| Ruta | Responsabilidad |
| --- | --- |
| `SentinelAI-Backend/main.py` | API, preparación de características, inferencia, métricas, mitigación y Telegram. |
| `SentinelAI-Backend/database.py` | Conexión SQLAlchemy y tablas de estado operacional. |
| `SentinelAI-Backend/models.py` | Esquema de sitios, sensores, configuración, proyecciones y eventos de mitigación. |
| `SentinelAI-Backend/auth.py` | Resolución del sensor autenticado mediante token Bearer. |
| `SentinelAI-Backend/provision_sensor.py` | Registro de sitio/sensor y emisión de un token para el Edge. |
| `SentinelAI-Backend/state_store.py` | Escrituras y consultas acotadas del estado actual por sitio e IP. |
| `SentinelAI-Backend/traffic_logging.py` | Registro de flujos y detecciones en archivos `.log` locales con rotación. |
| `SentinelAI-Backend/.env.example` | Variables de configuración de ejemplo; copiar a `.env` sin versionar secretos. |
| `SentinelAI-Edge/demo_replay.py` | Envía 80 flujos benignos y 20 ataques seleccionados del miércoles. |
| `SentinelAI-Edge/integracion_sensor.py` | Genera flujos desde un iterable en memoria; incluye un adaptador de CSV por bloques para replay y los envía con token Bearer. |
| `SentinelAI-Model/01_Exploracion_Dataset.ipynb` | Exploración, limpieza, entrenamiento y cálculo del umbral original. |
| `SentinelAI-Model/models/` | Scaler y modelo entrenado que consume el backend. |
| `SentinelAI-Model/evaluate_ood.py` | Evaluación por día y fuera de distribución con artefactos ya entrenados. |
| `scripts/archive_logs.py` | Archivo de logs antiguos para cron. |
| `docker-compose.yml` | Laboratorio opcional con un servidor Nginx `victima` y un contenedor Alpine `cliente`. |
| `start_demo.sh` | Orquestación interactiva de la demo en el entorno local original. |

## 3. Preparación y ejecución de la demo

### Requisitos

- Linux con Python 3.10 o posterior, Docker, PostgreSQL accesible y puertos 8000/5432 libres.
- Los archivos `SentinelAI-Model/models/sentinel_model.h5` y `SentinelAI-Model/models/sentinel_scaler.save`. El `.h5` está ignorado por Git y debe obtenerse del entrenamiento o de los artefactos de la entrega.
- Para el replay, `SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv`. Los CSV y los logs locales están ignorados por Git.
- Para un sitio con respuesta activa habilitada, `iptables` y una política de permisos que permita a la API ejecutar `sudo -n iptables`. Sin ese permiso, la clasificación puede funcionar, pero el aislamiento fallará.
- Para Telegram, un bot y un chat configurados en `.env`. El backend registra un error si faltan esas credenciales.

Preparar dependencias desde la raíz:

```bash
cd SentinelAI-Backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r ../SentinelAI-Edge/requirements.txt
cp -n .env.example .env
```

Editar `.env` con un `DATABASE_URL` válido y, si se utilizarán, `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID`. Para la demo local, PostgreSQL puede iniciarse con:

```bash
docker start sentinel-postgres 2>/dev/null || docker run -d \
  --name sentinel-postgres \
  -e POSTGRES_USER=sentinel_user \
  -e POSTGRES_PASSWORD=sentinel_password \
  -e POSTGRES_DB=sentinel_db \
  -p 5432:5432 postgres:15
```

Si se usa ese contenedor, configurar en `SentinelAI-Backend/.env`:

```dotenv
DATABASE_URL=postgresql://sentinel_user:sentinel_password@localhost:5432/sentinel_db
```

Estas credenciales son exclusivamente locales. En una base nueva, registrar un sitio y un sensor antes de enviar flujos. Desde `SentinelAI-Backend`, con el entorno virtual activo:

```bash
python provision_sensor.py \
  --site-slug demo \
  --site-name Demo \
  --sensor-name replay \
  --threshold 0.000308
```

El script muestra `SENTINEL_SENSOR_TOKEN=...` **una sola vez**. Guardar el valor fuera del repositorio: PostgreSQL conserva únicamente su SHA-256 y no permite recuperarlo en texto. `--threshold` define el umbral MSE de ese sitio; si se omite, se usa el valor base desplegado. La respuesta activa con `iptables` está deshabilitada por defecto y sólo se habilita para un sitio con `--active-response`. Para bases ya usadas en `fix-50%`, aplicar primero la migración descrita abajo.

Desde `SentinelAI-Backend`, con el entorno virtual activo, iniciar:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

En otra terminal, desde la raíz y con el mismo entorno:

```bash
curl http://127.0.0.1:8000/health
cd SentinelAI-Edge
read -rsp 'Token del sensor: ' SENTINEL_SENSOR_TOKEN; echo
export SENTINEL_SENSOR_TOKEN
../SentinelAI-Backend/.venv/bin/python demo_replay.py
```

Pegar en la lectura silenciosa sólo el valor del token emitido, sin el prefijo `SENTINEL_SENSOR_TOKEN=`. `demo_replay.py` selecciona 80 benignos y 20 ataques con `random_state=42`, mezcla la muestra, envía un flujo cada 0,3 segundos y muestra la etiqueta, decisión y MSE de cada uno. La selección se repite, pero el orden de envío y algunas IP simuladas pueden cambiar. El replay no calcula métricas agregadas.

### Sensor Edge y flujo en memoria

`integracion_sensor.py` separa la fuente de flujos del envío: `send_flows(flows, session=..., api_url=..., token=...)` consume cualquier iterable de diccionarios entregado por un extractor y publica cada flujo directamente desde memoria. No necesita crear un CSV intermedio. `iter_csv_flows(path, chunk_size=512)` sirve como adaptador para una demo con CSV: lee por bloques y entrega las filas en una sola pasada. Esto evita cargar el archivo completo en ese sensor; `demo_replay.py` sigue siendo una demo separada que selecciona 100 filas de un CSV.

El sensor usa `SENTINEL_SENSOR_TOKEN` para enviar `Authorization: Bearer <token>`; el backend obtiene el sensor y el sitio desde ese token. El Edge no envía `site_id` como dato confiable. `SENTINEL_API_URL`, `SENTINEL_CSV_FILE`, `SENTINEL_CSV_CHUNK_SIZE` y `SENTINEL_FLOW_DELAY` controlan el replay por bloques; `SENTINEL_REPLAY_CSV_FILE` cambia el CSV de `demo_replay.py`.

`start_demo.sh` abre ventanas con `ptyxis`, inicia el contenedor local de PostgreSQL y usa `sudo` para la demo de `iptables`. Exige `SENTINEL_SENSOR_TOKEN` exportado antes de iniciar, pero no aprovisiona el sensor; sólo la ventana Edge hereda ese token. Al terminar la presentación deja el backend y PostgreSQL activos para que las liberaciones temporizadas puedan completarse; después hay que detener Uvicorn con `Ctrl+C` y, si corresponde, ejecutar `docker stop sentinel-postgres`. El script no vacía la cadena `INPUT` ni elimina reglas ajenas a SentinelAI. Para observar el bloqueo hace falta un sitio creado con `--active-response` y permisos `sudo -n iptables` para el proceso backend.

### Laboratorio Docker de `demo50lv2`

`docker-compose.yml` define dos servicios aparte del replay: `victima` usa `nginx:alpine` y expone el puerto 8080 del host; `cliente` usa Alpine y permanece encendido con `tail -f /dev/null`. Se pueden iniciar y comprobar su conectividad desde la raíz:

```bash
docker compose up -d
docker compose exec cliente wget -qO- http://victima/
docker compose down
```

Este Compose sólo crea la red de laboratorio y una página de prueba. No arranca PostgreSQL ni FastAPI, no extrae características CIC y no envía flujos a `/ingest`. La demo de inferencia anterior se ejecuta por separado. Para conectar tráfico real de esos contenedores con el modelo haría falta una etapa de captura y extracción de las 78 características compatibles.

### API y observabilidad

| Ruta | Uso |
| --- | --- |
| `POST /ingest` | Requiere token Bearer del sensor, recibe un flujo y responde `mse_score`, `anomaly`, `message` y `dashboard_state_persisted`. |
| `GET /health` | Informa si cargaron los artefactos ML y el logger, y si la base estaba lista al iniciar. |
| `GET /dashboard/state` | Requiere token Bearer y devuelve sólo las cuarentenas y alertas críticas vigentes del sitio de ese sensor. |
| `GET /metrics` | Expone contadores de flujos/anomalías y el último MSE para Prometheus. |
| `GET /docs` | Documentación interactiva OpenAPI generada por FastAPI. |

Estructura ilustrativa del payload para `POST /ingest` (completar las 78 características; el objeto de ejemplo por sí solo devuelve 422):

```json
{
  "source_ip": "192.168.1.25",
  "destination_ip": "10.0.0.8",
  "destination_port": 443,
  "features": {"<nombre exacto de cada característica CIC>": 0.0}
}
```

`features` debe contener las 78 características numéricas esperadas por el scaler. Si se envía un diccionario con nombres, el backend las ordena según `scaler.feature_names_in_`; también acepta listas. Para compatibilidad con una fila plana completa de CIC-IDS2017, una secuencia de 79 elementos descarta el último `Label` antes de validar los números, incluso cuando la etiqueta es texto. Se rechazan características no numéricas, booleanas y no finitas. La etiqueta real se usa para evaluar, nunca para inferir.

El `Authorization: Bearer <token>` identifica al sensor activo y al sitio activo en PostgreSQL. El backend calcula el SHA-256 del token recibido y consulta `sensors.token_hash`; no acepta el sitio declarado por el cliente como autoridad. Un token ausente, inválido o de un sensor/sitio desactivado devuelve HTTP 401. Si PostgreSQL no está disponible durante esa autenticación, devuelve 503. El endpoint del dashboard aplica el mismo alcance de sitio, por lo que un sensor de un sitio no puede leer las proyecciones de otro. `GET /health`, `/metrics` y `/docs` son rutas operacionales sin ese token.

Bearer autentica, pero no cifra el tráfico. `http://localhost` corresponde sólo a la demo local; en un despliegue entre nodos se necesita HTTPS/TLS y control de acceso a `/metrics` y `/docs` mediante la configuración de red o un proxy.

Con el token exportado, el estado del sitio se consulta así:

```bash
curl -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
  http://127.0.0.1:8000/dashboard/state
```

La respuesta normal tiene HTTP 200. `dashboard_state_persisted` vale `true` cuando el intento de persistencia en PostgreSQL terminó sin error, `false` cuando se intentó y falló, y `null` cuando el flujo no requería una escritura. Un fallo de PostgreSQL no descarta el registro local ni la decisión del modelo; queda indicado en ese campo y en `message`. La API devuelve 422 para características inválidas, 503 si faltan artefactos ML o no se puede escribir el log local, y 500 ante un fallo interno de inferencia. `GET /dashboard/state` devuelve 503 si no puede consultar PostgreSQL. La disponibilidad de PostgreSQL se comprueba al iniciar; el campo `database_ready_at_startup` no es una prueba continua de salud.

## 4. Persistencia y ciclo de vida de los logs

El cambio de esta entrega separa dos necesidades:

1. **Historial de tráfico y decisiones:** cada inferencia escribe un registro local en un `.log`, tanto si es normal como si es anómala. Los archivos rotan para impedir que uno solo crezca indefinidamente.
2. **Estado y auditoría de mitigaciones:** PostgreSQL conserva las proyecciones operacionales `active_quarantines` y `critical_alerts`, además de un historial acotado a acciones de firewall en `mitigation_events`. No almacena cada flujo ni cada decisión de inferencia.

Los logs locales representan la historia de tráfico y detecciones e incluyen identificadores de sitio y sensor. `active_quarantines` y `critical_alerts` se identifican por `(site_id, source_ip)`, por lo que una IP puede tener estados distintos en dos sitios. La primera guarda la cuarentena y su vencimiento; la segunda mantiene la última alerta crítica con `first_seen`, `last_seen` y vencimiento. El umbral crítico efectivo es el mayor entre `SENTINEL_CRITICAL_MSE` y tres veces el umbral MSE del sitio. Las actualizaciones de alertas se limitan temporalmente para evitar una escritura por cada inferencia. La consulta filtra filas vencidas; la limpieza física de alertas vencidas ocurre cuando llega otra crítica.

`mitigation_events` conserva eventos de acción `APPLY` y `REVERSION`. Cada reversión referencia el evento de aplicación original; la base exige que corresponda al mismo sitio e IP y permite una sola reversión por aplicación. Un trigger de PostgreSQL prohíbe modificar, borrar o truncar esos eventos. Así, la vista actual del dashboard puede cambiar sin reescribir la evidencia de una acción de firewall. Para reconstruir una línea temporal de todas las detecciones se consultan los `.log` y sus archivos comprimidos; los eventos SQL sólo cubren mitigaciones.

Si PostgreSQL falla después de que `iptables` aplica una regla, la respuesta indica `dashboard_state_persisted=false` y el log local conserva el resultado, pero la acción no queda en `mitigation_events`. La conciliación posterior del firewall y el registro persistente de ese caso quedan como trabajo operativo pendiente.

| Tabla | Alcance |
| --- | --- |
| `sites` | Identificador estable `slug`, nombre y estado activo del sitio. |
| `sensors` | Sensor vinculado a un sitio; guarda sólo `token_hash` SHA-256 y estado activo. |
| `site_configs` | Umbral MSE opcional y habilitación de respuesta activa por sitio; deshabilitada por defecto. |
| `active_quarantines` | Proyección actual por `(site_id, source_ip)`, enlazada al evento `APPLY` cuando existe. |
| `critical_alerts` | Última alerta crítica vigente por `(site_id, source_ip)`. |
| `mitigation_events` | Historial inmutable de aplicaciones y reversiones de reglas. |

La tabla heredada `alerts` puede seguir existiendo en una base iniciada con versiones anteriores. El backend nuevo no agrega filas allí; su contenido previo requiere una migración o purga manual después de hacer un respaldo. `create_all()` crea tablas faltantes, pero no convierte ni borra filas antiguas.

### Migración de una base existente

La configuración multisitio cambia las claves de cuarentenas y alertas activas para distinguir la misma IP en sitios diferentes. Una base creada con `fix-50%` necesita una migración explícita antes de usar el nuevo backend: `Base.metadata.create_all()` crea tablas ausentes, pero no modifica columnas, restricciones ni claves primarias existentes. El inicio de la API y el aprovisionamiento rechazan el esquema anterior para evitar mezclar datos de sitios.

Detener la API, respaldar PostgreSQL y ejecutar desde la raíz con el entorno virtual activo y `DATABASE_URL` configurado en `SentinelAI-Backend/.env`:

```bash
docker exec sentinel-postgres pg_dump -U sentinel_user -Fc sentinel_db \
  > /ruta/segura/sentinel_before_multisite.dump
python SentinelAI-Backend/migrate_multisite.py \
  --site-slug legacy \
  --site-name 'Sitio heredado'
```

El ejemplo de `pg_dump` corresponde al contenedor local de esta guía; adaptar usuario, base y destino del respaldo a cada instalación. La migración de PostgreSQL se ejecuta en una transacción, conserva filas de `active_quarantines` y `critical_alerts`, las asigna al sitio heredado y cambia la clave a `(site_id, source_ip)`. Cada cuarentena previa recibe un evento `APPLY` importado con `sensor_id` vacío, ya que el esquema anterior no guardaba sensor. No inventa detecciones históricas. La configuración del sitio migrado deja deshabilitada la respuesta activa. Si se repite sobre un esquema ya migrado, valida su integridad y no duplica filas; rechaza esquemas parciales o inesperados.

Después, ejecutar `provision_sensor.py` para registrar al menos un sensor en `legacy`, conservar el nuevo token y recién entonces iniciar la API. La tabla heredada `alerts` no se modifica; respaldarla y aplicar una política de retención antes de purgarla manualmente. `create_all()` tampoco convierte futuras revisiones del esquema: los cambios posteriores requieren migraciones nuevas.

La tarea `scripts/archive_logs.py` está prevista para cron: considera sólo los `.log` con nombres generados por `AuditLogWriter`, pertenecientes a días ya cerrados y con fecha de modificación anterior a seis meses calendario. Genera un `.log.tar.gz` por archivo, verifica que su contenido recuperado coincida en tamaño y SHA-256 con el original y recién entonces elimina el `.log`. Usa bloqueos para no archivar un archivo en escritura ni solaparse con otra ejecución. Conviene conservar los `.tar.gz` con una política de retención aparte: comprimir reduce espacio, pero no impone una fecha de borrado del archivo comprimido. El cron y el proceso FastAPI deben tener permisos compatibles sobre los directorios configurados.

`AuditLogWriter` produce archivos JSON Lines (`.log`) separados para `traffic` y `detection`. Cada línea contiene un objeto JSON, con `timestamp` UTC, `event` y `schema_version`; así se pueden procesar sin parsear mensajes de consola. El evento `traffic` contiene metadatos, características, MSE y decisión de cada flujo; `detection` registra anomalía, resultado de mitigación y liberación. Por defecto escribe en `SentinelAI-Backend/logs`, rota al cambio de día UTC y antes de superar 50 MiB. Los nombres incluyen fecha, PID e identificador de instancia para que dos procesos Uvicorn no escriban el mismo archivo. `SENTINEL_LOG_DIR` y `SENTINEL_LOG_MAX_BYTES` permiten cambiar ruta y máximo de bytes.

Si `SENTINEL_LOG_DIR` es relativo, se interpreta desde el directorio de trabajo del proceso. Para un servicio o cron, conviene configurarlo con una ruta absoluta compartida por ambos.

Para comprobar el estado y los archivos después de un replay, con el token exportado y desde la raíz:

```bash
curl -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
  http://127.0.0.1:8000/dashboard/state
find SentinelAI-Backend/logs -maxdepth 1 -name '*.log' -type f -print
```

Si acaba de iniciarse el proyecto, todavía no habrá archivos elegibles para archivado. Se puede ejecutar manualmente el comando del cron para verificar que la tarea termina sin archivar archivos recientes. La lógica de rotación y archivo tiene pruebas con directorios temporales:

```bash
python -m unittest discover -s tests -v
```

Ejemplo de archivado diario a las 02:15 del servidor:

```cron
15 2 * * * /ruta/al/venv/bin/python /ruta/a/SentinelAI/scripts/archive_logs.py --log-dir /ruta/a/SentinelAI/SentinelAI-Backend/logs --archive-dir /ruta/a/SentinelAI/SentinelAI-Backend/logs/archive --months 6
```

Usar rutas absolutas y un usuario con acceso de lectura/escritura al directorio. `SENTINEL_ARCHIVE_DIR` permite configurar el destino de los `.tar.gz` si no se pasa `--archive-dir`. Verificar los archivos de salida antes de aplicar una política que elimine archivos comprimidos.

### Recuperación y operación

- El estado de `iptables` pertenece al sistema operativo; PostgreSQL permite saber qué IPs deberían estar en cuarentena. En esta demo, la liberación se programa con tareas en memoria de FastAPI. Al arrancar, la API lee cuarentenas registradas y vuelve a programar las liberaciones pendientes. Si la escritura a PostgreSQL falló o una regla cambió fuera de la API, no hay reconciliación completa; una implementación de producción necesita un planificador persistente y conciliación del firewall.
- Ejecutar esta demo con un solo worker de Uvicorn. El bloqueo de `iptables`, la limitación temporal de escrituras y las tareas de liberación viven en cada proceso; varios workers requieren coordinación distribuida para evitar reglas o liberaciones duplicadas.
- Las tablas se crean actualmente con `Base.metadata.create_all()`; una modificación de columnas sobre una base existente requiere migraciones o una decisión explícita sobre los datos previos. `create_all()` no migra esquemas.
- Restringir permisos de los logs porque pueden incluir IPs y detalles operativos. Respaldar y controlar el volumen que contiene los archivos y archivos comprimidos.

## 5. Modelo y evaluación de generalización

### Entrenamiento que produjo los artefactos actuales

El notebook `SentinelAI-Model/01_Exploracion_Dataset.ipynb` carga el lunes de CIC-IDS2017, quita espacios de nombres de columnas, reemplaza infinitos por nulos y descarta filas incompletas. Excluye `Label`, ajusta un `MinMaxScaler` y entrena el autoencoder para reconstruir esos flujos. La red densa tiene capas de 64, 32 y 16 unidades en el codificador y 32, 64 y una salida sigmoide en el decodificador; entrena 15 épocas con pérdida MSE y `validation_split=0.1`.

El notebook aplica ese mismo scaler al miércoles sin volver a ajustarlo, calcula el MSE por flujo y obtiene un umbral a partir del percentil 99 del MSE benigno de entrenamiento. El valor `TAU = 0.000308` quedó como **valor base** en `SentinelAI-Backend/main.py`; cada sitio puede configurarse con otro umbral positivo. Todos los sitios usan los mismos artefactos `.h5` y scaler, que esperan 78 entradas. El modelo debe corresponder a ese scaler. El resultado OOD documentado abajo evalúa el valor base, no cada configuración específica de sitio.

La evaluación anterior cubría principalmente el escenario de la demo. El F1 de 0,97 informado en esa entrega no demuestra que el modelo generalice a otros días, tipos de ataque o redes. Tampoco es apropiado usar etiquetas de un conjunto de prueba para reajustar el umbral que se pretende evaluar. Por eso esta entrega añade una evaluación por día de CIC-IDS2017 y una prueba fuera de distribución (OOD) con UNSW-NB15 cuando exista un mapeo explícito y válido de características.

### Ejecutar la evaluación

Desde la raíz, con el entorno virtual del backend activo y los CSV bajo `SentinelAI-Model/data/`, instalar también las dependencias del informe y ejecutar:

```bash
python -m pip install -r SentinelAI-Model/requirements-validation.txt
python SentinelAI-Model/evaluate_ood.py \
  --cic-dir SentinelAI-Model/data \
  --output-dir SentinelAI-Model/reports/ood
```

El script usa por defecto `sentinel_model.h5`, `sentinel_scaler.save` y el umbral desplegado `0.000308`, sin volver a ajustar ninguno. Recorre los CSV por partes para controlar memoria y excluye el lunes del conjunto de evaluación porque se utilizó para ajustar el scaler y entrenar el modelo. `--include-training-day` permite mostrarlo únicamente como referencia contaminada, fuera del agregado de días no vistos. `--sample-fraction` y `--seed` permiten una corrida exploratoria reproducible; para el resultado de la entrega, usar el valor predeterminado `--sample-fraction 1.0`.

Para datos externos, el CSV debe contener las 78 variables que espera el scaler, con la misma definición y unidades, y una columna `label` binaria (`0` benigno, `1` ataque). Si los nombres cambian pero las variables son realmente equivalentes, `--external-feature-map` acepta un JSON que mapea **cada** nombre CIC esperado a su columna externa. Ejemplo de invocación después de verificar ese contrato:

```bash
python SentinelAI-Model/evaluate_ood.py \
  --cic-dir SentinelAI-Model/data \
  --external-csv /ruta/a/UNSW_reextraido_con_features_CIC.csv \
  --external-feature-map /ruta/a/mapa_verificado.json \
  --output-dir SentinelAI-Model/reports/ood
```

Si el CSV externo ya usa los nombres exactos del scaler, se omite `--external-feature-map`. El UNSW-NB15 tabular original no cumple este contrato y el script lo rechaza en vez de producir una comparación engañosa.

La [UNB publica CIC-UNSW-NB15](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html), una versión de UNSW-NB15 reextraída con CICFlowMeter que puede servir como punto de partida externo. El conjunto ofrece `Data.csv` y `Label.csv` separados y se descarga mediante un formulario. Antes de pasarlo al script hay que verificar que sus características tengan la misma definición y unidades que el scaler guardado, alinear las etiquetas con cada fila y producir un CSV con `label` binaria. El [UNSW-NB15 tabular original](https://research.unsw.edu.au/projects/unsw-nb15-dataset) se extrajo con Argus/Bro-IDS y no ofrece directamente ese contrato de entrada.

En el directorio de salida se generan `metrics.csv` (métricas y soporte por archivo y agregado), `confusion_matrices.csv` (TN/FP/FN/TP explícitos) y `evaluation.json` (artefactos, umbral, nombres de variables y parámetros). Si `matplotlib` está disponible, también se genera `confusion_matrices.png` para la presentación. Conservar los resultados junto con la versión del CSV y del modelo para poder repetir la evaluación.

La lógica del evaluador tiene pruebas con un modelo sintético, sin cargar TensorFlow:

```bash
python -m unittest discover -s SentinelAI-Model/tests -v
```

### Interpretación de resultados

La matriz de confusión usa `BENIGN` como clase negativa y cualquier ataque como positiva:

| | Predicción normal | Predicción anómala |
| --- | ---: | ---: |
| Real benigno | TN | FP |
| Real ataque | FN | TP |

El validador informa, por conjunto y en agregado, soporte de ambas clases, precisión, recall y F1 junto a TN/FP/FN/TP. Comparar matrices y proporciones por día deja ver cambios de comportamiento. Una caída en F1 o en recall OOD es evidencia de límites de generalización; si no hay caída, se debe reportar ese resultado tal como se observó. El script mide el rendimiento, no presupone que empeorará. Si un conjunto no contiene ambas clases, algunas métricas pueden no tener interpretación útil y deben leerse junto al soporte.

**Compatibilidad de dominios:** CIC-IDS2017 y UNSW-NB15 no comparten de forma directa las 78 variables de entrada del artefacto actual. La evaluación externa sólo es válida si se proporciona una transformación reproducible que produzca exactamente las variables del scaler, con mismas unidades y semántica. Rellenar columnas ausentes con ceros o renombrarlas por posición fabricaría un resultado. Si no se dispone de esa correspondencia, el informe debe indicar que UNSW-NB15 no pudo evaluarse en condiciones comparables.

### Resultado medido en los CSV locales completos

Se ejecutó `evaluate_ood.py` con el modelo y scaler locales, `--sample-fraction 1.0` y el umbral congelado `0.000308`. De 2.300.825 filas de los siete CSV de martes a viernes, 2.430 tenían entradas inválidas y se evaluaron **2.298.395**. El lunes quedó fuera porque participó del entrenamiento. La tabla resume las matrices de confusión completas; TN/FP/FN/TP usan el orden definido arriba.

| Conjunto | Válidos | TN | FP | FN | TP | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Martes | 445.645 | 426.887 | 4.926 | 13.823 | 9 | 0,0010 |
| Miércoles | 691.406 | 430.678 | 9.005 | 86.708 | 165.015 | 0,7752 |
| Jueves, WebAttacks | 170.231 | 166.320 | 1.731 | 2.158 | 22 | 0,0112 |
| Jueves, Infiltration | 288.395 | 261.400 | 26.959 | 7 | 29 | 0,0021 |
| Viernes, mañana | 190.911 | 186.713 | 2.242 | 1.911 | 45 | 0,0212 |
| Viernes, DDoS | 225.711 | 70.375 | 27.311 | 52.108 | 75.917 | 0,6566 |
| Viernes, PortScan | 286.096 | 125.602 | 1.690 | 127.302 | 31.502 | 0,3282 |
| **Agregado de días no vistos** | **2.298.395** | **1.667.975** | **73.864** | **284.017** | **272.539** | **0,6037** |

La figura compara las matrices obtenidas de los siete CSV locales de CIC-IDS2017 reservados para evaluación:

![Matrices de confusión por día](confusion_matrices.png)

En el agregado, la precisión fue **0,7868** y el recall **0,4897**. El F1 de **0,97** comunicado para la muestra acotada de la entrega anterior no se reprodujo al evaluar todos los flujos: incluso el miércoles completo dio **0,7752**. El comportamiento depende mucho del tipo de tráfico: el martes detectó 9 de 13.832 ataques; en el jueves de Infiltration sólo había 36 ataques y hubo 26.959 falsos positivos, de modo que ese F1 requiere leer también el soporte y la matriz. Estos resultados muestran una limitación real de generalización de los artefactos y umbral actuales; por sí solos no identifican una única causa, como sobreajuste, deriva de distribución o diferencias de clases.

Los valores exactos y parámetros de la corrida están en `SentinelAI-Model/reports/ood-full/`: `metrics.csv`, `confusion_matrices.csv`, `confusion_matrices.png` y `evaluation.json`. Ese directorio está ignorado por Git y debe conservarse aparte o regenerarse con los datos y artefactos correspondientes; una copia de la figura quedó en `docs/confusion_matrices.png`. No se reporta un F1 de UNSW-NB15: en este workspace no hay un CSV externo con las 78 características equivalentes, y el formato tabular original no es compatible.

## 6. Variables y artefactos

| Elemento | Función |
| --- | --- |
| `DATABASE_URL` | Cadena SQLAlchemy para PostgreSQL. |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Avisos de bloqueo y liberación. |
| `SENTINEL_LOG_DIR` | Directorio de logs; por defecto `SentinelAI-Backend/logs`. |
| `SENTINEL_LOG_MAX_BYTES` | Tamaño máximo de un segmento; por defecto `52428800` bytes (50 MiB). |
| `SENTINEL_ARCHIVE_DIR` | Destino de archivos comprimidos; por defecto subdirectorio `archive` de los logs. |
| `SENTINEL_CRITICAL_MSE` | Piso global de alerta crítica; se usa el mayor entre este valor (por defecto `3 × TAU`) y tres veces el umbral del sitio. |
| `SENTINEL_QUARANTINE_SECONDS` | Duración de la cuarentena; por defecto 60 segundos. |
| `SENTINEL_ALERT_TTL_HOURS` | Vigencia de alerta crítica; por defecto 24 horas. |
| `SENTINEL_ALERT_UPDATE_SECONDS` | Intervalo mínimo entre actualizaciones de una misma alerta crítica; por defecto 300 segundos. |
| `SENTINEL_API_URL` | URL de destino de `integracion_sensor.py`; por defecto `http://localhost:8000/ingest`. |
| `SENTINEL_CSV_FILE` | CSV usado por `integracion_sensor.py`; por defecto `SentinelAI-Edge/flujos_capturados.csv`. |
| `SENTINEL_CSV_CHUNK_SIZE` | Filas leídas por bloque en el replay CSV de `integracion_sensor.py`; por defecto 512. |
| `SENTINEL_FLOW_DELAY` | Pausa de `integracion_sensor.py` en segundos; por defecto 0,5. |
| `SENTINEL_REPLAY_CSV_FILE` | CSV del replay de 100 flujos; por defecto el miércoles de CIC-IDS2017 bajo `SentinelAI-Model/data/`. |
| `SENTINEL_SENSOR_TOKEN` | Token Bearer del sensor Edge, emitido al aprovisionarlo; no pertenece al `.env` del backend. |
| `SentinelAI-Model/models/sentinel_scaler.save` | Normalización ajustada durante el entrenamiento. |
| `SentinelAI-Model/models/sentinel_model.h5` | Autoencoder Keras entrenado; no versionado. |

Los datasets bajo `SentinelAI-Model/data/`, los `.log`, `.env` y el modelo `.h5` están ignorados por Git. Para reproducir un resultado es necesario guardar por separado versión y procedencia de esos archivos, versión de dependencias, umbral y parámetros del experimento.

## 7. Límites conocidos y próximos pasos

- El umbral base del backend sigue fijo en código, pero cada sitio puede configurar un override. Una recalibración requiere validación con datos separados y cambio controlado de la configuración del sitio.
- La cuarentena de la demo admite IPv4 y reglas `iptables INPUT` del host. Aunque PostgreSQL distingue `(site_id, source_ip)`, un firewall compartido no puede aplicar aislamientos independientes para la misma IP en dos sitios. Una implementación distribuida necesita definir qué nodo aplica cada regla y cómo sincroniza su estado.
- Las tareas de liberación y Telegram dependen del proceso FastAPI. Para operación continua se necesitan reintentos, reconciliación de reglas y tareas durables.
- `mitigation_events` es de sólo agregado y crece con las acciones reales de firewall. Aunque su volumen es menor que el de flujos, necesita monitoreo de almacenamiento y una política de archivo que conserve su valor probatorio.
- En varios servidores, cada instancia conserva sus `.log` localmente. Para investigar incidentes entre nodos se necesita recolectar y respaldar esos archivos con identificador de host y relojes sincronizados.
- Prometheus cuenta anomalías por `site_id`; los flujos totales y el último MSE son métricas globales de la instancia. Para observabilidad por sensor o sitio se necesitarían métricas adicionales con etiquetas controladas.
- La evaluación completa por día ya reveló diferencias fuertes. Sigue pendiente la prueba externa con UNSW-NB15 después de obtener o extraer las mismas 78 características y verificar su correspondencia.

El [README de la raíz](../README.md) resume la ejecución; este documento es la referencia de arquitectura y cambios de la rama `new-fix-50`. Las notas específicas de cada módulo están en [Backend](../SentinelAI-Backend/README.md) y [Modelo](../SentinelAI-Model/README.md).
