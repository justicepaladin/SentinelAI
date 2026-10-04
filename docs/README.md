# SentinelAI: arquitectura, operación y validación

Documento de referencia para continuar el proyecto después de la entrega del 50 %. Describe el código de esta rama, los artefactos que necesita y la forma de comprobar los cambios de persistencia y validación del modelo. Los ejemplos parten de la raíz del repositorio.

La rama `fix-50%` reúne la demo con notificaciones de Telegram y la rama `demo50lv2`, que aportó el laboratorio de contenedores cliente/víctima.

## 1. Qué hace el proyecto

SentinelAI es un prototipo de IDPS distribuido. Un proceso *Edge* envía características numéricas de flujos de red a una API FastAPI. El backend aplica el `MinMaxScaler` usado al entrenar un autoencoder de TensorFlow, calcula el error cuadrático medio de reconstrucción (MSE) y marca una anomalía cuando `MSE > 0.000308`. La demo agrega respuesta activa con `iptables`, liberación temporal de la IP y avisos por Telegram. Prometheus puede consultar métricas de inferencia.

```text
CSV de CIC-IDS2017 → Edge/replay → POST /ingest → validación de 78 características
                                               → scaler → autoencoder → MSE > TAU
                                               ├─ registro local rotativo
                                               ├─ estado y alertas críticas en PostgreSQL
                                               └─ anomalía → iptables → Telegram
```

El replay usa datos ya procesados de CIC-IDS2017. No captura paquetes de red en vivo. Las direcciones IP de la demo se construyen para mostrar el bloqueo, y no provienen del CSV de características.

## 2. Mapa del repositorio

| Ruta | Responsabilidad |
| --- | --- |
| `SentinelAI-Backend/main.py` | API, preparación de características, inferencia, métricas, mitigación y Telegram. |
| `SentinelAI-Backend/database.py` | Conexión SQLAlchemy y tablas de estado operacional. |
| `SentinelAI-Backend/state_store.py` | Escrituras y consultas acotadas del estado actual por IP. |
| `SentinelAI-Backend/traffic_logging.py` | Registro de flujos y detecciones en archivos `.log` locales con rotación. |
| `SentinelAI-Backend/.env.example` | Variables de configuración de ejemplo; copiar a `.env` sin versionar secretos. |
| `SentinelAI-Edge/demo_replay.py` | Envía 80 flujos benignos y 20 ataques seleccionados del miércoles. |
| `SentinelAI-Edge/integracion_sensor.py` | Envía las filas de un CSV indicado por `SENTINEL_CSV_FILE`. |
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
- Para la respuesta activa, `iptables` y una política de permisos que permita a la API ejecutar `sudo -n iptables`. Sin ese permiso, la clasificación puede funcionar, pero el aislamiento fallará.
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

Estas credenciales son exclusivamente locales. Desde `SentinelAI-Backend`, con el entorno virtual activo, iniciar:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

En otra terminal, desde la raíz y con el mismo entorno:

```bash
curl http://127.0.0.1:8000/health
cd SentinelAI-Edge
../SentinelAI-Backend/.venv/bin/python demo_replay.py
```

`demo_replay.py` resuelve el CSV desde `SentinelAI-Edge`, por lo que conviene ejecutarlo desde ese directorio. Selecciona 80 benignos y 20 ataques con `random_state=42`, mezcla la muestra, envía un flujo cada 0,3 segundos y muestra la etiqueta, decisión y MSE de cada uno. La selección se repite, pero el orden de envío y algunas IP simuladas pueden cambiar. El replay no calcula métricas agregadas.

El archivo `start_demo.sh` automatiza una puesta en escena específica de la máquina original: tiene una ruta absoluta, abre ventanas con `ptyxis`, usa `sudo` y, al finalizar, ejecuta `iptables -F INPUT`. Revisar y adaptar ese script antes de usarlo en otro host porque ese último comando elimina todas las reglas de la cadena `INPUT`.

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
| `POST /ingest` | Recibe un flujo; responde `mse_score`, `anomaly`, `message` y `dashboard_state_persisted`. |
| `GET /health` | Informa si cargaron los artefactos ML y el logger, y si la base estaba lista al iniciar. |
| `GET /dashboard/state` | Devuelve las cuarentenas activas y las alertas críticas vigentes; no expone historial crudo. |
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

La respuesta normal tiene HTTP 200. `dashboard_state_persisted` vale `true` cuando el intento de persistencia en PostgreSQL terminó sin error, `false` cuando se intentó y falló, y `null` cuando el flujo no requería una escritura. Un fallo de PostgreSQL no descarta el registro local ni la decisión del modelo; queda indicado en ese campo y en `message`. La API devuelve 422 para características inválidas, 503 si faltan artefactos ML o no se puede escribir el log local, y 500 ante un fallo interno de inferencia. `GET /dashboard/state` devuelve 503 si no puede consultar PostgreSQL. La disponibilidad de PostgreSQL se comprueba al iniciar; el campo `database_ready_at_startup` no es una prueba continua de salud.

## 4. Persistencia y ciclo de vida de los logs

El cambio de esta entrega separa dos necesidades:

1. **Historial de tráfico y decisiones:** cada inferencia escribe un registro local en un `.log`, tanto si es normal como si es anómala. Los archivos rotan para impedir que uno solo crezca indefinidamente.
2. **Estado consultable por la aplicación:** PostgreSQL conserva sólo información operacional acotada en `active_quarantines` y `critical_alerts`. No es el almacén de todos los flujos ni de todas las detecciones.

El flujo de escritura es `inferir → registrar el resultado → actualizar estado crítico si corresponde → responder`. Los logs locales representan el historial de la detección; una consulta de PostgreSQL refleja el estado actual. `active_quarantines` guarda una fila por IP aislada, con su vencimiento. `critical_alerts` mantiene la última alerta crítica por IP, con `first_seen`, `last_seen` y vencimiento. El umbral de criticidad es independiente del de detección: `SENTINEL_CRITICAL_MSE` vale por defecto tres veces `TAU`. Las actualizaciones de alertas se limitan temporalmente para evitar una escritura por cada inferencia. La consulta filtra filas vencidas; la limpieza física de alertas vencidas ocurre cuando llega otra crítica. Para reconstruir una línea temporal histórica se deben consultar los `.log` y sus archivos comprimidos.

La tabla heredada `alerts` puede seguir existiendo en una base iniciada con versiones anteriores. El backend nuevo no agrega filas allí; su contenido previo requiere una migración o purga manual después de hacer un respaldo. `create_all()` crea tablas faltantes, pero no convierte ni borra filas antiguas.

La tarea `scripts/archive_logs.py` está prevista para cron: considera sólo los `.log` con nombres generados por `AuditLogWriter`, pertenecientes a días ya cerrados y con fecha de modificación anterior a seis meses calendario. Genera un `.log.tar.gz` por archivo, verifica que su contenido recuperado coincida en tamaño y SHA-256 con el original y recién entonces elimina el `.log`. Usa bloqueos para no archivar un archivo en escritura ni solaparse con otra ejecución. Conviene conservar los `.tar.gz` con una política de retención aparte: comprimir reduce espacio, pero no impone una fecha de borrado del archivo comprimido. El cron y el proceso FastAPI deben tener permisos compatibles sobre los directorios configurados.

`AuditLogWriter` produce archivos JSON Lines (`.log`) separados para `traffic` y `detection`. Cada línea contiene un objeto JSON, con `timestamp` UTC, `event` y `schema_version`; así se pueden procesar sin parsear mensajes de consola. El evento `traffic` contiene metadatos, características, MSE y decisión de cada flujo; `detection` registra anomalía, resultado de mitigación y liberación. Por defecto escribe en `SentinelAI-Backend/logs`, rota al cambio de día UTC y antes de superar 50 MiB. Los nombres incluyen fecha, PID e identificador de instancia para que dos procesos Uvicorn no escriban el mismo archivo. `SENTINEL_LOG_DIR` y `SENTINEL_LOG_MAX_BYTES` permiten cambiar ruta y máximo de bytes.

Si `SENTINEL_LOG_DIR` es relativo, se interpreta desde el directorio de trabajo del proceso. Para un servicio o cron, conviene configurarlo con una ruta absoluta compartida por ambos.

Para comprobar el estado y los archivos después de un replay:

```bash
curl http://127.0.0.1:8000/dashboard/state
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

El notebook aplica ese mismo scaler al miércoles sin volver a ajustarlo, calcula el MSE por flujo y obtiene un umbral a partir del percentil 99 del MSE benigno de entrenamiento. El valor `TAU = 0.000308` quedó fijado en `SentinelAI-Backend/main.py` para la inferencia. El scaler versionado espera 78 entradas. El modelo `.h5` debe corresponder a ese scaler y a ese umbral.

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
| `SENTINEL_CRITICAL_MSE` | Umbral de alerta crítica para el dashboard; por defecto `3 × TAU`. |
| `SENTINEL_QUARANTINE_SECONDS` | Duración de la cuarentena; por defecto 60 segundos. |
| `SENTINEL_ALERT_TTL_HOURS` | Vigencia de alerta crítica; por defecto 24 horas. |
| `SENTINEL_ALERT_UPDATE_SECONDS` | Intervalo mínimo entre actualizaciones de una misma alerta crítica; por defecto 300 segundos. |
| `SENTINEL_API_URL` | URL de destino de `integracion_sensor.py`; por defecto `http://localhost:8000/ingest`. |
| `SENTINEL_CSV_FILE` | CSV usado por `integracion_sensor.py`; por defecto `SentinelAI-Edge/flujos_capturados.csv`. |
| `SENTINEL_FLOW_DELAY` | Pausa de `integracion_sensor.py` en segundos; por defecto 0,5. |
| `SentinelAI-Model/models/sentinel_scaler.save` | Normalización ajustada durante el entrenamiento. |
| `SentinelAI-Model/models/sentinel_model.h5` | Autoencoder Keras entrenado; no versionado. |

Los datasets bajo `SentinelAI-Model/data/`, los `.log`, `.env` y el modelo `.h5` están ignorados por Git. Para reproducir un resultado es necesario guardar por separado versión y procedencia de esos archivos, versión de dependencias, umbral y parámetros del experimento.

## 7. Límites conocidos y próximos pasos

- El umbral del backend está fijo en código. Una recalibración requiere validación por datos separados y cambio controlado del artefacto/configuración.
- La cuarentena de la demo admite IPv4 y reglas `iptables INPUT`. Una implementación distribuida necesita definir qué nodo aplica la regla y cómo sincroniza su estado con PostgreSQL.
- Las tareas de liberación y Telegram dependen del proceso FastAPI. Para operación continua se necesitan reintentos, reconciliación de reglas y tareas durables.
- En varios servidores, cada instancia conserva sus `.log` localmente. Para investigar incidentes entre nodos se necesita recolectar y respaldar esos archivos con identificador de host y relojes sincronizados.
- Las métricas Prometheus etiquetan anomalías por `source_ip`. En tráfico real, la cantidad de IPs distintas puede elevar la cardinalidad de series.
- La evaluación completa por día ya reveló diferencias fuertes. Sigue pendiente la prueba externa con UNSW-NB15 después de obtener o extraer las mismas 78 características y verificar su correspondencia.

El [README de la raíz](../README.md) resume la ejecución; este documento es la referencia de arquitectura y cambios de la rama `fix-50%`. Las notas específicas de cada módulo están en [Backend](../SentinelAI-Backend/README.md) y [Modelo](../SentinelAI-Model/README.md).
