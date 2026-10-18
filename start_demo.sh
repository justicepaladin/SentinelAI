#!/usr/bin/env bash

set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$BASE_DIR/SentinelAI-Backend"
EDGE_DIR="$BASE_DIR/SentinelAI-Edge"
PYTHON_BIN="$BACKEND_DIR/.venv/bin/python"
API_BASE_URL="http://127.0.0.1:8000"
POSTGRES_CONTAINER="${SENTINEL_DEMO_POSTGRES_CONTAINER:-sentinel-postgres}"
SITE_ID="${SENTINEL_SITE_ID:-1}"
SENSOR_ID="${SENTINEL_SENSOR_ID:-1}"
RUN_REPLAY=1

usage() {
    cat <<'EOF'
Uso:
  export SENTINEL_SENSOR_TOKEN='<token emitido por provision_sensor.py>'
  export TOKEN_ADMIN='<token administrador sin hashear>'
  ./start_demo.sh [--site-id N] [--sensor-id N] [--no-replay]

Abre cuatro terminales:
  1. Monitor de reglas INPUT de iptables.
  2. Backend FastAPI con un solo worker.
  3. Replay Edge de 100 flujos CIC-IDS2017.
  4. Consola interactiva para demostrar las funciones del 75 %.

Opciones:
  --site-id N       Sitio usado por la consola operativa (por defecto: 1).
  --sensor-id N     Sensor usado para heartbeat/telemetría (por defecto: 1).
  --no-replay       Abre la terminal Edge sin iniciar el replay automáticamente.
  -h, --help        Muestra esta ayuda.

Variables opcionales:
  SENTINEL_DEMO_POSTGRES_CONTAINER  Contenedor PostgreSQL local.
  SENTINEL_DEMO_SKIP_POSTGRES=1     No inicia ni crea el contenedor local.
EOF
}

die() {
    printf '[!] %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Falta el comando requerido: $1"
}

require_file() {
    [[ -f "$1" ]] || die "Falta el archivo requerido: $1"
}

pretty_json() {
    "$PYTHON_BIN" -m json.tool
}

sensor_get() {
    curl -sS \
        -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
        "$API_BASE_URL$1" | pretty_json
}

sensor_post() {
    local path="$1"
    local body="$2"
    curl -sS -X POST \
        -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
        -H 'Content-Type: application/json' \
        -d "$body" \
        "$API_BASE_URL$path" | pretty_json
}

admin_get() {
    curl -sS \
        -H "Authorization: Bearer ${TOKEN_ADMIN}" \
        "$API_BASE_URL$1" | pretty_json
}

admin_put() {
    local path="$1"
    local body="$2"
    curl -sS -X PUT \
        -H "Authorization: Bearer ${TOKEN_ADMIN}" \
        -H 'Content-Type: application/json' \
        -d "$body" \
        "$API_BASE_URL$path" | pretty_json
}

admin_post() {
    local path="$1"
    curl -sS -X POST \
        -H "Authorization: Bearer ${TOKEN_ADMIN}" \
        "$API_BASE_URL$path" | pretty_json
}

operations_console() {
    require_file "$PYTHON_BIN"
    require_command curl
    [[ -n "${SENTINEL_SENSOR_TOKEN:-}" ]] || die "Falta SENTINEL_SENSOR_TOKEN"
    [[ -n "${TOKEN_ADMIN:-}" ]] || die "Falta TOKEN_ADMIN"
    # Una respuesta 4xx forma parte de la demo (por ejemplo, revertir una IP
    # inexistente) y no debe cerrar la consola interactiva.
    set +e

    while true; do
        cat <<EOF

============================================================
 SentinelAI · Consola de demostración del avance 75 %
 API: $API_BASE_URL · sitio: $SITE_ID · sensor: $SENSOR_ID
============================================================
  1) Salud de la API
  2) Configuración del sitio (RF-07/RF-08/RNF-06)
  3) Activar respuesta y salir de modo informativo
  4) Activar modo informativo
  5) Reportar enlace sano (RNF-05)
  6) Reportar enlace degradado (RNF-05)
  7) Consultar telemetría (RF-06)
  8) Listar alertas del sitio (RF-05)
  9) Consultar dashboard del sitio
 10) Revertir manualmente una cuarentena (RF-05)
 11) Ejecutar nuevamente el replay Edge
 12) Ejecutar benchmark RNF y regenerar Markdown/CSV
 13) Ejecutar análisis estadístico del umbral
  q) Salir de esta consola
EOF
        if ! read -r -p 'Elegí una opción: ' choice; then
            exit 0
        fi
        printf '\n'
        case "$choice" in
            1)
                curl -sS "$API_BASE_URL/health" | pretty_json
                ;;
            2)
                admin_get "/sites/$SITE_ID/config"
                ;;
            3)
                admin_put "/sites/$SITE_ID/config" \
                    '{"active_response_enabled":true,"informative_only_mode":false}'
                printf '\n[+] Respuesta activa. Ejecutá la opción 11 y observá iptables.\n'
                ;;
            4)
                admin_put "/sites/$SITE_ID/config" \
                    '{"informative_only_mode":true}'
                printf '\n[+] Modo informativo activo: detecta y alerta sin bloquear.\n'
                ;;
            5)
                sensor_post "/sensors/$SENSOR_ID/heartbeat" '{"link_degraded":false}'
                printf '\n[+] El sensor informó recuperación del enlace.\n'
                ;;
            6)
                sensor_post "/sensors/$SENSOR_ID/heartbeat" '{"link_degraded":true}'
                printf '\n[+] Enlace degradado durante la vigencia configurada. Usá la opción 11.\n'
                ;;
            7)
                admin_get "/sensors/$SENSOR_ID/telemetry"
                ;;
            8)
                admin_get "/alerts?site_id=$SITE_ID&limit=20"
                ;;
            9)
                sensor_get '/dashboard/state'
                ;;
            10)
                read -r -p 'IP en cuarentena que querés revertir: ' source_ip
                [[ -n "$source_ip" ]] || { printf '[!] La IP no puede estar vacía.\n'; continue; }
                admin_post "/quarantines/$source_ip/revert?site_id=$SITE_ID"
                ;;
            11)
                (cd "$EDGE_DIR" && "$PYTHON_BIN" demo_replay.py)
                ;;
            12)
                (cd "$BASE_DIR" && "$PYTHON_BIN" scripts/benchmark_rnf.py \
                    --requests 500 --warmup 5)
                printf '\n[+] Resultados: docs/benchmark_rnf_results.md y .csv\n'
                ;;
            13)
                (cd "$BASE_DIR" && "$PYTHON_BIN" SentinelAI-Model/threshold_analysis.py \
                    --cic-dir SentinelAI-Model/data \
                    --output docs/threshold_justification.md)
                printf '\n[+] Resultado: docs/threshold_justification.md\n'
                ;;
            q|Q)
                exit 0
                ;;
            *)
                printf '[!] Opción inválida.\n'
                ;;
        esac
        printf '\n'
        if ! read -r -p 'Presioná ENTER para volver al menú...'; then
            exit 0
        fi
    done
}

start_postgres() {
    if [[ "${SENTINEL_DEMO_SKIP_POSTGRES:-0}" == "1" ]]; then
        printf '[+] Se omitió PostgreSQL local por SENTINEL_DEMO_SKIP_POSTGRES=1.\n'
        return
    fi

    printf '[1/4] Preparando PostgreSQL local...\n'
    if docker container inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1; then
        docker start "$POSTGRES_CONTAINER" >/dev/null
    else
        docker run -d --name "$POSTGRES_CONTAINER" \
            -e POSTGRES_USER=sentinel_user \
            -e POSTGRES_PASSWORD=sentinel_password \
            -e POSTGRES_DB=sentinel_db \
            -p 5432:5432 postgres:15 >/dev/null
    fi

    local attempt
    for attempt in {1..45}; do
        if docker exec "$POSTGRES_CONTAINER" \
            pg_isready -U sentinel_user -d sentinel_db >/dev/null 2>&1; then
            printf '[+] PostgreSQL está listo.\n'
            return
        fi
        sleep 1
    done
    die "PostgreSQL no quedó listo dentro de 45 segundos"
}

wait_for_api() {
    local attempt health
    for attempt in {1..90}; do
        if health="$(curl -fsS "$API_BASE_URL/health" 2>/dev/null)"; then
            printf '%s\n' "$health" | pretty_json
            [[ "$health" == *'"ml_ready":true'* ]] || \
                die "La API arrancó sin los artefactos ML"
            [[ "$health" == *'"database_ready_at_startup":true'* ]] || \
                die "La API arrancó sin PostgreSQL; revisá la migración y DATABASE_URL"
            [[ "$health" == *'"logging_ready":true'* ]] || \
                die "La API arrancó sin el logger de auditoría"
            return
        fi
        sleep 1
    done
    die "FastAPI no respondió en $API_BASE_URL después de 90 segundos"
}

validate_demo_identity() {
    local status_code
    status_code="$(curl -sS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${TOKEN_ADMIN}" \
        "$API_BASE_URL/sites/$SITE_ID/config")"
    [[ "$status_code" == "200" ]] || \
        die "El token administrador no puede acceder al sitio $SITE_ID (HTTP $status_code)"

    status_code="$(curl -sS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
        "$API_BASE_URL/sites/$SITE_ID/config")"
    [[ "$status_code" == "200" ]] || \
        die "El token del sensor no puede acceder al sitio $SITE_ID (HTTP $status_code)"

    status_code="$(curl -sS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${SENTINEL_SENSOR_TOKEN}" \
        "$API_BASE_URL/sensors/$SENSOR_ID/telemetry")"
    [[ "$status_code" == "200" ]] || \
        die "El token no corresponde al sensor $SENSOR_ID (HTTP $status_code)"
}

launch_terminal() {
    local secret_scope="$1"
    local command_text="$2"
    case "$secret_scope" in
        none)
            env -u SENTINEL_SENSOR_TOKEN -u TOKEN_ADMIN -u SENTINEL_ADMIN_TOKEN_SHA256 \
                ptyxis -- bash -lc "$command_text" &
            ;;
        sensor)
            env -u TOKEN_ADMIN ptyxis -- bash -lc "$command_text" &
            ;;
        all)
            ptyxis -- bash -lc "$command_text" &
            ;;
        *)
            die "Alcance de secretos inválido: $secret_scope"
            ;;
    esac
}

if [[ "${1:-}" == "--operations-console" ]]; then
    shift
    operations_console
    exit 0
fi

while (($#)); do
    case "$1" in
        --site-id)
            [[ $# -ge 2 ]] || die "--site-id requiere un valor"
            SITE_ID="$2"
            shift 2
            ;;
        --sensor-id)
            [[ $# -ge 2 ]] || die "--sensor-id requiere un valor"
            SENSOR_ID="$2"
            shift 2
            ;;
        --no-replay)
            RUN_REPLAY=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Opción desconocida: $1"
            ;;
    esac
done

[[ "$SITE_ID" =~ ^[1-9][0-9]*$ ]] || die "--site-id debe ser un entero positivo"
[[ "$SENSOR_ID" =~ ^[1-9][0-9]*$ ]] || die "--sensor-id debe ser un entero positivo"

require_command curl
require_command docker
require_command ptyxis
require_command sha256sum
require_file "$PYTHON_BIN"
require_file "$BACKEND_DIR/.env"
require_file "$BASE_DIR/SentinelAI-Model/models/sentinel_model.h5"
require_file "$BASE_DIR/SentinelAI-Model/models/sentinel_scaler.save"
require_file "$BASE_DIR/SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv"
require_file "$EDGE_DIR/demo_replay.py"

[[ -n "${SENTINEL_SENSOR_TOKEN:-}" ]] || \
    die "Falta SENTINEL_SENSOR_TOKEN. Ejecutá provision_sensor.py y exportá el valor emitido."
[[ -n "${TOKEN_ADMIN:-}" ]] || \
    die "Falta TOKEN_ADMIN con el token administrador en texto plano."
(( ${#SENTINEL_SENSOR_TOKEN} >= 32 && ${#SENTINEL_SENSOR_TOKEN} <= 512 )) || \
    die "SENTINEL_SENSOR_TOKEN debe tener entre 32 y 512 caracteres"
(( ${#TOKEN_ADMIN} >= 32 && ${#TOKEN_ADMIN} <= 512 )) || \
    die "TOKEN_ADMIN debe tener entre 32 y 512 caracteres"

configured_admin_hash="$(sed -nE \
    's/^[[:space:]]*SENTINEL_ADMIN_TOKEN_SHA256[[:space:]]*=[[:space:]]*([0-9A-Fa-f]{64})[[:space:]]*$/\1/p' \
    "$BACKEND_DIR/.env" | tail -n 1 | tr '[:upper:]' '[:lower:]')"
[[ -n "$configured_admin_hash" ]] || \
    die "SENTINEL_ADMIN_TOKEN_SHA256 no está configurado correctamente en SentinelAI-Backend/.env"
actual_admin_hash="$(printf '%s' "$TOKEN_ADMIN" | sha256sum | cut -d ' ' -f 1)"
[[ "$actual_admin_hash" == "$configured_admin_hash" ]] || \
    die "TOKEN_ADMIN no coincide con SENTINEL_ADMIN_TOKEN_SHA256 del backend"

export SENTINEL_SITE_ID="$SITE_ID"
export SENTINEL_SENSOR_ID="$SENSOR_ID"
export SENTINEL_DEMO_API_URL="$API_BASE_URL"
export SENTINEL_API_URL="$API_BASE_URL/ingest"

if curl -fsS "$API_BASE_URL/health" >/dev/null 2>&1; then
    die "Ya hay una API respondiendo en $API_BASE_URL; detenela antes de iniciar la demo"
fi

start_postgres

printf '[2/4] Abriendo monitor de iptables...\n'
printf -v quoted_base '%q' "$BASE_DIR"
firewall_command="
    printf '\\n=== SentinelAI · Firewall INPUT ===\\n';
    printf 'Ingresá la contraseña sudo si se solicita. Ctrl+C detiene el monitor.\\n\\n';
    sudo -v || exit 1;
    sudo watch -n 1 iptables -L INPUT -n --line-numbers;
    exec bash
"
launch_terminal none "$firewall_command"

printf '[3/4] Abriendo FastAPI...\n'
backend_command="
    cd ${quoted_base}/SentinelAI-Backend || exit 1;
    printf '\\n=== SentinelAI · Backend FastAPI ===\\n';
    printf 'Se usa un solo worker. Ingresá sudo para habilitar iptables durante la demo.\\n\\n';
    sudo -v || exit 1;
    (while true; do sudo -n -v || exit 1; sleep 60; done) &
    sudo_keepalive=\$!;
    trap 'kill \"\$sudo_keepalive\" 2>/dev/null || true' EXIT;
    .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000;
    kill \"\$sudo_keepalive\" 2>/dev/null || true;
    wait \"\$sudo_keepalive\" 2>/dev/null || true;
    trap - EXIT;
    printf '\\n[!] Uvicorn terminó.\\n';
    exec bash
"
launch_terminal none "$backend_command"

printf '[+] Esperando que FastAPI cargue TensorFlow y valide PostgreSQL...\n'
wait_for_api
validate_demo_identity

printf '[4/4] Abriendo consola operativa y Edge...\n'
operations_command="${quoted_base}/start_demo.sh --operations-console; exec bash"
launch_terminal all "$operations_command"

if [[ "$RUN_REPLAY" == "1" ]]; then
    edge_action="${quoted_base}/SentinelAI-Backend/.venv/bin/python demo_replay.py"
else
    edge_action="printf 'Replay automático omitido. Ejecutá: ../SentinelAI-Backend/.venv/bin/python demo_replay.py\\n'"
fi
edge_command="
    cd ${quoted_base}/SentinelAI-Edge || exit 1;
    printf '\\n=== SentinelAI · Sensor Edge ===\\n\\n';
    $edge_action;
    printf '\\n[+] La terminal queda disponible para repetir el replay.\\n';
    exec bash
"
launch_terminal sensor "$edge_command"

cat <<EOF

[+] Demo iniciada en cuatro terminales.
[+] Swagger: $API_BASE_URL/docs
[+] Métricas: $API_BASE_URL/metrics

Secuencia sugerida en la consola del 75 %:
  1. Revisar configuración y telemetría (opciones 2, 7 y 8).
  2. Activar respuesta (3), reportar enlace sano (5) y repetir replay (11).
  3. Reportar degradación (6) y repetir replay: debe detectar sin agregar reglas.
  4. Recuperar enlace (5), activar modo informativo (4) y repetir replay.
  5. Consultar alertas/dashboard (8 y 9) o revertir una IP (10).

Para finalizar:
  - Ctrl+C en las terminales Backend y Firewall.
  - docker stop $POSTGRES_CONTAINER

El script no vacía INPUT ni elimina reglas ajenas a SentinelAI.
EOF
