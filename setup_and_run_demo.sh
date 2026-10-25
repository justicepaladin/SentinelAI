#!/usr/bin/env bash

set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$BASE_DIR/SentinelAI-Backend"
EDGE_DIR="$BASE_DIR/SentinelAI-Edge"
ENV_FILE="$BACKEND_DIR/.env"
PYTHON_BIN="$BACKEND_DIR/.venv/bin/python"
POSTGRES_CONTAINER="sentinel-postgres"
POSTGRES_USER="sentinel_user"
POSTGRES_DB="sentinel_db"
API_BASE_URL="http://127.0.0.1:8000"
SENSOR_ID=1

API_PID=""
REPLAY_PID=""
ENV_TMP_FILE=""

# Ni curl ni requests deben enviar credenciales locales a un proxy heredado.
export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"

usage() {
    cat <<'EOF'
Uso: ./setup_and_run_demo.sh

ATENCIÓN: este script elimina todos los datos operativos de SentinelAI,
aprovisiona el sitio "Depósito Central" y ejecuta la demo completa.

Uvicorn permanece activo al finalizar el replay. Presioná Ctrl+C para detenerlo
de forma ordenada. Los tokens exportados existen sólo en este proceso y sus
subprocesos; copiá TOKEN_ADMIN del recuadro para usarlo en otra terminal.
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

require_writable() {
    [[ -w "$1" ]] || die "Se requiere permiso de escritura sobre: $1"
}

cleanup() {
    local exit_status=$?

    trap - EXIT INT TERM
    if [[ -n "$REPLAY_PID" ]] && kill -0 "$REPLAY_PID" 2>/dev/null; then
        printf '\n[*] Deteniendo el replay...\n'
        kill -TERM "$REPLAY_PID" 2>/dev/null || true
        wait "$REPLAY_PID" 2>/dev/null || true
    fi
    if [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
        printf '\n[*] Deteniendo Uvicorn de forma ordenada...\n'
        kill -TERM "$API_PID" 2>/dev/null || true
        wait "$API_PID" 2>/dev/null || true
    fi
    if [[ -n "$ENV_TMP_FILE" && -f "$ENV_TMP_FILE" ]]; then
        rm -f -- "$ENV_TMP_FILE"
    fi
    exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_postgres() {
    printf '[1/7] Preparando PostgreSQL (%s)...\n' "$POSTGRES_CONTAINER"
    if docker container inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1; then
        if [[ "$(docker inspect -f '{{.State.Running}}' "$POSTGRES_CONTAINER")" != "true" ]]; then
            docker start "$POSTGRES_CONTAINER" >/dev/null
        fi
    else
        docker run -d --name "$POSTGRES_CONTAINER" \
            -e POSTGRES_USER=sentinel_user \
            -e POSTGRES_PASSWORD=sentinel_password \
            -e POSTGRES_DB=sentinel_db \
            -p 127.0.0.1:5432:5432 postgres:15 >/dev/null
    fi

    local attempt mapping port_mapping mapping_exposed
    port_mapping="$(docker port "$POSTGRES_CONTAINER" 5432/tcp)" ||
        die "El contenedor no publica el puerto PostgreSQL"
    [[ -n "$port_mapping" ]] || die "El contenedor no publica el puerto PostgreSQL"
    mapping_exposed=0
    while IFS= read -r mapping; do
        case "$mapping" in
            "127.0.0.1:5432"|"[::1]:5432") ;;
            "0.0.0.0:5432"|"[::]:5432"|":::5432")
                mapping_exposed=1
                ;;
            *)
                die "Mapeo inesperado para PostgreSQL en sentinel-postgres: $mapping"
                ;;
        esac
    done <<<"$port_mapping"
    if (( mapping_exposed )); then
        printf '[!] ADVERTENCIA: sentinel-postgres está publicado en todas las interfaces (%s).\n' \
            "${port_mapping//$'\n'/, }" >&2
        printf '[!] Se reutilizará sin recrearlo; restringí el puerto cuando finalice la demo.\n' >&2
    fi

    for attempt in {1..45}; do
        if docker exec "$POSTGRES_CONTAINER" \
            pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
            printf '[+] PostgreSQL está listo.\n'
            return
        fi
        sleep 1
    done
    die "PostgreSQL no quedó listo dentro de 45 segundos"
}

validate_database_target() {
    # El TRUNCATE se ejecuta dentro del contenedor, mientras que SQLAlchemy se
    # conecta por el puerto publicado. Impedir que ambos apunten a bases distintas.
    if "$PYTHON_BIN" - "$ENV_FILE" "$POSTGRES_USER" "$POSTGRES_DB" <<'PY'
import sys

from dotenv import dotenv_values
from sqlalchemy.engine import make_url

env_file, expected_user, expected_database = sys.argv[1:]
database_url = dotenv_values(env_file).get("DATABASE_URL")
if not database_url:
    print("DATABASE_URL no está definido en SentinelAI-Backend/.env", file=sys.stderr)
    raise SystemExit(1)

try:
    url = make_url(database_url)
except (TypeError, ValueError) as exc:
    print(f"DATABASE_URL no es una URL válida: {exc}", file=sys.stderr)
    raise SystemExit(1)

valid_hosts = {"localhost", "127.0.0.1", "::1"}
is_expected = (
    url.drivername.startswith("postgresql")
    and url.username == expected_user
    and url.database == expected_database
    and url.host in valid_hosts
    and url.port in (None, 5432)
)
if not is_expected:
    print(
        "DATABASE_URL debe apuntar a "
        f"postgresql://{expected_user}:***@localhost:5432/{expected_database} "
        "para coincidir con el contenedor sentinel-postgres",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
    then
        return
    fi
    die "Se rechazó la limpieza porque DATABASE_URL apunta a otra base"
}

port_8000_is_open() {
    "$PYTHON_BIN" -c '
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
    connection.settimeout(0.5)
    raise SystemExit(0 if connection.connect_ex(("127.0.0.1", 8000)) == 0 else 1)
'
}

initialize_schema() {
    # Permite que el mismo script funcione también con un contenedor recién creado.
    (
        cd "$BACKEND_DIR"
        exec env \
            -u DATABASE_URL \
            -u SENTINEL_SENSOR_TOKEN \
            -u TOKEN_ADMIN \
            -u SENTINEL_ADMIN_TOKEN_SHA256 \
            "$PYTHON_BIN" -c \
            'from dotenv import load_dotenv; load_dotenv(".env"); from database import create_database_tables; create_database_tables()'
    )
}

reset_database() {
    printf '[2/7] Limpiando completamente la base de datos...\n'
    # La transacción garantiza que el trigger vuelva a quedar habilitado incluso
    # si PostgreSQL rechaza o interrumpe el TRUNCATE.
    docker exec -i "$POSTGRES_CONTAINER" \
        psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
BEGIN;
ALTER TABLE mitigation_events DISABLE TRIGGER ALL;
TRUNCATE sites RESTART IDENTITY CASCADE;
ALTER TABLE mitigation_events ENABLE TRIGGER ALL;
COMMIT;
SQL
    printf '[+] Base de datos limpia y trigger de inmutabilidad habilitado.\n'
}

provision_demo_sensor() {
    local provision_output sensor_token

    printf '[3/7] Aprovisionando sitio y sensor...\n'
    if provision_output="$(
        cd "$BACKEND_DIR"
        env \
            -u DATABASE_URL \
            -u SENTINEL_SENSOR_TOKEN \
            -u TOKEN_ADMIN \
            -u SENTINEL_ADMIN_TOKEN_SHA256 \
            "$PYTHON_BIN" provision_sensor.py \
                --site-slug "deposito-central" \
                --site-name "Depósito Central" \
                --sensor-name "Replay-Edge" 2>&1
    )"; then
        :
    else
        printf '%s\n' "$provision_output" >&2
        die "No se pudo aprovisionar Replay-Edge"
    fi

    sensor_token="$(
        printf '%s\n' "$provision_output" |
            sed -n 's/^SENTINEL_SENSOR_TOKEN=//p'
    )"
    [[ -n "$sensor_token" && "$sensor_token" != *$'\n'* ]] ||
        die "provision_sensor.py no emitió un único token de sensor"
    [[ "$sensor_token" =~ ^[A-Za-z0-9_-]+$ ]] ||
        die "provision_sensor.py emitió un token con formato inesperado"

    export SENTINEL_SENSOR_TOKEN="$sensor_token"
    unset provision_output sensor_token
    printf '[+] SENTINEL_SENSOR_TOKEN capturado y exportado para el replay.\n'
}

update_admin_hash() {
    local admin_data admin_hash

    printf '[4/7] Generando credencial administrativa...\n'
    admin_data="$("$PYTHON_BIN" -c '
import hashlib
import secrets

# 36 bytes producen exactamente 48 caracteres Base64 URL-safe sin padding.
token = secrets.token_urlsafe(36)
assert len(token) == 48
print(token)
print(hashlib.sha256(token.encode("utf-8")).hexdigest())
')"
    TOKEN_ADMIN="${admin_data%%$'\n'*}"
    admin_hash="${admin_data#*$'\n'}"
    unset admin_data

    [[ ${#TOKEN_ADMIN} -eq 48 && "$TOKEN_ADMIN" =~ ^[A-Za-z0-9_-]+$ ]] ||
        die "No se pudo generar un TOKEN_ADMIN seguro de 48 caracteres"
    [[ "$admin_hash" =~ ^[0-9a-f]{64}$ ]] ||
        die "No se pudo calcular el SHA-256 de TOKEN_ADMIN"

    ENV_TMP_FILE="$(mktemp "$BACKEND_DIR/.env.tmp.XXXXXX")"
    awk -v hash="$admin_hash" '
        BEGIN { updated = 0 }
        /^[[:space:]]*(export[[:space:]]+)?SENTINEL_ADMIN_TOKEN_SHA256[[:space:]]*=/ {
            if (!updated) {
                print "SENTINEL_ADMIN_TOKEN_SHA256=" hash
                updated = 1
            }
            next
        }
        { print }
        END {
            if (!updated) {
                print "SENTINEL_ADMIN_TOKEN_SHA256=" hash
            }
        }
    ' "$ENV_FILE" >"$ENV_TMP_FILE"
    chmod --reference="$ENV_FILE" "$ENV_TMP_FILE"
    mv -f -- "$ENV_TMP_FILE" "$ENV_FILE"
    ENV_TMP_FILE=""

    export TOKEN_ADMIN
    unset admin_hash
    printf '[+] Hash administrativo actualizado en SentinelAI-Backend/.env.\n'
}

show_admin_token() {
    printf '\n'
    printf '%s\n' '################################################################################'
    printf '%s\n' '#                !!! TOKEN ADMINISTRADOR - COPIAR AHORA !!!                    #'
    printf '# %-76s #\n' "TOKEN_ADMIN=$TOKEN_ADMIN"
    printf '%s\n' '################################################################################'
    printf '\n'
}

sensor_flow_count() {
    local telemetry

    telemetry="$("$PYTHON_BIN" - "$API_BASE_URL/sensors/$SENSOR_ID/telemetry" <<'PY'
import os
import sys

import requests

try:
    response = requests.get(
        sys.argv[1],
        headers={"Authorization": f"Bearer {os.environ['SENTINEL_SENSOR_TOKEN']}"},
        timeout=(1, 2),
    )
    response.raise_for_status()
    value = response.json().get("flow_count")
except (KeyError, requests.RequestException, ValueError) as exc:
    print(f"No se pudo consultar la telemetría: {exc}", file=sys.stderr)
    raise SystemExit(1)

if type(value) is not int or value < 0:
    raise SystemExit(1)
print(value)
PY
)" || return 1
    printf '%s\n' "$telemetry"
}

api_is_ready() {
    local health

    health="$(
        curl --connect-timeout 1 --max-time 2 -fsS \
            "$API_BASE_URL/health" 2>/dev/null
    )" || return 1
    printf '%s' "$health" | "$PYTHON_BIN" -c '
import json
import sys

health = json.load(sys.stdin)
required = ("ml_ready", "database_ready_at_startup", "logging_ready")
raise SystemExit(0 if all(health.get(key) is True for key in required) else 1)
' >/dev/null
}

validate_admin_token() {
    if "$PYTHON_BIN" - "$API_BASE_URL/sites/1/config" <<'PY'
import os
import sys

import requests

try:
    response = requests.get(
        sys.argv[1],
        headers={"Authorization": f"Bearer {os.environ['TOKEN_ADMIN']}"},
        timeout=(1, 2),
    )
except (KeyError, requests.RequestException) as exc:
    print(f"No se pudo validar TOKEN_ADMIN: {exc}", file=sys.stderr)
    raise SystemExit(1)

if response.status_code != 200:
    print(f"TOKEN_ADMIN no fue aceptado por la API (HTTP {response.status_code})", file=sys.stderr)
    raise SystemExit(1)
PY
    then
        :
    else
        die "No se pudo validar TOKEN_ADMIN contra la API"
    fi
    printf '[+] TOKEN_ADMIN validado contra la API.\n'
}

wait_for_api() {
    local api_status deadline

    printf '[6/7] Esperando que la API complete sus chequeos de salud...\n'
    deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
        if ! kill -0 "$API_PID" 2>/dev/null; then
            if wait "$API_PID"; then
                api_status=0
            else
                api_status=$?
            fi
            API_PID=""
            die "Uvicorn terminó antes de estar listo (código $api_status)"
        fi
        if api_is_ready; then
            printf '[+] API lista en %s.\n' "$API_BASE_URL"
            return
        fi
        sleep 1
    done
    die "La API no quedó completamente lista dentro de 90 segundos"
}

start_api() {
    printf '[5/7] Iniciando Uvicorn...\n'
    (
        cd "$BACKEND_DIR"
        exec env \
            -u DATABASE_URL \
            -u SENTINEL_SENSOR_TOKEN \
            -u TOKEN_ADMIN \
            -u SENTINEL_ADMIN_TOKEN_SHA256 \
            "$PYTHON_BIN" -m uvicorn main:app --host 127.0.0.1 --port 8000
    ) &
    API_PID=$!
}

run_replay() {
    local replay_status api_status health_poll flows_before flows_after expected_flows

    flows_before="$(sensor_flow_count)" ||
        die "No se pudo leer la telemetría del sensor antes del replay"

    printf '[7/7] Ejecutando demo_replay.py...\n'
    (
        cd "$EDGE_DIR"
        exec env \
            -u TOKEN_ADMIN \
            -u SENTINEL_ADMIN_TOKEN_SHA256 \
            "$PYTHON_BIN" demo_replay.py
    ) &
    REPLAY_PID=$!
    health_poll=0

    while kill -0 "$REPLAY_PID" 2>/dev/null; do
        if ! kill -0 "$API_PID" 2>/dev/null; then
            if wait "$API_PID"; then
                api_status=0
            else
                api_status=$?
            fi
            API_PID=""
            die "Uvicorn se detuvo durante el replay (código $api_status)"
        fi
        health_poll=$((health_poll + 1))
        if (( health_poll >= 5 )); then
            api_is_ready || die "La API dejó de estar saludable durante el replay"
            health_poll=0
        fi
        sleep 1
    done

    if wait "$REPLAY_PID"; then
        replay_status=0
    else
        replay_status=$?
    fi
    REPLAY_PID=""

    (( replay_status == 0 )) || die "demo_replay.py terminó con código $replay_status"
    kill -0 "$API_PID" 2>/dev/null || die "Uvicorn se detuvo durante el replay"
    api_is_ready || die "La API dejó de estar saludable durante el replay"
    flows_after="$(sensor_flow_count)" ||
        die "No se pudo leer la telemetría del sensor después del replay"
    expected_flows=$((flows_before + 100))
    (( flows_after == expected_flows )) ||
        die "El replay intentó 100 flujos, pero la API registró $((flows_after - flows_before))"
}

if (($#)); then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Opción desconocida: $1"
            ;;
    esac
fi

require_command docker
require_command curl
require_command sed
require_command awk
require_command mktemp
require_file "$PYTHON_BIN"
require_file "$ENV_FILE"
require_writable "$ENV_FILE"
require_writable "$BACKEND_DIR"
require_file "$BACKEND_DIR/provision_sensor.py"
require_file "$EDGE_DIR/demo_replay.py"
require_file "$BASE_DIR/SentinelAI-Model/models/sentinel_model.h5"
require_file "$BASE_DIR/SentinelAI-Model/models/sentinel_scaler.save"
require_file "$BASE_DIR/SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv"

validate_database_target

if port_8000_is_open; then
    die "El puerto 127.0.0.1:8000 ya está ocupado; liberalo antes de limpiar la base"
fi

start_postgres
initialize_schema
reset_database
provision_demo_sensor
update_admin_hash
show_admin_token

export SENTINEL_API_URL="$API_BASE_URL/ingest"
start_api
wait_for_api
validate_admin_token
run_replay

printf '\n[+] Replay finalizado correctamente. Uvicorn continúa activo en %s.\n' "$API_BASE_URL"
printf '[+] Presioná Ctrl+C para detener la API de forma ordenada.\n'
show_admin_token

if wait "$API_PID"; then
    api_status=0
else
    api_status=$?
fi
API_PID=""
die "Uvicorn terminó inesperadamente con código $api_status"
