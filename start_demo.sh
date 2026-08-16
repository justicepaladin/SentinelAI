#!/usr/bin/env bash

set -u

readonly PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly BACKEND_DIR="$PROJECT_DIR/SentinelAI-Backend"
readonly EDGE_DIR="$PROJECT_DIR/SentinelAI-Edge"
readonly BACKEND_LOG="$BACKEND_DIR/backend.log"
readonly DATABASE_URL="postgresql://sentinel_user:sentinel_password@localhost:5432/sentinel_db"
BACKEND_PID=""

cleanup() {
    if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo
        echo "Deteniendo SentinelAI Backend..."
        kill "$BACKEND_PID"
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Iniciando la demostración de SentinelAI"
echo "---------------------------------------"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker no está instalado o no está disponible en PATH."
    exit 1
fi

if [[ ! -f "$BACKEND_DIR/.venv/bin/activate" ]]; then
    echo "Error: falta el entorno virtual en SentinelAI-Backend/.venv."
    echo "Consultá la preparación del entorno en README.md."
    exit 1
fi

if [[ ! -f "$EDGE_DIR/flujos_capturados.csv" ]]; then
    echo "Error: falta SentinelAI-Edge/flujos_capturados.csv."
    echo "Copiá allí el dataset que quieras reproducir durante la demo."
    exit 1
fi

if [[ ! -f "$PROJECT_DIR/SentinelAI-Model/models/sentinel_model.h5" ]]; then
    echo "Error: falta SentinelAI-Model/models/sentinel_model.h5."
    exit 1
fi

echo "[1/4] Iniciando PostgreSQL..."
if ! docker start sentinel-postgres >/dev/null 2>&1; then
    if ! docker run \
        --name sentinel-postgres \
        -e POSTGRES_USER=sentinel_user \
        -e POSTGRES_PASSWORD=sentinel_password \
        -e POSTGRES_DB=sentinel_db \
        -p 5432:5432 \
        -d postgres:16 >/dev/null; then
        echo "Error: no se pudo iniciar el contenedor sentinel-postgres."
        exit 1
    fi
fi

echo "[2/4] Iniciando SentinelAI Backend..."
# El backend se ejecuta en segundo plano para dejar la consola disponible al Edge.
source "$BACKEND_DIR/.venv/bin/activate"
export DATABASE_URL
(
    cd "$BACKEND_DIR" || exit 1
    exec python -m uvicorn main:app --host 0.0.0.0 --port 8000
) >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

# Esperamos una respuesta real para no perder los primeros flujos del dataset.
backend_ready=false
for _ in {1..20}; do
    if python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=1)" \
        >/dev/null 2>&1; then
        backend_ready=true
        break
    fi

    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo "Error: el backend terminó durante el inicio. Revisá $BACKEND_LOG."
        exit 1
    fi
    sleep 1
done

if [[ "$backend_ready" != true ]]; then
    echo "Error: el backend no respondió dentro de los 20 segundos esperados."
    echo "Revisá $BACKEND_LOG para ver el detalle."
    exit 1
fi

echo "[3/4] Dataset Edge listo: SentinelAI-Edge/flujos_capturados.csv"
echo "[4/4] Reproduciendo los flujos capturados..."
python "$EDGE_DIR/integracion_sensor.py"

echo
echo "Demostración finalizada. PostgreSQL queda activo para conservar las alertas."
