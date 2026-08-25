#!/bin/bash

# ==========================================
# SentinelAI - Demo Orchestration Script
# ==========================================

BASE_DIR="/home/facundo/SentinelAI"

echo "[+] Iniciando orquestación interactiva de la demo..."
echo "----------------------------------------------------"

# ---------------------------------------------------------
# TERMINAL 1: Base de Datos y Monitoreo de Firewall
# ---------------------------------------------------------
echo "[1/3] Levantando PostgreSQL y monitoreo de iptables..."
ptyxis -- bash -c "
    echo '=> Verificando contenedor sentinel-postgres...';
    if [ \$(docker ps -a -q -f name=sentinel-postgres) ]; then
        echo 'Contenedor encontrado. Iniciando...';
        docker start sentinel-postgres;
    else
        echo 'Contenedor no encontrado. Creando e iniciando...';
        docker run -d --name sentinel-postgres \
            -e POSTGRES_USER=sentinel_user \
            -e POSTGRES_PASSWORD=sentinel_password \
            -e POSTGRES_DB=sentinel_db \
            -p 5432:5432 postgres:15;
    fi;
    echo '------------------------------------------------';
    echo '=> Iniciando watch sobre iptables...';
    sudo watch -n1 sudo iptables -L INPUT -n --line-numbers;
    exec bash
" &
PID_TERM1=$!

echo ""
echo "⏳ [ACCIÓN REQUERIDA]: Ingresar contraseña de sudo en la nueva ventana."
read -p "👉 Presionar ENTER cuando el watch esté corriendo para lanzar el Backend..."

# ---------------------------------------------------------
# TERMINAL 2: Backend y FastAPI
# ---------------------------------------------------------
echo ""
echo "[2/3] Levantando Backend (Uvicorn)..."
ptyxis -- bash -c "
    cd $BASE_DIR/SentinelAI-Backend || exit;
    echo '=> Iniciando Uvicorn...';
    sudo .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000;
    exec bash
" &
PID_TERM2=$!

echo ""
echo "⏳ [ACCIÓN REQUERIDA]: Ingresar contraseña de sudo en la nueva ventana."
read -p "👉 Presioná ENTER cuando Uvicorn diga 'Application startup complete' para lanzar el ataque..."

# ---------------------------------------------------------
# TERMINAL 3: Edge (Inyector de Tráfico)
# ---------------------------------------------------------
echo ""
echo "[3/3] Preparando entorno Edge y lanzando inyector..."
ptyxis -- bash -c "
    cd $BASE_DIR/SentinelAI-Edge || exit;
    echo '=> Activando entorno virtual...';
    source ../SentinelAI-Backend/.venv/bin/activate;
    
    echo '=> Instalando dependencias del Edge...';
    pip install -r requirements.txt;
    
    echo '------------------------------------------------';
    echo '=> Ejecutando replay de tráfico...';
    python demo_replay.py;
    exec bash
" &
PID_TERM3=$!

echo ""
echo "[+] ¡Boom! 🚀 Ataque inyectado. La orquestación está completa."
echo "[+] en localhost:8000/metrics vamos a poder visualizar las métricas"
read -p "👉 Presioná ENTER para finalizar la demo..."

# ---------------------------------------------------------
# FINALIZACIÓN DE DEMO
# ---------------------------------------------------------
echo ""
echo "[+] Finalizando la demo..."

echo "=> Cerrando terminales secundarias..."
kill $PID_TERM1 $PID_TERM2 $PID_TERM3 2>/dev/null

echo "=> Limpiando iptables (poner contraseña de sudo)"
sudo iptables -F INPUT

echo "=> Apagando contenedor PostgreSQL..."
docker stop sentinel-postgres

echo "----------------------------------------------------"
echo "[+] ¡Finalizó la demo! Gracias a todos por ver :)" 
echo "atentamente: Augusto Fredes y Facundo Mayordomo"