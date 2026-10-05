import os
import random
import sys
import time
from pathlib import Path

import pandas as pd
import requests

from integracion_sensor import flow_payload, sensor_headers

# Configuración
API_URL = os.getenv("SENTINEL_API_URL", "http://localhost:8000/ingest")
# Dataset del miércoles (contiene ataques DoS), leído una sola vez para la demo.
CSV_FILE = Path(
    os.getenv(
        "SENTINEL_REPLAY_CSV_FILE",
        str(
            Path(__file__).resolve().parent.parent
            / "SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv"
        ),
    )
).expanduser()


def main():
    try:
        headers = sensor_headers()
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    print("[*] Cargando dataset para el Replay (Nivel 1)...")
    try:
        # Cargamos el CSV y limpiamos espacios en los nombres de las columnas
        df = pd.read_csv(CSV_FILE)
        df.columns = df.columns.str.strip()
    except FileNotFoundError:
        print(f"[!] Error: No se encontró el archivo {CSV_FILE}")
        print("[!] Configurá SENTINEL_REPLAY_CSV_FILE con un CSV válido.")
        sys.exit(1)

    # Filtramos para tener una muestra desbalanceada realista (80 benignos, 20 ataques)
    try:
        benignos = df[df['Label'] == 'BENIGN'].sample(80, random_state=42)
        maliciosos = df[df['Label'] != 'BENIGN'].sample(20, random_state=42)
        # Unimos y mezclamos las filas aleatoriamente
        muestra = pd.concat([benignos, maliciosos]).sample(frac=1).reset_index(drop=True)
    except KeyError:
        print("[!] Error: No se encontró la columna 'Label'.")
        sys.exit(1)

    print("[+] Dataset preparado. Iniciando inyección de 100 flujos...")
    print("-" * 85)

    with requests.Session() as session:
        for index, fila in muestra.iterrows():
            etiqueta_real = fila['Label']

            # La IP simulada permite reconocer el tipo de flujo en la demo.
            if etiqueta_real == "DoS Hulk":
                ip_simulada = "10.0.50.11"
            elif etiqueta_real == "DoS GoldenEye":
                ip_simulada = "10.0.50.12"
            elif etiqueta_real == "DoS slowloris":
                ip_simulada = "10.0.50.13"
            elif etiqueta_real != "BENIGN":
                ip_simulada = f"10.0.50.{random.randint(20, 99)}"
            else:
                # 2. El tráfico benigno simula venir de distintos usuarios legítimos de tu red local
                ip_simulada = f"192.168.1.{random.randint(10, 99)}"

            try:
                payload = flow_payload({
                    "source_ip": ip_simulada,
                    "destination_ip": "10.0.0.1",
                    "destination_port": 80,
                    "features": fila.drop('Label').to_dict(),
                })
                r = session.post(API_URL, json=payload, headers=headers, timeout=5)
                if r.status_code == 200:
                    resultado = r.json()
                    mse = resultado.get('mse_score', 0)
                    es_anomalia = resultado.get('anomaly', False)

                    if es_anomalia:
                        marca_ia = "🚨 ANOMALÍA DETECTADA"
                    else:
                        marca_ia = "🟢 NORMAL"

                    print(f"[{index+1:03d}] REAL: {etiqueta_real:<15} | IA: {marca_ia:<20} | MSE: {mse:.6f}")
                else:
                    print(f"[-] Error HTTP {r.status_code}: {r.text}")
            except (requests.RequestException, TypeError, ValueError) as exc:
                print(f"[-] Error enviando el flujo {index}: {exc}")

            # Pausa de presentación; el envío en vivo no la necesita.
            time.sleep(0.3)


if __name__ == "__main__":
    main()
