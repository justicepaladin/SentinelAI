"""Envía flujos de un CSV de CIC-IDS2017 a la API de SentinelAI."""

import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests


EDGE_DIR = Path(__file__).resolve().parent
API_URL = os.getenv("SENTINEL_API_URL", "http://localhost:8000/ingest")
CSV_FILE = Path(
    os.getenv("SENTINEL_CSV_FILE", str(EDGE_DIR / "flujos_capturados.csv"))
).expanduser()
FLOW_DELAY_SECONDS = float(os.getenv("SENTINEL_FLOW_DELAY", "0.5"))


def _row_value(row: pd.Series, *names: str, default: object) -> object:
    """Devuelve el primer nombre de columna disponible."""

    for name in names:
        if name in row.index:
            return row[name]
    return default


def main() -> None:
    print(f"[*] Enviando flujos a SentinelAI Backend ({API_URL})...")

    try:
        flows = pd.read_csv(CSV_FILE)
        flows.columns = flows.columns.str.strip()
    except FileNotFoundError:
        print(f"[!] No se encontró el dataset: {CSV_FILE}")
        print("[!] Copiá un CSV de CIC-IDS2017 en esa ruta y volvé a ejecutar la demo.")
        sys.exit(1)
    except (OSError, pd.errors.ParserError) as exc:
        print(f"[!] No se pudo leer el dataset: {exc}")
        sys.exit(1)

    print(f"[+] Dataset cargado: {len(flows)} flujos listos para analizar.\n")
    print("-" * 75)

    for index, row in flows.iterrows():
        try:
            # Algunas exportaciones de CICFlowMeter no incluyen las direcciones IP.
            source_ip = _row_value(
                row, "Src IP", "Source IP", default="127.0.0.1"
            )
            destination_ip = _row_value(
                row, "Dst IP", "Destination IP", default="127.0.0.1"
            )
            destination_port = int(
                _row_value(row, "Dst Port", "Destination Port", default=80)
            )

            # El backend selecciona y ordena las columnas guardadas en el scaler.
            payload = {
                "source_ip": str(source_ip),
                "destination_ip": str(destination_ip),
                "destination_port": destination_port,
                "features": row.to_dict(),
            }

            response = requests.post(API_URL, json=payload, timeout=5)

            if response.status_code == 200:
                result = response.json()
                mse = result.get("mse_score", 0)
                is_anomaly = result.get("anomaly", False)

                if is_anomaly:
                    print(
                        f"[!] ANOMALÍA | Origen: {source_ip:<15} | "
                        f"MSE: {mse:.6f} | Alerta guardada"
                    )
                else:
                    print(
                        f"[+] NORMAL   | Origen: {source_ip:<15} | MSE: {mse:.6f}"
                    )
            else:
                print(f"[-] Error HTTP {response.status_code}: {response.text}")
        except requests.RequestException as exc:
            print(f"[-] No se pudo enviar el flujo {index}: {exc}")
        except (TypeError, ValueError) as exc:
            print(f"[-] El flujo {index} contiene datos inválidos: {exc}")

        # La pausa permite seguir la clasificación de cada flujo durante la demo.
        time.sleep(FLOW_DELAY_SECONDS)


if __name__ == "__main__":
    main()
