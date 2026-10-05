"""Envía flujos CIC al backend desde un generador, sin CSV intermedio.

``send_flows`` acepta cualquier iterable de diccionarios producido por un
extractor de tráfico. El CSV se conserva únicamente como fuente de replay:
``iter_csv_flows`` lo recorre una vez y entrega cada flujo en memoria.
"""

from __future__ import annotations

import math
import os
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import requests


EDGE_DIR = Path(__file__).resolve().parent
DEFAULT_API_URL = "http://localhost:8000/ingest"
DEFAULT_CSV_FILE = EDGE_DIR / "flujos_capturados.csv"


def sensor_headers(token: str | None = None) -> dict[str, str]:
    """Usa el token asignado al sensor registrado; nunca lo registra en logs."""

    token = token if token is not None else os.getenv("SENTINEL_SENSOR_TOKEN", "")
    token = token.strip()
    if not token:
        raise ValueError("Configurá SENTINEL_SENSOR_TOKEN con el token del sensor registrado")
    return {"Authorization": f"Bearer {token}"}


def iter_csv_flows(path: Path, *, chunk_size: int = 512) -> Iterator[dict[str, Any]]:
    """Lee un CSV de replay en una sola pasada, sin escribir archivos temporales."""

    if chunk_size <= 0:
        raise ValueError("chunk_size debe ser positivo")
    for chunk in pd.read_csv(path, chunksize=chunk_size):
        chunk.columns = [str(column).strip() for column in chunk.columns]
        if len(set(chunk.columns)) != len(chunk.columns):
            raise ValueError("El CSV contiene columnas duplicadas al quitar espacios")
        yield from chunk.to_dict(orient="records")


def _native_json(value: Any) -> Any:
    """Convierte escalares de pandas/NumPy y rechaza NaN/inf antes de enviar."""

    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("El flujo contiene NaN o infinito")
    if isinstance(value, Mapping):
        return {
            str(key).strip(): _native_json(item)
            for key, item in value.items()
            if str(key).strip().casefold() != "label"
        }
    if isinstance(value, (list, tuple)):
        return [_native_json(item) for item in value]
    if value is pd.NA:
        raise ValueError("El flujo contiene valores faltantes")
    return value


def flow_payload(flow: Mapping[str, Any]) -> dict[str, Any]:
    """Transforma un flujo extraído en el contrato de POST /ingest."""

    source_ip = flow.get("source_ip", flow.get("Src IP", flow.get("Source IP", "127.0.0.1")))
    destination_ip = flow.get(
        "destination_ip", flow.get("Dst IP", flow.get("Destination IP", "127.0.0.1"))
    )
    destination_port = flow.get(
        "destination_port", flow.get("Dst Port", flow.get("Destination Port", 80))
    )

    if "features" in flow:
        features = flow["features"]
    else:
        # Label es la verdad de referencia y jamás debe entrar al modelo.
        # El backend alinea por nombre las columnas numéricas del scaler.
        excluded = {
            "label", "source_ip", "destination_ip", "destination_port",
            "src ip", "source ip", "dst ip", "destination ip",
        }
        features = {
            str(name).strip(): value
            for name, value in flow.items()
            if str(name).strip().casefold() not in excluded
        }

    return {
        "source_ip": str(source_ip),
        "destination_ip": str(destination_ip),
        "destination_port": int(destination_port),
        "features": _native_json(features),
    }


def send_flows(
    flows: Iterable[Mapping[str, Any]],
    *,
    session: requests.Session,
    api_url: str,
    token: str | None = None,
    delay_seconds: float = 0,
) -> int:
    """Consume un generador de captura/replay y envía cada flujo desde RAM."""

    if delay_seconds < 0:
        raise ValueError("delay_seconds no puede ser negativo")
    headers = sensor_headers(token)
    sent = 0
    for index, flow in enumerate(flows):
        try:
            payload = flow_payload(flow)
            response = session.post(
                api_url, json=payload, headers=headers, timeout=5
            )
            if response.status_code == 200:
                result = response.json()
                mse = result.get("mse_score", 0)
                if result.get("anomaly", False):
                    print(
                        f"[!] ANOMALÍA | Origen: {payload['source_ip']:<15} | "
                        f"MSE: {mse:.6f}"
                    )
                else:
                    print(
                        f"[+] NORMAL   | Origen: {payload['source_ip']:<15} | "
                        f"MSE: {mse:.6f}"
                    )
                sent += 1
            else:
                print(f"[-] Error HTTP {response.status_code}: {response.text}")
        except requests.RequestException as exc:
            print(f"[-] No se pudo enviar el flujo {index}: {exc}")
        except (TypeError, ValueError) as exc:
            print(f"[-] El flujo {index} contiene datos inválidos: {exc}")

        if delay_seconds:
            time.sleep(delay_seconds)
    return sent


def main() -> None:
    api_url = os.getenv("SENTINEL_API_URL", DEFAULT_API_URL)
    csv_file = Path(os.getenv("SENTINEL_CSV_FILE", str(DEFAULT_CSV_FILE))).expanduser()
    try:
        delay = float(os.getenv("SENTINEL_FLOW_DELAY", "0.5"))
        chunk_size = int(os.getenv("SENTINEL_CSV_CHUNK_SIZE", "512"))
        token = os.getenv("SENTINEL_SENSOR_TOKEN", "")
        sensor_headers(token)
        print(f"[*] Enviando flujos a SentinelAI Backend ({api_url})...")
        print(f"[*] Fuente de replay: {csv_file}")
        with requests.Session() as session:
            sent = send_flows(
                iter_csv_flows(csv_file, chunk_size=chunk_size),
                session=session,
                api_url=api_url,
                token=token,
                delay_seconds=delay,
            )
        print(f"[+] Flujos enviados: {sent}")
    except FileNotFoundError:
        print(f"[!] No se encontró el dataset: {csv_file}", file=sys.stderr)
        sys.exit(1)
    except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        print(f"[!] No se pudo iniciar el sensor: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
