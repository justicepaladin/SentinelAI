"""FastAPI service for real-time SentinelAI autoencoder inference."""

from __future__ import annotations

import asyncio
import logging
import math
import os
import subprocess
import time
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from numbers import Real
from pathlib import Path
from threading import Lock
from typing import Any

import numpy as np
import pandas as pd
import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, Response
from prometheus_client import Counter, Gauge, make_asgi_app
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy.exc import SQLAlchemyError

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")

try:
    from .database import create_database_tables
    from .state_store import (
        list_current_state,
        list_quarantines_for_recovery,
        record_detection_state,
        release_quarantine_state,
    )
    from .traffic_logging import AuditLogWriter
except ImportError:  # También permite iniciar Uvicorn desde SentinelAI-Backend.
    from database import create_database_tables
    from state_store import (
        list_current_state,
        list_quarantines_for_recovery,
        record_detection_state,
        release_quarantine_state,
    )
    from traffic_logging import AuditLogWriter


logger = logging.getLogger("sentinelai")

TAU = 0.000308


def _positive_int_setting(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


CRITICAL_MSE = float(os.getenv("SENTINEL_CRITICAL_MSE", str(TAU * 3)))
if not math.isfinite(CRITICAL_MSE) or CRITICAL_MSE <= TAU:
    raise ValueError("SENTINEL_CRITICAL_MSE must be finite and greater than TAU")
QUARANTINE_SECONDS = _positive_int_setting("SENTINEL_QUARANTINE_SECONDS", 60)
ALERT_TTL_HOURS = _positive_int_setting("SENTINEL_ALERT_TTL_HOURS", 24)
ALERT_UPDATE_SECONDS = _positive_int_setting("SENTINEL_ALERT_UPDATE_SECONDS", 300)

MODEL_PATH = (BACKEND_DIR / "../SentinelAI-Model/models/sentinel_model.h5").resolve()
SCALER_PATH = (
    BACKEND_DIR / "../SentinelAI-Model/models/sentinel_scaler.save"
).resolve()

_PREDICTION_LOCK = Lock()
_FIREWALL_LOCK = Lock()
_STATE_WRITE_LOCK = Lock()
_CRITICAL_WRITE_CACHE: OrderedDict[str, float] = OrderedDict()
_CRITICAL_WRITE_CACHE_SIZE = 10_000


def _reserve_critical_snapshot(source_ip: str) -> bool:
    """Avoid a PostgreSQL transaction for every flow in an ongoing attack."""

    now = time.monotonic()
    with _STATE_WRITE_LOCK:
        previous = _CRITICAL_WRITE_CACHE.get(source_ip)
        if previous is not None and now - previous < ALERT_UPDATE_SECONDS:
            return False
        _CRITICAL_WRITE_CACHE[source_ip] = now
        _CRITICAL_WRITE_CACHE.move_to_end(source_ip)
        if len(_CRITICAL_WRITE_CACHE) > _CRITICAL_WRITE_CACHE_SIZE:
            _CRITICAL_WRITE_CACHE.popitem(last=False)
        return True


def _forget_critical_snapshot(source_ip: str) -> None:
    with _STATE_WRITE_LOCK:
        _CRITICAL_WRITE_CACHE.pop(source_ip, None)

# Métricas de observabilidad expuestas a Prometheus.
PROM_FLOWS = Counter(
    "sentinelai_flows_total",
    "Total de flujos de red analizados",
)
PROM_ANOMALIES = Counter(
    "sentinelai_anomalies_total",
    "Total de anomalías detectadas",
    ["source_ip"],
)
PROM_MSE = Gauge(
    "sentinelai_mse_score",
    "Último Error Cuadrático Medio (MSE) registrado",
)


class NetworkFlow(BaseModel):
    """Network-flow metadata and CIC-IDS2017 feature values.

    ``features`` accepts a flat/nested JSON list or dictionary. Named dictionaries
    are reordered according to the feature names stored in the fitted scaler.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "source_ip": "192.168.1.25",
                "destination_ip": "10.0.0.8",
                "destination_port": 443,
                "features": [0.0] * 78,
            }
        },
    )

    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    destination_port: int = Field(ge=0, le=65535)
    features: list[Any] | dict[str, Any]


class IngestResponse(BaseModel):
    mse_score: float
    anomaly: bool
    message: str
    dashboard_state_persisted: bool | None = None


class HealthResponse(BaseModel):
    status: str
    ml_ready: bool
    database_ready_at_startup: bool
    logging_ready: bool


class QuarantineView(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: int
    mse_score: float
    quarantined_at: datetime
    expires_at: datetime


class CriticalAlertView(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: int
    mse_score: float
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime


class DashboardState(BaseModel):
    active_quarantines: list[QuarantineView]
    critical_alerts: list[CriticalAlertView]


def _load_ml_assets() -> tuple[Any, Any]:
    """Load Keras and scikit-learn artifacts with actionable error messages."""

    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Autoencoder not found at {MODEL_PATH}")
    if not SCALER_PATH.is_file():
        raise FileNotFoundError(f"Scaler not found at {SCALER_PATH}")

    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError("joblib is not installed") from exc

    try:
        from tensorflow.keras.models import load_model
    except ImportError as exc:
        raise RuntimeError("TensorFlow/Keras is not installed") from exc

    try:
        scaler = joblib.load(SCALER_PATH)
        model = load_model(MODEL_PATH, compile=False)
    except Exception as exc:
        raise RuntimeError(f"Could not deserialize the ML artifacts: {exc}") from exc

    scaler_width = getattr(scaler, "n_features_in_", None)
    model_width = model.input_shape[-1] if model.input_shape else None
    if scaler_width is None:
        raise RuntimeError("The loaded scaler does not expose n_features_in_")
    if model_width != scaler_width:
        raise RuntimeError(
            f"Artifact mismatch: model expects {model_width} features and scaler "
            f"expects {scaler_width}"
        )

    return model, scaler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize external resources without terminating the API on failure."""

    app.state.model = None
    app.state.scaler = None
    app.state.ml_load_error = None
    app.state.database_ready = False
    app.state.audit_log = None
    app.state.release_tasks = set()

    try:
        app.state.audit_log = AuditLogWriter()
        logger.info("Local traffic and detection logs are ready")
    except Exception:
        logger.exception("Audit log initialization failed; /ingest will return HTTP 503")

    try:
        app.state.model, app.state.scaler = _load_ml_assets()
        logger.info("ML artifacts loaded from %s", MODEL_PATH.parent)
    except Exception as exc:
        app.state.ml_load_error = str(exc)
        logger.exception("ML initialization failed; /ingest will return HTTP 503")

    try:
        create_database_tables()
        app.state.database_ready = True
        logger.info("PostgreSQL schema is ready")
        for quarantine in list_quarantines_for_recovery():
            remaining = max(
                0,
                int((quarantine.expires_at - datetime.now(timezone.utc)).total_seconds()),
            )
            task = asyncio.create_task(
                _remove_quarantine(
                    quarantine.source_ip,
                    remaining,
                    quarantine.mse_score,
                )
            )
            app.state.release_tasks.add(task)
            task.add_done_callback(app.state.release_tasks.discard)
    except Exception:
        # Las solicitudes posteriores pueden funcionar si PostgreSQL se recupera.
        logger.exception("Database initialization failed; API is running in degraded mode")

    try:
        yield
    finally:
        pending_releases = list(app.state.release_tasks)
        for task in pending_releases:
            task.cancel()
        if pending_releases:
            await asyncio.gather(*pending_releases, return_exceptions=True)
        if app.state.audit_log is not None:
            app.state.audit_log.close()


app = FastAPI(
    title="SentinelAI IDS API",
    version="1.0.0",
    description="Real-time intrusion detection using a pretrained autoencoder.",
    lifespan=lifespan,
)

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Servir el icono de la pestaña o silenciar si no existe."""
    ruta_icono = BACKEND_DIR / "favicon.ico"
    if ruta_icono.is_file():
        return FileResponse(ruta_icono)
    return Response(status_code=204)

# Prometheus consulta este endpoint para recolectar las métricas.
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


def _flatten_numeric_values(value: Any) -> list[float]:
    """Recursively flatten numeric leaves while retaining JSON insertion order."""

    if isinstance(value, bool):
        raise ValueError("boolean values are not valid CIC-IDS2017 features")
    if isinstance(value, Real):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("all features must be finite numbers")
        return [number]
    if isinstance(value, Mapping):
        flattened: list[float] = []
        for nested_value in value.values():
            flattened.extend(_flatten_numeric_values(nested_value))
        return flattened
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        flattened = []
        for nested_value in value:
            flattened.extend(_flatten_numeric_values(nested_value))
        return flattened
    raise ValueError(f"feature value {value!r} is not numeric")


def _collect_named_numeric_values(value: Any, output: dict[str, float]) -> None:
    """Collect scalar dictionary leaves by their trimmed CIC feature name."""

    if not isinstance(value, Mapping):
        return

    for raw_key, nested_value in value.items():
        key = str(raw_key).strip()
        if isinstance(nested_value, Mapping):
            _collect_named_numeric_values(nested_value, output)
        elif isinstance(nested_value, Real) and not isinstance(nested_value, bool):
            number = float(nested_value)
            if not math.isfinite(number):
                raise ValueError(f"feature {key!r} must be a finite number")
            if key in output:
                raise ValueError(f"duplicate feature name: {key!r}")
            output[key] = number


def _features_dataframe(raw_features: Any, scaler: Any) -> pd.DataFrame:
    """Validate, order and shape one flow for the persisted MinMaxScaler."""

    expected_count = int(scaler.n_features_in_)
    stored_names = getattr(scaler, "feature_names_in_", None)
    feature_names = [str(name).strip() for name in stored_names] if stored_names is not None else None

    if isinstance(raw_features, Mapping) and feature_names:
        named_values: dict[str, float] = {}
        _collect_named_numeric_values(raw_features, named_values)
        missing = [name for name in feature_names if name not in named_values]
        if not missing:
            values = [named_values[name] for name in feature_names]
            return pd.DataFrame([values], columns=feature_names, dtype=np.float64)

    # CIC-IDS2017 agrega Label a las 78 entradas numéricas. Quitamos esa última
    # celda antes de validar números porque suele ser texto (BENIGN, DoS, etc.).
    if (
        isinstance(raw_features, Sequence)
        and not isinstance(raw_features, (str, bytes, bytearray))
        and len(raw_features) == expected_count + 1
    ):
        values = _flatten_numeric_values(raw_features[:-1])
    else:
        values = _flatten_numeric_values(raw_features)

    if len(values) != expected_count:
        raise ValueError(
            f"expected {expected_count} model features (or {expected_count + 1} "
            f"values including the final CIC-IDS2017 Label), received {len(values)}"
        )

    columns = feature_names if feature_names else list(range(expected_count))
    return pd.DataFrame([values], columns=columns, dtype=np.float64)


def _predict_mse(model: Any, scaler: Any, raw_features: Any) -> float:
    """Scale one flow, reconstruct it and return its mean squared error."""

    feature_frame = _features_dataframe(raw_features, scaler)
    scaled_features = np.asarray(scaler.transform(feature_frame), dtype=np.float32)

    with _PREDICTION_LOCK:
        reconstructed_data = np.asarray(
            model.predict(scaled_features, verbose=0),
            dtype=np.float32,
        )

    if reconstructed_data.shape != scaled_features.shape:
        raise RuntimeError(
            "Autoencoder output shape does not match its input: "
            f"{reconstructed_data.shape} != {scaled_features.shape}"
        )

    mse_score = float(np.mean(np.square(scaled_features - reconstructed_data)))
    if not math.isfinite(mse_score):
        raise RuntimeError("The autoencoder returned a non-finite MSE")
    return mse_score


def _quarantine_source_ip(source_ip: IPvAnyAddress) -> tuple[bool, bool]:
    """Add an IPv4 firewall rule and report whether it was newly created."""

    source_ip_text = str(source_ip)
    if source_ip.version != 4:
        logger.error(
            "[-] No se puede aislar %s: esta demo solo administra reglas IPv4",
            source_ip_text,
        )
        return False, False

    if (
        source_ip.is_loopback
        or source_ip.is_unspecified
        or source_ip.is_multicast
        or source_ip.is_link_local
    ):
        logger.error("[-] Se rechazó el bloqueo de la IP protegida %s", source_ip_text)
        return False, False

    firewall = ["sudo", "-n", "iptables", "-w", "2"]
    rule = ["INPUT", "-s", source_ip_text, "-j", "DROP"]

    try:
        with _FIREWALL_LOCK:
            current_rule = subprocess.run(
                [*firewall, "-C", *rule],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if current_rule.returncode == 0:
                logger.warning("[=] La IP %s ya estaba aislada", source_ip_text)
                return True, False

            subprocess.run(
                [*firewall, "-I", "INPUT", "1", "-s", source_ip_text, "-j", "DROP"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or str(exc)).strip()
        logger.error("[-] Error al aplicar iptables para %s: %s", source_ip_text, detail)
        return False, False
    except subprocess.TimeoutExpired:
        logger.error("[-] Tiempo de espera agotado al aislar %s", source_ip_text)
        return False, False
    except OSError as exc:
        logger.error("[-] No se pudo ejecutar iptables para %s: %s", source_ip_text, exc)
        return False, False

    logger.warning("[+] Regla de firewall aplicada con éxito para %s", source_ip_text)
    return True, True


async def _remove_quarantine(
    source_ip: str,
    delay: int = 60,
    mse_score: float | None = None,
) -> None:
    """Remove a firewall rule and its live DB state after a delay."""
    await asyncio.sleep(delay)

    firewall = ["sudo", "-n", "iptables", "-w", "2"]
    rule = ["INPUT", "-s", source_ip, "-j", "DROP"]

    try:
        with _FIREWALL_LOCK:
            current_rule = subprocess.run(
                [*firewall, "-C", *rule],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if current_rule.returncode == 0:
                subprocess.run(
                    [*firewall, "-D", *rule],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            elif current_rule.returncode != 1 or not any(
                marker in (current_rule.stderr or "").lower()
                for marker in ("bad rule", "matching rule")
            ):
                raise subprocess.CalledProcessError(
                    current_rule.returncode,
                    current_rule.args,
                    stderr=current_rule.stderr,
                )

        try:
            release_quarantine_state(source_ip)
        except SQLAlchemyError:
            logger.exception("Firewall released %s, but its DB state could not be cleared", source_ip)

        if current_rule.returncode == 0:
            logger.warning(
                "[~] Cuarentena levantada para %s tras %s segundos",
                source_ip,
                delay,
            )
            if mse_score is not None:
                _send_telegram_alert(source_ip, mse_score, False)
        else:
            logger.info("Firewall rule for %s was already absent", source_ip)

        if app.state.audit_log is not None:
            try:
                app.state.audit_log.log_detection(
                    action="quarantine_released",
                    source_ip=source_ip,
                    rule_was_present=current_rule.returncode == 0,
                )
            except Exception:
                logger.exception("Could not write quarantine release to the local audit log")
    except subprocess.CalledProcessError as exc:
        logger.error(
            "[-] Error al levantar cuarentena de %s: %s",
            source_ip,
            (exc.stderr or "").strip(),
        )
    except Exception as exc:
        logger.error("[-] Fallo inesperado al borrar regla de %s: %s", source_ip, exc)


def _send_telegram_alert(
    source_ip: str,
    mse_score: float,
    malicious: bool = True,
) -> None:
    """Envía una notificación a Telegram usando la API oficial."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        logger.error(
            "[-] No se pudo enviar la alerta de Telegram: faltan las variables "
            "TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID"
        )
        return

    mensaje_malicioso = (
        "🚨 *ALERTA SentinelAI* 🚨\n\n"
        "Se ha detectado y bloqueado tráfico anómalo.\n\n"
        f"🛑 *IP de origen:* `{source_ip}`\n"
        f"📈 *MSE Score:* `{mse_score:.6f}`"
    )

    mensaje_liberacion = (
        "🚨 *ALERTA SentinelAI* 🚨\n\n"
        "Se ha quitado la siguiente IP de cuarentena.\n\n"
        f"✅ *IP de origen:* `{source_ip}`\n"
    )

    mensaje = mensaje_malicioso if malicious else mensaje_liberacion

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": mensaje,
        "parse_mode": "Markdown",
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        
        # Si Telegram nos rebota, imprimimos el motivo exacto:
        if r.status_code != 200:
            logger.error("[-] Telegram rechazó el mensaje: %s", r.text)
            
        r.raise_for_status()
        logger.warning("[📱] Alerta de Telegram enviada exitosamente para %s", source_ip)
            
    except requests.exceptions.RequestException as exc:
        logger.error("[-] Fallo de red/HTTP al enviar alerta: %s", exc)
    except Exception as exc:
        logger.error("[-] Error inesperado en Telegram: %s", exc)


async def _notify_and_release_quarantine(source_ip: str, mse_score: float) -> None:
    """Start the timer and Telegram delivery together after the HTTP response."""

    await asyncio.gather(
        asyncio.to_thread(_send_telegram_alert, source_ip, mse_score, True),
        _remove_quarantine(source_ip, QUARANTINE_SECONDS, mse_score),
    )


@app.get("/health", response_model=HealthResponse, tags=["operations"])
def health(request: Request) -> HealthResponse:
    ml_ready = request.app.state.model is not None and request.app.state.scaler is not None
    database_ready = bool(request.app.state.database_ready)
    logging_ready = request.app.state.audit_log is not None
    return HealthResponse(
        status="ok" if ml_ready and database_ready and logging_ready else "degraded",
        ml_ready=ml_ready,
        database_ready_at_startup=database_ready,
        logging_ready=logging_ready,
    )


@app.get("/dashboard/state", response_model=DashboardState, tags=["operations"])
def dashboard_state() -> DashboardState:
    """Expose only live quarantine and recent critical alert snapshots."""

    try:
        quarantines, alerts = list_current_state()
    except SQLAlchemyError as exc:
        logger.exception("Could not load dashboard state")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PostgreSQL dashboard state is unavailable",
        ) from exc

    return DashboardState(
        active_quarantines=[
            QuarantineView(
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                destination_port=row.destination_port,
                mse_score=row.mse_score,
                quarantined_at=row.quarantined_at,
                expires_at=row.expires_at,
            )
            for row in quarantines
        ],
        critical_alerts=[
            CriticalAlertView(
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                destination_port=row.destination_port,
                mse_score=row.mse_score,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                expires_at=row.expires_at,
            )
            for row in alerts
        ],
    )


@app.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_200_OK,
    tags=["detection"],
)
def ingest(
    flow: NetworkFlow,
    request: Request,
    background_tasks: BackgroundTasks,
) -> IngestResponse:
    """Classify, audit locally, and persist only live response state."""

    model = request.app.state.model
    scaler = request.app.state.scaler
    audit_log = request.app.state.audit_log
    if model is None or scaler is None:
        detail = request.app.state.ml_load_error or "ML artifacts are unavailable"
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Inference service is unavailable: {detail}",
        )
    if audit_log is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Local audit logging is unavailable",
        )

    try:
        mse_score = _predict_mse(model, scaler, flow.features)

        # Solo contamos los flujos que completaron la inferencia.
        PROM_MSE.set(mse_score)
        PROM_FLOWS.inc()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Inference failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The network flow could not be analyzed",
        ) from exc

    anomaly = mse_score > TAU
    critical = mse_score >= CRITICAL_MSE
    source_ip = str(flow.source_ip)
    destination_ip = str(flow.destination_ip)

    try:
        audit_log.log_traffic(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=flow.destination_port,
            features=flow.features,
            mse_score=mse_score,
            anomaly=anomaly,
            critical=critical,
        )
    except Exception as exc:
        logger.exception("Could not write flow to the local audit log")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The flow was analyzed, but its local audit log could not be written",
        ) from exc

    mitigation_applied = False
    dashboard_state_persisted: bool | None = None
    if anomaly:
        # Separamos las anomalías por IP para poder seguir cada origen.
        PROM_ANOMALIES.labels(source_ip=source_ip).inc()

        logger.warning(
            "[!] ANOMALÍA DETECTADA (MSE: %.6f). Aislando IP: %s",
            mse_score,
            source_ip,
        )
        mitigation_applied, is_new = _quarantine_source_ip(flow.source_ip)
        if is_new:
            # La cuarentena temporal se libera aun si PostgreSQL falla.
            background_tasks.add_task(_notify_and_release_quarantine, source_ip, mse_score)

        write_critical_snapshot = critical and _reserve_critical_snapshot(source_ip)
        if is_new or write_critical_snapshot:
            try:
                record_detection_state(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=flow.destination_port,
                    mse_score=mse_score,
                    newly_quarantined=is_new,
                    critical=write_critical_snapshot,
                    quarantine_seconds=QUARANTINE_SECONDS,
                    alert_ttl_hours=ALERT_TTL_HOURS,
                    alert_update_seconds=ALERT_UPDATE_SECONDS,
                )
                dashboard_state_persisted = True
            except SQLAlchemyError:
                if write_critical_snapshot:
                    _forget_critical_snapshot(source_ip)
                dashboard_state_persisted = False
                logger.exception("Could not update the PostgreSQL dashboard state")

        try:
            audit_log.log_detection(
                action="anomaly_detected",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=flow.destination_port,
                mse_score=mse_score,
                threshold=TAU,
                critical=critical,
                critical_threshold=CRITICAL_MSE,
                mitigation_applied=mitigation_applied,
                quarantine_new=is_new,
                dashboard_state_persisted=dashboard_state_persisted,
            )
        except Exception as exc:
            logger.exception("Could not write detection to the local audit log")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="The anomaly was handled, but its local audit log could not be written",
            ) from exc

    if not anomaly:
        response_message = "Flow analyzed successfully; no anomaly detected"
    elif mitigation_applied:
        response_message = "Anomaly recorded locally and source IP quarantined"
    else:
        response_message = "Anomaly recorded locally, but source IP quarantine failed"

    if dashboard_state_persisted is False:
        response_message += "; PostgreSQL dashboard state is unavailable"

    return IngestResponse(
        mse_score=mse_score,
        anomaly=anomaly,
        message=response_message,
        dashboard_state_persisted=dashboard_state_persisted,
    )
