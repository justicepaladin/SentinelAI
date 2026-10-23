"""FastAPI service for real-time SentinelAI autoencoder inference."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import os
import subprocess
import time
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager, nullcontext
from datetime import datetime, timezone
from numbers import Real
from pathlib import Path
from threading import Lock, RLock
from typing import Any, Annotated, Literal

import numpy as np
import pandas as pd
import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response
from prometheus_client import Counter, Gauge, make_asgi_app
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator
from sqlalchemy.exc import SQLAlchemyError

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")

try:
    from .auth import (AdminIdentity, SensorIdentity, get_authenticated_admin,
                       get_authenticated_reader, get_authenticated_sensor)
    from .database import create_database_tables
    from .state_store import (
        list_current_state,
        list_mitigation_events,
        list_alerts,
        find_active_quarantines,
        list_active_quarantines,
        get_sensor_telemetry,
        get_site_config,
        list_quarantines_for_recovery,
        list_site_sensors,
        list_sites,
        record_detection_state,
        release_quarantine_state,
        update_sensor_telemetry,
        update_site_config,
    )
    from .traffic_logging import AuditLogWriter
except ImportError:  # También permite iniciar Uvicorn desde SentinelAI-Backend.
    from auth import (AdminIdentity, SensorIdentity, get_authenticated_admin,
                      get_authenticated_reader, get_authenticated_sensor)
    from database import create_database_tables
    from state_store import (
        list_current_state,
        list_mitigation_events,
        list_alerts,
        find_active_quarantines,
        list_active_quarantines,
        get_sensor_telemetry,
        get_site_config,
        list_quarantines_for_recovery,
        list_site_sensors,
        list_sites,
        record_detection_state,
        release_quarantine_state,
        update_sensor_telemetry,
        update_site_config,
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
LINK_STATE_TTL_SECONDS = _positive_int_setting("SENTINEL_LINK_STATE_TTL_SECONDS", 120)

MODEL_PATH = (BACKEND_DIR / "../SentinelAI-Model/models/sentinel_model.h5").resolve()
SCALER_PATH = (
    BACKEND_DIR / "../SentinelAI-Model/models/sentinel_scaler.save"
).resolve()

_PREDICTION_LOCK = Lock()
_FIREWALL_LOCK = RLock()
_QUARANTINE_GENERATIONS: dict[tuple[int, str], object] = {}
_STATE_WRITE_LOCK = Lock()
_CRITICAL_WRITE_CACHE: OrderedDict[tuple[int, str], float] = OrderedDict()
_CRITICAL_WRITE_CACHE_SIZE = 10_000


def _reserve_critical_snapshot(site_id: int, source_ip: str) -> bool:
    """Avoid a PostgreSQL transaction for every flow in an ongoing attack."""

    now = time.monotonic()
    key = (site_id, source_ip)
    with _STATE_WRITE_LOCK:
        previous = _CRITICAL_WRITE_CACHE.get(key)
        if previous is not None and now - previous < ALERT_UPDATE_SECONDS:
            return False
        _CRITICAL_WRITE_CACHE[key] = now
        _CRITICAL_WRITE_CACHE.move_to_end(key)
        if len(_CRITICAL_WRITE_CACHE) > _CRITICAL_WRITE_CACHE_SIZE:
            _CRITICAL_WRITE_CACHE.popitem(last=False)
        return True


def _forget_critical_snapshot(site_id: int, source_ip: str) -> None:
    with _STATE_WRITE_LOCK:
        _CRITICAL_WRITE_CACHE.pop((site_id, source_ip), None)


_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def _is_unrecognized_device(source_ip: IPvAnyAddress, known_devices: Sequence[str]) -> bool:
    """Only RFC1918/ULA addresses participate in site inventory detection."""

    if not any(source_ip in network for network in _INTERNAL_NETWORKS
               if network.version == source_ip.version):
        return False
    return not any(source_ip in ipaddress.ip_network(cidr, strict=False)
                   for cidr in known_devices)


def _new_quarantine_generation(site_id: int, source_ip: str) -> object:
    generation = object()
    with _FIREWALL_LOCK:
        _QUARANTINE_GENERATIONS[(site_id, source_ip)] = generation
    return generation

# Métricas de observabilidad expuestas a Prometheus.
PROM_FLOWS = Counter(
    "sentinelai_flows_total",
    "Total de flujos de red analizados",
)
PROM_ANOMALIES = Counter(
    "sentinelai_anomalies_total",
    "Total de anomalías detectadas",
    ["site_id"],
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
    link_degraded: bool | None = None


class IngestResponse(BaseModel):
    mse_score: float
    anomaly: bool
    message: str
    dashboard_state_persisted: bool | None = None
    unrecognized_device: bool = False
    mitigation_applied: bool = False
    response_suspended: bool = False


class AlertView(BaseModel):
    id: int
    site_id: int
    sensor_id: int
    source_ip: str
    destination_ip: str
    destination_port: int
    mse_score: float
    severity: Literal["warning", "high", "critical"]
    anomaly: bool
    unrecognized_device: bool
    link_degraded: bool
    informative_only_mode: bool
    mitigation_applied: bool
    occurred_at: datetime


class SensorTelemetryView(BaseModel):
    sensor_id: int
    site_id: int
    is_active: bool
    last_heartbeat_at: datetime | None
    last_ingest_at: datetime | None
    flow_count: int
    last_link_degraded: bool
    last_link_report_at: datetime | None


class SiteSensorView(SensorTelemetryView):
    name: str


class MitigationEventView(BaseModel):
    id: int
    site_id: int
    sensor_id: int | None
    event_type: Literal["APPLY", "REVERSION", "MANUAL_REVERSION"]
    original_event_id: int | None
    source_ip: str
    destination_ip: str | None
    destination_port: int | None
    mse_score: float | None
    reason: str | None
    occurred_at: datetime


class HeartbeatPayload(BaseModel):
    link_degraded: bool = False


class SiteConfigView(BaseModel):
    site_id: int
    custom_mse_threshold: float | None
    active_response_enabled: bool
    informative_only_mode: bool
    known_devices: list[str]


class SiteView(BaseModel):
    id: int
    slug: str
    name: str
    is_active: bool
    config: SiteConfigView


class SiteConfigUpdate(BaseModel):
    custom_mse_threshold: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    active_response_enabled: bool | None = None
    informative_only_mode: bool | None = None
    known_devices: list[str] | None = Field(default=None, max_length=512)

    @field_validator("known_devices")
    @classmethod
    def canonical_known_devices(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        canonical = []
        for value in values:
            try:
                network = ipaddress.ip_network(value.strip(), strict=False)
            except (ValueError, AttributeError) as exc:
                raise ValueError(f"invalid device IP or CIDR: {value!r}") from exc
            name = str(network)
            if name not in canonical:
                canonical.append(name)
        return canonical


class ManualReversionResponse(BaseModel):
    site_id: int
    source_ip: str
    reverted: bool
    rule_was_present: bool


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


class AdminQuarantineView(QuarantineView):
    site_id: int


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
            generation = _new_quarantine_generation(quarantine.site_id, quarantine.source_ip)
            remaining = max(
                0,
                int((quarantine.expires_at - datetime.now(timezone.utc)).total_seconds()),
            )
            task = asyncio.create_task(
                _remove_quarantine(
                    quarantine.site_id,
                    quarantine.source_ip,
                    remaining,
                    quarantine.mse_score,
                    quarantine.applied_event_id,
                    generation,
                )
            )
            app.state.release_tasks.add(task)
            task.add_done_callback(app.state.release_tasks.discard)
    except RuntimeError:
        logger.exception("Database schema is incompatible; run the required migration")
        raise
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


def _restore_quarantine_rule_locked(source_ip: str) -> None:
    """Compensate a failed DB release while the local firewall lock is held."""

    firewall = ["sudo", "-n", "iptables", "-w", "2"]
    rule = ["INPUT", "-s", source_ip, "-j", "DROP"]
    check = subprocess.run([*firewall, "-C", *rule], check=False,
                           capture_output=True, text=True, timeout=5)
    if check.returncode == 0:
        return
    if check.returncode != 1 or not any(
        marker in (check.stderr or "").lower()
        for marker in ("bad rule", "matching rule")
    ):
        raise subprocess.CalledProcessError(check.returncode, check.args,
                                            stderr=check.stderr)
    subprocess.run([*firewall, "-I", "INPUT", "1", "-s", source_ip, "-j", "DROP"],
                   check=True, capture_output=True, text=True, timeout=5)


def _rollback_unpersisted_firewall_rule_locked(source_ip: str) -> None:
    """Remove a newly inserted rule when its APPLY transaction did not commit."""

    firewall = ["sudo", "-n", "iptables", "-w", "2"]
    rule = ["INPUT", "-s", source_ip, "-j", "DROP"]
    subprocess.run([*firewall, "-D", *rule], check=True,
                   capture_output=True, text=True, timeout=5)


async def _remove_quarantine(
    site_id: int,
    source_ip: str,
    delay: int = 60,
    mse_score: float | None = None,
    expected_event_id: int | None = None,
    generation: object | None = None,
) -> None:
    """Release at TTL; restore the rule and retry if the DB commit fails."""

    firewall = ["sudo", "-n", "iptables", "-w", "2"]
    rule = ["INPUT", "-s", source_ip, "-j", "DROP"]
    while True:
        await asyncio.sleep(delay)
        try:
            retry = False
            with _FIREWALL_LOCK:
                if (generation is not None and
                        _QUARANTINE_GENERATIONS.get((site_id, source_ip)) is not generation):
                    return
                if expected_event_id is not None:
                    rows = find_active_quarantines(source_ip, site_id)
                    if not rows or rows[0].applied_event_id != expected_event_id:
                        return
                current_rule = subprocess.run(
                    [*firewall, "-C", *rule], check=False,
                    capture_output=True, text=True, timeout=5,
                )
                rule_removed = current_rule.returncode == 0
                if rule_removed:
                    subprocess.run([*firewall, "-D", *rule], check=True,
                                   capture_output=True, text=True, timeout=5)
                elif current_rule.returncode != 1 or not any(
                    marker in (current_rule.stderr or "").lower()
                    for marker in ("bad rule", "matching rule")
                ):
                    raise subprocess.CalledProcessError(
                        current_rule.returncode, current_rule.args,
                        stderr=current_rule.stderr,
                    )
                try:
                    released = release_quarantine_state(
                        site_id, source_ip, expected_event_id=expected_event_id
                    )
                except SQLAlchemyError:
                    logger.exception("DB release failed for %s; restoring firewall rule", source_ip)
                    if rule_removed:
                        _restore_quarantine_rule_locked(source_ip)
                    retry = True
                else:
                    if not released and rule_removed:
                        # Another worker may have replaced the projection. Keep
                        # its firewall protection if any live row still owns it.
                        if find_active_quarantines(source_ip):
                            _restore_quarantine_rule_locked(source_ip)
                    if generation is not None:
                        _QUARANTINE_GENERATIONS.pop((site_id, source_ip), None)
            if retry:
                delay = 30
                continue
            if rule_removed:
                logger.warning("[~] Cuarentena levantada para %s", source_ip)
                if mse_score is not None:
                    _send_telegram_alert(source_ip, mse_score, False)
            else:
                logger.info("Firewall rule for %s was already absent", source_ip)
            if getattr(app.state, "audit_log", None) is not None:
                try:
                    app.state.audit_log.log_detection(
                        action="quarantine_released", site_id=site_id,
                        source_ip=source_ip, rule_was_present=rule_removed,
                    )
                except Exception:
                    logger.exception("Could not write quarantine release to the local audit log")
            return
        except SQLAlchemyError:
            logger.exception("DB lookup failed during quarantine release for %s; retrying", source_ip)
            delay = 30
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            logger.exception("Firewall release or restoration failed for %s", source_ip)
            return


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


async def _notify_and_release_quarantine(
    site_id: int, source_ip: str, mse_score: float,
    expected_event_id: int | None = None, generation: object | None = None,
) -> None:
    """Start the timer and Telegram delivery together after the HTTP response."""

    await asyncio.gather(
        asyncio.to_thread(_send_telegram_alert, source_ip, mse_score, True),
        _remove_quarantine(
            site_id, source_ip, QUARANTINE_SECONDS, mse_score,
            expected_event_id, generation,
        ),
    )


def _record_alert_and_response(
    *, sensor: SensorIdentity, flow: NetworkFlow, mse_score: float,
    anomaly: bool, critical: bool, severity: str, unrecognized_device: bool,
    link_degraded: bool, response_suspended: bool,
) -> tuple[bool, bool, bool, int | None, object | None]:
    """Serialize firewall insertion and its APPLY event within one API worker."""

    mitigation_applied = False
    is_new = False
    applied_event_id = None
    generation = None
    active_response = anomaly and sensor.active_response_enabled and not response_suspended
    guard = _FIREWALL_LOCK if active_response else nullcontext()
    with guard:
        if active_response:
            mitigation_applied, is_new = _quarantine_source_ip(flow.source_ip)
        write_critical_snapshot = critical and _reserve_critical_snapshot(
            sensor.site_id, str(flow.source_ip)
        )
        try:
            applied_event_id = record_detection_state(
                site_id=sensor.site_id,
                sensor_id=sensor.sensor_id,
                source_ip=str(flow.source_ip),
                destination_ip=str(flow.destination_ip),
                destination_port=flow.destination_port,
                mse_score=mse_score,
                newly_quarantined=is_new,
                critical=write_critical_snapshot,
                quarantine_seconds=QUARANTINE_SECONDS,
                alert_ttl_hours=ALERT_TTL_HOURS,
                alert_update_seconds=ALERT_UPDATE_SECONDS,
                severity=severity,
                anomaly=anomaly,
                unrecognized_device=unrecognized_device,
                link_degraded=link_degraded,
                informative_only_mode=sensor.informative_only_mode,
                mitigation_applied=mitigation_applied,
            )
            persisted = True
        except SQLAlchemyError:
            if write_critical_snapshot:
                _forget_critical_snapshot(sensor.site_id, str(flow.source_ip))
            persisted = False
            logger.exception("Could not update the PostgreSQL alert and dashboard state")
            if is_new:
                try:
                    _rollback_unpersisted_firewall_rule_locked(str(flow.source_ip))
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                    logger.critical(
                        "Could not remove unrecorded firewall rule for %s; TTL fallback scheduled",
                        flow.source_ip, exc_info=True,
                    )
                else:
                    mitigation_applied = False
                    is_new = False
        if is_new:
            # Register the timer generation before another request can revert
            # or reapply this same source IP in this worker.
            generation = _new_quarantine_generation(sensor.site_id, str(flow.source_ip))
    return mitigation_applied, is_new, persisted, applied_event_id, generation


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
def dashboard_state(
    sensor: Annotated[SensorIdentity, Depends(get_authenticated_sensor)],
) -> DashboardState:
    """Expose live state only for the authenticated sensor's site."""

    try:
        quarantines, alerts = list_current_state(sensor.site_id)
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


@app.get("/quarantines", response_model=list[AdminQuarantineView], tags=["operations"])
def get_quarantines(
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
    site_id: int | None = Query(default=None, gt=0),
) -> list[AdminQuarantineView]:
    """List live quarantines across sites; a sensor may read only its own site's."""

    site_id = _reader_site_scope(principal, site_id, "quarantine")
    try:
        rows = list_active_quarantines(site_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Quarantine database is unavailable") from exc
    return [AdminQuarantineView.model_validate(row, from_attributes=True) for row in rows]


@app.get("/alerts", response_model=list[AlertView], tags=["operations"])
def get_alerts(
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
    site_id: int | None = Query(default=None, gt=0),
    sensor_id: int | None = Query(default=None, gt=0),
    source_ip: IPvAnyAddress | None = None,
    severity: Literal["warning", "high", "critical"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    unrecognized_device: bool | None = None,
    before_id: int | None = Query(default=None, gt=0),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AlertView]:
    """List recent alerts; a sensor may read only its own site's alerts.

    ``since`` is inclusive and ``until`` exclusive (naive values are UTC);
    ``before_id`` returns only alerts with a smaller id, to page backwards.
    """

    since, until = _as_utc(since), _as_utc(until)
    if since is not None and until is not None and since >= until:
        raise HTTPException(status_code=422, detail="since must be earlier than until")

    if isinstance(principal, SensorIdentity):
        if site_id is not None and site_id != principal.site_id:
            raise HTTPException(status_code=403, detail="Cross-site alert access is forbidden")
        site_id = principal.site_id
    try:
        rows = list_alerts(site_id=site_id, sensor_id=sensor_id,
                           source_ip=str(source_ip) if source_ip is not None else None,
                           severity=severity, limit=limit, since=since, until=until,
                           unrecognized_device=unrecognized_device, before_id=before_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Alert database is unavailable") from exc
    return [AlertView.model_validate(row, from_attributes=True) for row in rows]


def _telemetry_fields(sensor: Any, telemetry: Any) -> dict[str, Any]:
    """Telemetry projection with the defaults used before a sensor reports."""

    return dict(
        sensor_id=sensor.id, site_id=sensor.site_id, is_active=sensor.is_active,
        last_heartbeat_at=telemetry.last_heartbeat_at if telemetry else None,
        last_ingest_at=telemetry.last_ingest_at if telemetry else None,
        flow_count=telemetry.flow_count if telemetry else 0,
        last_link_degraded=telemetry.last_link_degraded if telemetry else False,
        last_link_report_at=telemetry.last_link_report_at if telemetry else None,
    )


def _as_utc(value: datetime | None) -> datetime | None:
    """Interpret naive timestamps as UTC and normalize offsets for comparison."""

    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _reader_site_scope(
    principal: AdminIdentity | SensorIdentity, site_id: int | None, resource: str,
) -> int | None:
    """Admins keep the requested site filter; a sensor is pinned to its own site."""

    if isinstance(principal, SensorIdentity):
        if site_id is not None and site_id != principal.site_id:
            raise HTTPException(status_code=403, detail=f"Cross-site {resource} access is forbidden")
        return principal.site_id
    return site_id


@app.get("/mitigation-events", response_model=list[MitigationEventView], tags=["operations"])
def get_mitigation_events(
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
    site_id: int | None = Query(default=None, gt=0),
    source_ip: IPvAnyAddress | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[MitigationEventView]:
    """List firewall events, newest first; a sensor may read only its own site's."""

    site_id = _reader_site_scope(principal, site_id, "mitigation event")
    try:
        rows = list_mitigation_events(
            site_id=site_id, source_ip=str(source_ip) if source_ip is not None else None,
            limit=limit,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Mitigation event database is unavailable") from exc
    return [MitigationEventView.model_validate(row, from_attributes=True) for row in rows]


@app.get("/sensors/{sensor_id}/telemetry", response_model=SensorTelemetryView,
         tags=["operations"])
def sensor_telemetry(
    sensor_id: int,
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
) -> SensorTelemetryView:
    if isinstance(principal, SensorIdentity) and principal.sensor_id != sensor_id:
        raise HTTPException(status_code=403, detail="Other sensor telemetry is forbidden")
    try:
        result = get_sensor_telemetry(sensor_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Telemetry database is unavailable") from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Sensor not found")
    sensor, telemetry = result
    return SensorTelemetryView(**_telemetry_fields(sensor, telemetry))


@app.post("/sensors/{sensor_id}/heartbeat", response_model=SensorTelemetryView,
          tags=["operations"])
def sensor_heartbeat(
    sensor_id: int,
    payload: HeartbeatPayload,
    sensor: Annotated[SensorIdentity, Depends(get_authenticated_sensor)],
) -> SensorTelemetryView:
    if sensor.sensor_id != sensor_id:
        raise HTTPException(status_code=403, detail="Other sensor heartbeat is forbidden")
    try:
        update_sensor_telemetry(sensor_id, link_degraded=payload.link_degraded, ingest=False)
        result = get_sensor_telemetry(sensor_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Telemetry database is unavailable") from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Sensor not found")
    row, telemetry = result
    return SensorTelemetryView(
        sensor_id=row.id, site_id=row.site_id, is_active=row.is_active,
        last_heartbeat_at=telemetry.last_heartbeat_at,
        last_ingest_at=telemetry.last_ingest_at,
        flow_count=telemetry.flow_count,
        last_link_degraded=telemetry.last_link_degraded,
        last_link_report_at=telemetry.last_link_report_at,
    )


def _config_view(site_id: int, config: Any) -> SiteConfigView:
    return SiteConfigView(
        site_id=site_id,
        custom_mse_threshold=config.custom_mse_threshold if config else None,
        active_response_enabled=bool(config.active_response_enabled) if config else False,
        informative_only_mode=bool(config.informative_only_mode) if config else True,
        known_devices=list(config.known_devices or ()) if config else [],
    )


@app.get("/sites", response_model=list[SiteView], tags=["operations"])
def get_sites(
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
) -> list[SiteView]:
    """List sites with their configuration; a sensor sees only its own site."""

    try:
        rows = list_sites(principal.site_id if isinstance(principal, SensorIdentity) else None)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Site database is unavailable") from exc
    return [
        SiteView(id=site.id, slug=site.slug, name=site.name, is_active=site.is_active,
                 config=_config_view(site.id, config))
        for site, config in rows
    ]


@app.get("/sites/{site_id}/sensors", response_model=list[SiteSensorView], tags=["operations"])
def site_sensors(
    site_id: int,
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
) -> list[SiteSensorView]:
    """List a site's sensors with telemetry; a sensor may read only its own site."""

    if isinstance(principal, SensorIdentity) and principal.site_id != site_id:
        raise HTTPException(status_code=403, detail="Cross-site sensor access is forbidden")
    try:
        rows = list_site_sensors(site_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Telemetry database is unavailable") from exc
    if rows is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return [SiteSensorView(name=sensor.name, **_telemetry_fields(sensor, telemetry))
            for sensor, telemetry in rows]


@app.get("/sites/{site_id}/config", response_model=SiteConfigView, tags=["operations"])
def site_config(
    site_id: int,
    principal: Annotated[AdminIdentity | SensorIdentity, Depends(get_authenticated_reader)],
) -> SiteConfigView:
    if isinstance(principal, SensorIdentity) and principal.site_id != site_id:
        raise HTTPException(status_code=403, detail="Cross-site configuration access is forbidden")
    try:
        result = get_site_config(site_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Site configuration database is unavailable") from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return _config_view(site_id, result[1])


@app.put("/sites/{site_id}/config", response_model=SiteConfigView, tags=["operations"])
def put_site_config(
    site_id: int,
    payload: SiteConfigUpdate,
    _admin: Annotated[AdminIdentity, Depends(get_authenticated_admin)],
) -> SiteConfigView:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one setting is required")
    for key in ("active_response_enabled", "informative_only_mode", "known_devices"):
        if key in changes and changes[key] is None:
            raise HTTPException(status_code=422, detail=f"{key} cannot be null")
    try:
        result = update_site_config(site_id, changes)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Site configuration database is unavailable") from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return _config_view(site_id, result[1])


@app.post("/quarantines/{source_ip}/revert", response_model=ManualReversionResponse,
          tags=["operations"])
def manual_revert_quarantine(
    source_ip: IPvAnyAddress,
    _admin: Annotated[AdminIdentity, Depends(get_authenticated_admin)],
    site_id: int | None = Query(default=None, gt=0),
    request: Request = None,
) -> ManualReversionResponse:
    """Remove one owned firewall rule and append an immutable manual event."""

    source = str(source_ip)
    firewall = ["sudo", "-n", "iptables", "-w", "2"]
    rule = ["INPUT", "-s", source, "-j", "DROP"]
    with _FIREWALL_LOCK:
        try:
            rows = find_active_quarantines(source, site_id)
            all_rows = rows if site_id is None else find_active_quarantines(source)
        except SQLAlchemyError as exc:
            raise HTTPException(status_code=503, detail="Quarantine database is unavailable") from exc
        if not rows:
            raise HTTPException(status_code=404, detail="Active quarantine not found")
        if len(all_rows) != 1:
            raise HTTPException(status_code=409, detail="Source IP is quarantined at multiple sites")
        row = rows[0]
        try:
            check = subprocess.run([*firewall, "-C", *rule], check=False,
                                   capture_output=True, text=True, timeout=5)
            if check.returncode == 0:
                subprocess.run([*firewall, "-D", *rule], check=True,
                               capture_output=True, text=True, timeout=5)
            elif check.returncode != 1 or not any(
                marker in (check.stderr or "").lower()
                for marker in ("bad rule", "matching rule")
            ):
                raise subprocess.CalledProcessError(check.returncode, check.args,
                                                    stderr=check.stderr)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            logger.exception("Manual firewall reversion failed for %s", source)
            raise HTTPException(status_code=503, detail="Firewall reversion failed") from exc
        try:
            reverted = release_quarantine_state(
                row.site_id, source, manual=True,
                expected_event_id=row.applied_event_id,
            )
        except SQLAlchemyError as exc:
            logger.exception("Manual audit event failed for %s; restoring firewall rule", source)
            if check.returncode == 0:
                try:
                    _restore_quarantine_rule_locked(source)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                    logger.critical("Could not restore firewall rule after DB failure for %s", source,
                                    exc_info=True)
                    raise HTTPException(
                        status_code=503,
                        detail="Audit database failed and firewall restoration failed",
                    ) from exc
            raise HTTPException(status_code=503, detail="Audit database is unavailable; firewall rule restored") from exc
        if not reverted:
            if check.returncode == 0:
                try:
                    if find_active_quarantines(source):
                        _restore_quarantine_rule_locked(source)
                except (SQLAlchemyError, subprocess.CalledProcessError,
                        subprocess.TimeoutExpired, OSError):
                    logger.critical("Could not reconcile firewall after a racing reversion", exc_info=True)
            raise HTTPException(status_code=409, detail="Quarantine changed during reversion")
        _QUARANTINE_GENERATIONS.pop((row.site_id, source), None)
    if request is not None and request.app.state.audit_log is not None:
        try:
            request.app.state.audit_log.log_detection(
                action="manual_reversion", site_id=row.site_id, source_ip=source,
                rule_was_present=check.returncode == 0,
            )
        except Exception:
            logger.exception("Could not write the local manual reversion log")
    return ManualReversionResponse(site_id=row.site_id, source_ip=source,
                                   reverted=True, rule_was_present=check.returncode == 0)


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
    sensor: Annotated[SensorIdentity, Depends(get_authenticated_sensor)],
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

    threshold = sensor.custom_mse_threshold or TAU
    critical_threshold = max(CRITICAL_MSE, threshold * 3)
    anomaly = mse_score > threshold
    critical = mse_score >= critical_threshold
    source_ip = str(flow.source_ip)
    destination_ip = str(flow.destination_ip)
    unrecognized_device = _is_unrecognized_device(flow.source_ip, sensor.known_devices)
    latest_report = sensor.last_link_report_at
    if latest_report is not None and latest_report.tzinfo is None:
        latest_report = latest_report.replace(tzinfo=timezone.utc)
    recent_link_degradation = bool(
        sensor.last_link_degraded
        and latest_report is not None
        and (datetime.now(timezone.utc) - latest_report).total_seconds()
        <= LINK_STATE_TTL_SECONDS
    )
    link_degraded = (
        flow.link_degraded if flow.link_degraded is not None else recent_link_degradation
    )
    response_suspended = link_degraded or sensor.informative_only_mode
    severity: Literal["warning", "high", "critical"] = (
        "critical" if critical else "high" if anomaly else "warning"
    )

    if link_degraded:
        logger.warning(
            "Sensor %s at site %s reported degraded connectivity; active response suspended",
            sensor.sensor_id, sensor.site_id,
        )

    try:
        audit_log.log_traffic(
            site_id=sensor.site_id,
            site_slug=sensor.site_slug,
            sensor_id=sensor.sensor_id,
            sensor_name=sensor.sensor_name,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=flow.destination_port,
            features=flow.features,
            mse_score=mse_score,
            anomaly=anomaly,
            critical=critical,
            unrecognized_device=unrecognized_device,
            link_degraded=link_degraded,
            link_degraded_reported=flow.link_degraded,
            informative_only_mode=sensor.informative_only_mode,
            response_suspended=response_suspended,
        )
    except Exception as exc:
        logger.exception("Could not write flow to the local audit log")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The flow was analyzed, but its local audit log could not be written",
        ) from exc

    try:
        update_sensor_telemetry(
            sensor.sensor_id, link_degraded=flow.link_degraded, ingest=True,
        )
    except SQLAlchemyError:
        logger.exception("Could not update telemetry for sensor %s", sensor.sensor_id)

    mitigation_applied = False
    dashboard_state_persisted: bool | None = None
    is_new = False
    if anomaly:
        PROM_ANOMALIES.labels(site_id=str(sensor.site_id)).inc()

        logger.warning(
            "[!] ANOMALÍA DETECTADA en sitio %s (MSE: %.6f, IP: %s)",
            sensor.site_slug,
            mse_score,
            source_ip,
        )

    alert_required = anomaly or unrecognized_device or link_degraded
    if alert_required:
        (mitigation_applied, is_new, dashboard_state_persisted,
         applied_event_id, generation) = _record_alert_and_response(
            sensor=sensor, flow=flow, mse_score=mse_score, anomaly=anomaly,
            critical=critical, severity=severity,
            unrecognized_device=unrecognized_device,
            link_degraded=link_degraded, response_suspended=response_suspended,
        )
        if is_new:
            # A generation token prevents a stale timer from deleting a later
            # quarantine. It also provides fallback after rollback failure.
            background_tasks.add_task(
                _notify_and_release_quarantine, sensor.site_id, source_ip,
                mse_score, applied_event_id, generation,
            )
        try:
            audit_log.log_detection(
                action=("anomaly_detected" if anomaly else
                        "unrecognized_device" if unrecognized_device else "link_degraded"),
                site_id=sensor.site_id,
                site_slug=sensor.site_slug,
                sensor_id=sensor.sensor_id,
                sensor_name=sensor.sensor_name,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=flow.destination_port,
                mse_score=mse_score,
                threshold=threshold,
                critical=critical,
                critical_threshold=critical_threshold,
                active_response_enabled=sensor.active_response_enabled,
                informative_only_mode=sensor.informative_only_mode,
                link_degraded=link_degraded,
                response_suspended=response_suspended,
                unrecognized_device=unrecognized_device,
                severity=severity,
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

    if not anomaly and unrecognized_device:
        response_message = "Unrecognized internal device recorded"
    elif not anomaly and link_degraded:
        response_message = "Flow analyzed; degraded connectivity warning recorded"
    elif not anomaly:
        response_message = "Flow analyzed successfully; no anomaly detected"
    elif mitigation_applied:
        response_message = "Anomaly recorded locally and source IP quarantined"
    elif link_degraded:
        response_message = "Anomaly recorded locally; active response suspended for degraded link"
    elif sensor.informative_only_mode:
        response_message = "Anomaly recorded locally; site is in informative-only mode"
    elif not sensor.active_response_enabled:
        response_message = "Anomaly recorded locally; active response is disabled for this site"
    else:
        response_message = "Anomaly recorded locally, but source IP quarantine failed"

    if dashboard_state_persisted is False:
        response_message += "; PostgreSQL dashboard state is unavailable"

    return IngestResponse(
        mse_score=mse_score,
        anomaly=anomaly,
        message=response_message,
        dashboard_state_persisted=dashboard_state_persisted,
        unrecognized_device=unrecognized_device,
        mitigation_applied=mitigation_applied,
        response_suspended=response_suspended,
    )
