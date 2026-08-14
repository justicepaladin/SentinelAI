"""FastAPI service for real-time SentinelAI autoencoder inference."""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from numbers import Real
from pathlib import Path
from threading import Lock
from typing import Any, Annotated

import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

try:
    from .database import Alert, create_database_tables, get_db
except ImportError:  # Allows `uvicorn main:app` from SentinelAI-Backend.
    from database import Alert, create_database_tables, get_db


logger = logging.getLogger("sentinelai")

TAU = 0.000308

BACKEND_DIR = Path(__file__).resolve().parent
MODEL_PATH = (BACKEND_DIR / "../SentinelAI-Model/models/sentinel_model.h5").resolve()
SCALER_PATH = (
    BACKEND_DIR / "../SentinelAI-Model/models/sentinel_scaler.save"
).resolve()

_PREDICTION_LOCK = Lock()


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


class HealthResponse(BaseModel):
    status: str
    ml_ready: bool
    database_ready_at_startup: bool


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
    except Exception:
        # A later request may still succeed if PostgreSQL becomes available.
        logger.exception("Database initialization failed; API is running in degraded mode")

    yield

    # Keras and SQLAlchemy manage their own process-level cleanup/pools.


app = FastAPI(
    title="SentinelAI IDS API",
    version="1.0.0",
    description="Real-time intrusion detection using a pretrained autoencoder.",
    lifespan=lifespan,
)


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

    values = _flatten_numeric_values(raw_features)

    # CIC-IDS2017 CSV files contain 79 columns: 78 numeric inputs plus Label.
    # Accept a raw 79-value row for compatibility, but never feed Label to a
    # scaler/model that were both fitted on the 78 model inputs.
    if len(values) == expected_count + 1:
        values = values[:-1]

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


@app.get("/health", response_model=HealthResponse, tags=["operations"])
def health(request: Request) -> HealthResponse:
    ml_ready = request.app.state.model is not None and request.app.state.scaler is not None
    database_ready = bool(request.app.state.database_ready)
    return HealthResponse(
        status="ok" if ml_ready and database_ready else "degraded",
        ml_ready=ml_ready,
        database_ready_at_startup=database_ready,
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
    db: Annotated[Session, Depends(get_db)],
) -> IngestResponse:
    """Classify a network flow and persist an alert when it is anomalous."""

    model = request.app.state.model
    scaler = request.app.state.scaler
    if model is None or scaler is None:
        detail = request.app.state.ml_load_error or "ML artifacts are unavailable"
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Inference service is unavailable: {detail}",
        )

    try:
        mse_score = _predict_mse(model, scaler, flow.features)
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
    if anomaly:
        alert = Alert(
            source_ip=str(flow.source_ip),
            destination_ip=str(flow.destination_ip),
            destination_port=flow.destination_port,
            mse_score=mse_score,
        )
        try:
            db.add(alert)
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            logger.exception("Could not persist anomaly alert")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Anomaly detected, but PostgreSQL could not persist the alert",
            ) from exc

    return IngestResponse(
        mse_score=mse_score,
        anomaly=anomaly,
        message=(
            "Flow analyzed successfully; anomaly alert stored"
            if anomaly
            else "Flow analyzed successfully; no anomaly detected"
        ),
    )
