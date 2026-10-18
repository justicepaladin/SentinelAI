"""Authenticate an ingest request against registered sensors in PostgreSQL."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

try:
    from .database import SessionLocal
    from .models import Sensor, SensorTelemetry, Site, SiteConfig
except ImportError:  # Uvicorn launched from SentinelAI-Backend.
    from database import SessionLocal
    from models import Sensor, SensorTelemetry, Site, SiteConfig


_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class SensorIdentity:
    sensor_id: int
    sensor_name: str
    site_id: int
    site_slug: str
    custom_mse_threshold: float | None
    active_response_enabled: bool
    informative_only_mode: bool = False
    known_devices: tuple[str, ...] = ()
    last_link_degraded: bool = False
    last_link_report_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AdminIdentity:
    """Administrative Bearer identity, configured outside the database."""

    is_admin: bool = True


def _admin_token_matches(credentials: HTTPAuthorizationCredentials | None) -> bool:
    configured_hash = os.getenv("SENTINEL_ADMIN_TOKEN_SHA256", "").strip().lower()
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or len(configured_hash) != 64
        or any(char not in "0123456789abcdef" for char in configured_hash)
        or not 32 <= len(credentials.credentials) <= 512
    ):
        return False
    actual_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual_hash, configured_hash)


def get_authenticated_admin(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AdminIdentity:
    """Require a dedicated high-entropy admin token for mutating operations."""

    if not os.getenv("SENTINEL_ADMIN_TOKEN_SHA256"):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Administrator authentication is not configured")
    if not _admin_token_matches(credentials):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid administrator token",
                            headers={"WWW-Authenticate": "Bearer"})
    return AdminIdentity()


def get_authenticated_reader(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AdminIdentity | SensorIdentity:
    """Allow global admin reads or site-scoped reads by a registered sensor."""

    if _admin_token_matches(credentials):
        return AdminIdentity()
    return get_authenticated_sensor(credentials)


def get_authenticated_sensor(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> SensorIdentity:
    """Resolve a Bearer token to one active sensor and its site configuration."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A sensor Bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    if not 32 <= len(token) <= 512:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid sensor token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    try:
        with SessionLocal() as db:
            match = db.execute(
                select(Sensor, Site, SiteConfig, SensorTelemetry)
                .join(Site, Sensor.site_id == Site.id)
                .outerjoin(SiteConfig, SiteConfig.site_id == Site.id)
                .outerjoin(SensorTelemetry, SensorTelemetry.sensor_id == Sensor.id)
                .where(
                    Sensor.token_hash == token_hash,
                    Sensor.is_active.is_(True),
                    Site.is_active.is_(True),
                )
            ).first()
            if match is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid sensor token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            sensor, site, config, telemetry = match
            return SensorIdentity(
                sensor_id=sensor.id,
                sensor_name=sensor.name,
                site_id=site.id,
                site_slug=site.slug,
                custom_mse_threshold=(
                    config.custom_mse_threshold if config is not None else None
                ),
                active_response_enabled=(
                    bool(config.active_response_enabled) if config is not None else False
                ),
                informative_only_mode=(
                    bool(config.informative_only_mode) if config is not None else True
                ),
                known_devices=tuple(config.known_devices or ()) if config is not None else (),
                last_link_degraded=(
                    bool(telemetry.last_link_degraded) if telemetry is not None else False
                ),
                last_link_report_at=(
                    telemetry.last_link_report_at if telemetry is not None else None
                ),
            )
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sensor authentication database is unavailable",
        ) from exc
