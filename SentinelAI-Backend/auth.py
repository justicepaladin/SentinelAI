"""Authenticate an ingest request against registered sensors in PostgreSQL."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

try:
    from .database import SessionLocal
    from .models import Sensor, Site, SiteConfig
except ImportError:  # Uvicorn launched from SentinelAI-Backend.
    from database import SessionLocal
    from models import Sensor, Site, SiteConfig


_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class SensorIdentity:
    sensor_id: int
    sensor_name: str
    site_id: int
    site_slug: str
    custom_mse_threshold: float | None
    active_response_enabled: bool


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
                select(Sensor, Site, SiteConfig)
                .join(Site, Sensor.site_id == Site.id)
                .outerjoin(SiteConfig, SiteConfig.site_id == Site.id)
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
            sensor, site, config = match
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
            )
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sensor authentication database is unavailable",
        ) from exc
