"""PostgreSQL stores current response state, never the raw flow history."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost/sentinel_db",
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


class ActiveQuarantine(Base):
    """A firewall quarantine that is currently scheduled for release."""

    __tablename__ = "active_quarantines"

    source_ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    mse_score: Mapped[float] = mapped_column(Float, nullable=False)
    quarantined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class CriticalAlert(Base):
    """One recent critical alert snapshot per source IP for the dashboard."""

    __tablename__ = "critical_alerts"

    source_ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    mse_score: Mapped[float] = mapped_column(Float, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


# Verificamos las conexiones del pool antes de reutilizarlas en una solicitud.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def create_database_tables() -> None:
    """Create tables that do not exist yet.

    For larger deployments this should be replaced by Alembic migrations.
    """

    Base.metadata.create_all(bind=engine)
