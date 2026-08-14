"""Database configuration and persistence models for SentinelAI."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost/sentinel_db",
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


class Alert(Base):
    """An anomalous network flow detected by the autoencoder."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    mse_score: Mapped[float] = mapped_column(Float, nullable=False)


# pool_pre_ping replaces stale PostgreSQL connections before they reach a request.
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


def get_db() -> Generator[Session, None, None]:
    """Provide one transaction-capable SQLAlchemy session per request."""

    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
