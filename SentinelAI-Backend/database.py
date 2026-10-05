"""Database engine, sessions and schema initialization.

ORM classes live in ``models.py``. This module re-exports them so existing
imports continue to work while the SQLAlchemy schema grows to multiple sites.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Connection
from sqlalchemy.orm import sessionmaker

try:
    from .models import (
        ActiveQuarantine,
        Base,
        CriticalAlert,
        MitigationEvent,
        Sensor,
        Site,
        SiteConfig,
    )
except ImportError:  # Uvicorn launched from SentinelAI-Backend.
    from models import (
        ActiveQuarantine,
        Base,
        CriticalAlert,
        MitigationEvent,
        Sensor,
        Site,
        SiteConfig,
    )


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost/sentinel_db",
)


# The guard rejects UPDATE, DELETE and TRUNCATE at the database boundary,
# including writes that bypass the ORM. It also ensures a reversion points to
# an APPLY for the same site and source IP. A unique constraint prevents two
# reversions from referring to the same APPLY event.
_POSTGRES_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION sentinelai_guard_mitigation_events()
RETURNS trigger LANGUAGE plpgsql AS $sentinelai$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'mitigation_events is append-only' USING ERRCODE = '55000';
    END IF;

    IF NEW.event_type = 'REVERSION' AND NOT EXISTS (
        SELECT 1 FROM mitigation_events AS original
        WHERE original.id = NEW.original_event_id
          AND original.event_type = 'APPLY'
          AND original.site_id = NEW.site_id
          AND original.source_ip = NEW.source_ip
    ) THEN
        RAISE EXCEPTION 'REVERSION must reference an APPLY for the same site and source IP'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$sentinelai$
"""

_POSTGRES_ROW_TRIGGER = """
DO $sentinelai$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_mitigation_events_guard_rows'
          AND tgrelid = 'mitigation_events'::regclass
    ) THEN
        CREATE TRIGGER trg_mitigation_events_guard_rows
        BEFORE INSERT OR UPDATE OR DELETE ON mitigation_events
        FOR EACH ROW EXECUTE FUNCTION sentinelai_guard_mitigation_events();
    END IF;
END;
$sentinelai$
"""

_POSTGRES_TRUNCATE_TRIGGER = """
DO $sentinelai$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_mitigation_events_guard_truncate'
          AND tgrelid = 'mitigation_events'::regclass
    ) THEN
        CREATE TRIGGER trg_mitigation_events_guard_truncate
        BEFORE TRUNCATE ON mitigation_events
        FOR EACH STATEMENT EXECUTE FUNCTION sentinelai_guard_mitigation_events();
    END IF;
END;
$sentinelai$
"""

_SQLITE_GUARD_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_mitigation_events_no_update
    BEFORE UPDATE ON mitigation_events
    BEGIN SELECT RAISE(ABORT, 'mitigation_events is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_mitigation_events_no_delete
    BEFORE DELETE ON mitigation_events
    BEGIN SELECT RAISE(ABORT, 'mitigation_events is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_mitigation_events_validate_reversion
    BEFORE INSERT ON mitigation_events
    WHEN NEW.event_type = 'REVERSION'
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM mitigation_events AS original
            WHERE original.id = NEW.original_event_id
              AND original.event_type = 'APPLY'
              AND original.site_id = NEW.site_id
              AND original.source_ip = NEW.source_ip
        ) THEN RAISE(ABORT,
            'REVERSION must reference an APPLY for the same site and source IP') END;
    END
    """,
)


def ensure_mitigation_event_guards(connection: Connection) -> None:
    """Install idempotent database guards for the append-only event table."""

    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(_POSTGRES_GUARD_FUNCTION)
        connection.exec_driver_sql(_POSTGRES_ROW_TRIGGER)
        connection.exec_driver_sql(_POSTGRES_TRUNCATE_TRIGGER)
    elif connection.dialect.name == "sqlite":
        for statement in _SQLITE_GUARD_TRIGGERS:
            connection.exec_driver_sql(statement)
    else:
        raise RuntimeError(
            "Append-only mitigation events require PostgreSQL or SQLite guards"
        )


@event.listens_for(MitigationEvent.__table__, "after_create")
def _guard_new_mitigation_event_table(_target: object, connection: Connection, **_kw: object) -> None:
    ensure_mitigation_event_guards(connection)


# Verify pool connections before a request reuses them.
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


def _verify_site_scoped_projections(connection: Connection) -> None:
    """Refuse legacy schemas until an explicit data-preserving migration runs."""

    inspector = inspect(connection)
    required_columns = {
        "active_quarantines": {"site_id", "source_ip", "applied_event_id"},
        "critical_alerts": {"site_id", "source_ip"},
    }
    for table_name, required in required_columns.items():
        existing = {column["name"] for column in inspector.get_columns(table_name)}
        primary_key = set(inspector.get_pk_constraint(table_name)["constrained_columns"])
        if not required <= existing or primary_key != {"site_id", "source_ip"}:
            raise RuntimeError(
                f"{table_name} uses the legacy single-site schema; run the "
                "explicit multi-site migration before starting the API"
            )


def create_database_tables() -> None:
    """Create a fresh schema; never silently rewrite existing projection data.

    Existing single-site databases require an explicit migration because
    changing primary keys at startup could leave quarantines ambiguous.
    """

    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            # Serializes concurrent workers performing create_all or guard DDL.
            connection.exec_driver_sql("SELECT pg_advisory_xact_lock(590041852)")
        Base.metadata.create_all(bind=connection)
        _verify_site_scoped_projections(connection)
        # If the table predated this release, after_create did not run.
        ensure_mitigation_event_guards(connection)
