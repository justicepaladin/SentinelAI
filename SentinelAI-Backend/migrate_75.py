"""Upgrade an existing new-fix-50 PostgreSQL schema for the 75% API block.

Stop the API, back up PostgreSQL, then run ``python migrate_75.py``. All DDL
and data changes occur in one transaction under the API's schema lock. Existing
quarantines and immutable mitigation events are preserved.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import inspect

load_dotenv(Path(__file__).resolve().parent / ".env")

try:
    from .database import (engine, ensure_mitigation_event_guards,
                           _verify_75_schema, _verify_site_scoped_projections)
    from .models import Base
except ImportError:
    from database import (engine, ensure_mitigation_event_guards,
                          _verify_75_schema, _verify_site_scoped_projections)
    from models import Base


def migrate_75() -> str:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("The 75% migration requires PostgreSQL")

    with engine.begin() as connection:
        connection.exec_driver_sql("SELECT pg_advisory_xact_lock(590041852)")
        inspector = inspect(connection)
        required_tables = {
            "sites", "sensors", "site_configs", "mitigation_events",
            "active_quarantines", "critical_alerts",
        }
        if not required_tables <= set(inspector.get_table_names()):
            raise RuntimeError(
                "Expected the new-fix-50 multi-site schema. Run its migration first."
            )
        _verify_site_scoped_projections(connection)
        existing_columns = {column["name"] for column in inspector.get_columns("site_configs")}
        if "informative_only_mode" not in existing_columns:
            connection.exec_driver_sql(
                "ALTER TABLE site_configs ADD COLUMN informative_only_mode "
                "BOOLEAN NOT NULL DEFAULT true"
            )
        if "known_devices" not in existing_columns:
            connection.exec_driver_sql(
                "ALTER TABLE site_configs ADD COLUMN known_devices "
                "JSON NOT NULL DEFAULT '[]'::json"
            )

        checks = {entry["name"]: entry["sqltext"] for entry in
                  inspector.get_check_constraints("mitigation_events")}
        if "MANUAL_REVERSION" not in checks.get("ck_mitigation_events_event_type", ""):
            if not {"ck_mitigation_events_event_type",
                    "ck_mitigation_events_original_required"} <= checks.keys():
                raise RuntimeError("Unexpected mitigation event constraints; migration aborted")
            connection.exec_driver_sql(
                "ALTER TABLE mitigation_events "
                "DROP CONSTRAINT ck_mitigation_events_event_type, "
                "DROP CONSTRAINT ck_mitigation_events_original_required"
            )
            connection.exec_driver_sql(
                "ALTER TABLE mitigation_events ADD CONSTRAINT "
                "ck_mitigation_events_event_type CHECK "
                "(event_type IN ('APPLY', 'REVERSION', 'MANUAL_REVERSION'))"
            )
            connection.exec_driver_sql(
                "ALTER TABLE mitigation_events ADD CONSTRAINT "
                "ck_mitigation_events_original_required CHECK "
                "((event_type = 'APPLY' AND original_event_id IS NULL) OR "
                "(event_type IN ('REVERSION', 'MANUAL_REVERSION') "
                "AND original_event_id IS NOT NULL))"
            )

        Base.metadata.create_all(bind=connection)
        ensure_mitigation_event_guards(connection)
        _verify_75_schema(connection)
    return "75% schema ready; existing mitigation history preserved."


def main() -> int:
    try:
        print(migrate_75())
    except RuntimeError as exc:
        print(f"Migration failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
