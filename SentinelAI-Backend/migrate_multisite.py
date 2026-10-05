"""Explicit PostgreSQL migration from the fix-50% single-site schema.

Run once before starting the new API, after taking a database backup::

    python SentinelAI-Backend/migrate_multisite.py \
        --site-slug legacy --site-name "Legacy site"

The migration preserves live quarantine and critical-alert rows. An existing
quarantine gets an imported APPLY event; no detection history is invented.
All DDL and data movement run in one transaction. Unexpected or partially
migrated schemas are rejected without changing them.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection


load_dotenv(Path(__file__).resolve().parent / ".env")

try:
    from .database import engine, ensure_mitigation_event_guards
    from .models import Base
except ImportError:  # Also works as ``python migrate_multisite.py``.
    from database import engine, ensure_mitigation_event_guards
    from models import Base


_LEGACY_COLUMNS = {
    "active_quarantines": {
        "source_ip",
        "destination_ip",
        "destination_port",
        "mse_score",
        "quarantined_at",
        "expires_at",
    },
    "critical_alerts": {
        "source_ip",
        "destination_ip",
        "destination_port",
        "mse_score",
        "first_seen",
        "last_seen",
        "expires_at",
    },
}
_NEW_TABLES = {"sites", "sensors", "site_configs", "mitigation_events"}


def _projection_shape(connection: Connection, table_name: str) -> tuple[set[str], set[str]]:
    inspector = inspect(connection)
    columns = {column["name"] for column in inspector.get_columns(table_name)}
    primary_key = set(inspector.get_pk_constraint(table_name)["constrained_columns"])
    return columns, primary_key


def _has_foreign_key(connection: Connection, table_name: str, columns: list[str], target: str) -> bool:
    return any(
        fk["constrained_columns"] == columns and fk["referred_table"] == target
        for fk in inspect(connection).get_foreign_keys(table_name)
    )


def _check_new_schema(connection: Connection) -> None:
    """Ensure an apparent prior run really reached the new projection shape."""

    for table_name, expected_extra in (
        ("active_quarantines", {"site_id", "applied_event_id"}),
        ("critical_alerts", {"site_id"}),
    ):
        columns, primary_key = _projection_shape(connection, table_name)
        if not (_LEGACY_COLUMNS[table_name] | expected_extra) <= columns:
            raise RuntimeError(f"{table_name} is missing new schema columns")
        if primary_key != {"site_id", "source_ip"}:
            raise RuntimeError(f"{table_name} does not have the multi-site primary key")
        if not _has_foreign_key(connection, table_name, ["site_id"], "sites"):
            raise RuntimeError(f"{table_name}.site_id lacks its site foreign key")

    if not _has_foreign_key(
        connection, "active_quarantines", ["applied_event_id"], "mitigation_events"
    ):
        raise RuntimeError("active_quarantines.applied_event_id lacks its event foreign key")
    unique_applies = any(
        constraint["column_names"] == ["applied_event_id"]
        for constraint in inspect(connection).get_unique_constraints("active_quarantines")
    )
    if not unique_applies:
        raise RuntimeError("active_quarantines.applied_event_id lacks its unique constraint")

    # New writes and migrated legacy rows have a corresponding APPLY event.
    unlinked = connection.execute(
        text(
            """
            SELECT count(*)
            FROM active_quarantines AS quarantine
            LEFT JOIN mitigation_events AS event
                ON event.id = quarantine.applied_event_id
               AND event.event_type = 'APPLY'
               AND event.site_id = quarantine.site_id
               AND event.source_ip = quarantine.source_ip
            WHERE event.id IS NULL
            """
        )
    ).scalar_one()
    if unlinked:
        raise RuntimeError(
            f"{unlinked} active quarantine(s) lack a matching APPLY event; "
            "repair the partial schema before rerunning"
        )


def migrate_multisite(*, site_slug: str = "legacy", site_name: str = "Legacy site") -> str:
    """Migrate in one PostgreSQL transaction and return a concise status."""

    site_slug = site_slug.strip()
    site_name = site_name.strip()
    if not site_slug or len(site_slug) > 80:
        raise ValueError("site slug must have 1 to 80 nonblank characters")
    if not site_name or len(site_name) > 200:
        raise ValueError("site name must have 1 to 200 nonblank characters")
    if engine.dialect.name != "postgresql":
        raise RuntimeError("The legacy migration requires PostgreSQL")

    with engine.begin() as connection:
        # The API schema initializer uses the same lock. A second CLI process
        # will inspect the committed result rather than race the first one.
        connection.exec_driver_sql("SELECT pg_advisory_xact_lock(590041852)")
        tables = set(inspect(connection).get_table_names())
        projections = set(_LEGACY_COLUMNS)
        if not projections <= tables:
            raise RuntimeError(
                "Expected both fix-50% projection tables. For a fresh database, "
                "start the API or run provision_sensor.py instead."
            )

        active_columns, active_pk = _projection_shape(connection, "active_quarantines")
        alert_columns, alert_pk = _projection_shape(connection, "critical_alerts")
        is_legacy = (
            active_columns == _LEGACY_COLUMNS["active_quarantines"]
            and alert_columns == _LEGACY_COLUMNS["critical_alerts"]
            and active_pk == alert_pk == {"source_ip"}
            and not tables.intersection(_NEW_TABLES)
        )
        is_new = (
            _NEW_TABLES <= tables
            and active_pk == alert_pk == {"site_id", "source_ip"}
        )
        if is_new:
            _check_new_schema(connection)
            ensure_mitigation_event_guards(connection)
            return "Already migrated; no rows changed."
        if not is_legacy:
            raise RuntimeError(
                "Unexpected or partially migrated schema. No changes were made. "
                "Restore the backup or inspect the projection tables manually."
            )

        invalid_ports = connection.execute(
            text(
                "SELECT count(*) FROM active_quarantines "
                "WHERE destination_port NOT BETWEEN 0 AND 65535"
            )
        ).scalar_one()
        if invalid_ports:
            raise RuntimeError(
                f"{invalid_ports} legacy quarantine(s) have an invalid port; "
                "correct them before running the migration"
            )

        # create_all skips existing projections, creates the four new tables in
        # FK order, and installs the event trigger on newly created tables.
        Base.metadata.create_all(bind=connection)
        site_id = connection.execute(
            text(
                "INSERT INTO sites (slug, name, is_active) "
                "VALUES (:slug, :name, true) RETURNING id"
            ),
            {"slug": site_slug, "name": site_name},
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO site_configs "
                "(site_id, custom_mse_threshold, active_response_enabled) "
                "VALUES (:site_id, NULL, false)"
            ),
            {"site_id": site_id},
        )

        for table_name in ("active_quarantines", "critical_alerts"):
            connection.exec_driver_sql(f"ALTER TABLE {table_name} ADD COLUMN site_id INTEGER")
            connection.execute(
                text(f"UPDATE {table_name} SET site_id = :site_id"),
                {"site_id": site_id},
            )
            connection.exec_driver_sql(
                f"ALTER TABLE {table_name} ALTER COLUMN site_id SET NOT NULL"
            )
            connection.exec_driver_sql(
                f"ALTER TABLE {table_name} "
                f"DROP CONSTRAINT {table_name}_pkey, "
                f"ADD CONSTRAINT {table_name}_pkey PRIMARY KEY (site_id, source_ip)"
            )
            connection.exec_driver_sql(
                f"ALTER TABLE {table_name} "
                f"ADD CONSTRAINT fk_{table_name}_site "
                "FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE RESTRICT"
            )

        connection.exec_driver_sql(
            "ALTER TABLE active_quarantines ADD COLUMN applied_event_id INTEGER"
        )
        connection.exec_driver_sql(
            "ALTER TABLE active_quarantines "
            "ADD CONSTRAINT ck_active_quarantines_destination_port "
            "CHECK (destination_port BETWEEN 0 AND 65535)"
        )

        # Imported events preserve the action time and measured score. They
        # intentionally have no sensor_id because the old schema stored none.
        imported = connection.execute(
            text(
                """
                WITH imported AS (
                    INSERT INTO mitigation_events
                        (site_id, sensor_id, event_type, original_event_id,
                         source_ip, destination_ip, destination_port,
                         mse_score, reason, occurred_at)
                    SELECT site_id, NULL, 'APPLY', NULL, source_ip,
                           destination_ip, destination_port, mse_score,
                           'legacy_quarantine_import', quarantined_at
                    FROM active_quarantines
                    RETURNING id, site_id, source_ip
                )
                UPDATE active_quarantines AS quarantine
                SET applied_event_id = imported.id
                FROM imported
                WHERE quarantine.site_id = imported.site_id
                  AND quarantine.source_ip = imported.source_ip
                """
            )
        ).rowcount
        connection.exec_driver_sql(
            "ALTER TABLE active_quarantines "
            "ADD CONSTRAINT uq_active_quarantines_applied_event_id "
            "UNIQUE (applied_event_id)"
        )
        connection.exec_driver_sql(
            "ALTER TABLE active_quarantines "
            "ADD CONSTRAINT fk_active_quarantines_applied_event "
            "FOREIGN KEY (applied_event_id) "
            "REFERENCES mitigation_events(id) ON DELETE RESTRICT"
        )

        _check_new_schema(connection)
        ensure_mitigation_event_guards(connection)
        return (
            f"Migrated legacy projections to site {site_slug!r} (id={site_id}); "
            f"imported {imported} active quarantine APPLY event(s)."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-slug", default="legacy")
    parser.add_argument("--site-name", default="Legacy site")
    args = parser.parse_args(argv)
    try:
        result = migrate_multisite(site_slug=args.site_slug, site_name=args.site_name)
    except (RuntimeError, ValueError) as exc:
        parser.exit(1, f"Migration failed: {exc}\n")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
