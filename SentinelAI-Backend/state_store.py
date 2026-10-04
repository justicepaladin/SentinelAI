"""Small, bounded PostgreSQL projections for the live dashboard.

Raw traffic and detection events belong in the local audit logs. A row in either
table here represents the current state of one source IP, not a historical event.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert

try:
    from .database import ActiveQuarantine, CriticalAlert, SessionLocal
except ImportError:  # Uvicorn launched from SentinelAI-Backend.
    from database import ActiveQuarantine, CriticalAlert, SessionLocal


def record_detection_state(
    *,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    mse_score: float,
    newly_quarantined: bool,
    critical: bool,
    quarantine_seconds: int,
    alert_ttl_hours: int,
    alert_update_seconds: int,
) -> None:
    """Write only a new quarantine and/or a rate-limited critical snapshot."""

    if not newly_quarantined and not critical:
        return

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        if newly_quarantined:
            quarantine_insert = insert(ActiveQuarantine).values(
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                mse_score=mse_score,
                quarantined_at=now,
                expires_at=now + timedelta(seconds=quarantine_seconds),
            )
            db.execute(
                quarantine_insert.on_conflict_do_update(
                    index_elements=[ActiveQuarantine.source_ip],
                    set_={
                        "destination_ip": quarantine_insert.excluded.destination_ip,
                        "destination_port": quarantine_insert.excluded.destination_port,
                        "mse_score": quarantine_insert.excluded.mse_score,
                        "quarantined_at": quarantine_insert.excluded.quarantined_at,
                        "expires_at": quarantine_insert.excluded.expires_at,
                    },
                )
            )

        if critical:
            # Critical alerts are current dashboard snapshots, not an event log.
            # Expired IPs are removed when the next critical event arrives.
            db.execute(delete(CriticalAlert).where(CriticalAlert.expires_at <= now))
            alert_insert = insert(CriticalAlert).values(
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                mse_score=mse_score,
                first_seen=now,
                last_seen=now,
                expires_at=now + timedelta(hours=alert_ttl_hours),
            )
            db.execute(
                alert_insert.on_conflict_do_update(
                    index_elements=[CriticalAlert.source_ip],
                    set_={
                        "destination_ip": alert_insert.excluded.destination_ip,
                        "destination_port": alert_insert.excluded.destination_port,
                        "mse_score": alert_insert.excluded.mse_score,
                        "last_seen": alert_insert.excluded.last_seen,
                        "expires_at": alert_insert.excluded.expires_at,
                    },
                    where=CriticalAlert.last_seen
                    <= now - timedelta(seconds=alert_update_seconds),
                )
            )


def release_quarantine_state(source_ip: str) -> None:
    """Remove the dashboard state after the firewall rule is removed."""

    with SessionLocal.begin() as db:
        db.execute(
            delete(ActiveQuarantine).where(ActiveQuarantine.source_ip == source_ip)
        )


def list_current_state() -> tuple[list[ActiveQuarantine], list[CriticalAlert]]:
    """Return only nonexpired state; old events stay in archived local logs."""

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        quarantines = list(
            db.scalars(
                select(ActiveQuarantine)
                .where(ActiveQuarantine.expires_at > now)
                .order_by(ActiveQuarantine.quarantined_at.desc())
            )
        )
        alerts = list(
            db.scalars(
                select(CriticalAlert)
                .where(CriticalAlert.expires_at > now)
                .order_by(CriticalAlert.last_seen.desc())
            )
        )
    return quarantines, alerts


def list_quarantines_for_recovery() -> list[ActiveQuarantine]:
    """Load pending firewall releases after an API process restart."""

    with SessionLocal() as db:
        return list(db.scalars(select(ActiveQuarantine)))
