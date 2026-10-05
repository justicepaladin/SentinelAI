"""Site-scoped dashboard projections and immutable mitigation events.

Traffic and detections are written to local rotated logs. PostgreSQL stores only
current dashboard snapshots plus the small, append-only firewall action ledger.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert

try:
    from .database import SessionLocal
    from .models import ActiveQuarantine, CriticalAlert, MitigationEvent
except ImportError:  # Uvicorn launched from SentinelAI-Backend.
    from database import SessionLocal
    from models import ActiveQuarantine, CriticalAlert, MitigationEvent


def record_detection_state(
    *,
    site_id: int,
    sensor_id: int,
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
    """Commit a new APPLY event and/or a rate-limited alert snapshot atomically."""

    if not newly_quarantined and not critical:
        return

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        if newly_quarantined:
            existing = db.get(ActiveQuarantine, (site_id, source_ip), with_for_update=True)
            if existing is None:
                event = MitigationEvent(
                    site_id=site_id,
                    sensor_id=sensor_id,
                    event_type="APPLY",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    mse_score=mse_score,
                    occurred_at=now,
                )
                db.add(event)
                db.flush()
                db.add(
                    ActiveQuarantine(
                        site_id=site_id,
                        source_ip=source_ip,
                        applied_event_id=event.id,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        mse_score=mse_score,
                        quarantined_at=now,
                        expires_at=now + timedelta(seconds=quarantine_seconds),
                    )
                )

        if critical:
            # A dashboard snapshot is mutable by design; it is not the event log.
            db.execute(
                delete(CriticalAlert).where(
                    CriticalAlert.site_id == site_id,
                    CriticalAlert.expires_at <= now,
                )
            )
            alert_insert = insert(CriticalAlert).values(
                site_id=site_id,
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
                    index_elements=[CriticalAlert.site_id, CriticalAlert.source_ip],
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


def release_quarantine_state(site_id: int, source_ip: str) -> bool:
    """Append one REVERSION and remove the live projection in one transaction.

    Repeated release attempts are idempotent. A legacy projection without an
    APPLY link is first represented by an imported APPLY event.
    """

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        quarantine = db.get(ActiveQuarantine, (site_id, source_ip), with_for_update=True)
        if quarantine is None:
            return False

        apply_id = quarantine.applied_event_id
        if apply_id is None:
            imported_apply = MitigationEvent(
                site_id=site_id,
                sensor_id=None,
                event_type="APPLY",
                source_ip=source_ip,
                destination_ip=quarantine.destination_ip,
                destination_port=quarantine.destination_port,
                mse_score=quarantine.mse_score,
                reason="legacy_quarantine_import",
                occurred_at=quarantine.quarantined_at,
            )
            db.add(imported_apply)
            db.flush()
            apply_id = imported_apply.id

        db.add(
            MitigationEvent(
                site_id=site_id,
                sensor_id=None,
                event_type="REVERSION",
                original_event_id=apply_id,
                source_ip=source_ip,
                destination_ip=quarantine.destination_ip,
                destination_port=quarantine.destination_port,
                mse_score=quarantine.mse_score,
                reason="quarantine_timer_elapsed",
                occurred_at=now,
            )
        )
        db.delete(quarantine)
    return True


def list_current_state(site_id: int) -> tuple[list[ActiveQuarantine], list[CriticalAlert]]:
    """Return current dashboard state for exactly one authenticated site."""

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        quarantines = list(
            db.scalars(
                select(ActiveQuarantine)
                .where(
                    ActiveQuarantine.site_id == site_id,
                    ActiveQuarantine.expires_at > now,
                )
                .order_by(ActiveQuarantine.quarantined_at.desc())
            )
        )
        alerts = list(
            db.scalars(
                select(CriticalAlert)
                .where(
                    CriticalAlert.site_id == site_id,
                    CriticalAlert.expires_at > now,
                )
                .order_by(CriticalAlert.last_seen.desc())
            )
        )
    return quarantines, alerts


def list_quarantines_for_recovery() -> list[ActiveQuarantine]:
    """Load pending local firewall releases after an API process restart."""

    with SessionLocal() as db:
        return list(db.scalars(select(ActiveQuarantine)))
