"""Site-scoped dashboard projections and immutable mitigation events.

Traffic and detections are written to local rotated logs. PostgreSQL stores only
current dashboard snapshots plus the small, append-only firewall action ledger.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

try:
    from .database import SessionLocal
    from .models import (ActiveQuarantine, CriticalAlert, DetectionAlert,
                         MitigationEvent, Sensor, SensorTelemetry, Site, SiteConfig)
except ImportError:  # Uvicorn launched from SentinelAI-Backend.
    from database import SessionLocal
    from models import (ActiveQuarantine, CriticalAlert, DetectionAlert,
                        MitigationEvent, Sensor, SensorTelemetry, Site, SiteConfig)


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
    severity: str = "high",
    anomaly: bool = True,
    unrecognized_device: bool = False,
    link_degraded: bool = False,
    informative_only_mode: bool = False,
    mitigation_applied: bool = False,
) -> int | None:
    """Record an alert and any firewall/projection changes in one transaction."""

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        db.add(DetectionAlert(
            site_id=site_id, sensor_id=sensor_id, source_ip=source_ip,
            destination_ip=destination_ip, destination_port=destination_port,
            mse_score=mse_score, severity=severity, anomaly=anomaly,
            unrecognized_device=unrecognized_device, link_degraded=link_degraded,
            informative_only_mode=informative_only_mode,
            mitigation_applied=mitigation_applied, occurred_at=now,
        ))
        applied_event_id = None
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
                applied_event_id = event.id
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
            alert_insert = (insert(CriticalAlert) if db.bind.dialect.name == "postgresql"
                            else sqlite_insert(CriticalAlert)).values(
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
    return applied_event_id


def release_quarantine_state(
    site_id: int, source_ip: str, *, manual: bool = False,
    expected_event_id: int | None = None,
) -> bool:
    """Append one REVERSION and remove the live projection in one transaction.

    Repeated release attempts are idempotent. A legacy projection without an
    APPLY link is first represented by an imported APPLY event.
    """

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        quarantine = db.get(ActiveQuarantine, (site_id, source_ip), with_for_update=True)
        if quarantine is None:
            return False
        if expected_event_id is not None and quarantine.applied_event_id != expected_event_id:
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
                event_type="MANUAL_REVERSION" if manual else "REVERSION",
                original_event_id=apply_id,
                source_ip=source_ip,
                destination_ip=quarantine.destination_ip,
                destination_port=quarantine.destination_port,
                mse_score=quarantine.mse_score,
                reason="administrator_manual_reversion" if manual else "quarantine_timer_elapsed",
                occurred_at=now,
            )
        )
        db.delete(quarantine)
    return True


def find_active_quarantines(source_ip: str, site_id: int | None = None) -> list[ActiveQuarantine]:
    """Find a live quarantine; callers resolve ambiguity across sites."""

    with SessionLocal() as db:
        stmt = select(ActiveQuarantine).where(ActiveQuarantine.source_ip == source_ip)
        if site_id is not None:
            stmt = stmt.where(ActiveQuarantine.site_id == site_id)
        return list(db.scalars(stmt))


def list_alerts(
    *, site_id: int | None = None, sensor_id: int | None = None,
    source_ip: str | None = None, severity: str | None = None, limit: int = 100,
) -> list[DetectionAlert]:
    """Return recent alerts with composable filters and bounded output."""

    stmt = select(DetectionAlert)
    if site_id is not None:
        stmt = stmt.where(DetectionAlert.site_id == site_id)
    if sensor_id is not None:
        stmt = stmt.where(DetectionAlert.sensor_id == sensor_id)
    if source_ip is not None:
        stmt = stmt.where(DetectionAlert.source_ip == source_ip)
    if severity is not None:
        stmt = stmt.where(DetectionAlert.severity == severity)
    with SessionLocal() as db:
        return list(db.scalars(stmt.order_by(DetectionAlert.occurred_at.desc(),
                                             DetectionAlert.id.desc()).limit(limit)))


def get_site_config(site_id: int) -> tuple[Site, SiteConfig | None] | None:
    with SessionLocal() as db:
        site = db.get(Site, site_id)
        if site is None:
            return None
        return site, db.get(SiteConfig, site_id)


def list_sites(site_id: int | None = None) -> list[tuple[Site, SiteConfig | None]]:
    """Return sites with their optional configuration, ordered by id."""

    stmt = select(Site, SiteConfig).outerjoin(SiteConfig, SiteConfig.site_id == Site.id)
    if site_id is not None:
        stmt = stmt.where(Site.id == site_id)
    with SessionLocal() as db:
        return [(site, config) for site, config in db.execute(stmt.order_by(Site.id))]


def update_site_config(site_id: int, changes: dict[str, object]) -> tuple[Site, SiteConfig] | None:
    """Apply validated partial configuration changes transactionally."""

    with SessionLocal.begin() as db:
        site = db.get(Site, site_id)
        if site is None:
            return None
        config = db.get(SiteConfig, site_id, with_for_update=True)
        if config is None:
            config = SiteConfig(site_id=site_id)
            db.add(config)
        for name, value in changes.items():
            setattr(config, name, value)
        db.flush()
        return site, config


def update_sensor_telemetry(sensor_id: int, *, link_degraded: bool | None, ingest: bool) -> None:
    """Upsert an ingest or explicit heartbeat without inventing heartbeat time."""

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        dialect = db.bind.dialect.name
        if dialect == "postgresql":
            stmt = insert(SensorTelemetry)
        elif dialect == "sqlite":
            stmt = sqlite_insert(SensorTelemetry)
        else:
            raise RuntimeError(f"Unsupported telemetry dialect: {dialect}")
        stmt = stmt.values(
            sensor_id=sensor_id, last_heartbeat_at=None if ingest else now,
            last_ingest_at=now if ingest else None,
            last_link_report_at=now if link_degraded is not None else None,
            flow_count=1 if ingest else 0,
            last_link_degraded=bool(link_degraded),
        )
        changes = {}
        if ingest:
            changes["last_ingest_at"] = now
            changes["flow_count"] = SensorTelemetry.flow_count + 1
        else:
            changes["last_heartbeat_at"] = now
        if link_degraded is not None:
            changes["last_link_degraded"] = link_degraded
            changes["last_link_report_at"] = now
        db.execute(stmt.on_conflict_do_update(
            index_elements=[SensorTelemetry.sensor_id], set_=changes,
        ))


def get_sensor_telemetry(sensor_id: int) -> tuple[Sensor, SensorTelemetry | None] | None:
    with SessionLocal() as db:
        sensor = db.get(Sensor, sensor_id)
        if sensor is None:
            return None
        return sensor, db.get(SensorTelemetry, sensor_id)


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
