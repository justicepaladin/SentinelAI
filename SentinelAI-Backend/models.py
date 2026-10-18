"""Relational schema for registered sites, sensors and response state.

``MitigationEvent`` is the durable audit trail for firewall actions. The two
projection tables contain only the current dashboard state and may be updated
or pruned without changing that trail.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base shared by all database models."""


class Site(Base):
    """A customer site or branch; deactivation rejects all its sensors."""

    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, server_default=func.now()
    )

    sensors: Mapped[list[Sensor]] = relationship(back_populates="site")
    config: Mapped[SiteConfig | None] = relationship(back_populates="site", uselist=False)


class Sensor(Base):
    """A registered edge sensor; only the SHA-256 digest of its bearer token is stored."""

    __tablename__ = "sensors"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_sensors_site_name"),
        # A composite key lets mitigation events verify that a sensor belongs
        # to the site recorded on the event.
        UniqueConstraint("site_id", "id", name="uq_sensors_site_id_id"),
        CheckConstraint("length(token_hash) = 64", name="ck_sensors_token_hash_length"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, server_default=func.now()
    )

    site: Mapped[Site] = relationship(back_populates="sensors")


class SiteConfig(Base):
    """Optional per-site overrides for model threshold and active response."""

    __tablename__ = "site_configs"
    __table_args__ = (
        CheckConstraint(
            "custom_mse_threshold IS NULL OR custom_mse_threshold > 0",
            name="ck_site_configs_positive_threshold",
        ),
    )

    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), primary_key=True
    )
    custom_mse_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    active_response_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    informative_only_mode: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    # Canonical IPv4/IPv6 CIDR strings. An empty inventory intentionally marks
    # every RFC1918/ULA source as unrecognized until the site is configured.
    known_devices: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list, server_default="[]"
    )

    site: Mapped[Site] = relationship(back_populates="config")


class MitigationEvent(Base):
    """Append-only firewall event; REVERSION references its original APPLY."""

    __tablename__ = "mitigation_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["site_id", "sensor_id"],
            ["sensors.site_id", "sensors.id"],
            name="fk_mitigation_events_sensor_site",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "event_type IN ('APPLY', 'REVERSION', 'MANUAL_REVERSION')",
            name="ck_mitigation_events_event_type",
        ),
        CheckConstraint(
            "(event_type = 'APPLY' AND original_event_id IS NULL) OR "
            "(event_type IN ('REVERSION', 'MANUAL_REVERSION') "
            "AND original_event_id IS NOT NULL)",
            name="ck_mitigation_events_original_required",
        ),
        CheckConstraint(
            "destination_port IS NULL OR destination_port BETWEEN 0 AND 65535",
            name="ck_mitigation_events_destination_port",
        ),
        UniqueConstraint("original_event_id", name="uq_mitigation_events_original_event_id"),
        Index("ix_mitigation_events_site_occurred", "site_id", "occurred_at"),
        Index(
            "ix_mitigation_events_site_source_occurred",
            "site_id",
            "source_ip",
            "occurred_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), nullable=False
    )
    sensor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    original_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("mitigation_events.id", ondelete="RESTRICT"), nullable=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mse_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, server_default=func.now()
    )


class ActiveQuarantine(Base):
    """Current quarantine projection, scoped by site and source IP."""

    __tablename__ = "active_quarantines"
    __table_args__ = (
        CheckConstraint(
            "destination_port BETWEEN 0 AND 65535",
            name="ck_active_quarantines_destination_port",
        ),
    )

    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), primary_key=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    # Nullable while legacy rows are migrated. All newly applied mitigations
    # should set this to the APPLY event committed in the same transaction.
    applied_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("mitigation_events.id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    )
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    mse_score: Mapped[float] = mapped_column(Float, nullable=False)
    quarantined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class CriticalAlert(Base):
    """One recent critical alert snapshot per source IP at each site."""

    __tablename__ = "critical_alerts"

    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), primary_key=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    mse_score: Mapped[float] = mapped_column(Float, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class DetectionAlert(Base):
    """One durable alert per anomalous flow or operational/device warning."""

    __tablename__ = "detection_alerts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["site_id", "sensor_id"], ["sensors.site_id", "sensors.id"],
            name="fk_detection_alerts_sensor_site", ondelete="RESTRICT",
        ),
        CheckConstraint("severity IN ('warning', 'high', 'critical')", name="ck_detection_alerts_severity"),
        CheckConstraint("destination_port BETWEEN 0 AND 65535", name="ck_detection_alerts_port"),
        Index("ix_detection_alerts_site_occurred", "site_id", "occurred_at"),
        Index("ix_detection_alerts_site_source", "site_id", "source_ip"),
        Index("ix_detection_alerts_sensor_occurred", "sensor_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"), nullable=False)
    sensor_id: Mapped[int] = mapped_column(Integer, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    mse_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False)
    unrecognized_device: Mapped[bool] = mapped_column(Boolean, nullable=False)
    link_degraded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    informative_only_mode: Mapped[bool] = mapped_column(Boolean, nullable=False)
    mitigation_applied: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)


class SensorTelemetry(Base):
    """Small operational counter and heartbeat projection for each sensor."""

    __tablename__ = "sensor_telemetry"

    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="RESTRICT"), primary_key=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ingest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_link_report_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    flow_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_link_degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
