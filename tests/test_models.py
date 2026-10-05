"""Schema invariants for multi-site state and append-only mitigations."""

from __future__ import annotations

import hashlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, delete, event, inspect, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "SentinelAI-Backend"))
from database import (  # noqa: E402
    ActiveQuarantine,
    Base,
    CriticalAlert,
    MitigationEvent,
    Sensor,
    Site,
    SiteConfig,
)


class ModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        event.listen(
            self.engine,
            "connect",
            lambda connection, _record: connection.execute("PRAGMA foreign_keys=ON"),
        )
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)
        self.site_a = Site(slug="branch-a", name="Branch A")
        self.site_b = Site(slug="branch-b", name="Branch B")
        self.session.add_all([self.site_a, self.site_b])
        self.session.flush()

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()

    def test_site_scoped_projections_allow_same_source_ip(self) -> None:
        now = datetime.now(timezone.utc)
        for site in (self.site_a, self.site_b):
            self.session.add(
                ActiveQuarantine(
                    site_id=site.id,
                    source_ip="192.0.2.10",
                    destination_ip="198.51.100.2",
                    destination_port=443,
                    mse_score=0.5,
                    quarantined_at=now,
                    expires_at=now + timedelta(minutes=1),
                )
            )
            self.session.add(
                CriticalAlert(
                    site_id=site.id,
                    source_ip="192.0.2.10",
                    destination_ip="198.51.100.2",
                    destination_port=443,
                    mse_score=0.5,
                    first_seen=now,
                    last_seen=now,
                    expires_at=now + timedelta(hours=1),
                )
            )
        self.session.commit()

        self.assertEqual(len(self.session.scalars(select(ActiveQuarantine)).all()), 2)
        self.assertEqual(len(self.session.scalars(select(CriticalAlert)).all()), 2)
        for table in ("active_quarantines", "critical_alerts"):
            self.assertEqual(
                set(inspect(self.engine).get_pk_constraint(table)["constrained_columns"]),
                {"site_id", "source_ip"},
            )

    def test_sensor_token_and_site_config_constraints(self) -> None:
        token_hash = hashlib.sha256(b"long random token").hexdigest()
        self.session.add_all(
            [
                Sensor(site_id=self.site_a.id, name="sensor-1", token_hash=token_hash),
                SiteConfig(
                    site_id=self.site_a.id,
                    custom_mse_threshold=0.003,
                    active_response_enabled=False,
                ),
            ]
        )
        self.session.commit()
        self.assertEqual(self.site_a.config.custom_mse_threshold, 0.003)
        self.assertEqual(len(self.site_a.sensors), 1)

        self.session.add(SiteConfig(site_id=self.site_b.id))
        self.session.commit()
        self.assertFalse(self.site_b.config.active_response_enabled)

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.add(
                Sensor(site_id=self.site_b.id, name="other", token_hash=token_hash)
            )
            self.session.flush()

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.add(
                Sensor(
                    site_id=self.site_a.id,
                    name="sensor-1",
                    token_hash=hashlib.sha256(b"other token").hexdigest(),
                )
            )
            self.session.flush()

        site_c = Site(slug="branch-c", name="Branch C")
        self.session.add(site_c)
        self.session.flush()

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.add(
                SiteConfig(site_id=site_c.id, custom_mse_threshold=-0.1)
            )
            self.session.flush()

    def test_mitigation_events_are_append_only_and_reversion_is_linked(self) -> None:
        sensor = Sensor(
            site_id=self.site_a.id,
            name="sensor-1",
            token_hash=hashlib.sha256(b"token-a").hexdigest(),
        )
        self.session.add(sensor)
        self.session.flush()
        apply_event = MitigationEvent(
            site_id=self.site_a.id,
            sensor_id=sensor.id,
            event_type="APPLY",
            source_ip="192.0.2.10",
            destination_ip="198.51.100.2",
            destination_port=443,
            mse_score=0.5,
        )
        self.session.add(apply_event)
        self.session.commit()

        reversion = MitigationEvent(
            site_id=self.site_a.id,
            event_type="REVERSION",
            original_event_id=apply_event.id,
            source_ip="192.0.2.10",
            reason="quarantine expired",
        )
        self.session.add(reversion)
        self.session.commit()

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.add(
                MitigationEvent(
                    site_id=self.site_a.id,
                    event_type="REVERSION",
                    original_event_id=apply_event.id,
                    source_ip="192.0.2.10",
                )
            )
            self.session.flush()

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.add(
                MitigationEvent(
                    site_id=self.site_b.id,
                    event_type="REVERSION",
                    original_event_id=apply_event.id,
                    source_ip="192.0.2.10",
                )
            )
            self.session.flush()

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.add(
                MitigationEvent(
                    site_id=self.site_b.id,
                    sensor_id=sensor.id,
                    event_type="APPLY",
                    source_ip="203.0.113.4",
                )
            )
            self.session.flush()

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.execute(
                update(MitigationEvent)
                .where(MitigationEvent.id == apply_event.id)
                .values(reason="overwritten")
            )

        with self.assertRaises(IntegrityError), self.session.begin_nested():
            self.session.execute(
                delete(MitigationEvent).where(MitigationEvent.id == apply_event.id)
            )

        self.assertEqual(len(self.session.scalars(select(MitigationEvent)).all()), 2)


if __name__ == "__main__":
    unittest.main()
