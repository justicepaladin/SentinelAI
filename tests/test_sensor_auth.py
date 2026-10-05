"""Sensor token lookup, FastAPI dependency wiring and site isolation."""

from __future__ import annotations

import hashlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "SentinelAI-Backend"))
import auth  # noqa: E402
import main  # noqa: E402
import state_store  # noqa: E402
from models import Base, CriticalAlert, Sensor, Site, SiteConfig  # noqa: E402


class SensorAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.token = "test-token-" + "a" * 48
        self.other_token = "test-token-" + "b" * 48
        with self.session_factory.begin() as session:
            site_a = Site(slug="branch-a", name="Branch A")
            site_b = Site(slug="branch-b", name="Branch B")
            session.add_all([site_a, site_b])
            session.flush()
            self.site_a_id = site_a.id
            self.site_b_id = site_b.id
            session.add_all(
                [
                    SiteConfig(site_id=site_a.id, custom_mse_threshold=0.002),
                    SiteConfig(site_id=site_b.id),
                    Sensor(
                        site_id=site_a.id,
                        name="edge-a",
                        token_hash=hashlib.sha256(self.token.encode()).hexdigest(),
                    ),
                    Sensor(
                        site_id=site_b.id,
                        name="edge-b",
                        token_hash=hashlib.sha256(self.other_token.encode()).hexdigest(),
                    ),
                    CriticalAlert(
                        site_id=site_b.id,
                        source_ip="203.0.113.9",
                        destination_ip="198.51.100.20",
                        destination_port=443,
                        mse_score=0.01,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                    ),
                ]
            )
        self.auth_patch = patch.object(auth, "SessionLocal", self.session_factory)
        self.state_patch = patch.object(state_store, "SessionLocal", self.session_factory)
        self.auth_patch.start()
        self.state_patch.start()

    def tearDown(self) -> None:
        self.state_patch.stop()
        self.auth_patch.stop()
        self.engine.dispose()

    def credentials(self, token: str) -> HTTPAuthorizationCredentials:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    def test_ingest_route_requires_auth_dependency(self) -> None:
        ingest_route = next(
            route for route in main.app.routes if getattr(route, "path", None) == "/ingest"
        )
        self.assertIn(
            auth.get_authenticated_sensor,
            [dependency.call for dependency in ingest_route.dependant.dependencies],
        )

    def test_missing_wrong_and_inactive_sensor_are_rejected(self) -> None:
        for credentials in (
            None,
            self.credentials("wrong-" + "x" * 45),
        ):
            with self.assertRaises(HTTPException) as raised:
                auth.get_authenticated_sensor(credentials)
            self.assertEqual(raised.exception.status_code, 401)

        with self.session_factory.begin() as session:
            sensor = session.query(Sensor).filter(Sensor.site_id == self.site_a_id).one()
            sensor.is_active = False
        with self.assertRaises(HTTPException) as raised:
            auth.get_authenticated_sensor(self.credentials(self.token))
        self.assertEqual(raised.exception.status_code, 401)

        with self.session_factory.begin() as session:
            site = session.get(Site, self.site_b_id)
            site.is_active = False
        with self.assertRaises(HTTPException) as raised:
            auth.get_authenticated_sensor(self.credentials(self.other_token))
        self.assertEqual(raised.exception.status_code, 401)

    def test_valid_sensor_ingests_and_dashboard_is_site_scoped(self) -> None:
        sensor_a = auth.get_authenticated_sensor(self.credentials(self.token))
        sensor_b = auth.get_authenticated_sensor(self.credentials(self.other_token))
        self.assertEqual(sensor_a.site_id, self.site_a_id)
        self.assertEqual(sensor_a.custom_mse_threshold, 0.002)

        traffic: list[dict] = []

        class MemoryLog:
            def log_traffic(self, **fields: object) -> None:
                traffic.append(fields)

            def log_detection(self, **fields: object) -> None:
                pass

        main.app.state.model = object()
        main.app.state.scaler = object()
        main.app.state.audit_log = MemoryLog()
        flow = main.NetworkFlow(
            source_ip="192.0.2.20",
            destination_ip="198.51.100.20",
            destination_port=443,
            features=[0.0] * 78,
        )
        request = Request({"type": "http", "app": main.app})
        with patch.object(main, "_predict_mse", return_value=0.00001):
            response = main.ingest(flow, request, BackgroundTasks(), sensor_a)
        self.assertFalse(response.anomaly)
        self.assertEqual(traffic[0]["site_id"], self.site_a_id)
        self.assertEqual(main.dashboard_state(sensor_a).critical_alerts, [])
        self.assertEqual(len(main.dashboard_state(sensor_b).critical_alerts), 1)


if __name__ == "__main__":
    unittest.main()
