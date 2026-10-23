"""Behavioral checks for the 75% API requirements using an in-memory database.

Starlette's TestClient is unavailable in the bundled environment (it requires
the optional ``httpx2`` package), so ``request_json`` drives the ASGI app
directly. This still exercises routing, request validation, and dependencies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlencode

import fastapi.dependencies.utils
import fastapi.routing
from fastapi import BackgroundTasks, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine, delete, event, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "SentinelAI-Backend"))
import auth  # noqa: E402
import main  # noqa: E402
import state_store  # noqa: E402
from models import (  # noqa: E402
    ActiveQuarantine,
    Base,
    CriticalAlert,
    DetectionAlert,
    MitigationEvent,
    Sensor,
    Site,
    SiteConfig,
)


async def _asgi_request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    payload = json.dumps(body).encode() if body is not None else b""
    headers = [(b"content-type", b"application/json")]
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    messages: list[dict[str, Any]] = []
    request_consumed = False

    async def receive() -> dict[str, Any]:
        nonlocal request_consumed
        if not request_consumed:
            request_consumed = True
            return {"type": "http.request", "body": payload, "more_body": False}
        # The app can poll for disconnect while it streams the response.
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": urlencode(query or {}).encode(),
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    await asyncio.wait_for(main.app(scope, receive, send), timeout=5)
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    response = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return status, json.loads(response) if response else None


def request_json(
    method: str,
    path: str,
    *,
    token: str | None = None,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    async def run_inline(func: Any, *args: Any, **kwargs: Any) -> Any:
        # This sandbox cannot start AnyIO worker threads. Test the ASGI path
        # with synchronous handlers running on the current event loop instead.
        return func(*args, **kwargs)

    with patch.object(fastapi.routing, "run_in_threadpool", run_inline), patch.object(
        fastapi.dependencies.utils, "run_in_threadpool", run_inline
    ):
        return asyncio.run(_asgi_request(method, path, token=token, query=query, body=body))


class Api75Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        event.listen(
            self.engine,
            "connect",
            lambda connection, _record: connection.execute("PRAGMA foreign_keys=ON"),
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.sensor_token_a = "sensor-a-" + "a" * 48
        self.sensor_token_b = "sensor-b-" + "b" * 48
        self.admin_token = "admin-" + "c" * 48
        with self.session_factory.begin() as db:
            site_a = Site(slug="site-a", name="Site A")
            site_b = Site(slug="site-b", name="Site B")
            db.add_all([site_a, site_b])
            db.flush()
            self.site_a_id, self.site_b_id = site_a.id, site_b.id
            sensor_a = Sensor(
                site_id=site_a.id,
                name="edge-a",
                token_hash=hashlib.sha256(self.sensor_token_a.encode()).hexdigest(),
            )
            sensor_b = Sensor(
                site_id=site_b.id,
                name="edge-b",
                token_hash=hashlib.sha256(self.sensor_token_b.encode()).hexdigest(),
            )
            db.add_all([sensor_a, sensor_b])
            db.flush()
            self.sensor_a_id, self.sensor_b_id = sensor_a.id, sensor_b.id
            db.add_all(
                [
                    SiteConfig(site_id=site_a.id, active_response_enabled=True),
                    SiteConfig(site_id=site_b.id, active_response_enabled=True),
                ]
            )
        self.patches = [
            patch.object(auth, "SessionLocal", self.session_factory),
            patch.object(state_store, "SessionLocal", self.session_factory),
            patch.dict(
                os.environ,
                {"SENTINEL_ADMIN_TOKEN_SHA256": hashlib.sha256(self.admin_token.encode()).hexdigest()},
            ),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(self._cleanup)
        self.audit_log = MemoryAuditLog()
        main.app.state.model = object()
        main.app.state.scaler = object()
        main.app.state.audit_log = self.audit_log
        main.app.state.database_ready = True
        main._CRITICAL_WRITE_CACHE.clear()
        main._QUARANTINE_GENERATIONS.clear()

    def _cleanup(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.engine.dispose()

    def test_asgi_harness_exercises_route(self) -> None:
        status, body = request_json("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ml_ready"])

    def _flow(self, source_ip: str = "8.8.8.8", *, link_degraded: bool = False) -> dict[str, Any]:
        return {
            "source_ip": source_ip,
            "destination_ip": "198.51.100.8",
            "destination_port": 443,
            "features": [0.0] * 78,
            "link_degraded": link_degraded,
        }

    def _seed_alert(
        self, site_id: int, sensor_id: int, source_ip: str, severity: str,
        *, occurred_at: datetime | None = None,
    ) -> None:
        with self.session_factory.begin() as db:
            db.add(DetectionAlert(
                site_id=site_id, sensor_id=sensor_id, source_ip=source_ip,
                destination_ip="198.51.100.8", destination_port=443,
                mse_score=0.01, severity=severity, anomaly=severity != "warning",
                unrecognized_device=False, link_degraded=False,
                informative_only_mode=False, mitigation_applied=False,
                occurred_at=occurred_at or datetime.now(timezone.utc),
            ))

    def _seed_quarantine(self, site_id: int, source_ip: str) -> int:
        now = datetime.now(timezone.utc)
        with self.session_factory.begin() as db:
            applied = MitigationEvent(
                site_id=site_id, event_type="APPLY", source_ip=source_ip,
                destination_ip="198.51.100.8", destination_port=443,
                mse_score=0.01, occurred_at=now,
            )
            db.add(applied)
            db.flush()
            db.add(ActiveQuarantine(
                site_id=site_id, source_ip=source_ip, applied_event_id=applied.id,
                destination_ip="198.51.100.8", destination_port=443,
                mse_score=0.01, quarantined_at=now,
                expires_at=now + timedelta(minutes=10),
            ))
            return applied.id

    def test_alert_filters_and_site_scoped_reader_permissions(self) -> None:
        self._seed_alert(self.site_a_id, self.sensor_a_id, "10.0.0.5", "warning")
        self._seed_alert(self.site_a_id, self.sensor_a_id, "10.0.0.6", "high")
        self._seed_alert(self.site_b_id, self.sensor_b_id, "10.0.0.5", "critical")

        status, rows = request_json("GET", "/alerts", token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(rows), 3)

        status, rows = request_json(
            "GET", "/alerts", token=self.admin_token,
            query={"site_id": self.site_a_id, "severity": "high"},
        )
        self.assertEqual(status, 200)
        self.assertEqual([(row["site_id"], row["source_ip"]) for row in rows],
                         [(self.site_a_id, "10.0.0.6")])

        status, rows = request_json(
            "GET", "/alerts", token=self.admin_token,
            query={"sensor_id": self.sensor_b_id, "source_ip": "10.0.0.5"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "critical")

        status, rows = request_json("GET", "/alerts", token=self.sensor_token_a)
        self.assertEqual(status, 200)
        self.assertEqual({row["site_id"] for row in rows}, {self.site_a_id})
        self.assertEqual(len(rows), 2)
        self.assertEqual(request_json(
            "GET", "/alerts", token=self.sensor_token_a,
            query={"site_id": self.site_b_id},
        )[0], 403)
        self.assertEqual(request_json(
            "GET", "/alerts", token=self.admin_token,
            query={"severity": "emergency"},
        )[0], 422)
        self.assertEqual(request_json("GET", "/alerts")[0], 401)

    def test_site_config_is_admin_mutable_and_site_scoped_for_sensors(self) -> None:
        path = f"/sites/{self.site_a_id}/config"
        status, initial = request_json("GET", path, token=self.sensor_token_a)
        self.assertEqual(status, 200)
        self.assertTrue(initial["informative_only_mode"])
        self.assertEqual(initial["known_devices"], [])
        self.assertEqual(request_json("GET", path, token=self.sensor_token_b)[0], 403)

        change = {
            "custom_mse_threshold": 0.0005,
            "active_response_enabled": True,
            "informative_only_mode": False,
            "known_devices": ["10.20.0.8/24", "192.168.1.7"],
        }
        self.assertEqual(request_json("PUT", path, token=self.sensor_token_a, body=change)[0], 401)
        status, updated = request_json("PUT", path, token=self.admin_token, body=change)
        self.assertEqual(status, 200)
        self.assertEqual(updated["custom_mse_threshold"], 0.0005)
        self.assertTrue(updated["active_response_enabled"])
        self.assertFalse(updated["informative_only_mode"])
        self.assertEqual(updated["known_devices"], ["10.20.0.0/24", "192.168.1.7/32"])
        self.assertEqual(request_json("GET", path, token=self.sensor_token_a)[1], updated)
        self.assertEqual(request_json(
            "PUT", path, token=self.admin_token,
            body={"custom_mse_threshold": -1},
        )[0], 422)
        self.assertEqual(request_json(
            "PUT", path, token=self.admin_token,
            body={"known_devices": ["not-an-address"]},
        )[0], 422)
        self.assertEqual(request_json("PUT", path, token=self.admin_token, body={})[0], 422)
        self.assertEqual(request_json(
            "GET", "/sites/99999/config", token=self.admin_token,
        )[0], 404)
        self.assertEqual(request_json("GET", path, token=self.admin_token)[1], updated)

    def test_sites_list_is_admin_global_and_sensor_scoped(self) -> None:
        with self.session_factory.begin() as db:
            db.add(Site(slug="site-c", name="Site C", is_active=False))
            db.execute(update(SiteConfig).where(SiteConfig.site_id == self.site_a_id).values(
                custom_mse_threshold=0.002, known_devices=["10.0.0.0/24"],
                informative_only_mode=False,
            ))

        status, sites = request_json("GET", "/sites", token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertEqual([site["slug"] for site in sites], ["site-a", "site-b", "site-c"])
        first = sites[0]
        self.assertEqual(set(first), {"id", "slug", "name", "is_active", "config"})
        self.assertEqual(first["config"], {
            "site_id": self.site_a_id, "custom_mse_threshold": 0.002,
            "active_response_enabled": True, "informative_only_mode": False,
            "known_devices": ["10.0.0.0/24"],
        })
        # A site without a SiteConfig row reports the same defaults as /config.
        self.assertFalse(sites[2]["is_active"])
        self.assertEqual(sites[2]["config"], {
            "site_id": sites[2]["id"], "custom_mse_threshold": None,
            "active_response_enabled": False, "informative_only_mode": True,
            "known_devices": [],
        })

        status, own = request_json("GET", "/sites", token=self.sensor_token_b)
        self.assertEqual(status, 200)
        self.assertEqual([site["id"] for site in own], [self.site_b_id])

        self.assertEqual(request_json("GET", "/sites")[0], 401)
        self.assertEqual(request_json("GET", "/sites", token="x" * 40)[0], 401)
        with patch.object(main, "list_sites", side_effect=SQLAlchemyError("down")):
            self.assertEqual(request_json("GET", "/sites", token=self.admin_token)[0], 503)

    def test_authenticated_ingest_uses_updated_site_threshold_immediately(self) -> None:
        config_path = f"/sites/{self.site_a_id}/config"
        status, _ = request_json(
            "PUT", config_path, token=self.admin_token,
            body={"custom_mse_threshold": 0.002,
                  "active_response_enabled": True,
                  "informative_only_mode": False},
        )
        self.assertEqual(status, 200)
        with patch.object(main, "_predict_mse", return_value=0.001), patch.object(
            main, "_quarantine_source_ip",
        ) as quarantine:
            status, below_site_threshold = request_json(
                "POST", "/ingest", token=self.sensor_token_a, body=self._flow(),
            )
            self.assertEqual(status, 200)
            self.assertFalse(below_site_threshold["anomaly"])
            quarantine.assert_not_called()

        status, _ = request_json(
            "PUT", config_path, token=self.admin_token,
            body={"custom_mse_threshold": 0.0004},
        )
        self.assertEqual(status, 200)
        with patch.object(main, "_predict_mse", return_value=0.001), patch.object(
            main, "_quarantine_source_ip", return_value=(False, False),
        ) as quarantine:
            status, above_site_threshold = request_json(
                "POST", "/ingest", token=self.sensor_token_a, body=self._flow(),
            )
            self.assertEqual(status, 200)
            self.assertTrue(above_site_threshold["anomaly"])
            self.assertFalse(above_site_threshold["response_suspended"])
            quarantine.assert_called_once()
        self.assertEqual([entry["anomaly"] for entry in self.audit_log.traffic],
                         [False, True])
        self.assertEqual(self.audit_log.detections[-1]["threshold"], 0.0004)

    def test_telemetry_counts_ingest_and_heartbeat_with_exact_sensor_access(self) -> None:
        path = f"/sensors/{self.sensor_a_id}/telemetry"
        status, initial = request_json("GET", path, token=self.sensor_token_a)
        self.assertEqual(status, 200)
        self.assertEqual(initial["flow_count"], 0)
        self.assertIsNone(initial["last_heartbeat_at"])
        self.assertEqual(request_json("GET", path, token=self.sensor_token_b)[0], 403)
        self.assertEqual(request_json(
            "POST", f"/sensors/{self.sensor_a_id}/heartbeat",
            token=self.sensor_token_b, body={"link_degraded": False},
        )[0], 403)

        status, beat = request_json(
            "POST", f"/sensors/{self.sensor_a_id}/heartbeat",
            token=self.sensor_token_a, body={"link_degraded": False},
        )
        self.assertEqual(status, 200)
        self.assertEqual(beat["flow_count"], 0)
        self.assertIsNotNone(beat["last_heartbeat_at"])
        self.assertIsNone(beat["last_ingest_at"])

        with patch.object(main, "_predict_mse", return_value=0.0001):
            self.assertEqual(request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=self._flow(link_degraded=False),
            )[0], 200)
            self.assertEqual(request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=self._flow(link_degraded=True),
            )[0], 200)
        status, telemetry = request_json("GET", path, token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(telemetry["flow_count"], 2)
        self.assertTrue(telemetry["last_link_degraded"])
        self.assertIsNotNone(telemetry["last_ingest_at"])
        self.assertEqual(request_json(
            "GET", "/sensors/99999/telemetry", token=self.admin_token,
        )[0], 404)

    def test_heartbeat_degradation_gates_omitted_ingest_field_until_explicit_recovery(self) -> None:
        config_path = f"/sites/{self.site_a_id}/config"
        telemetry_path = f"/sensors/{self.sensor_a_id}/telemetry"
        self.assertEqual(request_json(
            "PUT", config_path, token=self.admin_token,
            body={"active_response_enabled": True,
                  "informative_only_mode": False},
        )[0], 200)
        flow_without_report = self._flow()
        flow_without_report.pop("link_degraded")

        with patch.object(main, "_predict_mse", return_value=0.0001):
            status, baseline = request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=flow_without_report,
            )
        self.assertEqual(status, 200)
        self.assertFalse(baseline["anomaly"])
        status, before_heartbeat = request_json(
            "GET", telemetry_path, token=self.sensor_token_a,
        )
        self.assertEqual(status, 200)
        self.assertIsNone(before_heartbeat["last_heartbeat_at"])
        self.assertIsNotNone(before_heartbeat["last_ingest_at"])
        self.assertEqual(before_heartbeat["flow_count"], 1)

        status, degraded_heartbeat = request_json(
            "POST", f"/sensors/{self.sensor_a_id}/heartbeat",
            token=self.sensor_token_a, body={"link_degraded": True},
        )
        self.assertEqual(status, 200)
        self.assertTrue(degraded_heartbeat["last_link_degraded"])
        self.assertIsNotNone(degraded_heartbeat["last_heartbeat_at"])
        self.assertIsNotNone(degraded_heartbeat["last_link_report_at"])

        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main, "_quarantine_source_ip",
        ) as firewall:
            status, degraded_ingest = request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=flow_without_report,
            )
            self.assertEqual(status, 200)
            self.assertTrue(degraded_ingest["anomaly"])
            self.assertTrue(degraded_ingest["response_suspended"])
            firewall.assert_not_called()
        status, after_degraded_ingest = request_json(
            "GET", telemetry_path, token=self.sensor_token_a,
        )
        self.assertEqual(status, 200)
        self.assertEqual(after_degraded_ingest["last_heartbeat_at"],
                         degraded_heartbeat["last_heartbeat_at"])
        self.assertEqual(after_degraded_ingest["last_link_report_at"],
                         degraded_heartbeat["last_link_report_at"])
        self.assertTrue(after_degraded_ingest["last_link_degraded"])

        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main, "_quarantine_source_ip", return_value=(False, False),
        ) as firewall:
            status, recovered_ingest = request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=self._flow(link_degraded=False),
            )
            self.assertEqual(status, 200)
            self.assertTrue(recovered_ingest["anomaly"])
            self.assertFalse(recovered_ingest["response_suspended"])
            firewall.assert_called_once()
        status, recovered_telemetry = request_json(
            "GET", telemetry_path, token=self.sensor_token_a,
        )
        self.assertEqual(status, 200)
        self.assertEqual(recovered_telemetry["last_heartbeat_at"],
                         degraded_heartbeat["last_heartbeat_at"])
        self.assertFalse(recovered_telemetry["last_link_degraded"])
        self.assertEqual(recovered_telemetry["flow_count"], 3)

    def test_degraded_and_informative_modes_suppress_firewall_but_keep_detection(self) -> None:
        config_path = f"/sites/{self.site_a_id}/config"
        self.assertEqual(request_json(
            "PUT", config_path, token=self.admin_token,
            body={"informative_only_mode": False, "active_response_enabled": True},
        )[0], 200)
        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main, "_quarantine_source_ip", return_value=(False, False),
        ) as quarantine:
            status, normal = request_json(
                "POST", "/ingest", token=self.sensor_token_a, body=self._flow(),
            )
            self.assertEqual(status, 200)
            self.assertTrue(normal["anomaly"])
            self.assertFalse(normal["response_suspended"])
            quarantine.assert_called_once()

        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main, "_quarantine_source_ip",
        ) as quarantine:
            status, degraded = request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=self._flow(link_degraded=True),
            )
            self.assertEqual(status, 200)
            self.assertTrue(degraded["anomaly"])
            self.assertTrue(degraded["response_suspended"])
            self.assertFalse(degraded["mitigation_applied"])
            quarantine.assert_not_called()

        self.assertEqual(request_json(
            "PUT", config_path, token=self.admin_token,
            body={"informative_only_mode": True},
        )[0], 200)
        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main, "_quarantine_source_ip",
        ) as quarantine:
            status, informative = request_json(
                "POST", "/ingest", token=self.sensor_token_a, body=self._flow(),
            )
            self.assertEqual(status, 200)
            self.assertTrue(informative["anomaly"])
            self.assertTrue(informative["response_suspended"])
            self.assertFalse(informative["mitigation_applied"])
            quarantine.assert_not_called()

        status, alerts = request_json("GET", "/alerts", token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(alerts), 3)
        self.assertEqual(sum(alert["link_degraded"] for alert in alerts), 1)
        self.assertEqual(sum(alert["informative_only_mode"] for alert in alerts), 1)
        self.assertEqual(sum(alert["anomaly"] for alert in alerts), 3)
        self.assertEqual(len(self.audit_log.detections), 3)

    def test_unknown_private_device_is_flagged_in_response_alert_and_local_log(self) -> None:
        self.assertEqual(request_json(
            "PUT", f"/sites/{self.site_a_id}/config", token=self.admin_token,
            body={"known_devices": ["10.10.0.0/24"]},
        )[0], 200)
        with patch.object(main, "_predict_mse", return_value=0.0001), patch.object(
            main, "_quarantine_source_ip",
        ) as quarantine:
            status, unknown = request_json(
                "POST", "/ingest", token=self.sensor_token_a,
                body=self._flow("10.11.0.5"),
            )
            self.assertEqual(status, 200)
            self.assertFalse(unknown["anomaly"])
            self.assertTrue(unknown["unrecognized_device"])
            self.assertFalse(unknown["mitigation_applied"])
            quarantine.assert_not_called()
            self.assertTrue(self.audit_log.detections[-1]["unrecognized_device"])

            for source in ("10.10.0.7", "8.8.8.8"):
                status, known = request_json(
                    "POST", "/ingest", token=self.sensor_token_a,
                    body=self._flow(source),
                )
                self.assertEqual(status, 200)
                self.assertFalse(known["unrecognized_device"])
        status, alerts = request_json(
            "GET", "/alerts", token=self.admin_token,
            query={"source_ip": "10.11.0.5", "severity": "warning"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["unrecognized_device"])
        self.assertFalse(alerts[0]["anomaly"])
        self.assertEqual(len(self.audit_log.detections), 1)

    def test_manual_revert_requires_admin_and_appends_immutable_event(self) -> None:
        source = "203.0.113.25"
        applied_id = self._seed_quarantine(self.site_a_id, source)
        path = f"/quarantines/{source}/revert"
        with patch.object(main.subprocess, "run") as firewall:
            self.assertEqual(request_json("POST", path)[0], 401)
            self.assertEqual(request_json("POST", path, token=self.sensor_token_a)[0], 401)
            firewall.assert_not_called()

        successful = subprocess.CompletedProcess(args=["iptables"], returncode=0,
                                                 stdout="", stderr="")
        with patch.object(main.subprocess, "run", return_value=successful) as firewall:
            status, reverted = request_json("POST", path, token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertTrue(reverted["reverted"])
        self.assertEqual(reverted["site_id"], self.site_a_id)
        self.assertEqual(firewall.call_count, 2)
        self.assertEqual(firewall.call_args_list[0].args[0][-6:],
                         ["-C", "INPUT", "-s", source, "-j", "DROP"])
        self.assertEqual(firewall.call_args_list[1].args[0][-6:],
                         ["-D", "INPUT", "-s", source, "-j", "DROP"])

        with self.session_factory() as db:
            self.assertIsNone(db.get(ActiveQuarantine, (self.site_a_id, source)))
            events = list(db.scalars(select(MitigationEvent).order_by(MitigationEvent.id)))
        self.assertEqual([event.event_type for event in events],
                         ["APPLY", "MANUAL_REVERSION"])
        self.assertEqual(events[1].original_event_id, applied_id)
        self.assertEqual(events[1].source_ip, source)
        self.assertEqual(request_json("POST", path, token=self.admin_token)[0], 404)
        with self.session_factory.begin() as db:
            with self.assertRaises(IntegrityError), db.begin_nested():
                db.execute(update(MitigationEvent)
                           .where(MitigationEvent.id == events[1].id)
                           .values(reason="tampered"))

    def test_manual_reversion_event_rejects_update_and_delete_at_database_boundary(self) -> None:
        source = "203.0.113.28"
        applied_id = self._seed_quarantine(self.site_a_id, source)
        self.assertTrue(state_store.release_quarantine_state(
            self.site_a_id, source, manual=True, expected_event_id=applied_id,
        ))
        with self.session_factory() as db:
            manual = db.scalars(select(MitigationEvent).where(
                MitigationEvent.event_type == "MANUAL_REVERSION",
            )).one()
            manual_id = manual.id
        for statement in (
            update(MitigationEvent).where(MitigationEvent.id == manual_id).values(reason="changed"),
            delete(MitigationEvent).where(MitigationEvent.id == manual_id),
        ):
            with self.session_factory.begin() as db:
                with self.assertRaises(IntegrityError), db.begin_nested():
                    db.execute(statement)
        with self.session_factory() as db:
            retained = db.get(MitigationEvent, manual_id)
            self.assertIsNotNone(retained)
            self.assertEqual(retained.original_event_id, applied_id)

    def test_stale_timer_cannot_release_a_new_quarantine_after_manual_revert(self) -> None:
        source = "203.0.113.29"
        original_apply_id = self._seed_quarantine(self.site_a_id, source)
        stale_generation = main._new_quarantine_generation(self.site_a_id, source)
        firewall_ok = subprocess.CompletedProcess(
            args=["iptables"], returncode=0, stdout="", stderr="",
        )
        with patch.object(main.subprocess, "run", return_value=firewall_ok):
            status, _ = request_json(
                "POST", f"/quarantines/{source}/revert", token=self.admin_token,
            )
        self.assertEqual(status, 200)
        replacement_apply_id = self._seed_quarantine(self.site_a_id, source)
        self.assertNotEqual(replacement_apply_id, original_apply_id)
        current_generation = main._new_quarantine_generation(self.site_a_id, source)

        with patch.object(main.subprocess, "run") as firewall:
            asyncio.run(main._remove_quarantine(
                self.site_a_id, source, delay=0,
                expected_event_id=original_apply_id,
                generation=stale_generation,
            ))
            # A second worker would not share the in-memory generation map.
            # The persisted APPLY id must still prevent its old timer from
            # touching the replacement rule.
            asyncio.run(main._remove_quarantine(
                self.site_a_id, source, delay=0,
                expected_event_id=original_apply_id,
                generation=None,
            ))
            firewall.assert_not_called()
        with self.session_factory() as db:
            live = db.get(ActiveQuarantine, (self.site_a_id, source))
            self.assertIsNotNone(live)
            self.assertEqual(live.applied_event_id, replacement_apply_id)
            events = list(db.scalars(select(MitigationEvent).where(
                MitigationEvent.source_ip == source,
            )))
        self.assertEqual([event.event_type for event in events],
                         ["APPLY", "MANUAL_REVERSION", "APPLY"])
        self.assertIs(main._QUARANTINE_GENERATIONS[(self.site_a_id, source)],
                      current_generation)

    def test_manual_revert_refuses_ambiguous_source_and_firewall_failure(self) -> None:
        source = "203.0.113.26"
        self._seed_quarantine(self.site_a_id, source)
        self._seed_quarantine(self.site_b_id, source)
        path = f"/quarantines/{source}/revert"
        with patch.object(main.subprocess, "run") as firewall:
            self.assertEqual(request_json("POST", path, token=self.admin_token)[0], 409)
            firewall.assert_not_called()

        other_source = "203.0.113.27"
        self._seed_quarantine(self.site_a_id, other_source)
        valid_check = subprocess.CompletedProcess(args=["iptables"], returncode=0,
                                                  stdout="", stderr="")
        delete_failure = subprocess.CalledProcessError(1, ["iptables", "-D"], stderr="permission denied")
        with patch.object(main.subprocess, "run", side_effect=[valid_check, delete_failure]):
            self.assertEqual(request_json(
                "POST", f"/quarantines/{other_source}/revert",
                token=self.admin_token,
            )[0], 503)
        with self.session_factory() as db:
            self.assertIsNotNone(db.get(ActiveQuarantine, (self.site_a_id, other_source)))
            self.assertEqual(len(db.scalars(select(MitigationEvent).where(
                MitigationEvent.source_ip == other_source,
            )).all()), 1)

    def test_manual_revert_restores_firewall_if_audit_commit_fails(self) -> None:
        source = "203.0.113.30"
        applied_id = self._seed_quarantine(self.site_a_id, source)
        firewall = StatefulFirewall()
        with patch.object(main.subprocess, "run", side_effect=firewall), patch.object(
            main, "release_quarantine_state", side_effect=SQLAlchemyError("offline"),
        ):
            status, body = request_json(
                "POST", f"/quarantines/{source}/revert", token=self.admin_token,
            )
        self.assertEqual(status, 503)
        self.assertIn("restored", body["detail"])
        self.assertTrue(firewall.present)
        self.assertEqual(firewall.actions, ["-C", "-D", "-C", "-I"])
        with self.session_factory() as db:
            live = db.get(ActiveQuarantine, (self.site_a_id, source))
            events = list(db.scalars(select(MitigationEvent).where(
                MitigationEvent.source_ip == source,
            )))
        self.assertIsNotNone(live)
        self.assertEqual(live.applied_event_id, applied_id)
        self.assertEqual([event.event_type for event in events], ["APPLY"])

    def test_timer_restores_firewall_and_retries_after_audit_db_recovers(self) -> None:
        source = "203.0.113.31"
        applied_id = self._seed_quarantine(self.site_a_id, source)
        generation = main._new_quarantine_generation(self.site_a_id, source)
        firewall = StatefulFirewall()
        delays: list[int] = []
        release_calls = 0

        async def fake_sleep(seconds: int) -> None:
            delays.append(seconds)

        def fail_once_then_release(*args: Any, **kwargs: Any) -> bool:
            nonlocal release_calls
            release_calls += 1
            if release_calls == 1:
                raise SQLAlchemyError("temporarily offline")
            return state_store.release_quarantine_state(*args, **kwargs)

        with patch.object(main.asyncio, "sleep", fake_sleep), patch.object(
            main.subprocess, "run", side_effect=firewall,
        ), patch.object(
            main, "release_quarantine_state", side_effect=fail_once_then_release,
        ):
            asyncio.run(main._remove_quarantine(
                self.site_a_id, source, delay=0,
                expected_event_id=applied_id, generation=generation,
            ))
        self.assertEqual(delays, [0, 30])
        self.assertEqual(release_calls, 2)
        self.assertEqual(firewall.actions, ["-C", "-D", "-C", "-I", "-C", "-D"])
        self.assertFalse(firewall.present)
        with self.session_factory() as db:
            self.assertIsNone(db.get(ActiveQuarantine, (self.site_a_id, source)))
            events = list(db.scalars(select(MitigationEvent).where(
                MitigationEvent.source_ip == source,
            )))
        self.assertEqual([event.event_type for event in events], ["APPLY", "REVERSION"])
        self.assertEqual(events[1].original_event_id, applied_id)
        self.assertNotIn((self.site_a_id, source), main._QUARANTINE_GENERATIONS)

    def test_failed_apply_commit_removes_new_rule_without_projection_or_timer(self) -> None:
        source = "8.8.8.30"
        self.assertEqual(request_json(
            "PUT", f"/sites/{self.site_a_id}/config", token=self.admin_token,
            body={"active_response_enabled": True, "informative_only_mode": False},
        )[0], 200)
        sensor = auth.get_authenticated_sensor(HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=self.sensor_token_a,
        ))
        flow = main.NetworkFlow(**self._flow(source))
        request = Request({"type": "http", "app": main.app})
        background = BackgroundTasks()
        firewall = StatefulFirewall()
        firewall.present = False
        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main.subprocess, "run", side_effect=firewall,
        ), patch.object(
            main, "record_detection_state", side_effect=SQLAlchemyError("commit failed"),
        ):
            result = main.ingest(flow, request, background, sensor)
        self.assertTrue(result.anomaly)
        self.assertFalse(result.mitigation_applied)
        self.assertFalse(result.dashboard_state_persisted)
        self.assertFalse(firewall.present)
        self.assertEqual(firewall.actions, ["-C", "-I", "-D"])
        self.assertEqual(background.tasks, [])
        self.assertNotIn((self.site_a_id, source), main._QUARANTINE_GENERATIONS)
        with self.session_factory() as db:
            self.assertIsNone(db.get(ActiveQuarantine, (self.site_a_id, source)))
            self.assertEqual(db.scalars(select(MitigationEvent).where(
                MitigationEvent.source_ip == source,
            )).all(), [])

    def test_old_request_cannot_overwrite_new_generation_after_helper_returns(self) -> None:
        source = "8.8.8.31"
        self.assertEqual(request_json(
            "PUT", f"/sites/{self.site_a_id}/config", token=self.admin_token,
            body={"active_response_enabled": True, "informative_only_mode": False},
        )[0], 200)
        sensor = auth.get_authenticated_sensor(HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=self.sensor_token_a,
        ))
        flow = main.NetworkFlow(**self._flow(source))
        request = Request({"type": "http", "app": main.app})
        first_background = BackgroundTasks()
        second_background = BackgroundTasks()
        firewall = StatefulFirewall()
        firewall.present = False
        original_helper = main._record_alert_and_response
        first_apply: tuple[Any, ...] | None = None
        second_result: main.IngestResponse | None = None
        interleaved = False

        def interleave_after_helper(**kwargs: Any) -> tuple[Any, ...]:
            nonlocal first_apply, second_result, interleaved
            result = original_helper(**kwargs)
            if not interleaved:
                interleaved = True
                first_apply = result
                # The first request has returned from the helper but has not
                # yet scheduled its background task. Revert and then let a
                # second request commit a fresh APPLY for the same source.
                status, _ = request_json(
                    "POST", f"/quarantines/{source}/revert",
                    token=self.admin_token,
                )
                self.assertEqual(status, 200)
                second_result = main.ingest(flow, request, second_background, sensor)
            return result

        with patch.object(main, "_predict_mse", return_value=0.0005), patch.object(
            main.subprocess, "run", side_effect=firewall,
        ), patch.object(
            main, "_record_alert_and_response", side_effect=interleave_after_helper,
        ):
            first_result = main.ingest(flow, request, first_background, sensor)
            self.assertTrue(first_result.anomaly)
            self.assertIsNotNone(second_result)
            self.assertEqual(len(first_background.tasks), 1)
            self.assertEqual(len(second_background.tasks), 1)
            old_generation = first_background.tasks[0].args[-1]
            new_generation = second_background.tasks[0].args[-1]
            self.assertIsNot(old_generation, new_generation)
            self.assertIs(main._QUARANTINE_GENERATIONS[(self.site_a_id, source)],
                          new_generation)
            actions_before_stale_timer = list(firewall.actions)
            asyncio.run(main._remove_quarantine(
                self.site_a_id, source, delay=0,
                expected_event_id=first_apply[3], generation=old_generation,
            ))
            self.assertEqual(firewall.actions, actions_before_stale_timer)
        self.assertTrue(firewall.present)
        with self.session_factory() as db:
            live = db.get(ActiveQuarantine, (self.site_a_id, source))
            events = list(db.scalars(select(MitigationEvent).where(
                MitigationEvent.source_ip == source,
            )))
        self.assertIsNotNone(live)
        self.assertNotEqual(live.applied_event_id, first_apply[3])
        self.assertEqual([event.event_type for event in events],
                         ["APPLY", "MANUAL_REVERSION", "APPLY"])


class StatefulFirewall:
    """A single iptables rule with observable check/delete/restore operations."""

    def __init__(self) -> None:
        self.present = True
        self.actions: list[str] = []

    def __call__(self, command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        action = next(flag for flag in ("-C", "-D", "-I") if flag in command)
        self.actions.append(action)
        if action == "-C":
            return subprocess.CompletedProcess(
                args=command, returncode=0 if self.present else 1,
                stdout="", stderr="" if self.present else "Bad rule",
            )
        if action == "-D":
            self.present = False
        else:
            self.present = True
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")


class MemoryAuditLog:
    def __init__(self) -> None:
        self.traffic: list[dict[str, Any]] = []
        self.detections: list[dict[str, Any]] = []

    def log_traffic(self, **fields: Any) -> None:
        self.traffic.append(fields)

    def log_detection(self, **fields: Any) -> None:
        self.detections.append(fields)


if __name__ == "__main__":
    unittest.main()
