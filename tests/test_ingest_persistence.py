"""Verify that raw flows stay out of PostgreSQL during ingestion."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import BackgroundTasks, Request
from sqlalchemy.exc import SQLAlchemyError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "SentinelAI-Backend"))
import main  # noqa: E402


class MemoryAuditLog:
    def __init__(self) -> None:
        self.traffic: list[dict] = []
        self.detections: list[dict] = []

    def log_traffic(self, **fields: object) -> None:
        self.traffic.append(fields)

    def log_detection(self, **fields: object) -> None:
        self.detections.append(fields)


class IngestPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        main.app.state.model = object()
        main.app.state.scaler = object()
        main.app.state.audit_log = MemoryAuditLog()
        main._CRITICAL_WRITE_CACHE.clear()
        self.telemetry_patch = patch.object(main, "update_sensor_telemetry")
        self.telemetry_patch.start()
        self.addCleanup(self.telemetry_patch.stop)
        self.flow = main.NetworkFlow(
            source_ip="192.0.2.25",
            destination_ip="198.51.100.8",
            destination_port=443,
            features=[0.0] * 78,
        )
        self.request = Request({"type": "http", "app": main.app})
        self.sensor = main.SensorIdentity(
            sensor_id=7,
            sensor_name="edge-a",
            site_id=3,
            site_slug="branch-a",
            custom_mse_threshold=None,
            active_response_enabled=True,
        )

    def test_benign_flow_only_writes_local_traffic_log(self) -> None:
        with patch.object(main, "_predict_mse", return_value=0.00001), patch.object(
            main, "record_detection_state"
        ) as persist, patch.object(main, "_quarantine_source_ip") as quarantine:
            result = main.ingest(self.flow, self.request, BackgroundTasks(), self.sensor)

        self.assertFalse(result.anomaly)
        self.assertIsNone(result.dashboard_state_persisted)
        self.assertEqual(len(main.app.state.audit_log.traffic), 1)
        self.assertEqual(main.app.state.audit_log.detections, [])
        persist.assert_not_called()
        quarantine.assert_not_called()

    def test_anomaly_writes_one_state_snapshot_not_raw_flow(self) -> None:
        background = BackgroundTasks()
        with patch.object(main, "_predict_mse", return_value=0.001), patch.object(
            main, "_quarantine_source_ip", return_value=(True, True)
        ), patch.object(main, "record_detection_state") as persist:
            result = main.ingest(self.flow, self.request, background, self.sensor)

        self.assertTrue(result.anomaly)
        self.assertTrue(result.dashboard_state_persisted)
        self.assertEqual(len(main.app.state.audit_log.traffic), 1)
        self.assertEqual(len(main.app.state.audit_log.detections), 1)
        self.assertEqual(len(background.tasks), 1)
        persist.assert_called_once()
        kwargs = persist.call_args.kwargs
        self.assertTrue(kwargs["newly_quarantined"])
        self.assertTrue(kwargs["critical"])
        self.assertEqual(kwargs["site_id"], 3)
        self.assertEqual(kwargs["sensor_id"], 7)
        self.assertNotIn("features", kwargs)

    def test_postgres_outage_keeps_detection_in_local_log(self) -> None:
        with patch.object(main, "_predict_mse", return_value=0.001), patch.object(
            main, "_quarantine_source_ip", return_value=(True, True)
        ), patch.object(
            main, "record_detection_state", side_effect=SQLAlchemyError("offline")
        ), patch.object(main, "_rollback_unpersisted_firewall_rule_locked") as rollback:
            background = BackgroundTasks()
            result = main.ingest(self.flow, self.request, background, self.sensor)

        self.assertTrue(result.anomaly)
        self.assertFalse(result.dashboard_state_persisted)
        self.assertFalse(result.mitigation_applied)
        self.assertEqual(len(background.tasks), 0)
        rollback.assert_called_once_with("192.0.2.25")
        self.assertEqual(len(main.app.state.audit_log.traffic), 1)
        self.assertEqual(len(main.app.state.audit_log.detections), 1)
        self.assertFalse(
            main.app.state.audit_log.detections[0]["dashboard_state_persisted"]
        )

    def test_cic_row_with_text_label_keeps_only_numeric_features(self) -> None:
        scaler = SimpleNamespace(n_features_in_=78)
        frame = main._features_dataframe([1.0] * 78 + ["BENIGN"], scaler)
        self.assertEqual(frame.shape, (1, 78))
        self.assertEqual(frame.iloc[0, -1], 1.0)

    def test_firewall_permission_error_does_not_clear_quarantine_state(self) -> None:
        denied = subprocess.CompletedProcess(
            args=["sudo", "iptables", "-C"],
            returncode=1,
            stderr="sudo: a password is required",
        )
        with patch.object(main.subprocess, "run", return_value=denied), patch.object(
            main, "release_quarantine_state"
        ) as release:
            asyncio.run(main._remove_quarantine(3, "192.0.2.25", delay=0))
        release.assert_not_called()

    def test_site_response_flag_skips_firewall_and_uses_site_threshold(self) -> None:
        sensor = main.SensorIdentity(
            sensor_id=8,
            sensor_name="edge-b",
            site_id=4,
            site_slug="branch-b",
            custom_mse_threshold=0.002,
            active_response_enabled=False,
        )
        with patch.object(main, "_predict_mse", return_value=0.001), patch.object(
            main, "_quarantine_source_ip"
        ) as quarantine, patch.object(main, "record_detection_state") as persist:
            result = main.ingest(self.flow, self.request, BackgroundTasks(), sensor)
        self.assertFalse(result.anomaly)
        quarantine.assert_not_called()
        persist.assert_not_called()

        with patch.object(main, "_predict_mse", return_value=0.007), patch.object(
            main, "_quarantine_source_ip"
        ) as quarantine, patch.object(main, "record_detection_state") as persist:
            result = main.ingest(self.flow, self.request, BackgroundTasks(), sensor)
        self.assertTrue(result.anomaly)
        self.assertIn("disabled", result.message)
        quarantine.assert_not_called()
        persist.assert_called_once()
        self.assertEqual(persist.call_args.kwargs["site_id"], 4)
        self.assertFalse(persist.call_args.kwargs["newly_quarantined"])


if __name__ == "__main__":
    unittest.main()
