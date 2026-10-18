"""Unit tests for the latency arithmetic, ASGI client and RNF acceptance gate."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi import FastAPI
except ImportError:  # The arithmetic tests also run without backend dependencies.
    FastAPI = None


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_rnf.py"
spec = importlib.util.spec_from_file_location("benchmark_rnf", SCRIPT)
assert spec is not None and spec.loader is not None
benchmark_rnf = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = benchmark_rnf
spec.loader.exec_module(benchmark_rnf)


class BenchmarkArithmeticTests(unittest.TestCase):
    def test_latency_summary_uses_interpolated_percentiles(self) -> None:
        stats = benchmark_rnf.summarize_ns([1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000])
        self.assertEqual(stats.samples, 5)
        self.assertEqual(stats.mean_ms, 3.0)
        self.assertEqual(stats.p50_ms, 3.0)
        self.assertAlmostEqual(stats.p95_ms, 4.8)
        self.assertAlmostEqual(stats.p99_ms, 4.96)
        self.assertEqual(stats.maximum_ms, 5.0)

    def test_request_split_sums_to_exact_total(self) -> None:
        counts = benchmark_rnf.split_requests(500)
        self.assertEqual(sum(counts.values()), 500)
        self.assertEqual(counts, {
            "active": 167,
            "degraded_link": 167,
            "informative_only": 166,
        })
        with self.assertRaises(ValueError):
            benchmark_rnf.split_requests(2)

    def test_gate_rejects_firewall_calls_during_degradation(self) -> None:
        result = benchmark_rnf.ScenarioResult(
            "degraded_link",
            benchmark_rnf.summarize_ns([1_000_000] * 3),
            detections=3,
            firewall_calls=1,
            suspended_responses=3,
        )
        with self.assertRaisesRegex(RuntimeError, "zero firewall calls"):
            benchmark_rnf.validate_scenario(result)

    def test_gate_rejects_missing_detection_and_suspension(self) -> None:
        result = benchmark_rnf.ScenarioResult(
            "degraded_link",
            benchmark_rnf.summarize_ns([1_000_000] * 3),
            detections=2,
            firewall_calls=0,
            suspended_responses=1,
        )
        with self.assertRaisesRegex(RuntimeError, "anomaly detections"):
            benchmark_rnf.validate_scenario(result)
        result = benchmark_rnf.ScenarioResult(
            "degraded_link",
            result.latency,
            detections=3,
            firewall_calls=0,
            suspended_responses=2,
        )
        with self.assertRaisesRegex(RuntimeError, "suspended responses"):
            benchmark_rnf.validate_scenario(result)


class BenchmarkTransportTests(unittest.TestCase):
    def test_asgi_transport_sends_a_real_http_scope_and_returns_json(self) -> None:
        async def app(scope, receive, send):
            self.assertEqual(scope["method"], "POST")
            self.assertEqual(scope["path"], "/ingest")
            request = await receive()
            self.assertEqual(json.loads(request["body"]), {"probe": True})
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"anomaly":true}'})

        status, payload = asyncio.run(
            benchmark_rnf.post_asgi_json(app, b'{"probe":true}')
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["anomaly"])

    @unittest.skipIf(FastAPI is None, "FastAPI is unavailable")
    def test_asgi_transport_completes_a_synchronous_fastapi_route(self) -> None:
        app = FastAPI()

        @app.post("/ingest")
        def ingest(body: dict) -> dict:
            return {"anomaly": body["probe"]}

        status, payload = asyncio.run(
            benchmark_rnf.post_asgi_json(app, b'{"probe":true}')
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["anomaly"])

    def test_reports_preserve_measured_values_and_policy_counts(self) -> None:
        stats = benchmark_rnf.summarize_ns([1_000_000, 2_000_000])
        cases = [
            benchmark_rnf.ScenarioResult("active", stats, 2, 2, 0, (1_000_000, 2_000_000)),
            benchmark_rnf.ScenarioResult("degraded_link", stats, 2, 0, 2, (1_000_000, 2_000_000)),
            benchmark_rnf.ScenarioResult("informative_only", stats, 2, 0, 0, (1_000_000, 2_000_000)),
        ]
        environment = {
            "timestamp_utc": "2026-10-18T12:00:00+00:00",
            "requests_total": 6,
            "warmup_per_phase": 1,
            "probe_value_per_feature": 0.1,
            "probe_mse": 0.002,
            "python": "3.12",
            "fastapi": "0.1",
            "tensorflow": "2.1",
            "scikit_learn": "1.9",
            "platform": "test-platform",
            "processor": "test-cpu",
            "cpu_count": 1,
            "model_path": "model.h5",
            "scaler_path": "scaler.save",
        }
        with tempfile.TemporaryDirectory() as tmp:
            md_path, csv_path = benchmark_rnf.write_results(
                Path(tmp), stats, cases, environment
            )
            markdown = md_path.read_text(encoding="utf-8")
            csv_text = csv_path.read_text(encoding="utf-8")
        self.assertIn("0.0%", markdown)
        self.assertIn("100.0%", markdown)
        self.assertIn("degraded_link,2,", csv_text)
        self.assertIn("informative_only,2,", csv_text)
        self.assertIn("ingest_all_modes,6,", csv_text)


if __name__ == "__main__":
    unittest.main()
