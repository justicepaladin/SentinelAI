"""Pruebas del envío desde memoria y de la autenticación del sensor."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import demo_replay
import integracion_sensor as edge


class FakeResponse:
    status_code = 200
    text = ""

    def json(self):
        return {"mse_score": 0.0, "anomaly": False}


class FakeSession:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


class EdgePipelineTests(unittest.TestCase):
    def test_live_generator_sends_without_touching_disk(self):
        session = FakeSession()

        def captured_flows():
            yield {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.10",
                "destination_port": 443,
                "features": {"Flow Duration": 12, "Label": "BENIGN"},
            }
            yield {
                "Src IP": "192.0.2.11",
                "Dst IP": "198.51.100.10",
                "Dst Port": 443,
                "Flow Duration": 15,
                "Label": "DoS",
            }

        with patch("builtins.open", side_effect=AssertionError("disk I/O")), redirect_stdout(io.StringIO()):
            sent = edge.send_flows(
                captured_flows(),
                session=session,
                api_url="https://example.test/ingest",
                token="sensor-secret",
            )

        self.assertEqual(sent, 2)
        self.assertEqual(len(session.calls), 2)
        self.assertTrue(all(call[1]["headers"] == {"Authorization": "Bearer sensor-secret"} for call in session.calls))
        self.assertNotIn("Label", session.calls[0][1]["json"]["features"])
        self.assertNotIn("Label", session.calls[1][1]["json"]["features"])
        self.assertEqual(session.calls[1][1]["json"]["features"]["Flow Duration"], 15)

    def test_missing_token_rejects_before_consuming_flows(self):
        def captured_flows():
            raise AssertionError("El generador no debe consumirse")
            yield {}

        with patch.dict("os.environ", {"SENTINEL_SENSOR_TOKEN": ""}):
            with self.assertRaisesRegex(ValueError, "SENTINEL_SENSOR_TOKEN"):
                edge.send_flows(
                    captured_flows(), session=FakeSession(), api_url="https://example.test/ingest"
                )

    def test_link_health_is_metadata_not_a_model_feature(self):
        payload = edge.flow_payload({
            "Src IP": "10.0.0.8", "Dst IP": "10.0.0.9", "Dst Port": 443,
            "Flow Duration": 15, "link_degraded": True,
        })
        self.assertTrue(payload["link_degraded"])
        self.assertNotIn("link_degraded", payload["features"])
        with self.assertRaisesRegex(ValueError, "link_degraded"):
            edge.flow_payload({"features": [1.0], "link_degraded": "true"})

    def test_csv_replay_reads_source_once_in_chunks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "flows.csv"
            source.write_text("Src IP,Flow Duration,Label\n192.0.2.10,12,BENIGN\n192.0.2.11,15,DoS\n")
            with patch.object(pd, "read_csv", wraps=pd.read_csv) as read_csv:
                flows = list(edge.iter_csv_flows(source, chunk_size=1))

        read_csv.assert_called_once_with(source, chunksize=1)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[1]["Flow Duration"], 15)

    def test_demo_replay_attaches_bearer_token(self):
        dataframe = pd.DataFrame(
            {
                "Label": ["BENIGN"] * 80 + ["DoS Hulk"] * 20,
                "Flow Duration": [1] * 100,
            }
        )
        session = FakeSession()
        with patch.dict("os.environ", {"SENTINEL_SENSOR_TOKEN": "sensor-secret"}), patch.object(
            demo_replay.pd, "read_csv", return_value=dataframe
        ), patch.object(demo_replay.requests, "Session", return_value=session), patch.object(
            demo_replay.time, "sleep"
        ), redirect_stdout(io.StringIO()):
            demo_replay.main()

        self.assertEqual(len(session.calls), 100)
        self.assertTrue(all(call[1]["headers"] == {"Authorization": "Bearer sensor-secret"} for call in session.calls))
        self.assertTrue(all("Label" not in call[1]["json"]["features"] for call in session.calls))


if __name__ == "__main__":
    unittest.main()
