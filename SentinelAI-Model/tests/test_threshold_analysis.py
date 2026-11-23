"""Threshold calibration and held-out scoring with deterministic model doubles."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import threshold_analysis as analysis  # noqa: E402


class IdentityScaler:
    feature_names_in_ = np.array(["A"])
    n_features_in_ = 1

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        return frame.to_numpy()


class ZeroReconstructionModel:
    def predict(self, values: np.ndarray, **_: object) -> np.ndarray:
        return np.zeros_like(values)


class ThresholdAnalysisTests(unittest.TestCase):
    def test_right_skew_is_detected_and_candidate_percentiles_are_ordered(self) -> None:
        rng = np.random.default_rng(7)
        errors = rng.lognormal(mean=-10, sigma=1.4, size=5000)
        summary = analysis.describe_calibration(errors)
        candidates = dict(analysis.candidate_thresholds(errors))
        self.assertGreater(summary["skewness"], 1)
        self.assertGreater(summary["excess_kurtosis"], 0)
        self.assertLess(summary["normaltest_p"], 0.05)
        self.assertEqual(candidates["P99 desplegado"], 0.000308)
        levels = [80, 85, 90, 95, 97, 98, 99, 99.5, 99.9]
        values = [candidates["P99 recalculado" if p == 99 else f"P{p}"] for p in levels]
        self.assertEqual(values, sorted(values))
        np.testing.assert_allclose(values, np.percentile(errors, levels), rtol=1e-12)

    def test_critical_candidates_reuse_monday_thresholds(self) -> None:
        candidates = dict(analysis.candidate_thresholds(np.arange(1.0, 101.0)))
        critical = analysis.critical_thresholds(candidates)
        for name in ("P99.5", "P99.9", "μ + 3σ"):
            self.assertEqual(critical[name], candidates[name])
        for name in ("P90", "P95", "P97"):
            self.assertEqual(critical[f"3 × {name}"], 3 * candidates[name])

    def test_expected_precision_reweights_attacks_and_benign_flows(self) -> None:
        # Out of 10,000 flows at 1% prevalence: 80 TP and 99 FP.
        self.assertAlmostEqual(analysis.expected_precision(0.8, 0.01, 0.01), 80 / 179)
        self.assertEqual(analysis.expected_precision(0.8, 0.0, 0.001), 1.0)
        self.assertIsNone(analysis.expected_precision(0.0, 0.0, 0.1))

    def test_strict_boundary_and_confusion_metrics(self) -> None:
        mse = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
        labels = np.array([0, 0, 0, 1, 1])
        counts = analysis.confusion_counts(mse, labels, 0.2)
        self.assertEqual(counts, (2, 1, 0, 2))
        metrics = analysis.classification_metrics(counts)
        self.assertAlmostEqual(metrics["fpr"], 1 / 3)
        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertAlmostEqual(metrics["f1"], 4 / 5)
        self.assertIsNone(analysis.classification_metrics((2, 0, 0, 0))["f1"])
        self.assertEqual(analysis.confusion_counts(mse, labels, 0.2, inclusive=True),
                         (1, 2, 0, 2))

    def test_report_calibrates_only_on_monday_and_counts_invalid_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cic_dir = root / "cic"
            cic_dir.mkdir()
            monday = cic_dir / "Monday-WorkingHours.pcap_ISCX.csv"
            tuesday = cic_dir / "Tuesday-WorkingHours.pcap_ISCX.csv"
            # MSE values are A² under the identity scaler and zero model.
            pd.DataFrame({
                "A": [*range(1, 21), 999],
                "Label": ["BENIGN"] * 20 + ["Excluded attack"],
            }).to_csv(monday, index=False)
            pd.DataFrame({
                "A": [0, 19.25, 19, 19.5, 18, float("inf")],
                "Label": ["BENIGN", "BENIGN", "FTP-Patator", "SSH-Patator", "SSH-Patator", "BENIGN"],
            }).to_csv(tuesday, index=False)
            for name in (
                "Wednesday-workingHours", "Thursday-WorkingHours-Morning-WebAttacks",
                "Thursday-WorkingHours-Afternoon-Infilteration", "Friday-WorkingHours-Morning",
                "Friday-WorkingHours-Afternoon-PortScan", "Friday-WorkingHours-Afternoon-DDos",
            ):
                flows = {"A": [0], "Label": ["BENIGN"]}
                if name.endswith("PortScan"):
                    flows = {"A": [0, 31.75, 32], "Label": ["BENIGN", "BENIGN", "PortScan"]}
                pd.DataFrame(flows).to_csv(cic_dir / f"{name}.pcap_ISCX.csv", index=False)
            model_file = root / "model.h5"
            scaler_file = root / "scaler.save"
            model_file.write_bytes(b"fake model")
            scaler_file.write_bytes(b"fake scaler")
            report = root / "result.md"
            with patch.object(analysis, "load_assets", return_value=(
                ZeroReconstructionModel(), IdentityScaler(), ["A"]
            )):
                rc = analysis.main([
                    "--cic-dir", str(cic_dir), "--model", str(model_file),
                    "--scaler", str(scaler_file), "--output", str(report),
                    "--chunksize", "3", "--batch-size", "3",
                ])
            self.assertEqual(rc, 0)
            content = report.read_text(encoding="utf-8")
            self.assertIn("20 benignos válidos", content)
            self.assertIn("9 benignos", content)
            self.assertIn("4 ataques válidos", content)
            self.assertIn("filas inválidas descartadas fue 1", content)
            self.assertIn("P99 desplegado", content)
            self.assertIn("P99 recalculado", content)
            # Holdout labels and the Monday attack must never affect calibration.
            rows = [
                [cell.strip().strip("`") for cell in line.strip("|").split("|")]
                for line in content.splitlines() if line.startswith("|")
            ]
            expected_p90 = np.percentile(np.arange(1, 21) ** 2, 90)
            p90 = next(row for row in rows if row[0] == "P90" and len(row) == 10)
            self.assertAlmostEqual(float(p90[1]), expected_p90)
            self.assertEqual(p90[2:6], ["7", "2", "1", "3"])
            self.assertAlmostEqual(float(p90[8]), 22.22)
            critical = next(row for row in rows if row[0] == "3 × P90" and len(row) == 10)
            self.assertEqual(critical[2:6], ["8", "1", "3", "1"])
            family = next(row for row in rows if "SSH-Patator" in row)
            self.assertEqual(family[0], tuesday.name)
            self.assertEqual([float(value) for value in family[2:]], [2, 50, 50, 50, 0])
            projection = next(row for row in rows if row[:2] == ["Alerta", "P90"])
            observed = [float(value) for value in projection[2:]]
            expected = [
                100 * (3 / 4 * p) / (3 / 4 * p + 2 / 9 * (1 - p))
                for p in (0.242, 0.1, 0.01, 0.001)
            ]
            np.testing.assert_allclose(observed, expected, atol=0.005)


if __name__ == "__main__":
    unittest.main()
