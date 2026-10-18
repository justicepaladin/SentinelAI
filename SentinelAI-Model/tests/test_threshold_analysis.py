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
        self.assertLess(candidates["P99 recalculado"], candidates["P99.5"])
        self.assertLess(candidates["P99.5"], candidates["P99.9"])

    def test_strict_boundary_and_confusion_metrics(self) -> None:
        mse = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
        labels = np.array([0, 0, 0, 1, 1])
        counts = analysis.confusion_counts(mse, labels, 0.2)
        self.assertEqual(counts, (2, 1, 0, 2))
        metrics = analysis.classification_metrics(counts)
        self.assertAlmostEqual(metrics["fpr"], 1 / 3)
        self.assertAlmostEqual(metrics["f1"], 4 / 5)
        self.assertIsNone(analysis.classification_metrics((2, 0, 0, 0))["f1"])

    def test_report_calibrates_only_on_monday_and_counts_invalid_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cic_dir = root / "cic"
            cic_dir.mkdir()
            monday = cic_dir / "Monday-WorkingHours.csv"
            tuesday = cic_dir / "Tuesday-WorkingHours.csv"
            # MSE values are A² under the identity scaler and zero model.
            pd.DataFrame({
                "A": np.linspace(0.01, 0.20, 20),
                "Label": ["BENIGN"] * 20,
            }).to_csv(monday, index=False)
            pd.DataFrame({
                "A": [0.01, 0.1, 0.5, 0.7, float("inf")],
                "Label": ["BENIGN", "BENIGN", "DoS", "DoS", "BENIGN"],
            }).to_csv(tuesday, index=False)
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
            self.assertIn("2 benignos y 2 ataques válidos; 1 filas inválidas", content)
            self.assertIn("P99 desplegado", content)
            self.assertIn("P99 recalculado", content)
            self.assertIn("fuera de la calibración", content)
            expected = np.percentile(np.square(np.linspace(0.01, 0.20, 20)), 99)
            self.assertIn(f"{expected:.9g}", content)


if __name__ == "__main__":
    unittest.main()
