"""Small end-to-end checks with a deterministic stand-in autoencoder."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib.util import find_spec
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evaluate_ood  # noqa: E402


class ZeroReconstructionModel:
    def predict(self, values: np.ndarray, **_: object) -> np.ndarray:
        return np.zeros_like(values)


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cic = self.root / "cic"
        self.cic.mkdir()
        self.scaler = MinMaxScaler().fit(
            pd.DataFrame([[0, 0], [1, 1]], columns=["A", "B"])
        )
        self.model = ZeroReconstructionModel()

    def test_main_keeps_monday_out_of_holdout_and_writes_comparison(self) -> None:
        pd.DataFrame({"A": [0], "B": [0], "Label": ["BENIGN"]}).to_csv(
            self.cic / "Monday-WorkingHours.csv", index=False
        )
        pd.DataFrame({
            "A": [0, 1, 0, 1, float("inf")],
            "B": [0, 1, 0, 1, 0],
            "Label": ["BENIGN", "DoS", "DDoS", "BENIGN", "BENIGN"],
        }).to_csv(self.cic / "Tuesday-WorkingHours.csv", index=False)
        external = self.root / "unsw_equivalent.csv"
        pd.DataFrame({"A": [0, 1], "B": [0, 1], "label": [0.0, 1.0]}).to_csv(
            external, index=False
        )
        output = self.root / "output"
        with patch.object(
            evaluate_ood, "load_assets",
            return_value=(self.model, self.scaler, ["A", "B"]),
        ):
            self.assertEqual(evaluate_ood.main([
                "--cic-dir", str(self.cic),
                "--external-csv", str(external),
                "--output-dir", str(output),
                "--chunksize", "2",
            ]), 0)

        metrics = pd.read_csv(output / "metrics.csv").set_index("dataset")
        holdout = metrics.loc["CIC held-out aggregate"]
        self.assertEqual((holdout.tn, holdout.fp, holdout.fn, holdout.tp),
                         (1, 1, 1, 1))
        self.assertEqual(holdout.invalid_rows, 1)
        self.assertFalse(any("Monday" in name for name in metrics.index))
        self.assertEqual(metrics.loc["External aggregate", "tp"], 1)
        self.assertEqual(len(pd.read_csv(output / "confusion_matrices.csv")), 16)
        self.assertTrue((output / "evaluation.json").is_file())
        metadata = json.loads((output / "evaluation.json").read_text())
        self.assertEqual(metadata["threshold_mse"], evaluate_ood.DEPLOYED_THRESHOLD)
        self.assertNotIn("critical_fp", metrics.columns)
        self.assertEqual(
            metadata["comparison_png_written"],
            (output / "confusion_matrices.png").is_file(),
        )

    def test_two_thresholds_use_alert_for_matrix_and_critical_for_blocking(self) -> None:
        # With equal A/B coordinates, the MSE is A². Values of 0.25 and 0.5
        # land exactly on the alert and critical boundaries, respectively.
        for day, levels, labels in (
            ("Tuesday", [0, 0.25, 0.375, 0.5, 0.25], ["BENIGN"] * 4 + ["DoS"]),
            ("Wednesday", [1, 0.5, 1, 0.375], ["BENIGN"] + ["DDoS"] * 3),
        ):
            pd.DataFrame({"A": levels, "B": levels, "Label": labels}).to_csv(
                self.cic / f"{day}-WorkingHours.csv", index=False
            )
        output = self.root / "reports"
        plot = self.root / "docs" / "confusion_matrices.png"
        plot_args = ["--plot-path", str(plot)] if find_spec("matplotlib") else []
        summary = StringIO()
        with patch.object(
            evaluate_ood, "load_assets",
            return_value=(self.model, self.scaler, ["A", "B"]),
        ), redirect_stdout(summary):
            self.assertEqual(evaluate_ood.main([
                "--cic-dir", str(self.cic), "--output-dir", str(output),
                "--threshold", "0.0625", "--critical-threshold", "0.25",
                "--chunksize", "2", *plot_args,
            ]), 0)

        dataset = "CIC held-out aggregate"
        metrics = pd.read_csv(output / "metrics.csv").set_index("dataset").loc[dataset]
        self.assertEqual(metrics.threshold_mse, 0.0625)
        self.assertEqual(metrics.critical_threshold_mse, 0.25)
        self.assertEqual((metrics.critical_tp, metrics.critical_fp), (2, 2))
        self.assertAlmostEqual(metrics.critical_recall, 1 / 2)
        self.assertAlmostEqual(metrics.critical_false_positive_rate, 2 / 5)
        self.assertAlmostEqual(metrics.alert_fp_escalation_rate, 2 / 3)
        for pattern in (r"50(?:\.0+)?%", r"40(?:\.0+)?%", r"66\.6[67]\d*%"):
            self.assertRegex(summary.getvalue(), pattern)

        matrices = pd.read_csv(output / "confusion_matrices.csv")
        matrix = matrices[matrices.dataset == dataset].set_index(["actual", "predicted"])
        self.assertEqual(matrix["count"].to_dict(), {
            ("benign", "benign"): 2, ("benign", "attack"): 3,
            ("attack", "benign"): 1, ("attack", "attack"): 3,
        })
        self.assertEqual(
            json.loads((output / "evaluation.json").read_text())["critical_threshold_mse"],
            0.25,
        )
        if plot_args:
            self.assertTrue(plot.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))

    def test_rejects_nonfinite_or_non_increasing_critical_threshold(self) -> None:
        for value in ("nan", "inf", "-1", "0.125", "0.25"):
            with self.subTest(critical=value), self.assertRaisesRegex(ValueError, "critical"):
                evaluate_ood.main([
                    "--cic-dir", str(self.cic), "--threshold", "0.25",
                    "--critical-threshold", value,
                ])

    def test_interpolated_thresholds_retain_precision_when_compared_to_mse(self) -> None:
        path = self.cic / "Tuesday-WorkingHours.csv"
        pd.DataFrame({
            "A": [0.25, 0.5], "B": [0.25, 0.5], "Label": ["BENIGN", "DoS"],
        }).to_csv(path, index=False)
        # Interpolated cutoffs can be closer to an observed MSE than a float32 step.
        result = evaluate_ood.evaluate_file(
            path, model=self.model, scaler=self.scaler, expected=["A", "B"],
            threshold=float(np.nextafter(0.0625, 0)),
            critical_threshold=float(np.nextafter(0.25, 1)),
            chunksize=2, batch_size=2, sample_fraction=1, seed=42, external=False,
        )
        self.assertEqual((result.fp, result.tp), (1, 1))
        self.assertEqual((result.critical_fp, result.critical_tp), (0, 0))

    def test_rejects_raw_unsw_schema_instead_of_imputing_missing_features(self) -> None:
        raw_unsw = self.root / "unsw_raw.csv"
        pd.DataFrame({"dur": [1], "proto": ["tcp"], "label": [1]}).to_csv(
            raw_unsw, index=False
        )
        with self.assertRaisesRegex(ValueError, "incompatible feature schemas"):
            evaluate_ood.evaluate_file(
                raw_unsw, model=self.model, scaler=self.scaler,
                expected=["A", "B"], threshold=0.5, chunksize=2,
                batch_size=2, sample_fraction=1.0, seed=42, external=True,
            )

    def test_f1_is_undefined_when_a_sample_has_no_attacks(self) -> None:
        result = evaluate_ood.Result(
            dataset="benign-only", group="cic_holdout", source="test",
            evaluated_rows=3, tn=2, fp=1,
        )
        metrics = result.as_metrics(0.5)
        self.assertIsNone(metrics["recall"])
        self.assertIsNone(metrics["f1"])
        self.assertEqual(metrics["false_positive_rate"], 1 / 3)

    def test_complete_external_map_aligns_named_features(self) -> None:
        external = self.root / "mapped.csv"
        pd.DataFrame({
            "b_ext": [0, 1], "label": [0, 1], "a_ext": [0, 1],
        }).to_csv(external, index=False)
        mapping_file = self.root / "mapping.json"
        mapping_file.write_text('{"A": "a_ext", "B": "b_ext"}')
        mapping = evaluate_ood.load_feature_map(mapping_file, ["A", "B"])
        result = evaluate_ood.evaluate_file(
            external, model=self.model, scaler=self.scaler,
            expected=["A", "B"], threshold=0.5, chunksize=1,
            batch_size=2, sample_fraction=1.0, seed=42, external=True,
            feature_map=mapping,
        )
        self.assertEqual((result.tn, result.tp, result.fp, result.fn),
                         (1, 1, 0, 0))


if __name__ == "__main__":
    unittest.main()
