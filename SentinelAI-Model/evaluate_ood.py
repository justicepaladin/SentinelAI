"""Evaluate SentinelAI's frozen autoencoder on unseen CIC days and external flows.

The saved scaler, model and threshold are never fitted or tuned here. In particular,
Monday CIC-IDS2017 was used to train the existing artifacts and is not a holdout.
Run ``python evaluate_ood.py --help`` for the command-line interface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support


HERE = Path(__file__).resolve().parent
# Snapshot of the deployed threshold in SentinelAI-Backend/main.py. It originated
# from the 99th percentile of Monday training errors in the original notebook.
DEPLOYED_THRESHOLD = 0.000308


@dataclass
class Result:
    dataset: str
    group: str
    source: str
    source_rows: int = 0
    sampled_rows: int = 0
    invalid_rows: int = 0
    evaluated_rows: int = 0
    mse_sum: float = 0.0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    tp: int = 0
    critical_fp: int = 0
    critical_tp: int = 0

    def add(self, other: Result) -> None:
        for field in (
            "source_rows", "sampled_rows", "invalid_rows", "evaluated_rows",
            "mse_sum", "tn", "fp", "fn", "tp", "critical_fp", "critical_tp",
        ):
            setattr(self, field, getattr(self, field) + getattr(other, field))

    def as_metrics(
        self, threshold: float, critical_threshold: float | None = None,
    ) -> dict[str, Any]:
        # Four weighted observations are enough to recover binary metrics without
        # retaining millions of flow-level predictions in memory.
        _, recall, f1, _ = precision_recall_fscore_support(
            [0, 0, 1, 1], [0, 1, 0, 1],
            sample_weight=[self.tn, self.fp, self.fn, self.tp],
            average="binary", zero_division=0,
        )
        precision = self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0
        attack_rows = self.fn + self.tp
        benign_rows = self.tn + self.fp
        metrics = {
            "dataset": self.dataset,
            "group": self.group,
            "source": self.source,
            "threshold_mse": threshold,
            "source_rows": self.source_rows,
            "sampled_rows": self.sampled_rows,
            "invalid_rows": self.invalid_rows,
            "evaluated_rows": self.evaluated_rows,
            "benign_rows": benign_rows,
            "attack_rows": attack_rows,
            "tn": self.tn, "fp": self.fp, "fn": self.fn, "tp": self.tp,
            "accuracy": (self.tn + self.tp) / self.evaluated_rows,
            "precision": precision,
            "recall": float(recall) if attack_rows else None,
            "f1": float(f1) if attack_rows else None,
            "false_positive_rate": self.fp / benign_rows if benign_rows else None,
            "mean_mse": self.mse_sum / self.evaluated_rows,
        }
        if critical_threshold is not None:
            metrics.update({
                "critical_threshold_mse": critical_threshold,
                "critical_tp": self.critical_tp,
                "critical_fp": self.critical_fp,
                "critical_recall": self.critical_tp / attack_rows if attack_rows else None,
                "critical_false_positive_rate": self.critical_fp / benign_rows if benign_rows else None,
                "alert_fp_escalation_rate": self.critical_fp / self.fp if self.fp else None,
            })
        return metrics


def load_assets(model_path: Path, scaler_path: Path) -> tuple[Any, Any, list[str]]:
    """Load the same artifacts used by the API, validating their feature contract."""
    if not model_path.is_file():
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not scaler_path.is_file():
        raise FileNotFoundError(f"Scaler not found: {scaler_path}")

    from tensorflow.keras.models import load_model  # Imported only for a real run.

    scaler = joblib.load(scaler_path)
    model = load_model(model_path, compile=False)
    names = getattr(scaler, "feature_names_in_", None)
    if names is None:
        raise ValueError("The saved scaler has no feature_names_in_; column alignment cannot be verified")
    features = [str(name).strip() for name in names]
    if len(features) != len(set(features)):
        raise ValueError("The saved scaler contains duplicate feature names")
    width = len(features)
    if width != int(scaler.n_features_in_):
        raise ValueError("Scaler feature names and n_features_in_ disagree")
    if model.input_shape[-1] != width or model.output_shape[-1] != width:
        raise ValueError(
            f"Model/scaler width mismatch: model {model.input_shape} -> "
            f"{model.output_shape}, scaler {width}"
        )
    return model, scaler, features


def load_feature_map(path: Path | None, expected: list[str]) -> dict[str, str] | None:
    """A mapping names every CIC feature and its equivalent external CSV column."""
    if path is None:
        return None
    mapping = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(mapping, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in mapping.items()
    ):
        raise ValueError("Feature map must be a JSON object of CIC feature to CSV column")
    missing = sorted(set(expected) - set(mapping))
    extra = sorted(set(mapping) - set(expected))
    if missing or extra:
        raise ValueError(
            f"Feature map must cover exactly {len(expected)} scaler features; "
            f"missing={missing[:8]}, extra={extra[:8]}"
        )
    mapping = {key: value.strip() for key, value in mapping.items()}
    if not all(mapping.values()) or len(set(mapping.values())) != len(mapping):
        raise ValueError("Feature map contains empty or duplicate source columns")
    return mapping


def feature_sources(
    columns: list[str], expected: list[str], mapping: dict[str, str] | None,
    *, external: bool,
) -> list[str]:
    if len(columns) != len(set(columns)):
        raise ValueError("Duplicate CSV columns after stripping whitespace")
    sources = [mapping[name] if mapping is not None else name for name in expected]
    missing = [name for name in sources if name not in columns]
    if missing:
        qualifier = (
            "Raw UNSW-NB15 and CIC-IDS2017 use incompatible feature schemas. "
            "Re-extract external flows with the same 78 feature definitions or "
            "provide a complete --external-feature-map; do not fill missing "
            "features with zeros. "
        ) if external else ""
        raise ValueError(
            f"{qualifier}Missing {len(missing)} of {len(expected)} required "
            f"columns: {missing[:10]}"
        )
    return sources


def parse_labels(labels: pd.Series, *, external: bool) -> tuple[np.ndarray, np.ndarray]:
    """CIC: BENIGN vs named attacks. External: UNSW's binary label 0/1."""
    normalized = labels.astype("string").str.strip()
    valid = normalized.notna() & normalized.ne("")
    if external:
        binary = pd.to_numeric(normalized, errors="coerce")
        unexpected = sorted(set(normalized[valid & ~binary.isin([0, 1])].unique()))
        if unexpected:
            raise ValueError(
                "External labels must be binary 0=benign, 1=attack in the "
                f"'label' column; unexpected values: {unexpected[:8]}"
            )
        y = binary.eq(1).fillna(False).to_numpy(dtype=np.int8)
    else:
        y = normalized.str.upper().ne("BENIGN").fillna(False).to_numpy(dtype=np.int8)
    return y, valid.to_numpy(dtype=bool)


def evaluate_file(
    path: Path,
    *,
    model: Any,
    scaler: Any,
    expected: list[str],
    threshold: float,
    critical_threshold: float | None = None,
    chunksize: int,
    batch_size: int,
    sample_fraction: float,
    seed: int,
    external: bool,
    feature_map: dict[str, str] | None = None,
    external_label: str = "label",
    group: str | None = None,
) -> Result:
    kind = group or ("external" if external else "cic_holdout")
    result = Result(dataset=f"{kind}:{path.name}", group=kind, source=str(path))
    stable_seed = int.from_bytes(hashlib.sha256(str(path).encode()).digest()[:8], "little")
    rng = np.random.default_rng(seed ^ stable_seed)
    schema_checked = False
    sources: list[str] = []
    label_column = external_label if external else "Label"

    with pd.read_csv(path, chunksize=chunksize, low_memory=False) as reader:
        for chunk in reader:
            result.source_rows += len(chunk)
            chunk.columns = [str(column).strip() for column in chunk.columns]
            if not schema_checked:
                sources = feature_sources(
                    chunk.columns.tolist(), expected, feature_map, external=external
                )
                if label_column not in chunk.columns:
                    raise ValueError(f"Missing label column {label_column!r} in {path}")
                if label_column in sources:
                    raise ValueError("The label column appears in the model features")
                schema_checked = True

            if sample_fraction < 1:
                chunk = chunk.loc[rng.random(len(chunk)) < sample_fraction]
            result.sampled_rows += len(chunk)
            if chunk.empty:
                continue

            y, valid_label = parse_labels(chunk[label_column], external=external)
            numeric = chunk[sources].apply(pd.to_numeric, errors="coerce")
            numeric.columns = expected
            values = numeric.to_numpy(dtype=np.float64)
            finite = np.isfinite(values).all(axis=1)
            valid = finite & valid_label
            result.invalid_rows += int((~valid).sum())
            if not valid.any():
                continue

            features = numeric.loc[valid]
            scaled = np.asarray(scaler.transform(features), dtype=np.float32)
            reconstruction = np.asarray(
                model.predict(scaled, batch_size=batch_size, verbose=0), dtype=np.float32
            )
            if reconstruction.shape != scaled.shape or not np.isfinite(reconstruction).all():
                raise ValueError(f"Model output is invalid for {path}")
            # Compare the model's float32 MSE to full-precision Monday percentiles.
            mse = np.mean(np.square(scaled - reconstruction), axis=1).astype(np.float64)
            if not np.isfinite(mse).all():
                raise ValueError(f"Non-finite MSE for {path}")
            actual = y[valid]
            predicted = (mse > threshold).astype(np.int8)
            tn, fp, fn, tp = confusion_matrix(
                actual, predicted, labels=[0, 1]
            ).ravel()
            result.tn += int(tn)
            result.fp += int(fp)
            result.fn += int(fn)
            result.tp += int(tp)
            if critical_threshold is not None:
                # The backend alerts strictly above the alert threshold and
                # treats equality with the higher critical threshold as critical.
                blocked_labels = actual[mse >= critical_threshold]
                critical_tp = int(np.count_nonzero(blocked_labels))
                result.critical_tp += critical_tp
                result.critical_fp += len(blocked_labels) - critical_tp
            result.evaluated_rows += len(actual)
            result.mse_sum += float(mse.sum(dtype=np.float64))

    if not schema_checked:
        raise ValueError(f"CSV has no data rows: {path}")
    if result.evaluated_rows == 0:
        raise ValueError(f"No valid evaluated rows in {path}; check sampling and CSV quality")
    return result


def aggregate(results: list[Result], dataset: str, group: str) -> Result:
    merged = Result(dataset=dataset, group=group, source="multiple CSV files")
    for result in results:
        merged.add(result)
    return merged


def print_blocking_summary(result: Result, critical_threshold: float) -> None:
    print(f"{result.dataset} | simulated blocks at MSE >= {critical_threshold:.12g}")
    for description, count, total in (
        ("Attacks blocked / all attacks", result.critical_tp, result.tp + result.fn),
        ("Benign flows blocked / all benign flows (FPR)", result.critical_fp, result.fp + result.tn),
        ("False alerts escalated to a block / all false alerts", result.critical_fp, result.fp),
    ):
        rate = f"{count / total:.4%}" if total else "undefined"
        print(f"  {description}: {count:,}/{total:,} ({rate})")


def save_results(
    results: list[Result], output_dir: Path, *, threshold: float,
    args: argparse.Namespace, features: list[str],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics = [result.as_metrics(threshold, args.critical_threshold) for result in results]
    pd.DataFrame(metrics).to_csv(output_dir / "metrics.csv", index=False)
    matrix_rows = []
    for result in results:
        for actual, predicted, count in (
            ("benign", "benign", result.tn),
            ("benign", "attack", result.fp),
            ("attack", "benign", result.fn),
            ("attack", "attack", result.tp),
        ):
            matrix_rows.append({
                "dataset": result.dataset, "group": result.group,
                "actual": actual, "predicted": predicted, "count": count,
            })
    pd.DataFrame(matrix_rows).to_csv(output_dir / "confusion_matrices.csv", index=False)

    # The PNG is a presentation aid; the CSV is the exact machine-readable matrix.
    plot_written = False
    try:
        os.environ.setdefault("MPLCONFIGDIR", str(output_dir / ".matplotlib"))
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        if args.plot_path is not None:
            raise RuntimeError("Generating the requested --plot-path requires matplotlib")
        print("matplotlib is unavailable; CSV matrices saved, PNG skipped")
    else:
        columns = min(3, len(results))
        rows = math.ceil(len(results) / columns)
        fig, axes = plt.subplots(rows, columns, figsize=(5 * columns, 4 * rows), squeeze=False)
        for ax, result in zip(axes.flat, results):
            matrix = np.array([[result.tn, result.fp], [result.fn, result.tp]])
            ax.imshow(matrix, cmap="Blues")
            ax.set_title(result.dataset.replace(":", ":\n"), fontsize=9)
            ax.set_xticks([0, 1], ["Benign", "Attack"])
            ax.set_yticks([0, 1], ["Benign", "Attack"])
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            for (row, col), count in np.ndenumerate(matrix):
                ax.text(col, row, f"{count:,}", ha="center", va="center",
                        color="white" if count > matrix.max() / 2 else "black")
        for ax in list(axes.flat)[len(results):]:
            ax.axis("off")
        fig.suptitle(f"Frozen SentinelAI autoencoder | MSE > {threshold:.6g}")
        fig.tight_layout()
        plot_path = args.plot_path or output_dir / "confusion_matrices.png"
        plot_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(plot_path, dpi=160)
        plt.close(fig)
        plot_written = True

    metadata = {
        "model": str(args.model.resolve()),
        "scaler": str(args.scaler.resolve()),
        "threshold_mse": threshold,
        "threshold_provenance": (
            "Pre-existing deployed threshold; original notebook derived it from "
            "Monday training reconstruction errors. Never tuned on evaluated days."
            if threshold == DEPLOYED_THRESHOLD
            else "Alert threshold supplied via --threshold."
        ),
        "feature_count": len(features),
        "feature_names": features,
        "cic_training_day_excluded_from_holdout": True,
        "included_training_day_is_contaminated_reference": args.include_training_day,
        "external_evaluated": bool(args.external_csv),
        "comparison_png_written": plot_written,
        "sample_fraction": args.sample_fraction,
        "seed": args.seed,
        "limitations": [
            "Monday was used to fit both the current scaler and autoencoder; "
            "its optional metrics are not a holdout.",
            "Raw tabular UNSW-NB15 columns are not interchangeable with the "
            "78 CIC-IDS2017 flow features. External evaluation requires "
            "equivalent feature extraction and verified labels.",
            "The deployed threshold came from training errors; a future retraining "
            "run should reserve disjoint benign calibration data.",
        ],
    }
    if args.critical_threshold is not None:
        metadata["critical_threshold_mse"] = args.critical_threshold
    if args.plot_path is not None:
        metadata["comparison_png_path"] = str(args.plot_path.resolve())
        print(f"Wrote alert confusion matrices PNG to {args.plot_path.resolve()}")
    (output_dir / "evaluation.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def fraction(value: str) -> float:
    number = float(value)
    if not 0 < number <= 1 or not math.isfinite(number):
        raise argparse.ArgumentTypeError("must be finite and in (0, 1]")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cic-dir", type=Path, default=HERE / "data")
    parser.add_argument("--cic-pattern", default="*.csv",
                        help="Glob for CIC day CSVs inside --cic-dir")
    parser.add_argument("--external-csv", type=Path, action="append", default=[],
                        help="UNSW or other external CSV re-extracted to CIC features; repeatable")
    parser.add_argument("--external-label", default="label",
                        help="Binary external label column (0=benign, 1=attack)")
    parser.add_argument("--external-feature-map", type=Path,
                        help="JSON mapping all scaler features to equivalent external columns")
    parser.add_argument("--model", type=Path, default=HERE / "models/sentinel_model.h5")
    parser.add_argument("--scaler", type=Path, default=HERE / "models/sentinel_scaler.save")
    parser.add_argument("--threshold", type=float, default=DEPLOYED_THRESHOLD,
                        help="Alert when MSE exceeds this threshold (default: deployed 0.000308)")
    parser.add_argument("--critical-threshold", type=float,
                        help="Report simulated blocks at or above this MSE (must be > --threshold)")
    parser.add_argument("--output-dir", type=Path, default=HERE / "reports/ood")
    parser.add_argument("--plot-path", type=Path,
                        help="Destination of the alert confusion matrices PNG (default: in --output-dir)")
    parser.add_argument("--chunksize", type=positive_int, default=8192)
    parser.add_argument("--batch-size", type=positive_int, default=1024)
    parser.add_argument("--sample-fraction", type=fraction, default=1.0,
                        help="Reproducible Bernoulli sample per file for quick exploratory runs")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--include-training-day", action="store_true",
                        help="Show Monday as contaminated training reference, outside holdout aggregate")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not math.isfinite(args.threshold) or args.threshold < 0:
        raise ValueError("--threshold must be a finite non-negative MSE")
    if args.critical_threshold is not None and (
        not math.isfinite(args.critical_threshold) or args.critical_threshold <= args.threshold
    ):
        raise ValueError("--critical-threshold must be finite and > --threshold")
    if args.external_feature_map and not args.external_csv:
        raise ValueError("--external-feature-map requires --external-csv")
    days = sorted(args.cic_dir.glob(args.cic_pattern))
    if not days:
        raise FileNotFoundError(f"No CIC CSV files match {args.cic_dir / args.cic_pattern}")
    if any(not path.is_file() for path in days):
        raise ValueError("--cic-pattern must match only CSV files")
    if any(not path.is_file() for path in args.external_csv):
        raise FileNotFoundError("An --external-csv file does not exist")

    model, scaler, features = load_assets(args.model, args.scaler)
    feature_map = load_feature_map(args.external_feature_map, features)
    # Fail immediately on the common raw UNSW schema mismatch, before spending
    # time inferring over all of the large CIC-IDS2017 files.
    for path in args.external_csv:
        columns = [str(name).strip() for name in pd.read_csv(path, nrows=0).columns]
        sources = feature_sources(columns, features, feature_map, external=True)
        if args.external_label not in columns:
            raise ValueError(f"Missing external label column {args.external_label!r} in {path}")
        if args.external_label in sources:
            raise ValueError("The external label column appears in the model features")
    holdout: list[Result] = []
    training_reference: list[Result] = []
    for path in days:
        monday = path.name.lower().startswith("monday")
        if monday and not args.include_training_day:
            print(f"Skipping {path.name}: used to fit the saved model and scaler")
            continue
        group = "cic_training_reference" if monday else "cic_holdout"
        result = evaluate_file(
            path, model=model, scaler=scaler, expected=features,
            threshold=args.threshold, critical_threshold=args.critical_threshold,
            chunksize=args.chunksize,
            batch_size=args.batch_size, sample_fraction=args.sample_fraction,
            seed=args.seed, external=False, group=group,
        )
        print(f"{result.dataset}: {result.as_metrics(args.threshold, args.critical_threshold)}")
        (training_reference if monday else holdout).append(result)
    if not holdout:
        raise ValueError("No held-out CIC day found; Monday alone cannot validate this model")

    external_results = []
    for path in args.external_csv:
        result = evaluate_file(
            path, model=model, scaler=scaler, expected=features,
            threshold=args.threshold, critical_threshold=args.critical_threshold,
            chunksize=args.chunksize,
            batch_size=args.batch_size, sample_fraction=args.sample_fraction,
            seed=args.seed, external=True, feature_map=feature_map,
            external_label=args.external_label,
        )
        print(f"{result.dataset}: {result.as_metrics(args.threshold, args.critical_threshold)}")
        external_results.append(result)

    holdout_total = aggregate(holdout, "CIC held-out aggregate", "cic_holdout")
    results = [holdout_total, *holdout, *training_reference]
    if args.critical_threshold is not None:
        print_blocking_summary(holdout_total, args.critical_threshold)
    if external_results:
        external_total = aggregate(external_results, "External aggregate", "external")
        results += [external_total, *external_results]
        if args.critical_threshold is not None:
            print_blocking_summary(external_total, args.critical_threshold)
    else:
        print("No external CSV supplied: OOD performance is not evaluated.")
    save_results(results, args.output_dir, threshold=args.threshold, args=args, features=features)
    print(f"Wrote comparative metrics and confusion matrices to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
