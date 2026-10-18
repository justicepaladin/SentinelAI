"""Compare normal-theory and empirical MSE thresholds without test-set leakage.

The frozen model and scaler reconstruct benign Monday CIC-IDS2017 flows to
calibrate candidate thresholds. Tuesday--Friday are used only to measure FPR
and F1. Monday is *not* an independent calibration set for these artifacts:
it was used to fit both of them in the original notebook. Run ``--help`` for
the reproducible command and sampling options.
"""

from __future__ import annotations

import argparse
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pandas as pd
from scipy import stats

from evaluate_ood import DEPLOYED_THRESHOLD, feature_sources, load_assets, parse_labels


HERE = Path(__file__).resolve().parent
DEFAULT_REPORT = HERE.parent / "docs" / "threshold_justification.md"


@dataclass
class FileCounts:
    source_rows: int = 0
    sampled_rows: int = 0
    invalid_rows: int = 0
    evaluated_rows: int = 0
    benign_rows: int = 0
    attack_rows: int = 0

    def add(self, other: FileCounts) -> None:
        for field in self.__dataclass_fields__:
            setattr(self, field, getattr(self, field) + getattr(other, field))


def _file_seed(path: Path, seed: int) -> int:
    return seed ^ int.from_bytes(
        hashlib.sha256(path.name.encode("utf-8")).digest()[:8], "little"
    )


def iter_reconstruction_errors(
    path: Path, *, model: Any, scaler: Any, features: list[str],
    chunksize: int, batch_size: int, sample_fraction: float, seed: int,
    counts: FileCounts,
) -> Iterator[tuple[np.ndarray, np.ndarray]]:
    """Yield (MSE, attack label) using the same preprocessing as evaluate_ood."""
    rng = np.random.default_rng(_file_seed(path, seed))
    schema_checked = False
    with pd.read_csv(path, chunksize=chunksize, low_memory=False) as reader:
        for chunk in reader:
            counts.source_rows += len(chunk)
            chunk.columns = [str(column).strip() for column in chunk.columns]
            if not schema_checked:
                feature_sources(chunk.columns.tolist(), features, None, external=False)
                if "Label" not in chunk.columns:
                    raise ValueError(f"Missing Label column in {path}")
                schema_checked = True
            if sample_fraction < 1:
                chunk = chunk.loc[rng.random(len(chunk)) < sample_fraction]
            counts.sampled_rows += len(chunk)
            if chunk.empty:
                continue

            y, valid_label = parse_labels(chunk["Label"], external=False)
            numeric = chunk[features].apply(pd.to_numeric, errors="coerce")
            values = numeric.to_numpy(dtype=np.float64)
            valid = valid_label & np.isfinite(values).all(axis=1)
            counts.invalid_rows += int((~valid).sum())
            if not valid.any():
                continue

            scaled = np.asarray(scaler.transform(numeric.loc[valid]), dtype=np.float32)
            reconstructed = np.asarray(
                model.predict(scaled, batch_size=batch_size, verbose=0), dtype=np.float32
            )
            if reconstructed.shape != scaled.shape or not np.isfinite(reconstructed).all():
                raise ValueError(f"Invalid autoencoder output for {path}")
            mse = np.mean(np.square(scaled - reconstructed), axis=1)
            if not np.isfinite(mse).all() or (mse < 0).any():
                raise ValueError(f"Invalid MSE for {path}")
            labels = y[valid]
            counts.evaluated_rows += len(mse)
            counts.benign_rows += int((labels == 0).sum())
            counts.attack_rows += int((labels == 1).sum())
            yield mse.astype(np.float64), labels


def describe_calibration(benign_mse: np.ndarray) -> dict[str, float]:
    """D'Agostino-Pearson K² plus skewness and excess kurtosis."""
    errors = np.asarray(benign_mse, dtype=np.float64)
    if errors.ndim != 1 or len(errors) < 8 or not np.isfinite(errors).all() or (errors < 0).any():
        raise ValueError("At least 8 finite, non-negative benign MSE values are required")
    if np.std(errors) == 0:
        raise ValueError("A constant MSE distribution cannot be tested for normality")
    k2, p = stats.normaltest(errors)
    return {
        "n": len(errors),
        "mean": float(np.mean(errors)),
        "std_population": float(np.std(errors, ddof=0)),
        "skewness": float(stats.skew(errors, bias=False)),
        "excess_kurtosis": float(stats.kurtosis(errors, fisher=True, bias=False)),
        "normaltest_k2": float(k2),
        "normaltest_p": float(p),
    }


def candidate_thresholds(benign_mse: np.ndarray) -> list[tuple[str, float]]:
    """Calibrate alternatives from Monday only; keep deployed tau frozen."""
    summary = describe_calibration(benign_mse)
    return [
        ("μ + 3σ", summary["mean"] + 3 * summary["std_population"]),
        ("P99 desplegado", DEPLOYED_THRESHOLD),
        ("P99 recalculado", float(np.percentile(benign_mse, 99, method="linear"))),
        ("P99.5", float(np.percentile(benign_mse, 99.5, method="linear"))),
        ("P99.9", float(np.percentile(benign_mse, 99.9, method="linear"))),
    ]


def confusion_counts(mse: np.ndarray, labels: np.ndarray, threshold: float) -> tuple[int, int, int, int]:
    """Return TN, FP, FN, TP; anomaly is strictly MSE > threshold."""
    predicted = mse > threshold
    attack = labels == 1
    return (
        int((~attack & ~predicted).sum()),
        int((~attack & predicted).sum()),
        int((attack & ~predicted).sum()),
        int((attack & predicted).sum()),
    )


def classification_metrics(counts: tuple[int, int, int, int]) -> dict[str, float | int | None]:
    tn, fp, fn, tp = counts
    return {
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "fpr": fp / (tn + fp) if tn + fp else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fn else None,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fmt_p(p: float) -> str:
    return "< 1e-300" if p == 0 else f"{p:.3e}"


def _fmt_metric(value: float | None) -> str:
    return "N/D" if value is None else f"{value:.4f}"


def render_report(
    *, calibration: dict[str, float], rows: list[dict[str, Any]],
    monday: Path, holdouts: list[Path], calibration_counts: FileCounts,
    evaluation_counts: FileCounts, model_path: Path, scaler_path: Path,
    calibration_fraction: float, evaluation_fraction: float, seed: int,
) -> str:
    reject = calibration["normaltest_p"] < 0.05
    lines = [
        "# Justificación estadística del umbral de MSE",
        "",
        "## Diseño y procedencia",
        "",
        "Se reconstruyeron los flujos CIC-IDS2017 con el autoencoder y el scaler "
        "congelados del proyecto. Los candidatos μ + 3σ, P99, P99.5 y P99.9 "
        "se calcularon **solo** con flujos benignos del lunes. El umbral "
        "desplegado `τ = 0.000308` se mantuvo fijo; se muestra aparte del P99 "
        "recalculado para verificar el redondeo y la reproducibilidad. "
        "FPR y F1 se midieron en los archivos de martes a viernes, sin escoger "
        "el umbral mirando esas etiquetas.",
        "",
        f"- Calibración: `{monday.name}`; {calibration_counts.benign_rows:,} "
        f"benignos válidos, {calibration_counts.attack_rows:,} ataques excluidos, "
        f"{calibration_counts.invalid_rows:,} filas inválidas.",
        f"- Evaluación: {len(holdouts)} archivos de martes a viernes; "
        f"{evaluation_counts.benign_rows:,} benignos y "
        f"{evaluation_counts.attack_rows:,} ataques válidos; "
        f"{evaluation_counts.invalid_rows:,} filas inválidas.",
        f"- Fracciones de muestreo: calibración {calibration_fraction:g}, "
        f"evaluación {evaluation_fraction:g}; semilla {seed}. "
        "Una fracción menor que 1 produce resultados exploratorios.",
        f"- Modelo SHA-256: `{_sha256(model_path)}`; scaler SHA-256: "
        f"`{_sha256(scaler_path)}`.",
        "- Archivos de evaluación: " + ", ".join(f"`{p.name}`" for p in holdouts) + ".",
        "",
        "## Forma de la distribución benigna",
        "",
        "Se aplicó D'Agostino-Pearson K² sobre los MSE benignos del lunes "
        "(H₀: distribución normal; α = 0.05). La desviación estándar usa "
        "ddof = 0 y los percentiles usan interpolación lineal de NumPy.",
        "",
        "| n | Media MSE | σ | Asimetría | Curtosis excedente | K² | p | Decisión |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
        f"| {int(calibration['n']):,} | {calibration['mean']:.9g} | "
        f"{calibration['std_population']:.9g} | {calibration['skewness']:.4f} | "
        f"{calibration['excess_kurtosis']:.4f} | "
        f"{calibration['normaltest_k2']:.4f} | "
        f"{_fmt_p(calibration['normaltest_p'])} | "
        f"{'Se rechaza H₀' if reject else 'No se rechaza H₀'} |",
        "",
        "La asimetría y la curtosis cuantifican la forma de la cola; el p-valor "
        "por sí solo no mide el tamaño de la desviación, especialmente con "
        "muestras grandes. La regla μ + 3σ supone una cola aproximadamente "
        "normal si se interpreta como una garantía probabilística; P99 no "
        "necesita esa hipótesis.",
        "",
        "## Comparación en días no usados para calibrar",
        "",
        "Se marca anomalía cuando `MSE > umbral`. FPR = FP/(TN+FP) sobre "
        "benignos; F1 = 2TP/(2TP+FP+FN) para la clase ataque.",
        "",
        "| Método | Umbral MSE | TN | FP | FN | TP | FPR | F1 |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['method']} | {row['threshold']:.9g} | {row['tn']:,} | "
            f"{row['fp']:,} | {row['fn']:,} | {row['tp']:,} | "
            f"{_fmt_metric(row['fpr'])} | {_fmt_metric(row['f1'])} |"
        )
    normal_row = next(row for row in rows if row["method"] == "μ + 3σ")
    deployed_row = next(row for row in rows if row["method"] == "P99 desplegado")
    recalculated_row = next(row for row in rows if row["method"] == "P99 recalculado")
    lines += [
        "",
        f"El P99 recalculado ({recalculated_row['threshold']:.9g}) "
        f"difiere del τ desplegado ({DEPLOYED_THRESHOLD:.9g}) en "
        f"{abs(recalculated_row['threshold'] - DEPLOYED_THRESHOLD):.3g} MSE, "
        "compatible con el redondeo a seis decimales del notebook. "
        f"En estos días, P99 desplegado obtuvo F1 = {_fmt_metric(deployed_row['f1'])} "
        f"y FPR = {_fmt_metric(deployed_row['fpr'])}; μ + 3σ obtuvo "
        f"F1 = {_fmt_metric(normal_row['f1'])} y FPR = "
        f"{_fmt_metric(normal_row['fpr'])}. La elección implica un intercambio "
        "entre detección y falsas alarmas; rechazar normalidad no demuestra "
        "por sí solo que P99 sea óptimo. Tampoco debe interpretarse P99 como "
        "una FPR de 1 % en los días de prueba.",
        "",
        "## Alcance de la conclusión",
        "",
        "El lunes ya se utilizó para ajustar el scaler y entrenar el autoencoder "
        "original; por tanto, la calibración de estos candidatos es **dentro "
        "de muestra** y su FPR del 1 % nominal no está garantizado en producción. "
        "Los días restantes sí quedan fuera de la calibración de umbrales, "
        "aunque la elección final entre métodos después de ver esta tabla "
        "requeriría otra prueba independiente. Para afirmar una FPR calibrada "
        "sin contaminación, hay que volver a entrenar separando previamente "
        "entrenamiento y validación benigna, y reservar otros días para prueba.",
        "",
        "La tabla compara umbrales; no modifica la configuración del backend. "
        "Los CSV y el `.h5` son artefactos locales ignorados por Git; sus "
        "hashes y el comando siguiente permiten identificar la ejecución.",
        "",
        "| CSV | SHA-256 |",
        "| :--- | :--- |",
    ]
    for path in [monday, *holdouts]:
        lines.append(f"| `{path.name}` | `{_sha256(path)}` |")
    lines += [
        "",
        "```bash",
        "python SentinelAI-Model/threshold_analysis.py \\",
        "  --cic-dir SentinelAI-Model/data \\",
        "  --output docs/threshold_justification.md",
        "```",
        "",
    ]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cic-dir", type=Path, default=HERE / "data")
    parser.add_argument("--model", type=Path, default=HERE / "models/sentinel_model.h5")
    parser.add_argument("--scaler", type=Path, default=HERE / "models/sentinel_scaler.save")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--chunksize", type=int, default=20_000)
    parser.add_argument("--batch-size", type=int, default=4_096)
    parser.add_argument("--calibration-sample-fraction", type=float, default=1.0)
    parser.add_argument("--evaluation-sample-fraction", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    if args.chunksize < 1 or args.batch_size < 1:
        parser.error("--chunksize and --batch-size must be positive")
    for name in ("calibration_sample_fraction", "evaluation_sample_fraction"):
        value = getattr(args, name)
        if not math.isfinite(value) or not 0 < value <= 1:
            parser.error(f"--{name.replace('_', '-')} must be in (0, 1]")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    files = sorted(args.cic_dir.glob("*.csv"))
    monday_files = [path for path in files if path.name.lower().startswith("monday-")]
    holdouts = [path for path in files if path not in monday_files]
    if len(monday_files) != 1 or not holdouts:
        raise ValueError("Expected one Monday CSV and at least one Tuesday--Friday CSV")
    if any(not path.name.lower().startswith(("tuesday-", "wednesday-", "thursday-", "friday-")) for path in holdouts):
        raise ValueError("Only Tuesday--Friday CIC-IDS2017 files may be used for evaluation")
    model, scaler, features = load_assets(args.model, args.scaler)

    calibration_counts = FileCounts()
    benign_batches: list[np.ndarray] = []
    for mse, y in iter_reconstruction_errors(
        monday_files[0], model=model, scaler=scaler, features=features,
        chunksize=args.chunksize, batch_size=args.batch_size,
        sample_fraction=args.calibration_sample_fraction, seed=args.seed,
        counts=calibration_counts,
    ):
        benign_batches.append(mse[y == 0])
    if not benign_batches or not any(len(batch) for batch in benign_batches):
        raise ValueError("No valid benign Monday MSE values")
    benign = np.concatenate(benign_batches)
    calibration = describe_calibration(benign)
    thresholds = candidate_thresholds(benign)

    evaluation_counts = FileCounts()
    totals = np.zeros((len(thresholds), 4), dtype=np.int64)
    for path in holdouts:
        file_counts = FileCounts()
        for mse, y in iter_reconstruction_errors(
            path, model=model, scaler=scaler, features=features,
            chunksize=args.chunksize, batch_size=args.batch_size,
            sample_fraction=args.evaluation_sample_fraction, seed=args.seed,
            counts=file_counts,
        ):
            for index, (_, threshold) in enumerate(thresholds):
                totals[index] += confusion_counts(mse, y, threshold)
        evaluation_counts.add(file_counts)
        print(f"{path.name}: {file_counts.evaluated_rows:,} valid flows")
    if evaluation_counts.benign_rows == 0 or evaluation_counts.attack_rows == 0:
        raise ValueError("Evaluation needs both benign and attack flows to compare FPR and F1")

    rows = [
        {"method": name, "threshold": threshold,
         **classification_metrics(tuple(int(x) for x in totals[index]))}
        for index, (name, threshold) in enumerate(thresholds)
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_report(
        calibration=calibration, rows=rows, monday=monday_files[0],
        holdouts=holdouts, calibration_counts=calibration_counts,
        evaluation_counts=evaluation_counts, model_path=args.model,
        scaler_path=args.scaler,
        calibration_fraction=args.calibration_sample_fraction,
        evaluation_fraction=args.evaluation_sample_fraction, seed=args.seed,
    ), encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
