"""Compare normal-theory and empirical MSE thresholds without test-set leakage.

The frozen model and scaler reconstruct benign Monday CIC-IDS2017 flows to
calibrate candidate thresholds. Tuesday--Friday measure detection and false
positives for informative alerts and critical blocks. Monday is *not* an
independent calibration set for these artifacts:
it was used to fit both of them in the original notebook. Run ``--help`` for
the reproducible command and sampling options.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pandas as pd
from scipy import stats

from evaluate_ood import DEPLOYED_THRESHOLD, feature_sources, load_assets, parse_labels


HERE = Path(__file__).resolve().parent
DEFAULT_REPORT = HERE.parent / "docs" / "threshold_justification.md"
PERCENTILES = (80, 85, 90, 95, 97, 98, 99, 99.5, 99.9)
DETAIL_METHODS = ("P90", "P95", "P97", "P99 recalculado")
PREVALENCES = (0.242, 0.10, 0.01, 0.001)


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


@dataclass
class GroupCounts:
    flows: int = 0
    alerts: dict[str, int] = field(default_factory=dict)

    def add(self, mse: np.ndarray, thresholds: dict[str, float]) -> None:
        self.flows += len(mse)
        for name, threshold in thresholds.items():
            self.alerts[name] = self.alerts.get(name, 0) + int(np.count_nonzero(mse > threshold))


def _file_seed(path: Path, seed: int) -> int:
    return seed ^ int.from_bytes(
        hashlib.sha256(path.name.encode("utf-8")).digest()[:8], "little"
    )


def iter_reconstruction_errors(
    path: Path, *, model: Any, scaler: Any, features: list[str],
    chunksize: int, batch_size: int, sample_fraction: float, seed: int,
    counts: FileCounts,
) -> Iterator[tuple[np.ndarray, np.ndarray, np.ndarray]]:
    """Yield valid MSE, binary labels and CIC attack names in the same row order."""
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
            groups = chunk.loc[valid, "Label"].astype("string").str.strip().to_numpy(dtype=str)
            groups[labels == 0] = "BENIGN"
            yield mse.astype(np.float64), labels, groups


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
    values = np.percentile(benign_mse, PERCENTILES, method="linear")
    return [
        ("P99 recalculado" if p == 99 else f"P{p}", float(value))
        for p, value in zip(PERCENTILES, values)
    ] + [
        ("μ + 3σ", summary["mean"] + 3 * summary["std_population"]),
        ("P99 desplegado", DEPLOYED_THRESHOLD),
    ]


def critical_thresholds(candidates: dict[str, float]) -> dict[str, float]:
    return {
        **{name: candidates[name] for name in ("P99.5", "P99.9", "μ + 3σ")},
        **{f"3 × {name}": 3 * candidates[name] for name in ("P90", "P95", "P97")},
    }


def confusion_counts(
    mse: np.ndarray, labels: np.ndarray, threshold: float, *, inclusive: bool = False,
) -> tuple[int, int, int, int]:
    """Return TN, FP, FN, TP for a strict alert or inclusive critical cutoff."""
    predicted = mse >= threshold if inclusive else mse > threshold
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


def expected_precision(recall: float | None, fpr: float | None, prevalence: float) -> float | None:
    if recall is None or fpr is None:
        return None
    true_alerts = recall * prevalence
    all_alerts = true_alerts + fpr * (1 - prevalence)
    return true_alerts / all_alerts if all_alerts else None


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


def _fmt_pct(value: float | None) -> str:
    return "N/D" if value is None else f"{100 * value:.2f}"


def _score_table(thresholds: dict[str, float], metrics: dict[str, dict[str, Any]]) -> list[str]:
    lines = [
        "| Método | Umbral MSE | TN | FP | FN | TP | Sensibilidad (Recall) | Precisión | FPR (%) | F1 |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, threshold in thresholds.items():
        m = metrics[name]
        lines.append(
            f"| {name} | {threshold:.9g} | {m['tn']:,} | {m['fp']:,} | {m['fn']:,} | "
            f"{m['tp']:,} | {_fmt_metric(m['recall'])} | {_fmt_metric(m['precision'])} | "
            f"{_fmt_pct(m['fpr'])} | {_fmt_metric(m['f1'])} |"
        )
    return lines


def _cli_path(path: Path) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(HERE.parent):
        resolved = resolved.relative_to(HERE.parent)
    return shlex.quote(str(resolved))


def render_report(
    *, calibration: dict[str, float], candidates: dict[str, float], critical: dict[str, float],
    alert_metrics: dict[str, dict[str, Any]], critical_metrics: dict[str, dict[str, Any]],
    monday: Path, breakdown: dict[Path, dict[str, GroupCounts]], calibration_counts: FileCounts,
    evaluation_counts: FileCounts, args: argparse.Namespace,
) -> str:
    reject = calibration["normaltest_p"] < 0.05
    alert = alert_metrics["P90"]
    block = critical_metrics["P99.9"]
    reference = alert_metrics["P99 desplegado"]
    prevalence = evaluation_counts.attack_rows / evaluation_counts.evaluated_rows
    p99 = candidates["P99 recalculado"]
    rounding = (
        " A seis decimales reproduce el umbral histórico redondeado del notebook."
        if round(p99, 6) == DEPLOYED_THRESHOLD else ""
    )
    lines = [
        "# Sensibilidad de las alertas y falsos positivos del bloqueo crítico",
        "",
        "## Diseño de la evaluación",
        "",
        "El autoencoder y el scaler congelados de SentinelAI reconstruyeron los flujos "
        "de CIC-IDS2017. Los percentiles y la regla μ + 3σ se calcularon exclusivamente "
        "con el MSE de los flujos benignos del lunes. El P99 desplegado conserva su "
        f"valor histórico de `{DEPLOYED_THRESHOLD}`. Los siete archivos de martes a viernes "
        "quedaron fuera de la calibración y aportan las etiquetas para medir detección y falsas alarmas.",
        "",
        f"- El lunes (`{monday.name}`) aportó {calibration_counts.benign_rows:,} benignos válidos. "
        f"Se excluyeron {calibration_counts.attack_rows:,} ataques y "
        f"{calibration_counts.invalid_rows:,} filas inválidas.",
        f"- La evaluación reunió {evaluation_counts.benign_rows:,} benignos y "
        f"{evaluation_counts.attack_rows:,} ataques válidos. El número de filas inválidas "
        f"descartadas fue {evaluation_counts.invalid_rows:,}. La prevalencia observada de ataques "
        f"fue del {_fmt_pct(prevalence)} %.",
        f"- Las fracciones de muestreo fueron {args.calibration_sample_fraction:g} en calibración "
        f"y {args.evaluation_sample_fraction:g} en evaluación, con semilla {args.seed}.",
        "",
        "## Distribución del MSE benigno del lunes",
        "",
        "La prueba K² de D’Agostino-Pearson contrasta la hipótesis de normalidad con α = 0.05. "
        "Se usó la desviación estándar poblacional (ddof = 0) y la interpolación lineal "
        "de NumPy para los percentiles.",
        "",
        "| n | Media MSE | σ | Asimetría | Curtosis excedente | K² | p | Decisión |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
        f"| {int(calibration['n']):,} | {calibration['mean']:.9g} | "
        f"{calibration['std_population']:.9g} | {calibration['skewness']:.4f} | "
        f"{calibration['excess_kurtosis']:.4f} | {calibration['normaltest_k2']:.4f} | "
        f"{_fmt_p(calibration['normaltest_p'])} | "
        f"{'Se rechaza H₀' if reject else 'No se rechaza H₀'} |",
        "",
        "La asimetría y la curtosis describen cuánto se aparta la forma de la distribución "
        "de la normal. Los percentiles estiman directamente la cola empírica. El significado "
        "probabilístico de μ + 3σ depende de la distribución del MSE.",
        "",
        "## Candidatos de alerta informativa",
        "",
        "Se cuenta una alerta cuando `MSE > umbral`. La sensibilidad es la fracción de "
        "ataques detectados, TP/(TP+FN). La precisión es la fracción de alertas que corresponden "
        "a ataques, TP/(TP+FP). La FPR es el porcentaje de benignos marcados, 100 × FP/(TN+FP). "
        "F1 = 2TP/(2TP+FP+FN). Los conteos suman los siete archivos antes de calcular las tasas.",
        "",
        *_score_table(candidates, alert_metrics),
        "",
        f"La diferencia absoluta entre el P99 recalculado y el desplegado es "
        f"{abs(p99 - DEPLOYED_THRESHOLD):.3g} MSE.{rounding}",
        "",
        "## Candidatos de bloqueo crítico reversible",
        "",
        "Esta simulación cuenta un flujo como candidato al bloqueo cuando `MSE >= umbral crítico`. "
        "El umbral crítico de una pareja debe superar al de alerta para que todo bloqueo potencial "
        "sea también una alerta. Cada múltiplo 3 × P se calcula directamente sobre el percentil "
        "benigno del lunes, sin aplicar el piso de severidad del backend.",
        "",
        *_score_table(critical, critical_metrics),
        "",
        "### Lectura de la pareja P90 / P99.9",
        "",
    ]
    if candidates["P90"] < critical["P99.9"]:
        lines.extend([
            "Se ejemplifica la política con P90 para informar y P99.9 para bloquear. En la "
            "calibración benigna corresponden a colas nominales del 10 % y del 0.1 %, respectivamente.",
            "",
            f"- Con P90 se detectan {alert['tp']:,} ataques (recall {_fmt_pct(alert['recall'])} %) "
            f"y se marcan {alert['fp']:,} benignos (FPR {_fmt_pct(alert['fpr'])} %). "
            f"Frente al P99 desplegado, con recall {_fmt_pct(reference['recall'])} %, el cambio "
            f"es de {alert['tp'] - reference['tp']:+,} ataques detectados y "
            f"{alert['fp'] - reference['fp']:+,} falsas alertas.",
            f"- Superan o igualan P99.9 {block['tp']:,} ataques ({_fmt_pct(block['recall'])} % "
            f"de todos los ataques) y {block['fp']:,} benignos (FPR crítica "
            f"{_fmt_pct(block['fpr'])} %). De los falsos positivos de P90, la fracción "
            f"que también alcanzaría el bloqueo es "
            f"{_fmt_pct(block['fp'] / alert['fp'] if alert['fp'] else None)} %. "
            f"Quedarían solo como informativos {alert['tp'] - block['tp']:,} ataques "
            f"y {alert['fp'] - block['fp']:,} benignos.",
        ])
    else:
        lines.append("P90 y P99.9 coinciden para esta calibración. La pareja requiere dos cortes distintos.")
    lines.extend([
        "",
        "La unidad de evaluación es el flujo. La política propuesta reserva el bloqueo para "
        "el corte crítico. En el backend actual, con la respuesta activa habilitada y sin suspensión, "
        "cualquier anomalía puede poner una IP en cuarentena. La severidad emplea el máximo "
        "entre el piso crítico configurado y tres veces el umbral del sitio. Los conteos de "
        "esta simulación miden flujos candidatos a la acción.",
        "",
        "## Desglose por archivo y familia de ataque",
        "",
        "Cada celda indica qué porcentaje de los flujos del grupo superó el umbral de alerta. "
        "En BENIGN se lee la FPR del archivo. En cada etiqueta de ataque se lee la sensibilidad "
        "para esa familia. La columna Flujos da el denominador de cada porcentaje. "
        "P99 es el percentil recalculado del lunes.",
        "",
        "| Archivo | Grupo | Flujos | " + " | ".join(f"{name} (%)" for name in DETAIL_METHODS) + " |",
        "| :--- | :--- | ---: | " + " | ".join("---:" for _ in DETAIL_METHODS) + " |",
    ])
    for path, groups in breakdown.items():
        for label in sorted(groups, key=lambda value: (value != "BENIGN", value)):
            counts = groups[label]
            rates = " | ".join(_fmt_pct(counts.alerts[name] / counts.flows) for name in DETAIL_METHODS)
            display_label = label.replace("�", "–").replace("|", r"\|")
            lines.append(f"| `{path.name}` | {display_label} | {counts.flows:,} | {rates} |")
    lines.extend([
        "",
        "## Precisión esperada bajo distintas prevalencias",
        "",
        "Para una prevalencia π se estima el valor predictivo positivo con "
        "`recall × π / (recall × π + FPR × (1 − π))`. Aquí la FPR se expresa como fracción. "
        "La proyección conserva la sensibilidad y la FPR observadas en los siete archivos "
        "y solo cambia la proporción de ataques. Un cambio en la mezcla de familias o en el "
        "tráfico benigno también puede modificar esas tasas.",
        "",
        "| Acción | Método | 24,2 % | 10 % | 1 % | 0,1 % |",
        "| :--- | :--- | ---: | ---: | ---: | ---: |",
    ])
    for action, metrics in (("Alerta", alert_metrics), ("Bloqueo", critical_metrics)):
        for name, row in metrics.items():
            rates = " | ".join(
                _fmt_pct(expected_precision(row["recall"], row["fpr"], p)) for p in PREVALENCES
            )
            lines.append(f"| {action} | {name} | {rates} |")
    lines.extend([
        "",
        "El 24,2 % aproxima la prevalencia del conjunto completo. Cada celda expresa la "
        "precisión en porcentaje. N/D indica un denominador cero.",
        "",
        "## Alcance y reproducción",
        "",
        "El lunes se usó tanto para entrenar el autoencoder y ajustar el scaler como para "
        "calibrar los umbrales. La FPR de bloqueo cuantifica falsos positivos en estos días. "
        "Generalizarla a producción requiere una evaluación independiente con tráfico y "
        "prevalencias representativos. Una selección de umbrales basada en el desempeño "
        "observado de martes a viernes requiere un nuevo conjunto de prueba.",
        "",
        f"- SHA-256 del modelo: `{_sha256(args.model)}`.",
        f"- SHA-256 del scaler: `{_sha256(args.scaler)}`.",
        "",
        "| CSV | SHA-256 |",
        "| :--- | :--- |",
    ])
    for path in (monday, *breakdown):
        lines.append(f"| `{path.name}` | `{_sha256(path)}` |")
    common_args = [
        f"  --cic-dir {_cli_path(args.cic_dir)} \\",
        f"  --model {_cli_path(args.model)} --scaler {_cli_path(args.scaler)} \\",
        f"  --chunksize {args.chunksize} --batch-size {args.batch_size} --seed {args.seed} \\",
    ]
    lines.extend([
        "",
        "Desde la raíz del repositorio, el siguiente comando reproduce el análisis.",
        "",
        "```bash",
        "python SentinelAI-Model/threshold_analysis.py \\",
        *common_args,
        f"  --calibration-sample-fraction {args.calibration_sample_fraction:g} "
        f"--evaluation-sample-fraction {args.evaluation_sample_fraction:g} \\",
        f"  --output {_cli_path(args.output)}",
        "```",
    ])
    if candidates["P90"] < critical["P99.9"]:
        lines.extend([
            "",
            "El siguiente comando genera las matrices de alerta P90 y el resumen de bloqueo "
            "P99.9 con los valores completos de ambos umbrales.",
            "",
            "```bash",
            "python SentinelAI-Model/evaluate_ood.py \\",
            *common_args,
            f"  --sample-fraction {args.evaluation_sample_fraction:g} \\",
            f"  --threshold {candidates['P90']!r} --critical-threshold {critical['P99.9']!r} \\",
            "  --output-dir SentinelAI-Model/reports/ood-p90-p999 \\",
            "  --plot-path docs/confusion_matrices.png",
            "```",
        ])
        if args.evaluation_sample_fraction < 1:
            lines.extend([
                "",
                "Con muestreo parcial, ambos scripts generan muestras exploratorias distintas "
                "porque derivan la semilla de cada archivo de formas diferentes. La comparación "
                "exacta de las matrices entre scripts usa la fracción de evaluación 1.",
            ])
    return "\n".join(lines) + "\n"


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
    days = ("monday", "tuesday", "wednesday", "thursday", "friday")
    by_day = {
        day: [p for p in files if p.name.lower().startswith(f"{day}-")] for day in days
    }
    if len(files) != 8 or [len(by_day[d]) for d in days] != [1, 1, 1, 2, 3]:
        raise ValueError(
            "Expected the eight CIC-IDS2017 CSVs: one Monday, one Tuesday, "
            "one Wednesday, two Thursday and three Friday files"
        )
    monday = by_day["monday"][0]
    holdouts = [path for day in days[1:] for path in by_day[day]]
    model, scaler, features = load_assets(args.model, args.scaler)

    calibration_counts = FileCounts()
    benign_batches: list[np.ndarray] = []
    for mse, y, _ in iter_reconstruction_errors(
        monday, model=model, scaler=scaler, features=features,
        chunksize=args.chunksize, batch_size=args.batch_size,
        sample_fraction=args.calibration_sample_fraction, seed=args.seed,
        counts=calibration_counts,
    ):
        benign_batches.append(mse[y == 0])
    if not benign_batches or not any(len(batch) for batch in benign_batches):
        raise ValueError("No valid benign Monday MSE values")
    benign = np.concatenate(benign_batches)
    calibration = describe_calibration(benign)
    candidates = dict(candidate_thresholds(benign))
    critical = critical_thresholds(candidates)
    detail = {name: candidates[name] for name in DETAIL_METHODS}

    evaluation_counts = FileCounts()
    alert_totals = {name: np.zeros(4, dtype=np.int64) for name in candidates}
    critical_totals = {name: np.zeros(4, dtype=np.int64) for name in critical}
    breakdown: dict[Path, dict[str, GroupCounts]] = {}
    for path in holdouts:
        file_counts = FileCounts()
        groups: dict[str, GroupCounts] = {}
        for mse, y, labels in iter_reconstruction_errors(
            path, model=model, scaler=scaler, features=features,
            chunksize=args.chunksize, batch_size=args.batch_size,
            sample_fraction=args.evaluation_sample_fraction, seed=args.seed,
            counts=file_counts,
        ):
            for name, threshold in candidates.items():
                alert_totals[name] += confusion_counts(mse, y, threshold)
            for name, threshold in critical.items():
                critical_totals[name] += confusion_counts(mse, y, threshold, inclusive=True)
            for label in np.unique(labels):
                groups.setdefault(label, GroupCounts()).add(mse[labels == label], detail)
        if not groups:
            raise ValueError(f"No valid evaluated rows in {path}; check sampling and CSV quality")
        breakdown[path] = groups
        evaluation_counts.add(file_counts)
        print(f"{path.name}: {file_counts.evaluated_rows:,} valid flows")
    if evaluation_counts.benign_rows == 0 or evaluation_counts.attack_rows == 0:
        raise ValueError("Evaluation needs both benign and attack flows to compare FPR and F1")

    def metrics(totals: dict[str, np.ndarray]) -> dict[str, dict[str, Any]]:
        return {name: classification_metrics(tuple(map(int, counts))) for name, counts in totals.items()}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_report(
        calibration=calibration, candidates=candidates, critical=critical,
        alert_metrics=metrics(alert_totals), critical_metrics=metrics(critical_totals),
        monday=monday, breakdown=breakdown, calibration_counts=calibration_counts,
        evaluation_counts=evaluation_counts, args=args,
    ), encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
