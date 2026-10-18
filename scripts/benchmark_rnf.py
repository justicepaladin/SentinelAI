"""Measure RNF-03, RNF-05 and RNF-06 against the local SentinelAI API.

The trained scaler and autoencoder are real. Requests go through FastAPI's ASGI
stack in-process; authentication, disk logging, PostgreSQL, Telegram and the
firewall are replaced with in-memory collaborators. No external state changes.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import inspect
import json
import logging
import math
import os
import platform
import statistics
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "docs"
DEFAULT_REQUESTS = 500
SCENARIOS = ("active", "degraded_link", "informative_only")


@dataclass(frozen=True)
class LatencyStats:
    samples: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    maximum_ms: float


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    latency: LatencyStats
    detections: int
    firewall_calls: int
    suspended_responses: int
    durations_ns: tuple[int, ...] = ()

    @property
    def firewall_rate_pct(self) -> float:
        return 100.0 * self.firewall_calls / self.detections if self.detections else 0.0


class MemoryAuditLog:
    """Count audit calls without opening or writing files during measurement."""

    def __init__(self) -> None:
        self.traffic_count = 0
        self.detection_count = 0
        self.last_detection: dict[str, Any] | None = None

    def log_traffic(self, **_fields: Any) -> None:
        self.traffic_count += 1

    def log_detection(self, **fields: Any) -> None:
        self.detection_count += 1
        self.last_detection = fields


def percentile(sorted_values: list[float], fraction: float) -> float:
    """Linear interpolation at the fractional (n - 1) sample position."""

    if not sorted_values:
        raise ValueError("at least one latency sample is required")
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("percentile fraction must be in [0, 1]")
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (
        position - lower
    )


def summarize_ns(samples_ns: list[int]) -> LatencyStats:
    if not samples_ns or any(sample < 0 for sample in samples_ns):
        raise ValueError("latencies must be a nonempty list of nonnegative durations")
    ordered_ms = sorted(sample / 1_000_000 for sample in samples_ns)
    return LatencyStats(
        samples=len(ordered_ms),
        mean_ms=statistics.fmean(ordered_ms),
        p50_ms=percentile(ordered_ms, 0.5),
        p95_ms=percentile(ordered_ms, 0.95),
        p99_ms=percentile(ordered_ms, 0.99),
        maximum_ms=ordered_ms[-1],
    )


def split_requests(total: int) -> dict[str, int]:
    if total < len(SCENARIOS):
        raise ValueError(f"--requests must be at least {len(SCENARIOS)}")
    base, remainder = divmod(total, len(SCENARIOS))
    return {
        scenario: base + (index < remainder)
        for index, scenario in enumerate(SCENARIOS)
    }


async def post_asgi_json(app: Any, body: bytes) -> tuple[int, dict[str, Any]]:
    """Send a complete HTTP request through ASGI without sockets or httpx."""

    received = False
    response_complete = asyncio.Event()
    status_code: int | None = None
    response_parts: list[bytes] = []

    async def receive() -> dict[str, Any]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        await response_complete.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = message["status"]
        elif message["type"] == "http.response.body":
            response_parts.append(message.get("body", b""))
            if not message.get("more_body", False):
                response_complete.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/ingest",
        "raw_path": b"/ingest",
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"authorization", b"Bearer in-memory-benchmark-token"),
        ],
        "client": ("benchmark", 0),
        "server": ("benchmark", 80),
        "state": {},
    }
    request_task = asyncio.create_task(app(scope, receive, send))
    # A short timer also wakes event loops whose AnyIO worker completion alone
    # does not wake the selector (observed in the bundled Python environment).
    while not request_task.done():
        await asyncio.sleep(0.001)
    await request_task
    if status_code is None:
        raise RuntimeError("ASGI app did not start an HTTP response")
    payload = json.loads(b"".join(response_parts))
    if not isinstance(payload, dict):
        raise RuntimeError("/ingest did not return a JSON object")
    return status_code, payload


def import_backend() -> Any:
    sys.path.insert(0, str(ROOT / "SentinelAI-Backend"))
    try:
        import main  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "Backend dependencies are unavailable; run with "
            "SentinelAI-Backend/.venv/bin/python or install requirements.txt"
        ) from exc
    return main


def choose_anomalous_features(backend: Any, model: Any, scaler: Any) -> tuple[list[float], float]:
    """Pick a deterministic synthetic vector detected by the loaded artifacts."""

    width = int(scaler.n_features_in_)
    required = max(backend.TAU, backend.CRITICAL_MSE)
    for value in (0.1, 0.2, 0.5, 1.0):
        features = [value] * width
        try:
            score = backend._predict_mse(model, scaler, features)
        except (ValueError, RuntimeError):
            continue
        if math.isfinite(score) and score > required:
            return features, score
    raise RuntimeError(
        "The trained model did not classify any fixed synthetic probe as critical; "
        "provide a model-compatible anomalous fixture before benchmarking"
    )


def make_identity(backend: Any, *, informative_only: bool) -> Any:
    parameters = inspect.signature(backend.SensorIdentity).parameters
    if "informative_only_mode" not in parameters:
        raise RuntimeError("Backend does not yet expose informative_only_mode")
    return backend.SensorIdentity(
        sensor_id=1,
        sensor_name="benchmark-sensor",
        site_id=1,
        site_slug="benchmark-site",
        custom_mse_threshold=None,
        active_response_enabled=True,
        informative_only_mode=informative_only,
    )


def validate_scenario(result: ScenarioResult) -> None:
    """Reject a report if the actual API behavior violates the RNF policies."""

    expected = result.latency.samples
    if result.detections != expected:
        raise RuntimeError(
            f"{result.name}: expected {expected} anomaly detections, got {result.detections}"
        )
    if result.name == "active" and result.firewall_calls != expected:
        raise RuntimeError(
            f"active: expected {expected} simulated firewall calls, "
            f"got {result.firewall_calls}"
        )
    if result.name in ("degraded_link", "informative_only") and result.firewall_calls:
        raise RuntimeError(
            f"{result.name}: expected zero firewall calls, got {result.firewall_calls}"
        )
    if result.name == "degraded_link" and result.suspended_responses != expected:
        raise RuntimeError(
            f"degraded_link: expected {expected} suspended responses, "
            f"got {result.suspended_responses}"
        )


def combine_scenarios(cases: list[ScenarioResult]) -> LatencyStats:
    samples = [duration for case in cases for duration in case.durations_ns]
    if len(samples) != sum(case.latency.samples for case in cases):
        raise ValueError("combined API latency requires every raw scenario duration")
    return summarize_ns(samples)


async def measure_scenario(
    backend: Any,
    *,
    name: str,
    requests: int,
    warmup: int,
    body: bytes,
    audit: MemoryAuditLog,
) -> ScenarioResult:
    counts = {"firewall": 0}

    def firewall_mock(_ip: Any) -> tuple[bool, bool]:
        counts["firewall"] += 1
        return True, True

    identity = make_identity(backend, informative_only=(name == "informative_only"))
    backend.app.dependency_overrides[backend.get_authenticated_sensor] = lambda: identity
    detections = 0
    suspended = 0
    durations: list[int] = []
    async def no_background_work(*_args: Any, **_kwargs: Any) -> None:
        return None

    with patch.object(backend, "_quarantine_source_ip", side_effect=firewall_mock), patch.object(
        backend, "_notify_and_release_quarantine", no_background_work
    ):
        for index in range(warmup + requests):
            before_traffic = audit.traffic_count
            before_detection = audit.detection_count
            start_ns = time.perf_counter_ns()
            status_code, response = await post_asgi_json(backend.app, body)
            duration_ns = time.perf_counter_ns() - start_ns
            if status_code != 200:
                raise RuntimeError(f"{name}: /ingest returned HTTP {status_code}: {response}")
            if audit.traffic_count != before_traffic + 1:
                raise RuntimeError(f"{name}: traffic was not logged exactly once")
            if not response.get("anomaly") or audit.detection_count != before_detection + 1:
                raise RuntimeError(f"{name}: anomaly was not detected and logged")
            logged = audit.last_detection or {}
            if name == "degraded_link" and not (
                logged.get("link_degraded") and logged.get("response_suspended")
            ):
                raise RuntimeError("degraded_link: detection log lacks the suspension warning")
            if name == "informative_only" and not logged.get("informative_only_mode"):
                raise RuntimeError("informative_only: detection log lacks the site mode")
            if index >= warmup:
                durations.append(duration_ns)
                detections += 1
                suspended += bool(response.get("response_suspended", False))
            elif index == warmup - 1:
                counts["firewall"] = 0

    result = ScenarioResult(
        name, summarize_ns(durations), detections, counts["firewall"], suspended,
        tuple(durations),
    )
    validate_scenario(result)
    return result


async def benchmark(total_requests: int, warmup: int) -> tuple[LatencyStats, list[ScenarioResult], dict[str, Any]]:
    if warmup < 0:
        raise ValueError("--warmup must be nonnegative")
    counts = split_requests(total_requests)
    backend = import_backend()
    model, scaler = backend._load_ml_assets()
    features, probe_mse = choose_anomalous_features(backend, model, scaler)
    audit = MemoryAuditLog()
    previous_overrides = backend.app.dependency_overrides.copy()
    previous_states = {
        key: getattr(backend.app.state, key, None)
        for key in ("model", "scaler", "audit_log", "ml_load_error", "database_ready")
    }
    old_logger_level = backend.logger.level
    backend.logger.setLevel(logging.ERROR)
    backend.app.state.model = model
    backend.app.state.scaler = scaler
    backend.app.state.audit_log = audit
    backend.app.state.ml_load_error = None
    backend.app.state.database_ready = True
    backend._CRITICAL_WRITE_CACHE.clear()

    # Bodies are encoded before timing; FastAPI still parses and validates each one.
    common = {
        "source_ip": "198.51.100.25",
        "destination_ip": "203.0.113.8",
        "destination_port": 443,
        "features": features,
    }
    normal_body = json.dumps({**common, "link_degraded": False}).encode("utf-8")
    degraded_body = json.dumps({**common, "link_degraded": True}).encode("utf-8")

    try:
        with ExitStack() as stack:
            # Preserve the live decision path but perform no DB, disk or network I/O.
            stack.enter_context(patch.object(backend, "record_detection_state", return_value=None))
            if hasattr(backend, "update_sensor_telemetry"):
                stack.enter_context(
                    patch.object(backend, "update_sensor_telemetry", return_value=None)
                )
            for _ in range(warmup):
                backend._predict_mse(model, scaler, features)
            pure_durations = []
            for _ in range(total_requests):
                start_ns = time.perf_counter_ns()
                backend._predict_mse(model, scaler, features)
                pure_durations.append(time.perf_counter_ns() - start_ns)
            pure_stats = summarize_ns(pure_durations)

            cases = []
            for name in SCENARIOS:
                cases.append(
                    await measure_scenario(
                        backend,
                        name=name,
                        requests=counts[name],
                        warmup=warmup,
                        body=degraded_body if name == "degraded_link" else normal_body,
                        audit=audit,
                    )
                )
    finally:
        backend.logger.setLevel(old_logger_level)
        backend.app.dependency_overrides.clear()
        backend.app.dependency_overrides.update(previous_overrides)
        for key, value in previous_states.items():
            setattr(backend.app.state, key, value)
        backend._CRITICAL_WRITE_CACHE.clear()

    environment = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": processor_name(),
        "cpu_count": os.cpu_count(),
        "tensorflow": __import__("tensorflow").__version__,
        "fastapi": __import__("fastapi").__version__,
        "scikit_learn": __import__("sklearn").__version__,
        "model_path": str(backend.MODEL_PATH.relative_to(ROOT)),
        "scaler_path": str(backend.SCALER_PATH.relative_to(ROOT)),
        "probe_value_per_feature": features[0],
        "probe_mse": probe_mse,
        "requests_total": total_requests,
        "warmup_per_phase": warmup,
    }
    return pure_stats, cases, environment


def processor_name() -> str:
    """Describe the measured CPU without depending on an external command."""

    if platform.processor():
        return platform.processor()
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unreported"


def render_markdown(
    pure: LatencyStats, cases: list[ScenarioResult], environment: dict[str, Any]
) -> str:
    combined = combine_scenarios(cases)
    all_detections = sum(case.detections for case in cases)
    all_firewall_calls = sum(case.firewall_calls for case in cases)
    rows = [
        ("Inferencia pura (scaler + autoencoder)", pure, "—", "—", "—"),
        (
            "POST /ingest · todos los modos",
            combined,
            str(all_detections),
            str(all_firewall_calls),
            f"{100 * all_firewall_calls / all_detections:.1f}%",
        ),
        *[
            (
                {
                    "active": "POST /ingest · respuesta activa",
                    "degraded_link": "POST /ingest · enlace degradado",
                    "informative_only": "POST /ingest · modo informativo",
                }[case.name],
                case.latency,
                str(case.detections),
                str(case.firewall_calls),
                f"{case.firewall_rate_pct:.1f}%",
            )
            for case in cases
        ],
    ]
    table = [
        "| Medición | n | Media (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Máximo (ms) | Detecciones | Llamadas al firewall | Tasa por detección |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, stats, detections, calls, rate in rows:
        table.append(
            f"| {label} | {stats.samples} | {stats.mean_ms:.3f} | {stats.p50_ms:.3f} | "
            f"{stats.p95_ms:.3f} | {stats.p99_ms:.3f} | {stats.maximum_ms:.3f} | "
            f"{detections} | {calls} | {rate} |"
        )
    return "\n".join(
        [
            "# Benchmark RNF-03, RNF-05 y RNF-06",
            "",
            f"**Medición:** {environment['timestamp_utc']} · "
            f"{environment['requests_total']} peticiones POST /ingest en total "
            f"(repartidas entre los tres modos), "
            f"{environment['requests_total']} inferencias puras y "
            f"{environment['warmup_per_phase']} calentamientos por fase.",
            "",
            *table,
            "",
            "## Método y alcance",
            "",
            "Se usaron el scaler y el autoencoder entrenados, sin reemplazar la inferencia. "
            "El vector de prueba fue sintético y determinista: "
            f"{environment['probe_value_per_feature']} en cada una de las 78 entradas; "
            f"su MSE fue {environment['probe_mse']:.9g}. "
            "Se eligió un vector que supera el umbral crítico para verificar "
            "la ruta de detección y las tres políticas de respuesta.",
            "",
            "Cada POST pasó por el stack ASGI de FastAPI en el mismo proceso; "
            "la serialización del request se hizo antes del cronómetro. "
            "La inferencia pura incluye preparación del DataFrame, scaler, "
            "autoencoder y cálculo del MSE. Las latencias son de reloj monotónico "
            "y los percentiles usan interpolación lineal sobre las muestras medidas. "
            "El cliente ASGI revisa la finalización a intervalos de 1 ms; "
            "esa espera está incluida en el tiempo extremo a extremo.",
            "",
            "Durante las mediciones, la autenticación se resolvió en memoria, "
            "los logs se contaron en memoria y PostgreSQL, Telegram e iptables "
            "fueron sustituidos por dobles. La columna de firewall cuenta "
            "invocaciones al punto de aplicación de reglas; no representa reglas "
            "instaladas en el host. El test falla si se pierde alguna detección, "
            "si el modo activo no invoca el firewall, o si los modos degradado e "
            "informativo lo invocan. Esta prueba no mide latencia de red, disco, "
            "PostgreSQL ni iptables reales.",
            "",
            "La degradación se simuló con `link_degraded=true` en el payload; "
            "no se desconectó una interfaz física ni se introdujo pérdida de paquetes.",
            "",
            "No se encontró en los archivos versionados un límite numérico de "
            "aceptación para RNF-03. Estos percentiles permiten compararlo con "
            "el valor pactado en la cátedra, pero el informe no declara "
            "cumplimiento sin ese criterio.",
            "",
            "## Entorno",
            "",
            f"- Python {environment['python']}; FastAPI {environment['fastapi']}; "
            f"TensorFlow {environment['tensorflow']}; "
            f"scikit-learn {environment['scikit_learn']}.",
            f"- {environment['platform']}; CPU: {environment['processor']} "
            f"({environment['cpu_count']} CPU lógicas informadas).",
            f"- Modelo: `{environment['model_path']}`; scaler: `{environment['scaler_path']}`.",
            "- Comando: `SentinelAI-Backend/.venv/bin/python scripts/benchmark_rnf.py "
            f"--requests {environment['requests_total']} "
            f"--warmup {environment['warmup_per_phase']}`.",
            "",
        ]
    )


def write_results(
    output_dir: Path,
    pure: LatencyStats,
    cases: list[ScenarioResult],
    environment: dict[str, Any],
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    md_path = output_dir / "benchmark_rnf_results.md"
    csv_path = output_dir / "benchmark_rnf_results.csv"
    md_path.write_text(render_markdown(pure, cases, environment), encoding="utf-8")
    combined = combine_scenarios(cases)
    all_detections = sum(case.detections for case in cases)
    all_firewall_calls = sum(case.firewall_calls for case in cases)
    all_suspended = sum(case.suspended_responses for case in cases)
    fieldnames = (
        "scenario", "sample_count", "mean_ms", "p50_ms", "p95_ms", "p99_ms",
        "max_ms", "detections", "firewall_calls", "firewall_rate_pct",
        "suspended_responses", "timestamp_utc", "probe_mse",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for name, stats, detections, calls, suspended in [
            ("pure_inference", pure, None, None, None),
            ("ingest_all_modes", combined, all_detections, all_firewall_calls, all_suspended),
            *[
                (case.name, case.latency, case.detections, case.firewall_calls, case.suspended_responses)
                for case in cases
            ],
        ]:
            writer.writerow(
                {
                    "scenario": name,
                    "sample_count": stats.samples,
                    "mean_ms": f"{stats.mean_ms:.6f}",
                    "p50_ms": f"{stats.p50_ms:.6f}",
                    "p95_ms": f"{stats.p95_ms:.6f}",
                    "p99_ms": f"{stats.p99_ms:.6f}",
                    "max_ms": f"{stats.maximum_ms:.6f}",
                    "detections": detections,
                    "firewall_calls": calls,
                    "firewall_rate_pct": (
                        f"{100 * calls / detections:.6f}" if detections else ""
                    ),
                    "suspended_responses": suspended,
                    "timestamp_utc": environment["timestamp_utc"],
                    "probe_mse": f"{environment['probe_mse']:.9g}",
                }
            )
    return md_path, csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--requests", type=int, default=DEFAULT_REQUESTS,
        help="total measured POST requests, split across active/degraded/informative modes",
    )
    parser.add_argument("--warmup", type=int, default=5, help="unmeasured calls per phase")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    pure, cases, environment = asyncio.run(benchmark(args.requests, args.warmup))
    md_path, csv_path = write_results(args.output_dir, pure, cases, environment)
    print(f"Validated RNF policies; Markdown: {md_path}; CSV: {csv_path}")


if __name__ == "__main__":
    main()
