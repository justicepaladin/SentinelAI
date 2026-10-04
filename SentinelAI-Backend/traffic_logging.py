"""Local, structured audit logs for analyzed network flows.

Each ``.log`` file has one JSON object per line. A handler writes a private file
per process and instance, avoiding filename collisions between Uvicorn workers.
Files rotate at UTC midnight and before a write would exceed ``max_bytes``.
The companion ``scripts/archive_logs.py`` only archives closed, old log days.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import logging
import os
import tempfile
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_LOG_DIR = Path(__file__).resolve().parent / "logs"
DEFAULT_MAX_BYTES = 50 * 1024 * 1024


def _json_default(value: Any) -> Any:
    """Accept common values from Pydantic and NumPy without importing either."""

    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, Path)):
        return str(value)
    item = getattr(value, "item", None)
    if callable(item):  # NumPy scalar
        return item()
    tolist = getattr(value, "tolist", None)
    if callable(tolist):  # NumPy array
        return tolist()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


class _DailySizeJsonlHandler(logging.Handler):
    """Append UTF-8 JSON lines with day/size rotation and advisory file locks."""

    def __init__(self, stream_name: str, log_dir: Path, max_bytes: int) -> None:
        super().__init__(logging.INFO)
        self.stream_name = stream_name
        self.log_dir = log_dir
        self.max_bytes = max_bytes
        self._fd: int | None = None
        self._day: str | None = None
        self._pid = os.getpid()
        self._instance = uuid.uuid4().hex[:12]
        self._segment = 0
        self._size = 0

    def _close_file(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _open_file(self, day: str) -> None:
        self.log_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        while True:
            filename = (
                f"{self.stream_name}-{day}-{self._pid}-"
                f"{self._instance}-{self._segment:06d}.log"
            )
            path = self.log_dir / filename
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                self._fd = os.open(path, flags, 0o640)
                self._day = day
                self._size = 0
                return
            except FileExistsError:
                # This is unlikely with UUID names, but never append to a file
                # from a previous process or overwrite an existing audit record.
                self._segment += 1

    def emit(self, record: logging.LogRecord) -> None:
        payload = record.__dict__["audit_payload"]
        line = (
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
                default=_json_default,
            )
            + "\n"
        ).encode("utf-8")

        # Handler.handle holds the logging handler's thread lock. Reinitialize
        # inherited state if a Uvicorn worker was forked after construction.
        pid = os.getpid()
        if pid != self._pid:
            self._close_file()
            self._pid = pid
            self._instance = uuid.uuid4().hex[:12]
            self._segment = 0
            self._day = None

        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        if day != self._day:
            self._close_file()
            self._segment = 0
            self._open_file(day)
        elif self._fd is not None and self._size and self._size + len(line) > self.max_bytes:
            self._close_file()
            self._segment += 1
            self._open_file(day)

        assert self._fd is not None
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        try:
            view = memoryview(line)
            while view:
                written = os.write(self._fd, view)
                if written == 0:
                    raise OSError("audit log write returned zero bytes")
                view = view[written:]
            self._size += len(line)
        finally:
            fcntl.flock(self._fd, fcntl.LOCK_UN)

    def close(self) -> None:
        self.acquire()
        try:
            self._close_file()
            super().close()
        finally:
            self.release()


class AuditLogWriter:
    """Write a traffic entry for every analyzed flow and a detection entry for alerts.

    ``log_traffic`` and ``log_detection`` accept JSON-compatible keyword fields.
    The writer owns ``timestamp`` (UTC) and ``event``. File I/O errors propagate
    so the API can report that it could not durably record the analyzed flow.
    """

    def __init__(
        self,
        log_dir: str | Path | None = None,
        max_bytes: int | None = None,
    ) -> None:
        self.log_dir = Path(
            log_dir if log_dir is not None else os.getenv("SENTINEL_LOG_DIR", DEFAULT_LOG_DIR)
        ).expanduser()
        self.max_bytes = int(
            max_bytes if max_bytes is not None else os.getenv("SENTINEL_LOG_MAX_BYTES", DEFAULT_MAX_BYTES)
        )
        if self.max_bytes <= 0:
            raise ValueError("SENTINEL_LOG_MAX_BYTES must be a positive integer")

        # Fail at startup if the configured volume cannot accept new files.
        self.log_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".audit-check-", dir=self.log_dir):
            pass

        self._loggers: dict[str, logging.Logger] = {}
        for event in ("traffic", "detection"):
            logger = logging.Logger(f"sentinelai.audit.{event}", level=logging.INFO)
            logger.propagate = False
            logger.addHandler(_DailySizeJsonlHandler(event, self.log_dir, self.max_bytes))
            self._loggers[event] = logger

    def _write(self, event: str, fields: dict[str, Any]) -> None:
        payload = {
            "schema_version": 1,
            **fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        self._loggers[event].info("", extra={"audit_payload": payload})

    def log_traffic(self, **fields: Any) -> None:
        """Record one completed inference, including normal traffic."""

        self._write("traffic", fields)

    def log_detection(self, **fields: Any) -> None:
        """Record an anomalous flow and its mitigation outcome."""

        self._write("detection", fields)

    def close(self) -> None:
        """Close open descriptors during FastAPI shutdown or test teardown."""

        for logger in self._loggers.values():
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
                handler.close()
