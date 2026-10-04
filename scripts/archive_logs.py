#!/usr/bin/env python3
"""Archive old SentinelAI JSONL logs from cron.

Each eligible ``.log`` becomes one ``.log.tar.gz``. The archive is written to a
temporary file, read back and checked against the source SHA-256, and published
atomically before the source is removed. Re-running after a crash safely
verifies an existing archive before removing a leftover source file.
"""

from __future__ import annotations

import argparse
import calendar
import fcntl
import gzip
import hashlib
import os
import re
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO


DEFAULT_LOG_DIR = Path(__file__).resolve().parents[1] / "SentinelAI-Backend" / "logs"
MANAGED_LOG_NAME = re.compile(
    r"^(?:traffic|detection)-(\d{8})-\d+-[0-9a-f]{12}-\d{6}\.log$"
)
BUFFER_SIZE = 1024 * 1024


@dataclass
class ArchiveReport:
    archived: list[Path] = field(default_factory=list)
    skipped_busy: list[Path] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)


class ArchiveBusy(Exception):
    """A previous cron invocation still holds the directory lock."""


class _HashingReader:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        chunk = self.source.read(size)
        self.digest.update(chunk)
        return chunk


def _months_ago(now: datetime, months: int) -> datetime:
    if months <= 0:
        raise ValueError("months must be positive")
    month_index = now.year * 12 + now.month - 1 - months
    year, zero_based_month = divmod(month_index, 12)
    month = zero_based_month + 1
    day = min(now.day, calendar.monthrange(year, month)[1])
    return now.replace(year=year, month=month, day=day)


def _digest_source(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), "rb") as source:
        while chunk := source.read(BUFFER_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_archive(path: Path, member_name: str, size: int, digest: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"archive path is not a regular file: {path}")
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != 1 or members[0].name != member_name:
            raise ValueError(f"archive has unexpected members: {path}")
        member = members[0]
        if not member.isfile() or member.size != size:
            raise ValueError(f"archive member size/type mismatch: {path}")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise ValueError(f"archive member cannot be read: {path}")
        actual = hashlib.sha256()
        total = 0
        with extracted:
            while chunk := extracted.read(BUFFER_SIZE):
                actual.update(chunk)
                total += len(chunk)
        if total != size or actual.hexdigest() != digest:
            raise ValueError(f"archive content does not match source: {path}")

    # Consume the gzip trailer too, so CRC or truncation errors prevent deletion.
    with gzip.open(path, "rb") as compressed:
        while compressed.read(BUFFER_SIZE):
            pass


def _same_source(path: Path, fd: int, original: os.stat_result) -> bool:
    current = os.fstat(fd)
    try:
        named = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    expected = (
        original.st_dev,
        original.st_ino,
        original.st_size,
        original.st_mtime_ns,
    )
    return all(
        (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        ) == expected
        for item in (current, named)
    )


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _archive_one(source_path: Path, archive_dir: Path, cutoff: datetime, now: datetime) -> Path | None:
    match = MANAGED_LOG_NAME.fullmatch(source_path.name)
    if match is None:
        return None
    file_day = datetime.strptime(match.group(1), "%Y%m%d").date()
    if file_day >= now.date():
        return None  # A current-day file may still be open for writing.

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(source_path, flags)
    except FileNotFoundError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ArchiveBusy(source_path.name) from None

        original = os.fstat(fd)
        if not stat.S_ISREG(original.st_mode) or original.st_mtime >= cutoff.timestamp():
            return None
        if not _same_source(source_path, fd, original):
            raise RuntimeError("source changed before archiving")

        archive_path = archive_dir / f"{source_path.name}.tar.gz"
        created = False
        if archive_path.exists() or archive_path.is_symlink():
            digest = _digest_source(fd)
            _verify_archive(archive_path, source_path.name, original.st_size, digest)
        else:
            temp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w+b", prefix=f".{source_path.name}.", suffix=".tmp",
                    dir=archive_dir, delete=False,
                ) as temporary:
                    temp_path = Path(temporary.name)
                    os.lseek(fd, 0, os.SEEK_SET)
                    with os.fdopen(os.dup(fd), "rb") as source:
                        hashing_source = _HashingReader(source)
                        member = tarfile.TarInfo(source_path.name)
                        member.size = original.st_size
                        member.mtime = int(original.st_mtime)
                        member.mode = stat.S_IMODE(original.st_mode)
                        member.uid = 0
                        member.gid = 0
                        with tarfile.open(fileobj=temporary, mode="w:gz") as archive:
                            archive.addfile(member, hashing_source)
                    digest = hashing_source.digest.hexdigest()
                    temporary.flush()
                    os.fsync(temporary.fileno())

                _verify_archive(temp_path, source_path.name, original.st_size, digest)
                if not _same_source(source_path, fd, original):
                    raise RuntimeError("source changed while archiving")
                # A hard link publishes without overwriting an existing archive.
                os.link(temp_path, archive_path)
                created = True
                _sync_directory(archive_dir)
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)

        if not _same_source(source_path, fd, original):
            if created:
                archive_path.unlink(missing_ok=True)
            raise RuntimeError("source changed before deletion")
        source_path.unlink()
        _sync_directory(source_path.parent)
        return archive_path
    finally:
        os.close(fd)


def archive_old_logs(
    log_dir: str | Path,
    archive_dir: str | Path | None = None,
    *,
    months: int = 6,
    now: datetime | None = None,
) -> ArchiveReport:
    """Archive managed logs whose last modification is older than N calendar months."""

    log_dir = Path(log_dir).expanduser()
    archive_dir = Path(archive_dir).expanduser() if archive_dir else log_dir / "archive"
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    now = now.astimezone(timezone.utc)
    cutoff = _months_ago(now, months)
    if not log_dir.is_dir():
        raise FileNotFoundError(f"log directory does not exist: {log_dir}")
    archive_dir.mkdir(mode=0o750, parents=True, exist_ok=True)

    report = ArchiveReport()
    lock_fd = os.open(log_dir / ".archive.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ArchiveBusy("another archival job is running") from None
        for source_path in sorted(log_dir.glob("*.log")):
            try:
                result = _archive_one(source_path, archive_dir, cutoff, now)
                if result is not None:
                    report.archived.append(result)
            except ArchiveBusy:
                report.skipped_busy.append(source_path)
            except Exception as exc:
                report.errors.append((source_path, str(exc)))
        return report
    finally:
        os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log-dir", default=os.getenv("SENTINEL_LOG_DIR", str(DEFAULT_LOG_DIR)),
        help="directory containing the live .log files",
    )
    parser.add_argument(
        "--archive-dir", default=os.getenv("SENTINEL_ARCHIVE_DIR"),
        help="destination for .tar.gz files (default: <log-dir>/archive)",
    )
    parser.add_argument("--months", type=int, default=6, help="retention in calendar months")
    args = parser.parse_args(argv)
    try:
        report = archive_old_logs(args.log_dir, args.archive_dir, months=args.months)
    except ArchiveBusy as exc:
        print(f"SentinelAI archival skipped: {exc}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"SentinelAI archival failed: {exc}", file=sys.stderr)
        return 1

    for path in report.archived:
        print(f"archived {path}")
    for path in report.skipped_busy:
        print(f"busy, retry next run: {path}", file=sys.stderr)
    for path, error in report.errors:
        print(f"failed {path}: {error}", file=sys.stderr)
    print(
        f"SentinelAI archival: {len(report.archived)} archived, "
        f"{len(report.skipped_busy)} busy, {len(report.errors)} failed"
    )
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
