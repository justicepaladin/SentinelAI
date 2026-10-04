"""Safety checks for the local audit writer and six-month archive job."""

from __future__ import annotations

import fcntl
import json
import os
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "SentinelAI-Backend"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from archive_logs import ArchiveBusy, archive_old_logs  # noqa: E402
from traffic_logging import AuditLogWriter  # noqa: E402


class AuditLogWriterTests(unittest.TestCase):
    def test_json_lines_rotate_by_size_and_separate_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = AuditLogWriter(directory, max_bytes=170)
            try:
                for index in range(3):
                    writer.log_traffic(
                        source_ip=f"192.0.2.{index + 1}",
                        destination_ip="198.51.100.10",
                        destination_port=443,
                        features=[1.0, 2.0],
                        mse_score=0.001,
                        anomaly=index == 2,
                    )
                writer.log_detection(
                    source_ip="192.0.2.3", mse_score=0.001,
                    mitigation_applied=True,
                )
            finally:
                writer.close()

            traffic_files = sorted(Path(directory).glob("traffic-*.log"))
            detection_files = sorted(Path(directory).glob("detection-*.log"))
            self.assertEqual(len(traffic_files), 3)
            self.assertEqual(len(detection_files), 1)
            traffic = [json.loads(path.read_text()) for path in traffic_files]
            self.assertEqual([row["source_ip"] for row in traffic], [
                "192.0.2.1", "192.0.2.2", "192.0.2.3",
            ])
            self.assertTrue(all(row["event"] == "traffic" for row in traffic))
            self.assertTrue(all(row["timestamp"].endswith("+00:00") for row in traffic))
            self.assertEqual(json.loads(detection_files[0].read_text())["event"], "detection")

    def test_rotates_at_utc_day_boundary(self) -> None:
        class FakeDatetime(datetime):
            current = datetime(2026, 10, 3, 23, 59, tzinfo=timezone.utc)

            @classmethod
            def now(cls, tz=None):
                return cls.current.astimezone(tz)

        with tempfile.TemporaryDirectory() as directory:
            with patch("traffic_logging.datetime", FakeDatetime):
                writer = AuditLogWriter(directory)
                try:
                    writer.log_traffic(source_ip="192.0.2.1")
                    FakeDatetime.current = datetime(2026, 10, 4, 0, 0, tzinfo=timezone.utc)
                    writer.log_traffic(source_ip="192.0.2.2")
                finally:
                    writer.close()
            self.assertEqual(len(list(Path(directory).glob("traffic-20261003-*.log"))), 1)
            self.assertEqual(len(list(Path(directory).glob("traffic-20261004-*.log"))), 1)


class ArchiveTests(unittest.TestCase):
    NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
    OLD_NAME = "traffic-20260301-123-abcdef123456-000000.log"

    def _write_log(self, directory: Path, name: str, mtime: datetime, data: bytes) -> Path:
        path = directory / name
        path.write_bytes(data)
        timestamp = mtime.timestamp()
        os.utime(path, (timestamp, timestamp))
        return path

    def test_archives_old_logs_then_deletes_only_verified_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory)
            payload = b'{"event":"traffic"}\n'
            old = self._write_log(
                log_dir, self.OLD_NAME,
                datetime(2026, 3, 1, tzinfo=timezone.utc), payload,
            )
            fresh = self._write_log(
                log_dir, "detection-20260901-123-abcdef123456-000000.log",
                datetime(2026, 9, 1, tzinfo=timezone.utc), payload,
            )
            current_day = self._write_log(
                log_dir, "traffic-20261004-123-abcdef123456-000000.log",
                datetime(2026, 3, 1, tzinfo=timezone.utc), payload,
            )
            unrelated = self._write_log(
                log_dir, "application.log",
                datetime(2026, 3, 1, tzinfo=timezone.utc), payload,
            )

            report = archive_old_logs(log_dir, now=self.NOW)
            self.assertEqual(len(report.archived), 1)
            self.assertFalse(report.errors)
            self.assertFalse(old.exists())
            self.assertTrue(fresh.exists())
            self.assertTrue(current_day.exists())
            self.assertTrue(unrelated.exists())
            archive_path = report.archived[0]
            with tarfile.open(archive_path, "r:gz") as archive:
                self.assertEqual(archive.extractfile(self.OLD_NAME).read(), payload)

            # Simulate a crash after archive publication but before deletion.
            old = self._write_log(
                log_dir, self.OLD_NAME,
                datetime(2026, 3, 1, tzinfo=timezone.utc), payload,
            )
            second = archive_old_logs(log_dir, now=self.NOW)
            self.assertEqual(second.archived, [archive_path])
            self.assertFalse(old.exists())

    def test_corrupt_archive_or_failed_verification_preserves_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory)
            source = self._write_log(
                log_dir, self.OLD_NAME,
                datetime(2026, 3, 1, tzinfo=timezone.utc), b"important\n",
            )
            with patch("archive_logs._verify_archive", side_effect=ValueError("bad archive")):
                report = archive_old_logs(log_dir, now=self.NOW)
            self.assertEqual(len(report.errors), 1)
            self.assertTrue(source.exists())
            self.assertEqual(list((log_dir / "archive").iterdir()), [])

            (log_dir / "archive" / f"{self.OLD_NAME}.tar.gz").write_bytes(b"broken")
            report = archive_old_logs(log_dir, now=self.NOW)
            self.assertEqual(len(report.errors), 1)
            self.assertTrue(source.exists())

    def test_second_cron_run_does_not_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = os.open(Path(directory) / ".archive.lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(ArchiveBusy):
                    archive_old_logs(directory, now=self.NOW)
            finally:
                os.close(lock)


if __name__ == "__main__":
    unittest.main()
