"""Tests for MetricsCollector — SQLite persistence, rotation, export."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from redcheck.core.metrics import MetricsCollector


@pytest.fixture
def metrics_db(tmp_path: Path) -> MetricsCollector:
    """Fresh metrics collector with isolated DB."""
    return MetricsCollector(db_path=tmp_path / "test_metrics.db")


class TestMetricsRecord:
    """record() persistence."""

    def test_record_single(self, metrics_db: MetricsCollector):
        metrics_db.record("plugin.execution_time_ms", 42.5)
        rows = metrics_db.query("plugin.execution_time_ms")
        assert len(rows) == 1
        assert rows[0]["value"] == 42.5

    def test_record_with_tags(self, metrics_db: MetricsCollector):
        metrics_db.record("scan.targets_scanned", 5, tags={"plugin": "recon"})
        rows = metrics_db.query("scan.targets_scanned")
        assert rows[0]["tags"] == {"plugin": "recon"}

    def test_record_multiple(self, metrics_db: MetricsCollector):
        for i in range(10):
            metrics_db.record("counter", float(i))
        assert metrics_db.count("counter") == 10

    def test_record_preserves_name(self, metrics_db: MetricsCollector):
        metrics_db.record("plugin.findings_count", 3)
        metrics_db.record("plugin.error_rate", 0.01)
        assert metrics_db.count("plugin.findings_count") == 1
        assert metrics_db.count("plugin.error_rate") == 1

    def test_record_followed_by_select(self, metrics_db: MetricsCollector):
        """record() followed by SELECT returns the row."""
        metrics_db.record("test.metric", 99.9)
        rows = metrics_db.query("test.metric")
        assert len(rows) >= 1
        assert rows[0]["name"] == "test.metric"
        assert rows[0]["value"] == pytest.approx(99.9)


class TestMetricsQuery:
    """query() filtering and ordering."""

    def test_query_all(self, metrics_db: MetricsCollector):
        metrics_db.record("a", 1.0)
        metrics_db.record("b", 2.0)
        rows = metrics_db.query()
        assert len(rows) == 2

    def test_query_limit(self, metrics_db: MetricsCollector):
        for i in range(20):
            metrics_db.record("many", float(i))
        rows = metrics_db.query("many", limit=5)
        assert len(rows) == 5

    def test_query_nonexistent_name(self, metrics_db: MetricsCollector):
        rows = metrics_db.query("nonexistent")
        assert rows == []


class TestFlushSummary:
    """flush_summary() JSON export with digest."""

    def test_summary_creates_file(self, metrics_db: MetricsCollector, tmp_path: Path):
        metrics_db.record("plugin.execution_time_ms", 100)
        metrics_db.record("plugin.execution_time_ms", 200)
        output = tmp_path / "summary.json"
        metrics_db.flush_summary(output)
        assert output.exists()

    def test_summary_valid_json(self, metrics_db: MetricsCollector, tmp_path: Path):
        metrics_db.record("test", 42.0)
        output = tmp_path / "summary.json"
        metrics_db.flush_summary(output)
        with open(output) as f:
            data = json.load(f)
        assert "metrics" in data
        assert "test" in data["metrics"]

    def test_summary_has_digest(self, metrics_db: MetricsCollector, tmp_path: Path):
        metrics_db.record("test", 1.0)
        output = tmp_path / "summary.json"
        metrics_db.flush_summary(output)
        with open(output) as f:
            data = json.load(f)
        assert "sha256_digest" in data
        assert len(data["sha256_digest"]) == 64  # SHA-256 hex

    def test_summary_aggregation(self, metrics_db: MetricsCollector, tmp_path: Path):
        metrics_db.record("m", 10.0)
        metrics_db.record("m", 20.0)
        metrics_db.record("m", 30.0)
        output = tmp_path / "summary.json"
        metrics_db.flush_summary(output)
        with open(output) as f:
            data = json.load(f)
        m = data["metrics"]["m"]
        assert m["count"] == 3
        assert m["avg"] == pytest.approx(20.0)
        assert m["min"] == 10.0
        assert m["max"] == 30.0
        assert m["total"] == pytest.approx(60.0)

    def test_summary_all_metric_names(self, metrics_db: MetricsCollector, tmp_path: Path):
        names = ["plugin.execution_time_ms", "plugin.findings_count", "plugin.error_rate"]
        for n in names:
            metrics_db.record(n, 1.0)
        output = tmp_path / "summary.json"
        metrics_db.flush_summary(output)
        with open(output) as f:
            data = json.load(f)
        for n in names:
            assert n in data["metrics"]


class TestRotation:
    """rotate() archival and fresh DB creation."""

    def test_rotate_creates_archive(self, tmp_path: Path):
        mc = MetricsCollector(db_path=tmp_path / "metrics.db")
        mc.record("pre_rotate", 1.0)
        mc.rotate()
        # Archive file should exist
        archives = list(tmp_path.glob("metrics_archive_*"))
        assert len(archives) == 1

    def test_rotate_fresh_db(self, tmp_path: Path):
        mc = MetricsCollector(db_path=tmp_path / "metrics.db")
        mc.record("pre_rotate", 1.0)
        mc.rotate()
        # Fresh DB should be empty
        assert mc.count() == 0

    def test_rotate_preserves_old_data(self, tmp_path: Path):
        mc = MetricsCollector(db_path=tmp_path / "metrics.db")
        mc.record("old_data", 42.0)
        mc.rotate()
        # Old data in archive
        archives = list(tmp_path.glob("metrics_archive_*"))
        archive_mc = MetricsCollector(db_path=archives[0])
        rows = archive_mc.query("old_data")
        assert len(rows) == 1
        assert rows[0]["value"] == 42.0


class TestConcurrentWrites:
    """Atomic writes under concurrent access."""

    def test_concurrent_record_no_corruption(self, tmp_path: Path):
        mc = MetricsCollector(db_path=tmp_path / "concurrent.db")
        errors: list[Exception] = []

        def worker(worker_id: int) -> None:
            try:
                for i in range(20):
                    mc.record(f"worker.{worker_id}", float(i))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent writes: {errors}"
        total = mc.count()
        assert total == 100  # 5 workers × 20 records
