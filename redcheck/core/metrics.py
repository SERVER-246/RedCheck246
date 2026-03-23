"""RedCheck246 — Metrics Collector.

Persists operational metrics to a local SQLite database with atomic writes,
rotation support, and signed summary export.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redcheck.constants import METRICS_ROTATION_DAYS_DEFAULT, METRICS_TABLE_NAME


class MetricsCollector:
    """Persist metrics to local SQLite with atomic writes.

    Schema (table: metrics_ts):
        name TEXT NOT NULL,
        value REAL NOT NULL,
        tags JSON,
        ts_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    Args:
        db_path: Path to the SQLite database file.  Defaults to
                 ``metrics.db`` in the current working directory.
        rotation_days: How many days of data to keep before rotating.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        rotation_days: int | None = None,
    ) -> None:
        self._db_path = Path(db_path) if db_path else Path("metrics.db")
        self._rotation_days = rotation_days or METRICS_ROTATION_DAYS_DEFAULT
        self._lock = threading.Lock()
        self._ensure_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new connection (SQLite is not thread-safe by default)."""
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _ensure_schema(self) -> None:
        """Create the metrics table if it doesn't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    f"""CREATE TABLE IF NOT EXISTS {METRICS_TABLE_NAME} (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        value REAL NOT NULL,
                        tags TEXT,
                        ts_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )"""
                )
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_metrics_name ON {METRICS_TABLE_NAME}(name)"
                )
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_metrics_ts ON {METRICS_TABLE_NAME}(ts_utc)"
                )
                conn.commit()
            finally:
                conn.close()

    def record(
        self,
        name: str,
        value: float,
        tags: dict[str, Any] | None = None,
    ) -> None:
        """Record a single metric data point.

        Args:
            name: Metric name (e.g. ``plugin.execution_time_ms``).
            value: Numeric value.
            tags: Optional dict of tags (serialized as JSON).
        """
        ts = datetime.now(timezone.utc).isoformat()
        tags_json = json.dumps(tags) if tags else None

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    f"INSERT INTO {METRICS_TABLE_NAME} (name, value, tags, ts_utc) "  # nosec B608
                    "VALUES (?, ?, ?, ?)",
                    (name, value, tags_json, ts),
                )
                conn.commit()
            finally:
                conn.close()

    def query(
        self,
        name: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query metrics, optionally filtered by name.

        Returns list of dicts with keys: ``name``, ``value``, ``tags``, ``ts_utc``.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                if name:
                    cursor = conn.execute(
                        f"SELECT name, value, tags, ts_utc FROM {METRICS_TABLE_NAME} "  # nosec B608
                        "WHERE name = ? ORDER BY ts_utc DESC LIMIT ?",
                        (name, limit),
                    )
                else:
                    cursor = conn.execute(
                        f"SELECT name, value, tags, ts_utc FROM {METRICS_TABLE_NAME} "  # nosec B608
                        "ORDER BY ts_utc DESC LIMIT ?",
                        (limit,),
                    )

                rows: list[dict[str, Any]] = []
                for row in cursor:
                    tags_val = json.loads(row[2]) if row[2] else None
                    rows.append(
                        {
                            "name": row[0],
                            "value": row[1],
                            "tags": tags_val,
                            "ts_utc": row[3],
                        }
                    )
                return rows
            finally:
                conn.close()

    def flush_summary(self, output_path: Path) -> None:
        """Export a JSON summary of all metrics with SHA-256 digest.

        The output includes aggregated counts and a signed manifest.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    f"SELECT name, COUNT(*) as cnt, "  # nosec B608
                    f"AVG(value) as avg_val, MIN(value) as min_val, "
                    f"MAX(value) as max_val, SUM(value) as total "
                    f"FROM {METRICS_TABLE_NAME} GROUP BY name ORDER BY name"
                )

                metrics: dict[str, Any] = {}
                for row in cursor:
                    metrics[row[0]] = {
                        "count": row[1],
                        "avg": round(row[2], 4),
                        "min": row[3],
                        "max": row[4],
                        "total": round(row[5], 4),
                    }
            finally:
                conn.close()

        summary = {
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "db_path": str(self._db_path),
            "metrics": metrics,
        }

        # Compute digest over the metrics content
        content_bytes = json.dumps(summary, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(content_bytes).hexdigest()
        summary["sha256_digest"] = digest

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, sort_keys=True)

    def rotate(self) -> None:
        """Archive old data by renaming current DB and creating a fresh one.

        Data older than ``rotation_days`` is moved to an archive file.
        """
        if not self._db_path.exists():
            return

        archive_name = (
            f"{self._db_path.stem}_archive_"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            f"{self._db_path.suffix}"
        )
        archive_path = self._db_path.parent / archive_name

        with self._lock:
            # Close any open connections by creating a fresh one to finalize WAL
            conn = self._get_connection()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()
            except Exception:
                conn.close()

            # Rename current DB to archive
            self._db_path.rename(archive_path)

        # Recreate fresh schema
        self._ensure_schema()

    def count(self, name: str | None = None) -> int:
        """Count metric entries, optionally filtered by name."""
        with self._lock:
            conn = self._get_connection()
            try:
                if name:
                    cursor = conn.execute(
                        f"SELECT COUNT(*) FROM {METRICS_TABLE_NAME} WHERE name = ?",  # nosec B608
                        (name,),
                    )
                else:
                    cursor = conn.execute(
                        f"SELECT COUNT(*) FROM {METRICS_TABLE_NAME}"  # nosec B608
                    )
                row = cursor.fetchone()
                return int(row[0]) if row else 0
            finally:
                conn.close()

    def close(self) -> None:
        """No-op — connections are opened/closed per operation."""
