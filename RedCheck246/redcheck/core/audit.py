"""
RedCheck246 Audit Logger

Append-only, tamper-evident audit logging for all RedCheck operations.
Every action is timestamped (UTC), hashed, and chained to the previous entry.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Append-only audit logger with hash chaining for tamper detection."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, log_path: str | None = None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, log_path: str | None = None):
        if self._initialized:
            return
        self._log_path = Path(log_path or self._default_log_path())
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._previous_hash = self._get_last_hash()
        self._initialized = True

    @property
    def log_path(self) -> Path:
        """Public accessor for the log file path."""
        return self._log_path

    @staticmethod
    def _default_log_path() -> str:
        return os.environ.get(
            "REDCHECK_AUDIT_LOG",
            str(Path(__file__).resolve().parents[2] / "logs" / "audit.log"),
        )

    def _get_last_hash(self) -> str:
        """Read the last entry's hash to continue the chain."""
        if not self._log_path.exists():
            return "GENESIS"
        try:
            with open(self._log_path, encoding="utf-8") as f:
                lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if line and not line.startswith("===") and not line.startswith("---"):
                    try:
                        entry = json.loads(line)
                        return entry.get("hash", "GENESIS")
                    except json.JSONDecodeError:
                        continue
            return "GENESIS"
        except Exception:
            return "GENESIS"

    def _compute_hash(self, entry: dict) -> str:
        """Compute SHA-256 hash of entry + previous hash for chaining."""
        raw = json.dumps(entry, sort_keys=True) + self._previous_hash
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def log(
        self,
        action: str,
        details: str = "",
        operator: str = "system",
        level: str = "INFO",
        plugin: str = "",
        engagement_id: str = "",
    ) -> dict:
        """Append an audit entry. Returns the entry dict."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "action": action,
            "details": details,
            "operator": operator,
            "plugin": plugin,
            "engagement_id": engagement_id,
            "previous_hash": self._previous_hash,
        }
        entry["hash"] = self._compute_hash(entry)
        self._previous_hash = entry["hash"]

        with self._lock:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        return entry

    def log_policy_denial(self, plugin: str, reason: str, engagement_id: str = "") -> dict:
        return self.log(
            action="POLICY_DENIED",
            details=reason,
            level="WARN",
            plugin=plugin,
            engagement_id=engagement_id,
        )

    def log_activation_attempt(self, success: bool, operator: str = "user") -> dict:
        return self.log(
            action="ACTIVATION_ATTEMPT",
            details=f"success={success}",
            operator=operator,
            level="INFO" if success else "WARN",
        )

    def log_engagement_action(self, action: str, engagement_id: str, details: str = "") -> dict:
        return self.log(
            action=action,
            details=details,
            engagement_id=engagement_id,
        )

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the entire audit log chain integrity.

        Returns: (valid, entry_count, message)
        """
        if not self._log_path.exists():
            return True, 0, "No audit log found"

        entries = []
        with open(self._log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(
                    (
                        "===",
                        "---",
                        "Timestamp",
                        "Branch",
                        "HEAD",
                        "On branch",
                        "Untracked",
                        "(use",
                        "nothing",
                        "Python",
                        "pip",
                        "Isolated",
                        "Activation",
                        "origin",
                        "Phase",
                    )
                ):
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        if not entries:
            return True, 0, "No structured entries found"

        prev_hash = "GENESIS"
        for i, entry in enumerate(entries):
            stored_hash = entry.pop("hash", "")
            entry_copy = dict(entry)
            entry_copy["previous_hash"] = prev_hash
            raw = json.dumps(entry_copy, sort_keys=True) + prev_hash
            computed = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            entry["hash"] = stored_hash

            if entry.get("previous_hash") != prev_hash:
                return False, i, f"Chain break at entry {i}: expected prev_hash={prev_hash}"
            if stored_hash != computed:
                return (
                    False,
                    i,
                    f"Hash mismatch at entry {i}: stored={stored_hash} computed={computed}",
                )
            prev_hash = stored_hash

        return True, len(entries), f"Chain valid: {len(entries)} entries verified"


# Module-level convenience instance
_audit: AuditLogger | None = None


def get_audit_logger(log_path: str | None = None) -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = AuditLogger(log_path)
    return _audit
