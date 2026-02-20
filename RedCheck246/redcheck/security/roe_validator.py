"""RedCheck246 — Rules of Engagement (RoE) Validator.

Validates RoE YAML documents for structural integrity, required fields,
time window validity, and optional signature verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yaml

log = structlog.get_logger(__name__)

# Required top-level fields in any valid RoE document
ROE_REQUIRED_FIELDS = [
    "engagement_id",
    "authorizer",
    "authorized_targets",
    "allowed_tests",
    "start_time_utc",
    "end_time_utc",
]

# Optional but recognised fields
ROE_OPTIONAL_FIELDS = [
    "sensitivity",
    "contact",
    "signature",
    "exclusions",
    "notes",
    "max_concurrent",
]


def validate_roe_file(
    path: str | Path,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate an RoE YAML file.

    Returns ``(valid, message, roe_data)`` where *roe_data* is the parsed
    dict on success or an empty dict on failure.
    """
    path = Path(path)

    # 1. File existence
    if not path.exists():
        log.warning("roe_not_found", path=str(path))
        return False, f"RoE file not found: {path}", {}

    if not path.is_file():
        return False, f"RoE path is not a file: {path}", {}

    # 2. Extension check
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False, f"RoE must be a YAML file (.yml/.yaml), got: {path.suffix}", {}

    # 3. Parse YAML
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        log.error("roe_parse_error", path=str(path), error=str(exc))
        return False, f"RoE YAML parse error: {exc}", {}

    if not isinstance(data, dict):
        return False, "RoE must be a YAML mapping (dict), not a list or scalar", {}

    # 4. Required fields
    missing = [f for f in ROE_REQUIRED_FIELDS if f not in data]
    if missing:
        return False, f"Missing required RoE fields: {', '.join(missing)}", {}

    # 5. Field type checks
    if not isinstance(data["authorized_targets"], list):
        return False, "'authorized_targets' must be a list", {}
    if len(data["authorized_targets"]) == 0:
        return False, "'authorized_targets' must contain at least one target", {}

    if not isinstance(data["allowed_tests"], list):
        return False, "'allowed_tests' must be a list", {}
    if len(data["allowed_tests"]) == 0:
        return False, "'allowed_tests' must contain at least one test type", {}

    # 6. Sole authorizer check
    authorizer = data.get("authorizer", "")
    if not authorizer or not str(authorizer).strip():
        return False, "'authorizer' must be a non-empty string", {}

    # 7. Time window validation
    try:
        start = _parse_datetime(data["start_time_utc"])
        end = _parse_datetime(data["end_time_utc"])
    except (ValueError, TypeError) as exc:
        return False, f"Invalid date format in RoE: {exc}", {}

    if end <= start:
        return False, "RoE end_time_utc must be after start_time_utc", {}

    now = datetime.now(timezone.utc)
    if now < start:
        return (
            False,
            f"RoE engagement window has not started yet (starts {start.isoformat()})",
            {},
        )
    if now > end:
        return (
            False,
            f"RoE engagement window has expired (ended {end.isoformat()})",
            {},
        )

    # 8. Signature field presence (verification is done by signature_verifier)
    has_signature = "signature" in data and bool(data["signature"])

    message = "RoE validated successfully"
    if not has_signature:
        message += " (WARNING: no signature field — signature verification skipped)"

    log.info(
        "roe_validated",
        engagement_id=data.get("engagement_id"),
        authorizer=data.get("authorizer"),
        has_signature=has_signature,
    )
    return True, message, data


def _parse_datetime(value: Any) -> datetime:
    """Parse a datetime value from YAML (string or datetime object)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if isinstance(value, str):
        value = value.strip()
        # Handle Z suffix for Python 3.10 compat
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(value, fmt)  # noqa: DTZ007
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        raise ValueError(f"Cannot parse datetime: '{value}'")

    raise TypeError(f"Expected str or datetime, got {type(value).__name__}")
