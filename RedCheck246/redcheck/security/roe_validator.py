"""
RedCheck246 — Rules of Engagement (RoE) Validator

Validates RoE YAML documents for structural integrity, required fields,
time window validity, and optional signature verification.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# Required top-level fields in any valid RoE document
ROE_REQUIRED_FIELDS = [
    "engagement_id",
    "authorizer",
    "authorized_targets",
    "allowed_tests",
    "start_time_utc",
    "end_time_utc",
]

# Optional but recognized fields
ROE_OPTIONAL_FIELDS = [
    "sensitivity",
    "contact",
    "signature",
    "exclusions",
    "notes",
    "max_concurrent",
]


class RoEValidationError(Exception):
    """Raised when RoE validation fails."""

    def __init__(self, message: str, field: str = ""):
        self.field = field
        super().__init__(message)


def validate_roe_file(
    path: str | Path,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate an RoE YAML file.

    Returns: (valid, message, roe_data)
        - valid: True if all checks pass
        - message: Human-readable result
        - roe_data: Parsed RoE dict (empty if invalid)
    """
    path = Path(path)

    # 1. File existence
    if not path.exists():
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
    except yaml.YAMLError as e:
        return False, f"RoE YAML parse error: {e}", {}

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
    except (ValueError, TypeError) as e:
        return False, f"Invalid date format in RoE: {e}", {}

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

    return True, message, data


def _parse_datetime(value: Any) -> datetime:
    """Parse a datetime value from YAML (string or datetime object)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if isinstance(value, str):
        # Try ISO format
        value = value.strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        raise ValueError(f"Cannot parse datetime: '{value}'")

    raise TypeError(f"Expected str or datetime, got {type(value).__name__}")
