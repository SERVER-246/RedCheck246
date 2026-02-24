"""Tests for RoE validator — all validation paths and edge cases."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from redcheck.security.roe_validator import _parse_datetime, validate_roe_file


def _write_roe(path: Path, data: dict) -> Path:
    roe_file = path / "roe.yml"
    roe_file.write_text(yaml.dump(data), encoding="utf-8")
    return roe_file


def _valid_roe() -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "engagement_id": "ENG-1",
        "authorizer": "admin@test.com",
        "authorized_targets": ["10.0.0.1"],
        "allowed_tests": ["recon"],
        "start_time_utc": (now - timedelta(hours=1)).isoformat(),
        "end_time_utc": (now + timedelta(hours=1)).isoformat(),
        "signature": "abc123",
    }


class TestValidateRoeFile:
    def test_valid_roe(self, tmp_path: Path) -> None:
        roe_file = _write_roe(tmp_path, _valid_roe())
        valid, msg, data = validate_roe_file(roe_file)
        assert valid
        assert "validated" in msg.lower()

    def test_file_not_found(self, tmp_path: Path) -> None:
        valid, msg, data = validate_roe_file(tmp_path / "nope.yml")
        assert not valid
        assert "not found" in msg.lower()

    def test_not_a_file(self, tmp_path: Path) -> None:
        valid, msg, _ = validate_roe_file(tmp_path)
        assert not valid
        assert "not a file" in msg.lower()

    def test_wrong_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.txt"
        f.write_text("data", encoding="utf-8")
        valid, msg, _ = validate_roe_file(f)
        assert not valid
        assert "YAML file" in msg

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.yml"
        f.write_text("{{bad yaml: [", encoding="utf-8")
        valid, msg, _ = validate_roe_file(f)
        assert not valid
        assert "parse error" in msg.lower()

    def test_not_a_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.yml"
        f.write_text("- item1\n- item2", encoding="utf-8")
        valid, msg, _ = validate_roe_file(f)
        assert not valid
        assert "mapping" in msg.lower()

    def test_missing_fields(self, tmp_path: Path) -> None:
        roe_file = _write_roe(tmp_path, {"engagement_id": "E1"})
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "Missing" in msg

    def test_targets_not_list(self, tmp_path: Path) -> None:
        d = _valid_roe()
        d["authorized_targets"] = "single"
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "list" in msg.lower()

    def test_targets_empty(self, tmp_path: Path) -> None:
        d = _valid_roe()
        d["authorized_targets"] = []
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "at least one" in msg.lower()

    def test_tests_not_list(self, tmp_path: Path) -> None:
        d = _valid_roe()
        d["allowed_tests"] = "single"
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "list" in msg.lower()

    def test_tests_empty(self, tmp_path: Path) -> None:
        d = _valid_roe()
        d["allowed_tests"] = []
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "at least one" in msg.lower()

    def test_authorizer_empty(self, tmp_path: Path) -> None:
        d = _valid_roe()
        d["authorizer"] = "  "
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "non-empty" in msg.lower()

    def test_invalid_date(self, tmp_path: Path) -> None:
        d = _valid_roe()
        d["start_time_utc"] = "not-a-date"
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "date" in msg.lower() or "parse" in msg.lower() or "Invalid" in msg

    def test_end_before_start(self, tmp_path: Path) -> None:
        d = _valid_roe()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        d["start_time_utc"] = (now + timedelta(hours=2)).isoformat()
        d["end_time_utc"] = (now + timedelta(hours=1)).isoformat()
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "after" in msg.lower()

    def test_not_yet_started(self, tmp_path: Path) -> None:
        d = _valid_roe()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        d["start_time_utc"] = (now + timedelta(hours=1)).isoformat()
        d["end_time_utc"] = (now + timedelta(hours=2)).isoformat()
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "not started" in msg.lower()

    def test_expired(self, tmp_path: Path) -> None:
        d = _valid_roe()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        d["start_time_utc"] = (now - timedelta(hours=2)).isoformat()
        d["end_time_utc"] = (now - timedelta(hours=1)).isoformat()
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert not valid
        assert "expired" in msg.lower()

    def test_no_signature_warning(self, tmp_path: Path) -> None:
        d = _valid_roe()
        del d["signature"]
        roe_file = _write_roe(tmp_path, d)
        valid, msg, _ = validate_roe_file(roe_file)
        assert valid
        assert "no signature" in msg.lower() or "WARNING" in msg


class TestParseDatetime:
    def test_datetime_object_with_tz(self) -> None:
        dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
        assert _parse_datetime(dt) == dt

    def test_datetime_object_naive(self) -> None:
        dt = datetime(2025, 1, 1)  # noqa: DTZ001
        result = _parse_datetime(dt)
        assert result.tzinfo == timezone.utc

    def test_iso_string_with_z(self) -> None:
        result = _parse_datetime("2025-01-01T00:00:00Z")
        assert result.year == 2025
        assert result.tzinfo is not None

    def test_iso_string_with_offset(self) -> None:
        result = _parse_datetime("2025-01-01T00:00:00+00:00")
        assert result.year == 2025

    def test_datetime_string_no_tz(self) -> None:
        result = _parse_datetime("2025-01-01 00:00:00")
        assert result.tzinfo == timezone.utc

    def test_iso_no_tz(self) -> None:
        result = _parse_datetime("2025-01-01T00:00:00")
        assert result.tzinfo == timezone.utc

    def test_invalid_string(self) -> None:
        with pytest.raises(ValueError, match="not-a-date"):
            _parse_datetime("not-a-date")

    def test_invalid_type(self) -> None:
        with pytest.raises(TypeError):
            _parse_datetime(12345)
