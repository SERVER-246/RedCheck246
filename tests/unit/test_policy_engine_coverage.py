"""Tests for PolicyEngine — RoE validation, activation, authorization gate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from redcheck.core.policy_engine import PolicyEngine
from redcheck.exceptions import PolicyDeniedException


def _write_roe(path: Path, data: dict) -> Path:
    roe_file = path / "roe.yml"
    roe_file.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return roe_file


def _valid_roe_data() -> dict:
    now = datetime.now(timezone.utc)
    return {
        "engagement_id": "ENG-1",
        "authorizer": "admin@test.com",
        "authorized_targets": ["10.0.0.1"],
        "allowed_tests": ["recon", "sast"],
        "start_time_utc": (now - timedelta(hours=1)).isoformat(),
        "end_time_utc": (now + timedelta(hours=1)).isoformat(),
        "signature": "abc123",
    }


class TestPolicyEngineValidateRoE:
    def test_valid_roe(self, tmp_path: Path) -> None:
        pe = PolicyEngine()
        roe_file = _write_roe(tmp_path, _valid_roe_data())
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid
        assert data["engagement_id"] == "ENG-1"

    def test_file_not_found(self, tmp_path: Path) -> None:
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(tmp_path / "nope.yml")
        assert not valid

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.yml"
        f.write_text("{{{{", encoding="utf-8")
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(f)
        assert not valid

    def test_not_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.yml"
        f.write_text("- list\n", encoding="utf-8")
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(f)
        assert not valid

    def test_missing_fields(self, tmp_path: Path) -> None:
        roe_file = _write_roe(tmp_path, {"engagement_id": "E1"})
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(roe_file)
        assert not valid
        assert "Missing" in msg

    def test_empty_authorizer(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["authorizer"] = "  "
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(roe_file)
        assert not valid

    def test_targets_not_list(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["authorized_targets"] = "single"
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(roe_file)
        assert not valid

    def test_expired_roe(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        now = datetime.now(timezone.utc)
        d["start_time_utc"] = (now - timedelta(hours=2)).isoformat()
        d["end_time_utc"] = (now - timedelta(hours=1)).isoformat()
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert not valid
        assert "expired" in msg.lower()

    def test_no_signature_field(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        del d["signature"]
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert not valid
        assert "signature" in msg.lower()

    def test_z_suffix_times(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        now = datetime.now(timezone.utc)
        d["start_time_utc"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["end_time_utc"] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(roe_file)
        assert valid

    def test_invalid_time_format(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["start_time_utc"] = "not-a-date"
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, _ = pe.validate_roe(roe_file)
        assert not valid


class TestPolicyEngineActivation:
    def test_validate_activation_code(self) -> None:
        pe = PolicyEngine()
        mock_engine = MagicMock()
        mock_engine.verify_code.return_value = True
        with patch(
            "redcheck.core.activation_engine.get_activation_engine",
            return_value=mock_engine,
        ):
            result = pe.validate_activation_code("CODE-123")
        assert result is True

    def test_validate_activation_code_failure(self) -> None:
        pe = PolicyEngine()
        mock_engine = MagicMock()
        mock_engine.verify_code.return_value = False
        with patch(
            "redcheck.core.activation_engine.get_activation_engine",
            return_value=mock_engine,
        ):
            result = pe.validate_activation_code("BAD")
        assert result is False


class TestPolicyEngineAuthorize:
    def test_no_auth_required(self) -> None:
        pe = PolicyEngine()
        pe.authorize("plugin", requires_authorization=False)

    def test_no_engagement(self) -> None:
        pe = PolicyEngine()
        try:
            pe.authorize("plugin", engagement=None)
            assert False
        except PolicyDeniedException:
            pass

    def test_roe_not_validated(self) -> None:
        pe = PolicyEngine()
        try:
            pe.authorize("plugin", engagement={"roe_validated": False})
            assert False
        except PolicyDeniedException:
            pass

    def test_activation_not_verified(self) -> None:
        pe = PolicyEngine()
        try:
            pe.authorize("plugin", engagement={"roe_validated": True, "activation_verified": False})
            assert False
        except PolicyDeniedException:
            pass

    def test_plugin_not_in_allowed_tests(self) -> None:
        now = datetime.now(timezone.utc)
        pe = PolicyEngine()
        try:
            pe.authorize(
                "exploit",
                engagement={
                    "roe_validated": True,
                    "activation_verified": True,
                    "allowed_tests": ["recon"],
                    "start_time_utc": (now - timedelta(hours=1)).isoformat(),
                    "end_time_utc": (now + timedelta(hours=1)).isoformat(),
                },
            )
            assert False
        except PolicyDeniedException:
            pass

    def test_authorized_success(self) -> None:
        now = datetime.now(timezone.utc)
        pe = PolicyEngine()
        pe.authorize(
            "recon",
            engagement={
                "roe_validated": True,
                "activation_verified": True,
                "allowed_tests": ["recon"],
                "start_time_utc": (now - timedelta(hours=1)).isoformat(),
                "end_time_utc": (now + timedelta(hours=1)).isoformat(),
            },
        )

    def test_outside_time_window(self) -> None:
        now = datetime.now(timezone.utc)
        pe = PolicyEngine()
        try:
            pe.authorize(
                "recon",
                engagement={
                    "roe_validated": True,
                    "activation_verified": True,
                    "allowed_tests": ["recon"],
                    "start_time_utc": (now + timedelta(hours=1)).isoformat(),
                    "end_time_utc": (now + timedelta(hours=2)).isoformat(),
                },
            )
            assert False
        except PolicyDeniedException:
            pass

    def test_invalid_time_in_engagement(self) -> None:
        pe = PolicyEngine()
        try:
            pe.authorize(
                "recon",
                engagement={
                    "roe_validated": True,
                    "activation_verified": True,
                    "allowed_tests": ["recon"],
                    "start_time_utc": "bad",
                    "end_time_utc": "bad",
                },
            )
            assert False
        except PolicyDeniedException:
            pass
