"""Tests for PolicyEngine — denial, authorization, and RoE validation."""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from redcheck.core.policy_engine import PolicyDeniedException, PolicyEngine


@pytest.fixture
def engine():
    """Fresh policy engine for each test."""
    return PolicyEngine()


@pytest.fixture
def valid_roe_file(tmp_path):
    """Create a valid RoE YAML file in a temp directory."""
    now = datetime.now(timezone.utc)
    roe = {
        "engagement_id": "TEST-001",
        "authorizer": "Test Admin",
        "authorized_targets": [
            {"host": "testhost.local", "ports": [80, 443]}
        ],
        "allowed_tests": ["passive-recon", "sast-scanner"],
        "start_time_utc": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensitivity": "high",
        "signature": "test-signature",
    }
    path = tmp_path / "roe.yaml"
    with open(path, "w") as f:
        yaml.dump(roe, f)
    return path


@pytest.fixture
def expired_roe_file(tmp_path):
    """Create an expired RoE file."""
    now = datetime.now(timezone.utc)
    roe = {
        "engagement_id": "TEST-EXPIRED",
        "authorizer": "Test Admin",
        "authorized_targets": [{"host": "expired.local"}],
        "allowed_tests": ["passive-recon"],
        "start_time_utc": (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time_utc": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = tmp_path / "expired_roe.yaml"
    with open(path, "w") as f:
        yaml.dump(roe, f)
    return path


class TestPolicyEngine:
    """Policy engine validation tests."""

    def test_valid_roe_passes(self, engine, valid_roe_file):
        valid, message, data = engine.validate_roe(valid_roe_file)
        assert valid is True
        assert data["engagement_id"] == "TEST-001"

    def test_missing_roe_file_denied(self, engine):
        valid, message, data = engine.validate_roe("/nonexistent/roe.yaml")
        assert valid is False
        assert "not found" in message.lower()

    def test_expired_roe_denied(self, engine, expired_roe_file):
        valid, message, data = engine.validate_roe(expired_roe_file)
        assert valid is False
        assert "expired" in message.lower()

    def test_missing_fields_denied(self, engine, tmp_path):
        # RoE with missing required fields
        roe = {"engagement_id": "INCOMPLETE"}
        path = tmp_path / "bad_roe.yaml"
        with open(path, "w") as f:
            yaml.dump(roe, f)
        valid, message, _ = engine.validate_roe(path)
        assert valid is False
        assert "missing" in message.lower()

    def test_authorize_raises_without_roe(self, engine):
        """Authorize should deny when no RoE is loaded."""
        with pytest.raises(PolicyDeniedException):
            engine.authorize(
                plugin_name="test-plugin",
                engagement={},
                requires_authorization=True,
            )

    def test_authorize_passes_with_no_auth_required(self, engine):
        """Plugins that don't require auth should always pass."""
        # Should not raise
        engine.authorize(
            plugin_name="info-only",
            engagement={},
            requires_authorization=False,
        )

    def test_activation_code_validation(self, engine, tmp_path):
        """Activation code flow."""
        from redcheck.core.activation_engine import ActivationEngine

        ae = ActivationEngine(base_dir=str(tmp_path))
        ok, msg = ae.set_code("Test@Code123!")
        assert ok is True
        assert ae.verify_code("Test@Code123!")
        assert not ae.verify_code("wrong-code")
