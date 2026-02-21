"""Tests for PluginMetadata model — validation, bounds, frozen."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redcheck.models import PluginCapability, PluginMetadata

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


class TestPluginMetadataDefaults:
    """Default field values."""

    def test_minimal_creation(self):
        pm = PluginMetadata(name="test-plugin", capability=PluginCapability.PASSIVE)
        assert pm.name == "test-plugin"
        assert pm.capability == PluginCapability.PASSIVE
        assert pm.required_controls == []
        assert pm.timeout_seconds == 60
        assert pm.rate_limit_rps == 10
        assert pm.mitre_techniques == []
        assert pm.requires_isolation is False

    def test_full_creation(self):
        pm = PluginMetadata(
            name="adv-scanner",
            capability=PluginCapability.ACTIVE,
            required_controls=["allow_auth_testing"],
            timeout_seconds=120,
            rate_limit_rps=20,
            mitre_techniques=["T1046"],
            requires_isolation=True,
        )
        assert pm.timeout_seconds == 120
        assert pm.requires_isolation is True


# ---------------------------------------------------------------------------
# Frozen
# ---------------------------------------------------------------------------


class TestPluginMetadataFrozen:
    """Frozen model rejects mutation."""

    def test_mutation_rejected(self):
        pm = PluginMetadata(name="test", capability=PluginCapability.PASSIVE)
        with pytest.raises(ValidationError):
            pm.name = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Bound validation
# ---------------------------------------------------------------------------


class TestPluginMetadataBounds:
    """timeout_seconds ∈ [1, 600], rate_limit_rps ∈ [1, 50]."""

    # timeout_seconds
    def test_timeout_lower_bound_valid(self):
        pm = PluginMetadata(name="t", capability=PluginCapability.PASSIVE, timeout_seconds=1)
        assert pm.timeout_seconds == 1

    def test_timeout_upper_bound_valid(self):
        pm = PluginMetadata(name="t", capability=PluginCapability.PASSIVE, timeout_seconds=600)
        assert pm.timeout_seconds == 600

    def test_timeout_zero_rejected(self):
        with pytest.raises(ValidationError):
            PluginMetadata(name="t", capability=PluginCapability.PASSIVE, timeout_seconds=0)

    def test_timeout_over_cap_rejected(self):
        with pytest.raises(ValidationError):
            PluginMetadata(name="t", capability=PluginCapability.PASSIVE, timeout_seconds=601)

    # rate_limit_rps
    def test_rate_limit_lower_bound_valid(self):
        pm = PluginMetadata(name="t", capability=PluginCapability.PASSIVE, rate_limit_rps=1)
        assert pm.rate_limit_rps == 1

    def test_rate_limit_upper_bound_valid(self):
        pm = PluginMetadata(name="t", capability=PluginCapability.PASSIVE, rate_limit_rps=50)
        assert pm.rate_limit_rps == 50

    def test_rate_limit_zero_rejected(self):
        with pytest.raises(ValidationError):
            PluginMetadata(name="t", capability=PluginCapability.PASSIVE, rate_limit_rps=0)

    def test_rate_limit_over_cap_rejected(self):
        with pytest.raises(ValidationError):
            PluginMetadata(name="t", capability=PluginCapability.PASSIVE, rate_limit_rps=51)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestPluginMetadataSerialization:
    """Round-trip serialization."""

    def test_model_dump_round_trip(self):
        pm = PluginMetadata(
            name="ser-test",
            capability=PluginCapability.DESTRUCTIVE,
            required_controls=["allow_exploit_validation"],
            timeout_seconds=300,
            rate_limit_rps=5,
            mitre_techniques=["T1059"],
            requires_isolation=True,
        )
        d = pm.model_dump()
        pm2 = PluginMetadata(**d)
        assert pm == pm2

    def test_json_round_trip(self):
        pm = PluginMetadata(name="j", capability=PluginCapability.ACTIVE)
        j = pm.model_dump_json()
        pm2 = PluginMetadata.model_validate_json(j)
        assert pm == pm2


# ---------------------------------------------------------------------------
# Constants cross-check
# ---------------------------------------------------------------------------


class TestConstantsCrossCheck:
    """Config hard caps match constants module."""

    def test_rate_limit_caps(self):
        from redcheck.constants import HTTP_RPS_HARD_CAP, TCP_CPS_HARD_CAP

        assert HTTP_RPS_HARD_CAP == 50
        assert TCP_CPS_HARD_CAP == 20

    def test_timeout_caps(self):
        from redcheck.constants import (
            GLOBAL_SCAN_TIMEOUT_HARD,
            PER_REQUEST_TIMEOUT_HARD,
            PER_TARGET_TIMEOUT_HARD,
        )

        assert PER_REQUEST_TIMEOUT_HARD == 30
        assert PER_TARGET_TIMEOUT_HARD == 120
        assert GLOBAL_SCAN_TIMEOUT_HARD == 600

    def test_evidence_sampling_cap(self):
        from redcheck.constants import EVIDENCE_MAX_SAMPLE_BYTES

        assert EVIDENCE_MAX_SAMPLE_BYTES == 256

    def test_scope_cidr_cap(self):
        from redcheck.constants import SCOPE_MAX_CIDR_EXPANSION

        assert SCOPE_MAX_CIDR_EXPANSION == 256


# ---------------------------------------------------------------------------
# Finding & Evidence extensions
# ---------------------------------------------------------------------------


class TestFindingExtensions:
    """New fields on Finding model."""

    def test_finding_new_fields_defaults(self):
        from redcheck.models import Finding, FindingSeverity

        f = Finding(
            finding_type="xss",
            target="https://example.com",
            severity=FindingSeverity.HIGH,
            detail="test",
        )
        assert f.plugin is None
        assert f.timestamp is not None
        assert f.evidence_digest is None
        assert f.sampled_data_len is None
        assert f.mitre_technique is None

    def test_finding_with_new_fields(self):
        from redcheck.models import Finding, FindingSeverity

        f = Finding(
            finding_type="sqli",
            target="https://example.com",
            severity=FindingSeverity.CRITICAL,
            detail="test",
            plugin="dast-scanner",
            evidence_digest="sha256:abc123",
            sampled_data_len=128,
            mitre_technique="T1190",
        )
        assert f.plugin == "dast-scanner"
        assert f.mitre_technique == "T1190"
        assert f.sampled_data_len == 128


class TestEvidenceExtensions:
    """New fields on Evidence model."""

    def test_evidence_provenance_tag_default(self):
        from redcheck.models import Evidence

        e = Evidence(evidence_type="file", path="/tmp/test", sha256="abc123")
        assert e.provenance_tag is None

    def test_evidence_with_provenance_tag(self):
        from redcheck.models import Evidence

        e = Evidence(
            evidence_type="file",
            path="/tmp/test",
            sha256="abc123",
            provenance_tag="ENG-001:plugin:20250101",
        )
        assert e.provenance_tag == "ENG-001:plugin:20250101"
