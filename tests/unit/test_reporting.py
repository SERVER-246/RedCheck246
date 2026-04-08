"""Tests for Module 5.3 — Reporting & Evidence Export.

Coverage targets:
  - JSON report generation and validation
  - Ed25519 signing and verification
  - Template rendering (HTML via Jinja2)
  - PDF graceful fallback when weasyprint is missing
  - Audit trail encrypted export → decrypt → verify
  - SBOM generation (SPDX JSON, ≥ 5 deps)
  - Report exporter (unified high-level API)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from redcheck.models import (
    Evidence,
    Finding,
    FindingSeverity,
    PluginResult,
    ScanReport,
)

# ── Fixtures ──────────────────────────────────────────────────────


def _make_scan_report(
    *,
    engagement_id: str = "test-eng-001",
    findings_count: int = 3,
) -> ScanReport:
    """Create a sample ScanReport for testing."""
    now = datetime.now(timezone.utc)
    findings = []
    severities = [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM]
    for i in range(findings_count):
        findings.append(
            Finding(
                finding_type=f"test-finding-{i}",
                target=f"192.168.1.{i + 1}",
                severity=severities[i % len(severities)],
                detail=f"Test finding detail #{i}",
                cvss_score=7.5 - i,
                cwe_id=f"CWE-{100 + i}",
                remediation=f"Fix item #{i}",
            )
        )

    return ScanReport(
        engagement_id=engagement_id,
        scanner="redcheck-test",
        start_time=now - timedelta(minutes=5),
        end_time=now,
        findings=findings,
    )


def _make_plugin_result() -> PluginResult:
    """Create a sample PluginResult with evidence."""
    return PluginResult(
        plugin_name="test-plugin",
        success=True,
        findings=[
            Finding(
                finding_type="plugin-finding",
                target="10.0.0.1",
                severity=FindingSeverity.LOW,
                detail="Plugin test finding",
            )
        ],
        evidence=[
            Evidence(
                evidence_type="screenshot",
                path="/evidence/screenshot.png",
                sha256="a" * 64,
            )
        ],
    )


# ═══════════════════════════════════════════════════════════════════
# JSON Report Generation
# ═══════════════════════════════════════════════════════════════════


class TestJSONReportGenerator:
    """Tests for JSONReportGenerator."""

    def test_generate_returns_valid_structure(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        gen = JSONReportGenerator()
        report = gen.generate(_make_scan_report())

        assert "metadata" in report
        assert "summary" in report
        assert "findings" in report
        assert "evidence" in report
        assert "signature" in report
        assert report["signature"] is None  # unsigned

    def test_generate_metadata_fields(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator, ReportMetadata

        gen = JSONReportGenerator()
        meta = ReportMetadata(engagement_id="eng-42", generator_version="0.3.0")
        report = gen.generate(_make_scan_report(engagement_id="eng-42"), metadata=meta)

        assert report["metadata"]["engagement_id"] == "eng-42"
        assert report["metadata"]["generator_version"] == "0.3.0"
        assert "generated_at" in report["metadata"]

    def test_generate_summary_counts(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        gen = JSONReportGenerator()
        report = gen.generate(_make_scan_report(findings_count=3))

        assert report["summary"]["total_findings"] == 3
        assert "severity_counts" in report["summary"]
        assert report["summary"]["severity_counts"]["critical"] == 1

    def test_generate_includes_plugin_results(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        gen = JSONReportGenerator()
        report = gen.generate(
            _make_scan_report(findings_count=2),
            plugin_results=[_make_plugin_result()],
        )

        # 2 from scan + 1 from plugin
        assert report["summary"]["total_findings"] == 3
        assert len(report["evidence"]) == 1

    def test_generate_json_string(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        gen = JSONReportGenerator()
        json_str = gen.generate_json(_make_scan_report())

        # Must be valid JSON
        parsed = json.loads(json_str)
        assert "metadata" in parsed

    def test_save_writes_file(self, tmp_path: Path) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        gen = JSONReportGenerator()
        out = tmp_path / "reports" / "report.json"
        gen.save(_make_scan_report(), out)

        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["metadata"]["engagement_id"] == "test-eng-001"


# ═══════════════════════════════════════════════════════════════════
# Mode Segregation (Phase E)
# ═══════════════════════════════════════════════════════════════════


class TestModeSegregation:
    """Verify generate() splits findings into real / simulated / dry_run."""

    @staticmethod
    def _finding_with_mode(mode: str | None = None, sev: str = "high") -> Finding:
        meta = {}
        if mode is not None:
            meta["execution_mode"] = mode
        return Finding(
            finding_type="test",
            target="10.0.0.1",
            severity=sev,
            detail="test detail",
            metadata=meta,
        )

    def test_all_real_findings(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        sr = _make_scan_report(findings_count=2)
        gen = JSONReportGenerator()
        report = gen.generate(sr)

        assert report["summary"]["real_findings"] == 2
        assert report["summary"]["simulated_findings"] == 0
        assert report["summary"]["dry_run_findings"] == 0
        assert len(report["findings"]) == 2
        assert report["simulated_results"] == []
        assert report["dry_run_plans"] == []

    def test_mixed_mode_findings(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        real_f = self._finding_with_mode("real", sev="critical")
        sim_f = self._finding_with_mode("simulated", sev="high")
        dry_f = self._finding_with_mode("dry_run", sev="medium")

        sr = ScanReport(
            engagement_id="eng-mix",
            scanner="test",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            findings=[real_f, sim_f, dry_f],
        )
        gen = JSONReportGenerator()
        report = gen.generate(sr)

        assert report["summary"]["total_findings"] == 3
        assert report["summary"]["real_findings"] == 1
        assert report["summary"]["simulated_findings"] == 1
        assert report["summary"]["dry_run_findings"] == 1
        assert len(report["findings"]) == 1
        assert len(report["simulated_results"]) == 1
        assert len(report["dry_run_plans"]) == 1

    def test_severity_counts_only_real(self) -> None:
        """Executive summary severity_counts must exclude simulated findings."""
        from redcheck.core.reporting import JSONReportGenerator

        real_crit = self._finding_with_mode("real", sev="critical")
        sim_crit = self._finding_with_mode("simulated", sev="critical")

        sr = ScanReport(
            engagement_id="eng-sev",
            scanner="test",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            findings=[real_crit, sim_crit],
        )
        gen = JSONReportGenerator()
        report = gen.generate(sr)

        # Only the real critical should be counted
        assert report["summary"]["severity_counts"].get("critical") == 1

    def test_mode_breakdown_in_summary(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator

        sr = _make_scan_report(findings_count=2)
        gen = JSONReportGenerator()
        report = gen.generate(sr)

        mb = report["summary"]["mode_breakdown"]
        assert mb["real"] == 2
        assert mb["simulated"] == 0
        assert mb["dry_run"] == 0


# ═══════════════════════════════════════════════════════════════════
# Ed25519 Signing
# ═══════════════════════════════════════════════════════════════════


class TestReportSigning:
    """Tests for ReportSigner: sign + verify round-trip."""

    def test_generate_keypair(self) -> None:
        from redcheck.core.reporting import ReportSigner

        signer = ReportSigner()
        priv, pub = signer.generate_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_sign_and_verify(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator, ReportSigner

        gen = JSONReportGenerator()
        signer = ReportSigner()
        priv, pub = signer.generate_keypair()

        report = gen.generate(_make_scan_report())
        sig_hex = signer.sign_report(report, priv)
        assert isinstance(sig_hex, str)
        assert len(sig_hex) == 128  # Ed25519 sig = 64 bytes = 128 hex

        # Verify passes
        assert signer.verify_signature(report, sig_hex, pub) is True

    def test_verify_fails_with_wrong_key(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator, ReportSigner

        gen = JSONReportGenerator()
        signer = ReportSigner()
        priv1, pub1 = signer.generate_keypair()
        _, pub2 = signer.generate_keypair()

        report = gen.generate(_make_scan_report())
        sig_hex = signer.sign_report(report, priv1)

        # Wrong public key → verification fails
        assert signer.verify_signature(report, sig_hex, pub2) is False

    def test_verify_fails_with_tampered_data(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator, ReportSigner

        gen = JSONReportGenerator()
        signer = ReportSigner()
        priv, pub = signer.generate_keypair()

        report = gen.generate(_make_scan_report())
        sig_hex = signer.sign_report(report, priv)

        # Tamper with report
        report["summary"]["total_findings"] = 999

        assert signer.verify_signature(report, sig_hex, pub) is False


# ═══════════════════════════════════════════════════════════════════
# Template Rendering (HTML)
# ═══════════════════════════════════════════════════════════════════


class TestTemplateRenderer:
    """Tests for Jinja2 template rendering."""

    def test_render_executive_summary_html(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator, TemplateRenderer

        gen = JSONReportGenerator()
        report = gen.generate(_make_scan_report())

        renderer = TemplateRenderer()
        html = renderer.render_html(report, "executive_summary")

        assert "Executive Summary" in html
        assert "test-eng-001" in html
        assert "redcheck-test" in html

    def test_render_technical_detail_html(self) -> None:
        from redcheck.core.reporting import JSONReportGenerator, TemplateRenderer

        gen = JSONReportGenerator()
        report = gen.generate(_make_scan_report())

        renderer = TemplateRenderer()
        html = renderer.render_html(report, "technical_detail")

        assert "Technical Detail Report" in html
        assert "test-eng-001" in html

    def test_render_no_undefined_variables(self) -> None:
        """Ensure templates don't have {{ undefined }} references."""
        from redcheck.core.reporting import JSONReportGenerator, TemplateRenderer

        gen = JSONReportGenerator()
        report = gen.generate(
            _make_scan_report(findings_count=3),
            plugin_results=[_make_plugin_result()],
        )

        renderer = TemplateRenderer()
        # Should not raise UndefinedError
        html = renderer.render_html(report, "executive_summary")
        assert "{{ undefined }}" not in html
        assert "{{" not in html  # No unresolved template vars

    def test_render_from_filesystem_template(self, tmp_path: Path) -> None:
        """Load a template from the filesystem template directory."""
        from redcheck.core.reporting import TemplateRenderer

        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "custom.j2").write_text(
            "<h1>{{ metadata.engagement_id }}</h1>",
            encoding="utf-8",
        )

        renderer = TemplateRenderer(template_dir=template_dir)
        data = {
            "metadata": {"engagement_id": "eng-custom"},
            "summary": {},
            "findings": [],
            "evidence": [],
        }
        html = renderer.render_html(data, "custom")
        assert "eng-custom" in html

    def test_unknown_template_raises(self) -> None:
        from redcheck.core.reporting import TemplateRenderer

        renderer = TemplateRenderer()
        with pytest.raises(ValueError, match="Unknown template"):
            renderer.render_html(
                {"metadata": {}, "summary": {}, "findings": [], "evidence": []},
                "nonexistent_template",
            )


# ═══════════════════════════════════════════════════════════════════
# PDF Fallback
# ═══════════════════════════════════════════════════════════════════


class TestPDFFallback:
    """Verify graceful fallback when weasyprint is unavailable."""

    def test_pdf_unavailable_returns_none(self, tmp_path: Path) -> None:
        from redcheck.core.reporting import JSONReportGenerator, TemplateRenderer

        gen = JSONReportGenerator()
        report = gen.generate(_make_scan_report())

        renderer = TemplateRenderer()
        # Mock weasyprint as unavailable
        with patch("redcheck.core.reporting._HAS_WEASYPRINT", False):
            result = renderer.render_pdf(report, tmp_path / "test.pdf")
            assert result is None

    def test_is_pdf_available_check(self) -> None:
        from redcheck.core.reporting import TemplateRenderer

        # This just exercises the static method
        result = TemplateRenderer.is_pdf_available()
        assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════════════
# Audit Trail Export (Encrypt → Decrypt → Verify)
# ═══════════════════════════════════════════════════════════════════


class TestAuditExport:
    """Tests for AuditExporter encrypt/decrypt round-trip."""

    def test_export_decrypt_roundtrip(self, tmp_path: Path) -> None:
        from redcheck.core.audit_export import AuditExporter

        key = os.urandom(32)
        exporter = AuditExporter(key)

        entries = [
            {
                "action": "PLUGIN_EXECUTE",
                "plugin": "nmap-scan",
                "timestamp": "2025-01-01T00:00:00Z",
            },
            {
                "action": "FINDING_RECORDED",
                "severity": "critical",
                "timestamp": "2025-01-01T00:01:00Z",
            },
        ]

        out = tmp_path / "audit.enc"
        exporter.export_audit_trail(entries, out, engagement_id="eng-007")

        assert out.exists()
        assert out.stat().st_size > 0

        # Decrypt
        payload = exporter.import_audit_trail(out)
        assert payload["format"] == "redcheck-audit-export-v1"
        assert payload["engagement_id"] == "eng-007"
        assert payload["entry_count"] == 2
        assert len(payload["entries"]) == 2
        assert payload["entries"][0]["action"] == "PLUGIN_EXECUTE"

    def test_decrypt_wrong_key_fails(self, tmp_path: Path) -> None:
        from redcheck.core.audit_export import AuditExporter

        key1 = os.urandom(32)
        key2 = os.urandom(32)

        exporter1 = AuditExporter(key1)
        exporter1.export_audit_trail([{"test": True}], tmp_path / "audit.enc")

        exporter2 = AuditExporter(key2)
        with pytest.raises(ValueError, match="decryption failed"):
            exporter2.import_audit_trail(tmp_path / "audit.enc")

    def test_invalid_key_length_rejected(self) -> None:
        from redcheck.core.audit_export import AuditExporter

        with pytest.raises(ValueError, match="32 bytes"):
            AuditExporter(b"short-key")

    def test_truncated_file_rejected(self, tmp_path: Path) -> None:
        from redcheck.core.audit_export import AuditExporter

        key = os.urandom(32)
        exporter = AuditExporter(key)

        bad_file = tmp_path / "bad.enc"
        bad_file.write_bytes(b"too_short")

        with pytest.raises(ValueError, match="too short"):
            exporter.import_audit_trail(bad_file)


# ═══════════════════════════════════════════════════════════════════
# SBOM Generation
# ═══════════════════════════════════════════════════════════════════


class TestSBOMGenerator:
    """Tests for SBOMGenerator (SPDX JSON output)."""

    def test_generates_valid_spdx_json(self) -> None:
        from redcheck.core.sbom_integration import SBOMGenerator

        gen = SBOMGenerator()
        sbom = gen.generate(min_packages=1)

        assert sbom["spdxVersion"] == "SPDX-2.3"
        assert sbom["dataLicense"] == "CC0-1.0"
        assert sbom["SPDXID"] == "SPDXRef-DOCUMENT"
        assert "packages" in sbom
        assert len(sbom["packages"]) >= 1

    def test_sbom_has_at_least_5_deps(self) -> None:
        from redcheck.core.sbom_integration import SBOMGenerator

        gen = SBOMGenerator()
        sbom = gen.generate(min_packages=5)

        # A full redcheck install has many deps
        assert len(sbom["packages"]) >= 5

    def test_sbom_packages_have_required_fields(self) -> None:
        from redcheck.core.sbom_integration import SBOMGenerator

        gen = SBOMGenerator()
        sbom = gen.generate(min_packages=1)

        for pkg in sbom["packages"]:
            assert "SPDXID" in pkg
            assert "name" in pkg
            assert "versionInfo" in pkg
            assert "downloadLocation" in pkg
            assert "licenseConcluded" in pkg

    def test_sbom_save_writes_file(self, tmp_path: Path) -> None:
        from redcheck.core.sbom_integration import SBOMGenerator

        gen = SBOMGenerator()
        out = tmp_path / "sbom.json"
        gen.save(out, min_packages=1)

        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["spdxVersion"] == "SPDX-2.3"


# ═══════════════════════════════════════════════════════════════════
# ReportExporter (Unified API)
# ═══════════════════════════════════════════════════════════════════


class TestReportExporter:
    """Tests for ReportExporter high-level API."""

    def test_export_json_unsigned(self, tmp_path: Path) -> None:
        from redcheck.core.reporting import ReportExporter

        exporter = ReportExporter()
        out = exporter.export_json(
            _make_scan_report(),
            tmp_path / "report.json",
        )

        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["signature"] is None

    def test_export_json_signed(self, tmp_path: Path) -> None:
        from redcheck.core.reporting import ReportExporter, ReportSigner

        signer = ReportSigner()
        priv, pub = signer.generate_keypair()

        exporter = ReportExporter(signing_key=priv)
        out = exporter.export_json(
            _make_scan_report(),
            tmp_path / "signed_report.json",
            sign=True,
        )

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["signature"] is not None
        assert len(data["signature"]) == 128

        # Verify signature
        assert signer.verify_signature(data, data["signature"], pub) is True

    def test_export_all_json_and_pdf_fallback(self, tmp_path: Path) -> None:
        from redcheck.core.reporting import ReportExporter

        exporter = ReportExporter()

        with patch("redcheck.core.reporting._HAS_WEASYPRINT", False):
            results = exporter.export_all(
                _make_scan_report(),
                tmp_path / "output",
            )

        assert results["json"].exists()
        # PDF is None when weasyprint is unavailable
        assert results["pdf"] is None

    def test_export_pdf_returns_none_without_renderer(self, tmp_path: Path) -> None:
        from redcheck.core.reporting import ReportExporter

        with patch("redcheck.core.reporting._HAS_JINJA2", False):
            exporter = ReportExporter()
            result = exporter.export_pdf(
                _make_scan_report(),
                tmp_path / "test.pdf",
            )
            assert result is None
