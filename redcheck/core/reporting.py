"""RedCheck246 — Reporting & Evidence Export (Module 5.3).

Generates JSON and PDF reports from scan results:
  - JSON reports with JSON-Schema structure validation.
  - Ed25519 digital signatures for integrity verification.
  - Jinja2-based HTML/PDF rendering (weasyprint optional).
  - Graceful fallback to JSON-only when weasyprint is absent.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from pathlib import Path

    from redcheck.core.quality_scorer import QualityScore
    from redcheck.models import (
        PluginResult,
        ScanReport,
    )

log = structlog.get_logger(__name__)

# Optional: Ed25519 signing via cryptography
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False

# Optional: Jinja2 for templates
try:
    import jinja2

    _HAS_JINJA2 = True
except ImportError:  # pragma: no cover
    _HAS_JINJA2 = False

# Optional: WeasyPrint for PDF
try:
    import weasyprint  # pyright: ignore[reportMissingImports]

    _HAS_WEASYPRINT = True
except ImportError:  # pragma: no cover
    _HAS_WEASYPRINT = False


# ---------------------------------------------------------------------------
# JSON Report Generator
# ---------------------------------------------------------------------------


def _finding_dump(finding: Any) -> dict[str, Any]:
    """Serialize a Finding to a JSON-compatible dict."""
    return finding.model_dump(mode="json")


class ReportMetadata:
    """Metadata block for every generated report."""

    def __init__(
        self,
        engagement_id: str,
        generated_at: datetime | None = None,
        generator_version: str = "0.3.0",
        report_type: str = "scan_report",
    ) -> None:
        self.engagement_id = engagement_id
        self.generated_at = generated_at or datetime.now(timezone.utc)
        self.generator_version = generator_version
        self.report_type = report_type

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "generated_at": self.generated_at.isoformat(),
            "generator_version": self.generator_version,
            "report_type": self.report_type,
        }


class JSONReportGenerator:
    """Generates structured JSON scan reports.

    Report structure::

        {
          "metadata": { ... },
          "summary": { ... },
          "findings": [ ... ],
          "evidence": [ ... ],
          "signature": "hex-encoded Ed25519 signature" | null
        }
    """

    def generate(
        self,
        scan_report: ScanReport,
        plugin_results: list[PluginResult] | None = None,
        *,
        metadata: ReportMetadata | None = None,
        quality_score: QualityScore | None = None,
        attack_chain_summary: dict[str, Any] | None = None,
        trust_assessment: dict[str, Any] | None = None,
        input_snapshot: dict[str, Any] | None = None,
        production_readiness: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a JSON-serializable report dict.

        Args:
            scan_report: The aggregated scan report.
            plugin_results: Optional per-plugin results.
            metadata: Optional report metadata (auto-generated if None).
            quality_score: Optional pre-computed quality score.
            attack_chain_summary: Optional pre-computed attack chain scoring.

        Returns:
            A JSON-serializable dict with metadata, summary, findings,
            evidence, and mode-segregated sections.
        """
        from redcheck.core.mode_separator import segregate_findings

        if metadata is None:
            metadata = ReportMetadata(engagement_id=scan_report.engagement_id)

        # Aggregate findings from scan_report + plugin_results
        all_findings = list(scan_report.findings)
        all_evidence: list[dict[str, Any]] = []

        if plugin_results:
            for pr in plugin_results:
                all_findings.extend(pr.findings)
                all_evidence.extend(e.model_dump(mode="json") for e in pr.evidence)

        # --- Mode segregation (Phase E) ---
        seg = segregate_findings(all_findings)
        _dump = _finding_dump  # local alias

        # Executive summary counts ONLY real findings
        severity_counts: dict[str, int] = {}
        for f in seg.real:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report: dict[str, Any] = {
            "metadata": metadata.to_dict(),
            "summary": {
                "total_findings": len(all_findings),
                "real_findings": len(seg.real),
                "simulated_findings": len(seg.simulated),
                "dry_run_findings": len(seg.dry_run),
                "severity_counts": severity_counts,
                "mode_breakdown": seg.to_dict(),
                "duration_seconds": scan_report.duration_seconds,
                "scanner": scan_report.scanner,
            },
            "findings": [_dump(f) for f in seg.real],
            "simulated_results": [_dump(f) for f in seg.simulated],
            "dry_run_plans": [_dump(f) for f in seg.dry_run],
            "evidence": all_evidence,
            "signature": None,
        }

        if quality_score is not None:
            report["quality"] = quality_score.to_dict()

        if attack_chain_summary is not None:
            report["attack_chains"] = attack_chain_summary

        # Phase I: System Trust Assessment
        if trust_assessment is not None:
            report["system_trust"] = trust_assessment

        # Phase L: Input Snapshot
        if input_snapshot is not None:
            report["input_snapshot"] = input_snapshot

        # Phase J: Production Readiness Auto-Check
        if production_readiness is not None:
            report["production_readiness"] = production_readiness

        return report

    def generate_json(
        self,
        scan_report: ScanReport,
        plugin_results: list[PluginResult] | None = None,
        *,
        metadata: ReportMetadata | None = None,
        quality_score: QualityScore | None = None,
        attack_chain_summary: dict[str, Any] | None = None,
        indent: int = 2,
    ) -> str:
        """Generate a JSON string report."""
        report = self.generate(
            scan_report,
            plugin_results,
            metadata=metadata,
            quality_score=quality_score,
            attack_chain_summary=attack_chain_summary,
        )
        return json.dumps(report, indent=indent, default=str, ensure_ascii=False)

    def save(
        self,
        scan_report: ScanReport,
        output_path: Path,
        plugin_results: list[PluginResult] | None = None,
        *,
        metadata: ReportMetadata | None = None,
    ) -> Path:
        """Generate and save JSON report to a file."""
        json_str = self.generate_json(scan_report, plugin_results, metadata=metadata)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")
        log.info("json_report_saved", path=str(output_path))
        return output_path


# ---------------------------------------------------------------------------
# Report Signing (Ed25519)
# ---------------------------------------------------------------------------


class ReportSigner:
    """Ed25519 report signing and verification.

    Signs the canonical JSON payload (sorted keys, no whitespace)
    to produce a hex-encoded signature that can be embedded or stored
    alongside the report.
    """

    def __init__(self) -> None:
        if not _HAS_CRYPTO:
            raise ImportError(
                "cryptography package required for report signing. "
                "Install with: pip install cryptography"
            )

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate an Ed25519 keypair.

        Returns:
            Tuple of (private_key_bytes, public_key_bytes) in raw format.
        """
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return private_bytes, public_bytes

    @staticmethod
    def sign_report(
        report_data: dict[str, Any],
        private_key_bytes: bytes,
    ) -> str:
        """Sign report data with Ed25519 and return hex-encoded signature.

        The report's ``signature`` field is excluded before hashing.
        """
        # Create canonical representation
        signable = {k: v for k, v in report_data.items() if k != "signature"}
        canonical = json.dumps(signable, sort_keys=True, default=str, ensure_ascii=False)

        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        signature = private_key.sign(canonical.encode("utf-8"))
        return signature.hex()

    @staticmethod
    def verify_signature(
        report_data: dict[str, Any],
        signature_hex: str,
        public_key_bytes: bytes,
    ) -> bool:
        """Verify an Ed25519 signature against report data.

        Returns True if valid, False if verification fails.
        """
        signable = {k: v for k, v in report_data.items() if k != "signature"}
        canonical = json.dumps(signable, sort_keys=True, default=str, ensure_ascii=False)

        from cryptography.exceptions import InvalidSignature

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                canonical.encode("utf-8"),
            )
            return True
        except InvalidSignature:
            return False


# ---------------------------------------------------------------------------
# Template-Based HTML / PDF Rendering
# ---------------------------------------------------------------------------

# Default built-in templates (used when no external templates are provided)
_EXECUTIVE_SUMMARY_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><title>RedCheck Report — {{ metadata.engagement_id }}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 2em; }
  h1 { color: #c0392b; }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; }
  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
  th { background-color: #c0392b; color: white; }
  .critical { color: #c0392b; font-weight: bold; }
  .high { color: #e67e22; font-weight: bold; }
  .medium { color: #f1c40f; }
  .low { color: #27ae60; }
</style>
</head>
<body>
<h1>Executive Summary</h1>
<p><strong>Engagement:</strong> {{ metadata.engagement_id }}</p>
<p><strong>Generated:</strong> {{ metadata.generated_at }}</p>
<p><strong>Scanner:</strong> {{ summary.scanner }}</p>
<p><strong>Duration:</strong> {{ "%.1f"|format(summary.duration_seconds) }}s</p>

{% if quality is defined and quality %}
<div style="border:2px solid #2c3e50;padding:12px;
  margin:1em 0;border-radius:6px;background:#ecf0f1;">
<h2 style="margin-top:0">Quality Score:
  {{ quality.total }} / 100 &mdash; Grade {{ quality.grade }}</h2>
<table>
  <tr><th>Component</th><th>Score</th><th>Max</th></tr>
  <tr><td>Evidence Coverage</td>
    <td>{{ "%.1f"|format(quality.evidence_coverage) }}</td>
    <td>25</td></tr>
  <tr><td>Enrichment Completeness</td>
    <td>{{ "%.1f"|format(quality.enrichment_completeness) }}</td>
    <td>25</td></tr>
  <tr><td>Plugin Success Rate</td>
    <td>{{ "%.1f"|format(quality.plugin_success_rate) }}</td>
    <td>25</td></tr>
  <tr><td>Detection Realism</td>
    <td>{{ "%.1f"|format(quality.detection_realism) }}</td>
    <td>25</td></tr>
</table>
</div>
{% endif %}

<h2>Severity Breakdown</h2>
<table>
  <tr><th>Severity</th><th>Count</th></tr>
  {% for sev, count in summary.severity_counts.items() %}
  <tr><td class="{{ sev }}">{{ sev | upper }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>

<h2>Findings ({{ summary.total_findings }} total)</h2>
<table>
  <tr><th>#</th><th>Severity</th><th>Type</th><th>Target</th><th>Detail</th></tr>
  {% for f in findings %}
  <tr>
    <td>{{ loop.index }}</td>
    <td class="{{ f.severity }}">{{ f.severity | upper }}</td>
    <td>{{ f.finding_type }}</td>
    <td>{{ f.target }}</td>
    <td>{{ f.detail }}</td>
  </tr>
  {% endfor %}
</table>
</body>
</html>
"""

_TECHNICAL_DETAIL_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><title>RedCheck Technical Report — {{ metadata.engagement_id }}</title>
<style>
  body { font-family: monospace; margin: 2em; font-size: 13px; }
  h1 { color: #2c3e50; }
  pre { background: #ecf0f1; padding: 1em; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; }
  th, td { border: 1px solid #bdc3c7; padding: 6px; text-align: left; }
  th { background-color: #2c3e50; color: white; }
</style>
</head>
<body>
<h1>Technical Detail Report</h1>
<p><strong>Engagement:</strong> {{ metadata.engagement_id }}</p>
<p><strong>Generated:</strong> {{ metadata.generated_at }}</p>

{% for f in findings %}
<h2>Finding #{{ loop.index }}: {{ f.finding_type }}</h2>
<table>
  <tr><td><strong>Target</strong></td><td>{{ f.target }}</td></tr>
  <tr><td><strong>Severity</strong></td><td>{{ f.severity }}</td></tr>
  <tr><td><strong>Detail</strong></td><td>{{ f.detail }}</td></tr>
  {% if f.cvss_score %}<tr><td><strong>CVSS</strong></td><td>{{ f.cvss_score }}</td></tr>{% endif %}
  {% if f.cwe_id %}<tr><td><strong>CWE</strong></td><td>{{ f.cwe_id }}</td></tr>{% endif %}
  {% if f.remediation %}<tr><td><strong>Remediation</strong></td>
  <td>{{ f.remediation }}</td></tr>{% endif %}
  {% if f.mitre_technique %}<tr><td><strong>MITRE</strong></td>
  <td>{{ f.mitre_technique }}</td></tr>{% endif %}
</table>
{% endfor %}

<h2>Evidence Artifacts ({{ evidence | length }})</h2>
<table>
  <tr><th>#</th><th>Type</th><th>Path</th><th>SHA-256</th></tr>
  {% for e in evidence %}
  <tr>
    <td>{{ loop.index }}</td>
    <td>{{ e.evidence_type }}</td>
    <td>{{ e.path }}</td>
    <td><code>{{ e.sha256[:16] }}…</code></td>
  </tr>
  {% endfor %}
</table>
</body>
</html>
"""


class TemplateRenderer:
    """Renders reports using Jinja2 templates → HTML → optional PDF.

    Falls back gracefully when weasyprint is unavailable.
    """

    def __init__(
        self,
        *,
        template_dir: Path | None = None,
    ) -> None:
        if not _HAS_JINJA2:
            raise ImportError(
                "jinja2 package required for template rendering. Install with: pip install jinja2"
            )

        self._template_dir = template_dir

        # Build Jinja2 environment
        if template_dir and template_dir.is_dir():
            self._env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(template_dir)),
                autoescape=True,
                undefined=jinja2.StrictUndefined,
            )
        else:
            # Use built-in string templates
            self._env = jinja2.Environment(
                loader=jinja2.BaseLoader(),
                autoescape=True,
                undefined=jinja2.StrictUndefined,
            )

    def render_html(
        self,
        report_data: dict[str, Any],
        template_name: str = "executive_summary",
    ) -> str:
        """Render report data to an HTML string.

        Args:
            report_data: The JSON report dict.
            template_name: ``"executive_summary"`` or ``"technical_detail"``.

        Returns:
            Rendered HTML string.
        """
        # Try loading from filesystem first
        try:
            template = self._env.get_template(f"{template_name}.j2")
        except jinja2.TemplateNotFound:
            # Fall back to built-in templates
            builtin = {
                "executive_summary": _EXECUTIVE_SUMMARY_TEMPLATE,
                "technical_detail": _TECHNICAL_DETAIL_TEMPLATE,
            }
            template_str = builtin.get(template_name)
            if template_str is None:
                raise ValueError(f"Unknown template: {template_name}") from None
            template = self._env.from_string(template_str)

        return template.render(**report_data)

    def render_pdf(
        self,
        report_data: dict[str, Any],
        output_path: Path,
        template_name: str = "executive_summary",
    ) -> Path | None:
        """Render report to PDF via weasyprint.

        Returns the output path on success, or None if weasyprint is unavailable.
        """
        if not _HAS_WEASYPRINT:
            log.warning("weasyprint_unavailable", fallback="json_only")
            return None

        html_str = self.render_html(report_data, template_name)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = weasyprint.HTML(string=html_str)
        doc.write_pdf(str(output_path))
        log.info("pdf_report_saved", path=str(output_path))
        return output_path

    @staticmethod
    def is_pdf_available() -> bool:
        """Check if PDF rendering is available."""
        return _HAS_WEASYPRINT


# ---------------------------------------------------------------------------
# Unified Report Exporter
# ---------------------------------------------------------------------------


class ReportExporter:
    """High-level exporter combining JSON generation, signing, and rendering."""

    def __init__(
        self,
        *,
        signing_key: bytes | None = None,
        template_dir: Path | None = None,
    ) -> None:
        self._json_gen = JSONReportGenerator()
        self._signer: ReportSigner | None = None
        self._signing_key = signing_key
        self._renderer: TemplateRenderer | None = None

        if signing_key and _HAS_CRYPTO:
            self._signer = ReportSigner()

        if _HAS_JINJA2:
            self._renderer = TemplateRenderer(template_dir=template_dir)

    @staticmethod
    def _compute_quality(
        plugin_results: list[PluginResult] | None,
    ) -> QualityScore | None:
        if not plugin_results:
            return None
        from redcheck.core.quality_scorer import score_engagement

        return score_engagement(plugin_results)

    def export_json(
        self,
        scan_report: ScanReport,
        output_path: Path,
        plugin_results: list[PluginResult] | None = None,
        *,
        sign: bool = True,
    ) -> Path:
        """Export a signed JSON report.

        If signing is enabled and a key is provided, the report's
        ``signature`` field is populated with the Ed25519 signature.
        """
        qs = self._compute_quality(plugin_results)
        report = self._json_gen.generate(scan_report, plugin_results, quality_score=qs)

        if sign and self._signer and self._signing_key:
            sig = self._signer.sign_report(report, self._signing_key)
            report["signature"] = sig

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("report_exported_json", path=str(output_path))
        return output_path

    def export_pdf(
        self,
        scan_report: ScanReport,
        output_path: Path,
        plugin_results: list[PluginResult] | None = None,
        template_name: str = "executive_summary",
    ) -> Path | None:
        """Export a PDF report. Returns None if weasyprint is unavailable."""
        if self._renderer is None:
            log.warning("template_renderer_unavailable")
            return None

        qs = self._compute_quality(plugin_results)
        report = self._json_gen.generate(scan_report, plugin_results, quality_score=qs)
        return self._renderer.render_pdf(report, output_path, template_name)

    def export_markdown(
        self,
        scan_report: ScanReport,
        output_path: Path,
        plugin_results: list[PluginResult] | None = None,
    ) -> Path:
        """Export a Markdown (.md) report."""
        qs = self._compute_quality(plugin_results)
        report = self._json_gen.generate(scan_report, plugin_results, quality_score=qs)
        meta = report.get("metadata", {})
        summary = report.get("summary", {})
        findings = report.get("findings", [])
        evidence = report.get("evidence", [])

        lines: list[str] = []
        lines.append(f"# RedCheck Scan Report — {meta.get('engagement_id', 'N/A')}")
        lines.append("")
        lines.append(f"**Generated:** {meta.get('generated_at', 'N/A')}  ")
        lines.append(f"**Scanner:** {summary.get('scanner', 'N/A')}  ")
        lines.append(f"**Duration:** {summary.get('duration_seconds', 0):.1f}s  ")
        lines.append(f"**Report Type:** {meta.get('report_type', 'scan_report')}  ")
        lines.append(f"**Generator:** RedCheck v{meta.get('generator_version', '0.3.0')}")
        lines.append("")

        # Quality score
        quality = report.get("quality")
        if quality:
            lines.append("## Quality Score")
            lines.append("")
            lines.append(f"**Total: {quality['total']} / 100 — Grade {quality['grade']}**")
            lines.append("")
            lines.append("| Component | Score | Max |")
            lines.append("|-----------|-------|-----|")
            lines.append(f"| Evidence Coverage | {quality['evidence_coverage']} | 25 |")
            lines.append(f"| Enrichment Completeness | {quality['enrichment_completeness']} | 25 |")
            lines.append(f"| Plugin Success Rate | {quality['plugin_success_rate']} | 25 |")
            lines.append(f"| Detection Realism | {quality['detection_realism']} | 25 |")
            lines.append("")

        # Severity summary
        sev_counts = summary.get("severity_counts", {})
        lines.append("## Severity Summary")
        lines.append("")
        lines.append(f"**Total Findings:** {summary.get('total_findings', 0)}")
        lines.append("")
        if sev_counts:
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ("critical", "high", "medium", "low", "info"):
                if sev in sev_counts:
                    lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
            lines.append("")

        # Findings table
        if findings:
            lines.append("## Findings")
            lines.append("")
            lines.append("| # | Severity | Type | Target | Detail |")
            lines.append("|---|----------|------|--------|--------|")
            for i, f in enumerate(findings, 1):
                sev = f.get("severity", "info")
                if isinstance(sev, dict):
                    sev = sev.get("value", sev)
                ftype = f.get("finding_type", "unknown")
                target = f.get("target", "—")
                detail = str(f.get("detail", "")).replace("|", "\\|").replace("\n", " ")
                if len(detail) > 120:
                    detail = detail[:117] + "..."
                lines.append(f"| {i} | {str(sev).upper()} | {ftype} | {target} | {detail} |")
            lines.append("")

            # Detailed findings
            lines.append("## Finding Details")
            lines.append("")
            for i, f in enumerate(findings, 1):
                sev = f.get("severity", "info")
                if isinstance(sev, dict):
                    sev = sev.get("value", sev)
                lines.append(f"### {i}. {f.get('finding_type', 'unknown')}")
                lines.append("")
                lines.append(f"- **Severity:** {str(sev).upper()}")
                lines.append(f"- **Target:** {f.get('target', '—')}")
                lines.append(f"- **Detail:** {f.get('detail', '—')}")
                if f.get("cvss_score") is not None:
                    lines.append(f"- **CVSS:** {f['cvss_score']}")
                if f.get("cwe_id"):
                    lines.append(f"- **CWE:** {f['cwe_id']}")
                if f.get("mitre_technique"):
                    lines.append(f"- **MITRE:** {f['mitre_technique']}")
                if f.get("remediation"):
                    lines.append(f"- **Remediation:** {f['remediation']}")
                if f.get("plugin"):
                    lines.append(f"- **Plugin:** {f['plugin']}")
                lines.append("")

        # Evidence
        if evidence:
            lines.append("## Evidence Artifacts")
            lines.append("")
            lines.append("| # | Type | Path | SHA-256 |")
            lines.append("|---|------|------|---------|")
            for i, e in enumerate(evidence, 1):
                sha = e.get("sha256", "—")
                if len(sha) > 16:
                    sha = sha[:16] + "…"
                lines.append(
                    f"| {i} | {e.get('evidence_type', '—')} | {e.get('path', '—')} | `{sha}` |"
                )
            lines.append("")

        lines.append("---")
        lines.append("*Report generated by RedCheck246*")
        lines.append("")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        log.info("report_exported_markdown", path=str(output_path))
        return output_path

    def export_all(
        self,
        scan_report: ScanReport,
        output_dir: Path,
        plugin_results: list[PluginResult] | None = None,
        *,
        sign: bool = True,
    ) -> dict[str, Path | None]:
        """Export JSON, Markdown, and PDF reports.

        Returns dict with ``"json"``, ``"md"``, and ``"pdf"`` paths (pdf may be None).
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        eid = scan_report.engagement_id

        json_path = self.export_json(
            scan_report,
            output_dir / f"{eid}_report.json",
            plugin_results,
            sign=sign,
        )

        md_path = self.export_markdown(
            scan_report,
            output_dir / f"{eid}_report.md",
            plugin_results,
        )

        pdf_path = self.export_pdf(
            scan_report,
            output_dir / f"{eid}_report.pdf",
            plugin_results,
        )

        return {"json": json_path, "md": md_path, "pdf": pdf_path}
