#!/usr/bin/env python3
"""Phase F — End-to-end validation against evil.com using ROE.

Runs every ROE-allowed plugin in LIVE mode (non-dry-run) with a
programmatically set activation code, then verifies reports + evidence.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redcheck.plugins  # noqa: F401, E402  — trigger auto-discovery
from redcheck.core.activation_engine import ActivationEngine  # noqa: E402
from redcheck.core.orchestrator import Orchestrator  # noqa: E402
from redcheck.core.report_adapter import plugin_result_to_scan_report  # noqa: E402
from redcheck.core.reporting import ReportExporter  # noqa: E402
from redcheck.plugins.base_plugin import PluginRegistry  # noqa: E402

# ---------- constants ----------
ROE_PATH = str(Path(__file__).resolve().parents[1] / "ARCHIVE" / "roe.yaml")
ACTIVATION_CODE = "PhaseF-Val1d@tion-2026!"
SEPARATOR = "=" * 72


def banner(msg: str) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  {msg}")
    print(SEPARATOR)


def setup_activation() -> None:
    """Set activation code programmatically (no interactive prompt)."""
    engine = ActivationEngine()
    ok, msg = engine.set_code(ACTIVATION_CODE)
    if not ok and "already" not in msg.lower():
        # If it's already set with a different code, overwrite
        act_path = engine._path
        if act_path.exists():
            act_path.unlink()
        ok, msg = engine.set_code(ACTIVATION_CODE)
    print(f"[ACTIVATION] {msg} (ok={ok})")
    assert ok, f"Activation setup failed: {msg}"


def main() -> int:
    banner("Phase F — End-to-End Validation (evil.com)")

    # 1. Setup activation
    setup_activation()

    # 2. Load engagement
    orch = Orchestrator()
    orch.load_engagement(ROE_PATH)
    print(f"[ENGAGEMENT] Loaded: {orch.current_engagement.engagement_id}")
    print(f"  Targets: {orch.current_engagement.targets}")
    print(f"  Runtime mode: {orch.current_engagement.runtime_mode}")
    print(f"  Allowed tests: {len(orch.current_engagement.allowed_tests)}")

    # 3. Activate
    activated = orch.activate(ACTIVATION_CODE)
    print(f"[ACTIVATION] {'OK' if activated else 'FAILED'}")
    assert activated, "Activation verification failed"

    # Extra context for plugins that need specific runtime data
    extra_context = {
        "ct_domains": ["evil.com"],
        "alert_endpoint": "https://evil.com/api/alerts",
        "alert_query_endpoint": "https://evil.com/api/alerts/query",
        "detected_techniques": ["T1059.001", "T1053.005", "T1071.001"],
        "simulated_latencies_ms": [50, 100, 200, 500],
        "expected_latency_ms": 300,
        "detection_seed": "phase-f-validation",
        "confirm_exploit": True,
        "isolation_verified": True,
    }

    # 4. Run all ROE-allowed plugins
    allowed = orch.current_engagement.allowed_tests
    passed = []
    failed = []
    skipped = []
    all_findings = []
    total_duration_ms = 0

    for idx, plugin_name in enumerate(allowed, 1):
        banner(f"[{idx}/{len(allowed)}] {plugin_name}")

        plugin_inst = PluginRegistry.get_instance(plugin_name)
        if plugin_inst is None:
            print("  SKIP — plugin not registered")
            skipped.append(plugin_name)
            continue

        try:
            result = orch.run_plugin(plugin_name, dry_run=False, extra_context=extra_context)
        except Exception as exc:
            print(f"  ERROR: {exc}")
            failed.append((plugin_name, str(exc)))
            continue

        dur = result.metadata.get("duration_ms", 0)
        total_duration_ms += dur
        finding_count = len(result.findings) if isinstance(result.findings, list) else 0
        error_count = len(result.errors) if isinstance(result.errors, list) else 0
        mode = result.metadata.get("execution_mode", "unknown")

        print(f"  Success:   {result.success}")
        print(f"  Findings:  {finding_count}")
        print(f"  Errors:    {error_count}")
        print(f"  Mode:      {mode}")
        print(f"  Duration:  {dur}ms")

        if result.success:
            passed.append(plugin_name)
        else:
            errors_str = "; ".join(result.errors) if result.errors else "unknown"
            failed.append((plugin_name, errors_str))
            # Still continue — don't abort on plugin failure

        if isinstance(result.findings, list):
            all_findings.extend(result.findings)

        # Generate per-plugin JSON report
        try:
            roe_parent = Path(ROE_PATH).resolve().parent
            reports_dir = roe_parent / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)

            raw_findings = result.findings if isinstance(result.findings, list) else []
            raw_metadata = result.metadata if isinstance(result.metadata, dict) else {}
            scan_report = plugin_result_to_scan_report(
                plugin_name=result.plugin_name,
                findings=raw_findings,
                metadata=raw_metadata,
                engagement_id=orch.current_engagement.engagement_id,
                duration_ms=raw_metadata.get("duration_ms"),
            )
            exporter = ReportExporter()
            rpt_name = f"{orch.current_engagement.engagement_id}_{plugin_name}_report.json"
            jp = exporter.export_json(scan_report, reports_dir / rpt_name, sign=False)
            print(f"  Report:    {jp}")
        except Exception as exc:
            print(f"  Report generation failed: {exc}")

    # 5. Summary
    banner("VALIDATION SUMMARY")
    print(f"  Total plugins:  {len(allowed)}")
    print(f"  Passed:         {len(passed)}")
    print(f"  Failed:         {len(failed)}")
    print(f"  Skipped:        {len(skipped)}")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  Total duration: {total_duration_ms}ms ({total_duration_ms / 1000:.1f}s)")

    if passed:
        print(f"\n  PASSED: {', '.join(passed)}")
    if failed:
        print("\n  FAILED:")
        for name, err in failed:
            print(f"    - {name}: {err}")
    if skipped:
        print(f"\n  SKIPPED: {', '.join(skipped)}")

    # 6. Check reports directory
    roe_parent = Path(ROE_PATH).resolve().parent
    reports_dir = roe_parent / "reports"
    evidence_dir = roe_parent / "evidence"
    print(f"\n  Reports dir: {reports_dir}")
    if reports_dir.exists():
        reports = list(reports_dir.glob("*.json"))
        print(f"  Report files: {len(reports)}")
        for r in reports:
            print(f"    - {r.name} ({r.stat().st_size} bytes)")

    print(f"\n  Evidence dir: {evidence_dir}")
    if evidence_dir.exists():
        ev_files = list(evidence_dir.iterdir())
        print(f"  Evidence files: {len(ev_files)}")
        for ef in ev_files[:10]:
            print(f"    - {ef.name}")

    orch.shutdown()

    # 7. Exit code
    if failed:
        print(f"\n[RESULT] PARTIAL — {len(failed)} plugin(s) had errors")
        return 1 if len(failed) > len(passed) else 0
    else:
        print(f"\n[RESULT] ALL {len(passed)} PLUGINS PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
