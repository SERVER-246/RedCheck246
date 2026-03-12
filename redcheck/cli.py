"""RedCheck246 — Command-Line Interface (Typer + Rich).

Commands:
  init            Initialize a new engagement directory
  recon           Run passive reconnaissance (supports --dry-run)
  run <plugin>    Execute a specific plugin
  run-all         Execute all plugins listed in the RoE
  list-plugins    List all registered plugins
  verify-roe      Validate a Rules of Engagement file
  activate        Set or verify activation code
  status          Show current framework status
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console

import redcheck.plugins  # noqa: F401  # trigger auto-discovery
from redcheck import __version__
from redcheck.core.activation_engine import ActivationEngine
from redcheck.core.audit import get_audit_logger
from redcheck.core.orchestrator import Orchestrator
from redcheck.core.policy_engine import get_policy_engine
from redcheck.exceptions import PolicyDeniedException
from redcheck.output import (
    console as out,
)
from redcheck.output import (
    format_plugin_list,
    format_scan_result,
    format_status,
    print_banner,
)

# Explicit imports kept as fallback until auto-discovery is proven on CI.
from redcheck.plugins.base_plugin import PluginRegistry
from redcheck.plugins.dast.dast_scanner import DASTPlugin  # noqa: F401
from redcheck.plugins.fuzzing.protocol_fuzzer import FuzzingPlugin  # noqa: F401
from redcheck.plugins.recon.passive_recon import PassiveReconPlugin  # noqa: F401
from redcheck.plugins.sast.sast_scanner import SASTPlugin  # noqa: F401
from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin  # noqa: F401

app = typer.Typer(
    name="redcheck",
    help="RedCheck246 — Policy-gated security assessment framework",
    add_completion=True,
    no_args_is_help=True,
)

err = Console(stderr=True)

# Global options
_format: str = "text"
_verbose: bool = False


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"RedCheck246 v{__version__}")
        raise typer.Exit()


@app.callback()
def global_options(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version",
    ),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """RedCheck246 — Policy-gated security assessment framework."""
    global _format, _verbose  # noqa: PLW0603
    _format = fmt
    _verbose = verbose


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@app.command()
def init(
    name: str = typer.Argument(..., help="Engagement name / ID"),
    directory: str = typer.Option(".", "--dir", "-d", help="Parent directory"),
) -> None:
    """Initialize a new engagement directory."""
    base = Path(directory) / name
    if base.exists():
        out.print(f"[red]✗[/red] Directory already exists: {base}")
        raise typer.Exit(1)

    base.mkdir(parents=True)
    for sub in ("evidence", "reports", "logs", "scans"):
        (base / sub).mkdir()

    roe_template = {
        "engagement_id": name,
        "authorizer": "CHANGE_ME",
        "authorized_targets": [{"host": "example.com", "ports": [80, 443], "protocols": ["tcp"]}],
        "allowed_tests": ["passive-recon", "sast-scanner"],
        "start_time_utc": "2025-01-01T00:00:00Z",
        "end_time_utc": "2025-12-31T23:59:59Z",
        "sensitivity": "high",
        "contact": {"name": "CHANGE_ME", "email": "change@me.com"},
        "signature": "",
    }
    roe_path = base / "roe.yaml"
    with open(roe_path, "w", encoding="utf-8") as f:
        yaml.dump(roe_template, f, default_flow_style=False, sort_keys=False)

    with open(base / "engagement.yaml", "w", encoding="utf-8") as f:
        yaml.dump(
            {"engagement_id": name, "safety_mode": "dry-run", "roe_file": "roe.yaml"},
            f,
            default_flow_style=False,
        )

    out.print(f"[green]✓[/green] Engagement initialized: [bold]{base}[/bold]")
    out.print(f"  RoE template: {roe_path}")
    out.print("  Edit roe.yaml before running any active scans.")

    audit = get_audit_logger()
    audit.log(action="ENGAGEMENT_INIT", details=f"Created engagement: {name}")


# ---------------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------------


@app.command()
def recon(
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate only"),
) -> None:
    """Run passive reconnaissance."""
    _run_plugin_impl("passive-recon", roe, dry_run)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@app.command("run")
def run_cmd(
    plugin: str = typer.Argument(..., help="Plugin name to execute"),
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate only"),
    output_dir: str | None = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to write JSON/PDF reports into (optional)",
    ),
    report_format: str = typer.Option(
        "json",
        "--report-format",
        help="Report format: json, pdf, all (default: json)",
    ),
) -> None:
    """Execute a specific plugin."""
    _run_plugin_impl(plugin, roe, dry_run, output_dir=output_dir, report_format=report_format)


def _run_plugin_impl(
    plugin_name: str,
    roe_path: str,
    dry_run: bool,
    *,
    output_dir: str | None = None,
    report_format: str = "json",
) -> None:
    """Common plugin execution logic."""
    orch = Orchestrator()

    try:
        orch.load_engagement(roe_path)
    except PolicyDeniedException as e:
        out.print(f"[red]✗ POLICY DENIED[/red] {e}")
        raise typer.Exit(2) from None

    if not dry_run:
        activation = ActivationEngine()
        if not activation.is_configured:
            out.print(
                "[yellow]![/yellow] No activation code set. "
                "Run [bold]redcheck activate --set[/bold] first."
            )
            raise typer.Exit(3)
        code = typer.prompt("Enter activation code", hide_input=True)
        if not orch.activate(code):
            out.print("[red]✗ DENIED[/red] Invalid activation code.")
            raise typer.Exit(3)

    try:
        result = orch.run_plugin(plugin_name, dry_run=dry_run)
    except PolicyDeniedException as e:
        out.print(f"[red]✗ POLICY DENIED[/red] {e}")
        raise typer.Exit(2) from None

    # Output
    result_dict = {
        "plugin_name": result.plugin_name,
        "success": result.success,
        "findings": result.findings if isinstance(result.findings, list) else [],
        "errors": result.errors if isinstance(result.errors, list) else [],
        "metadata": result.metadata if isinstance(result.metadata, dict) else {},
        "mode": "dry-run" if dry_run else "live",
    }
    format_scan_result(result_dict, _format)

    # --- Report generation (BC-7: failure here must never abort the scan) ---
    if output_dir and not dry_run:
        try:
            from redcheck.core.report_adapter import plugin_result_to_scan_report
            from redcheck.core.reporting import ReportExporter

            engagement_id = ""
            if orch.current_engagement:
                engagement_id = orch.current_engagement.engagement_id

            raw_findings = result.findings if isinstance(result.findings, list) else []
            raw_metadata = result.metadata if isinstance(result.metadata, dict) else {}
            scan_report = plugin_result_to_scan_report(
                plugin_name=result.plugin_name,
                findings=raw_findings,
                metadata=raw_metadata,
                engagement_id=engagement_id,
                duration_ms=raw_metadata.get("duration_ms"),
            )

            exporter = ReportExporter()
            out_path = Path(output_dir)

            if report_format == "all":
                paths = exporter.export_all(
                    scan_report,
                    out_path,
                    sign=False,
                )
                out.print(
                    f"[green]✓[/green] JSON report: {paths['json']}",
                )
                if paths.get("pdf"):
                    out.print(
                        f"[green]✓[/green] PDF report:  {paths['pdf']}",
                    )
            elif report_format == "pdf":
                rpt_name = f"{engagement_id}_report.pdf"
                pdf = exporter.export_pdf(
                    scan_report,
                    out_path / rpt_name,
                )
                if pdf:
                    out.print(f"[green]✓[/green] PDF report: {pdf}")
                else:
                    out.print(
                        "[yellow]![/yellow] PDF generation unavailable (weasyprint not installed)",
                    )
            else:
                rpt_name = f"{engagement_id}_report.json"
                jp = exporter.export_json(
                    scan_report,
                    out_path / rpt_name,
                    sign=False,
                )
                out.print(f"[green]✓[/green] JSON report: {jp}")
        except Exception as exc:
            out.print(
                f"[yellow]![/yellow] Report generation failed (scan results still valid): {exc}",
            )

    orch.shutdown()
    if not result.success:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# run-all
# ---------------------------------------------------------------------------


@app.command("run-all")
def run_all_cmd(
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate only"),
    output_dir: str | None = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to write JSON/PDF reports into (optional)",
    ),
    report_format: str = typer.Option(
        "json",
        "--report-format",
        help="Report format: json, pdf, all (default: json)",
    ),
) -> None:
    """Execute every plugin listed in the RoE's allowed_tests sequentially."""
    orch = Orchestrator()

    try:
        orch.load_engagement(roe)
    except PolicyDeniedException as e:
        out.print(f"[red]✗ POLICY DENIED[/red] {e}")
        raise typer.Exit(2) from None

    if not dry_run:
        activation = ActivationEngine()
        if not activation.is_configured:
            out.print(
                "[yellow]![/yellow] No activation code set. "
                "Run [bold]redcheck activate --set[/bold] first."
            )
            raise typer.Exit(3)
        code = typer.prompt("Enter activation code", hide_input=True)
        if not orch.activate(code):
            out.print("[red]✗ DENIED[/red] Invalid activation code.")
            raise typer.Exit(3)

    eng = orch.current_engagement
    if not eng:
        out.print("[red]✗[/red] No engagement loaded.")
        raise typer.Exit(2)

    allowed = eng.allowed_tests
    out.print(
        f"[cyan]ℹ[/cyan] Running [bold]{len(allowed)}[/bold] plugin(s) "
        f"from RoE: {', '.join(allowed)}"
    )

    passed: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []

    for idx, plugin_name in enumerate(allowed, 1):
        out.print(f"\n[bold]── [{idx}/{len(allowed)}] {plugin_name} ──[/bold]")

        plugin_inst = PluginRegistry.get_instance(plugin_name)
        if plugin_inst is None:
            out.print(f"[yellow]![/yellow] Plugin '{plugin_name}' not registered — skipping.")
            skipped.append(plugin_name)
            continue

        try:
            result = orch.run_plugin(plugin_name, dry_run=dry_run)
        except PolicyDeniedException as e:
            out.print(f"[yellow]![/yellow] POLICY DENIED for {plugin_name}: {e} — skipping.")
            skipped.append(plugin_name)
            continue

        result_dict = {
            "plugin_name": result.plugin_name,
            "success": result.success,
            "findings": result.findings if isinstance(result.findings, list) else [],
            "errors": result.errors if isinstance(result.errors, list) else [],
            "metadata": result.metadata if isinstance(result.metadata, dict) else {},
            "mode": "dry-run" if dry_run else "live",
        }
        format_scan_result(result_dict, _format)

        if result.success:
            passed.append(plugin_name)
        else:
            failed.append(plugin_name)

        # Report generation per-plugin (failures never abort)
        if output_dir and not dry_run and result.success:
            try:
                from redcheck.core.report_adapter import plugin_result_to_scan_report
                from redcheck.core.reporting import ReportExporter

                engagement_id = eng.engagement_id
                raw_findings = result.findings if isinstance(result.findings, list) else []
                raw_metadata = result.metadata if isinstance(result.metadata, dict) else {}
                scan_report = plugin_result_to_scan_report(
                    plugin_name=result.plugin_name,
                    findings=raw_findings,
                    metadata=raw_metadata,
                    engagement_id=engagement_id,
                    duration_ms=raw_metadata.get("duration_ms"),
                )
                exporter = ReportExporter()
                out_path = Path(output_dir)

                if report_format == "all":
                    paths = exporter.export_all(scan_report, out_path, sign=False)
                    out.print(f"[green]✓[/green] JSON report: {paths['json']}")
                    if paths.get("pdf"):
                        out.print(f"[green]✓[/green] PDF report:  {paths['pdf']}")
                elif report_format == "pdf":
                    rpt_name = f"{engagement_id}_{plugin_name}_report.pdf"
                    pdf = exporter.export_pdf(scan_report, out_path / rpt_name)
                    if pdf:
                        out.print(f"[green]✓[/green] PDF report: {pdf}")
                    else:
                        msg = (
                            "[yellow]![/yellow] PDF generation"
                            " unavailable (weasyprint not installed)"
                        )
                        out.print(msg)
                else:
                    rpt_name = f"{engagement_id}_{plugin_name}_report.json"
                    jp = exporter.export_json(scan_report, out_path / rpt_name, sign=False)
                    out.print(f"[green]✓[/green] JSON report: {jp}")
            except Exception as exc:
                out.print(f"[yellow]![/yellow] Report generation failed for {plugin_name}: {exc}")

    # Summary
    out.print("\n[bold]═══ Run-All Summary ═══[/bold]")
    out.print(f"  Total:   {len(allowed)}")
    out.print(f"  [green]Passed:[/green]  {len(passed)}")
    if failed:
        out.print(f"  [red]Failed:[/red]  {len(failed)} — {', '.join(failed)}")
    else:
        out.print("  [red]Failed:[/red]  0")
    if skipped:
        out.print(f"  [yellow]Skipped:[/yellow] {len(skipped)} — {', '.join(skipped)}")

    orch.shutdown()
    if failed:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# list-plugins
# ---------------------------------------------------------------------------


@app.command("list-plugins")
def list_plugins() -> None:
    """List all registered plugins."""
    plugins = PluginRegistry.list_plugins()
    if not plugins:
        out.print("[yellow]![/yellow] No plugins registered.")
        raise typer.Exit(1)

    if _format == "json":
        out.print_json(json.dumps(plugins, indent=2, default=str))
    else:
        out.print(format_plugin_list(plugins))


# ---------------------------------------------------------------------------
# verify-roe
# ---------------------------------------------------------------------------


@app.command("verify-roe")
def verify_roe(
    file: str = typer.Argument(..., help="Path to RoE YAML file"),
) -> None:
    """Validate a Rules of Engagement file."""
    from redcheck.security.roe_validator import validate_roe_file

    valid, message, data = validate_roe_file(file)
    if _format == "json":
        out.print_json(
            json.dumps(
                {"valid": valid, "message": message, "data": data},
                indent=2,
                default=str,
            )
        )
        if not valid:
            raise typer.Exit(1)
        return

    if valid:
        out.print(f"[green]✓[/green] {message}")
        out.print(f"  Engagement: {data.get('engagement_id', '?')}")
        out.print(f"  Authorizer: {data.get('authorizer', '?')}")
        out.print(f"  Targets:    {len(data.get('authorized_targets', []))}")
        out.print(f"  Tests:      {', '.join(data.get('allowed_tests', []))}")
    else:
        out.print(f"[red]✗[/red] {message}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# activate
# ---------------------------------------------------------------------------


@app.command()
def activate(
    set_code: bool = typer.Option(False, "--set", help="Set a new activation code"),
    verify_code: bool = typer.Option(False, "--verify", help="Verify existing activation code"),
) -> None:
    """Set or verify activation code."""
    engine = ActivationEngine()

    if set_code:
        code = typer.prompt("Enter new activation code", hide_input=True)
        confirm = typer.prompt("Confirm activation code", hide_input=True)
        if code != confirm:
            out.print("[red]✗[/red] Codes do not match.")
            raise typer.Exit(1)
        ok, msg = engine.set_code(code)
        if ok:
            out.print(f"[green]✓[/green] {msg}")
        else:
            out.print(f"[red]✗[/red] {msg}")
            raise typer.Exit(1)
        return

    if verify_code:
        code = typer.prompt("Enter activation code to verify", hide_input=True)
        if engine.verify_code(code):
            out.print("[green]✓[/green] Activation code verified.")
        else:
            out.print("[red]✗[/red] Invalid activation code.")
            raise typer.Exit(1)
        return

    if engine.is_configured:
        out.print("[green]✓[/green] Activation code is configured.")
    else:
        out.print(
            "[yellow]![/yellow] No activation code set. Use [bold]redcheck activate --set[/bold]."
        )


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@app.command()
def status() -> None:
    """Show framework status."""
    if _format != "json":
        print_banner(__version__)

    engine = ActivationEngine()
    plugins = PluginRegistry.list_plugins()
    policy = get_policy_engine()
    audit = get_audit_logger()

    status_data = {
        "version": __version__,
        "activation": "CONFIGURED" if engine.is_configured else "NOT SET",
        "plugins": f"{len(plugins)} registered",
        "policy_engine": policy.__class__.__name__,
        "audit_log": str(audit.log_path),
        "audit_log_exists": audit.log_path.exists(),
    }
    format_status(status_data, _format)


# ---------------------------------------------------------------------------
# research (Phase 1)
# ---------------------------------------------------------------------------


@app.command()
def research(
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    plugin: str = typer.Option("passive-recon", "--plugin", "-p", help="Plugin to run"),
) -> None:
    """Run a plugin in RESEARCH mode (isolated lab environment)."""
    from redcheck.models import RuntimeMode

    orch = Orchestrator()
    try:
        orch.load_engagement(roe)
    except PolicyDeniedException as e:
        out.print(f"[red]✗ POLICY DENIED[/red] {e}")
        raise typer.Exit(2) from None

    out.print(f"[cyan]ℹ[/cyan] Running [bold]{plugin}[/bold] in RESEARCH mode (dry-run)")
    result = orch.run_plugin(plugin, dry_run=True)
    result_dict = {
        "plugin_name": result.plugin_name,
        "success": result.success,
        "findings": result.findings if isinstance(result.findings, list) else [],
        "errors": result.errors if isinstance(result.errors, list) else [],
        "metadata": result.metadata if isinstance(result.metadata, dict) else {},
        "mode": "research",
        "runtime_mode": RuntimeMode.RESEARCH.value,
    }
    format_scan_result(result_dict, _format)
    orch.shutdown()


# ---------------------------------------------------------------------------
# report (Phase 1)
# ---------------------------------------------------------------------------


@app.command()
def report(
    engagement_dir: str = typer.Argument(..., help="Path to engagement directory"),
    output_format: str = typer.Option("text", "--output", "-o", help="Output format: text, json"),
) -> None:
    """Generate a summary report for an engagement."""
    eng_path = Path(engagement_dir)
    if not eng_path.is_dir():
        out.print(f"[red]✗[/red] Not a directory: {eng_path}")
        raise typer.Exit(1)

    reports_dir = eng_path / "reports"
    if not reports_dir.exists():
        out.print(f"[yellow]![/yellow] No reports directory found in {eng_path}")
        raise typer.Exit(1)

    report_files = list(reports_dir.glob("*.json")) + list(reports_dir.glob("*.yaml"))
    report_data = {
        "engagement_dir": str(eng_path),
        "report_count": len(report_files),
        "reports": [f.name for f in report_files],
    }

    if output_format == "json":
        out.print_json(json.dumps(report_data, indent=2, default=str))
    else:
        out.print(f"[bold]Engagement Report: {eng_path.name}[/bold]")
        out.print(f"  Reports found: {len(report_files)}")
        for rf in report_files:
            out.print(f"    • {rf.name}")

    audit = get_audit_logger()
    audit.log(action="REPORT_GENERATED", details=f"Report for {eng_path.name}")


# ---------------------------------------------------------------------------
# tenant (Phase 1)
# ---------------------------------------------------------------------------


@app.command("test-mode")
def test_mode_cmd(
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    plugins: str = typer.Option(
        ..., "--plugins", "-p", help="Comma-separated list of plugin names"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate only"),
    chain: bool = typer.Option(False, "--chain", help="Enable chain mode"),
) -> None:
    """Execute plugins in Test Mode with OTP gating."""
    import asyncio as _asyncio

    from redcheck.core.otp_engine import get_otp_engine
    from redcheck.core.test_mode import TestModeController
    from redcheck.models import RuntimeMode

    plugin_list = [p.strip() for p in plugins.split(",") if p.strip()]
    if not plugin_list:
        out.print("[red]✗[/red] No plugins specified.")
        raise typer.Exit(1)

    orch = Orchestrator()
    try:
        orch.load_engagement(roe)
    except PolicyDeniedException as e:
        out.print(f"[red]✗ POLICY DENIED[/red] {e}")
        raise typer.Exit(2) from None

    eng = orch.engagement
    if eng is None or eng.runtime_mode != RuntimeMode.TEST:
        out.print("[red]✗[/red] Engagement must use runtime_mode: test")
        raise typer.Exit(2)

    if not dry_run:
        activation = ActivationEngine()
        if not activation.is_configured:
            out.print(
                "[yellow]![/yellow] No activation code set. "
                "Run [bold]redcheck activate --set[/bold] first."
            )
            raise typer.Exit(3)
        code = typer.prompt("Enter activation code", hide_input=True)
        if not orch.activate(code):
            out.print("[red]✗ DENIED[/red] Invalid activation code.")
            raise typer.Exit(3)

    otp_engine = get_otp_engine()
    controller = TestModeController(orch, otp_engine)

    try:
        report = _asyncio.run(
            controller.run_test_mode(eng, plugin_list, dry_run=dry_run, chain=chain)
        )
    except Exception as exc:
        out.print(f"[red]✗ TEST MODE FAILED[/red] {exc}")
        raise typer.Exit(1) from None

    report_dict = report.model_dump(mode="json")
    if _format == "json":
        out.print_json(json.dumps(report_dict, indent=2, default=str))
    else:
        out.print("[bold green]✓ Test Mode Complete[/bold green]")
        out.print(f"  Executed: {len(report.plugins_executed)}")
        out.print(f"  Skipped:  {len(report.plugins_skipped)}")
        out.print(f"  Findings: {report.total_findings}")
        out.print(f"  OTP challenges: {report.otp_challenges}")
        out.print(f"  OTP verified:   {report.otp_verified}")
        out.print(f"  OTP cancelled:  {report.otp_cancelled}")
        out.print(f"  Duration: {report.duration_seconds:.2f}s")


@app.command()
def tenant(
    show: bool = typer.Option(False, "--show", help="Show current tenant configuration"),
) -> None:
    """Manage multi-tenant configuration."""
    from redcheck.config import get_config

    config = get_config()

    tenant_data = {
        "multi_tenant_enabled": config.multi_tenant_enabled,
        "default_tenant_id": config.default_tenant_id,
    }
    if _format == "json":
        out.print_json(json.dumps(tenant_data, indent=2))
    else:
        out.print("[bold]Tenant Configuration[/bold]")
        out.print(f"  Multi-tenant: {'enabled' if config.multi_tenant_enabled else 'disabled'}")
        out.print(f"  Default tenant: {config.default_tenant_id}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    try:
        app()
    except KeyboardInterrupt:
        out.print("\n[yellow]![/yellow] Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
