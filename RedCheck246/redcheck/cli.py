"""
RedCheck246 — Command-Line Interface

Commands:
  init            Initialize a new engagement directory
  recon           Run passive reconnaissance (supports --dry-run)
  run <plugin>    Execute a specific plugin
  list-plugins    List all registered plugins
  verify-roe      Validate a Rules of Engagement file
  activate        Set or verify activation code
  status          Show current framework status
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

from redcheck import __version__
from redcheck.core.activation_engine import ActivationEngine
from redcheck.core.audit import get_audit_logger
from redcheck.core.orchestrator import Orchestrator
from redcheck.core.policy_engine import PolicyDeniedException, get_policy_engine

# Import plugins to trigger auto-registration
from redcheck.plugins.base_plugin import PluginRegistry
from redcheck.plugins.dast.dast_scanner import DASTPlugin  # noqa: F401
from redcheck.plugins.fuzzing.protocol_fuzzer import FuzzingPlugin  # noqa: F401
from redcheck.plugins.recon.passive_recon import PassiveReconPlugin  # noqa: F401
from redcheck.plugins.sast.sast_scanner import SASTPlugin  # noqa: F401
from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin  # noqa: F401


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="redcheck",
        description="RedCheck246 — Policy-gated security assessment framework",
    )
    parser.add_argument("--version", action="version", version=f"RedCheck246 v{__version__}")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- init ---
    p_init = sub.add_parser("init", help="Initialize a new engagement directory")
    p_init.add_argument("name", help="Engagement name / ID")
    p_init.add_argument("--dir", default=".", help="Parent directory (default: cwd)")

    # --- recon ---
    p_recon = sub.add_parser("recon", help="Run passive reconnaissance")
    p_recon.add_argument("--roe", required=True, help="Path to RoE YAML file")
    p_recon.add_argument("--dry-run", action="store_true", help="Simulate only")

    # --- run ---
    p_run = sub.add_parser("run", help="Execute a specific plugin")
    p_run.add_argument("plugin", help="Plugin name to execute")
    p_run.add_argument("--roe", required=True, help="Path to RoE YAML file")
    p_run.add_argument("--dry-run", action="store_true", help="Simulate only")

    # --- list-plugins ---
    sub.add_parser("list-plugins", help="List all registered plugins")

    # --- verify-roe ---
    p_roe = sub.add_parser("verify-roe", help="Validate a Rules of Engagement file")
    p_roe.add_argument("file", help="Path to RoE YAML file")

    # --- activate ---
    p_act = sub.add_parser("activate", help="Set or verify activation code")
    p_act.add_argument(
        "--set",
        action="store_true",
        dest="set_code",
        help="Set a new activation code (prompted securely)",
    )
    p_act.add_argument(
        "--verify",
        action="store_true",
        dest="verify_code",
        help="Verify an existing activation code",
    )

    # --- status ---
    sub.add_parser("status", help="Show framework status")

    return parser


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new engagement directory."""
    base = Path(args.dir) / args.name
    if base.exists():
        print(f"[!] Directory already exists: {base}")
        return 1

    base.mkdir(parents=True)
    (base / "evidence").mkdir()
    (base / "reports").mkdir()
    (base / "logs").mkdir()
    (base / "scans").mkdir()

    # Create template RoE
    roe_template = {
        "engagement_id": args.name,
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

    # Create engagement config
    config = {
        "engagement_id": args.name,
        "created_utc": "auto-generated",
        "safety_mode": "dry-run",
        "roe_file": "roe.yaml",
    }
    with open(base / "engagement.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"[+] Engagement initialized: {base}")
    print(f"    RoE template: {roe_path}")
    print("    Edit roe.yaml before running any active scans.")
    print("    Directories: evidence/, reports/, logs/, scans/")

    audit = get_audit_logger()
    audit.log(action="ENGAGEMENT_INIT", details=f"Created engagement: {args.name}")

    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    """Run passive recon plugin."""
    return _run_plugin("passive-recon", args.roe, args.dry_run)


def cmd_run(args: argparse.Namespace) -> int:
    """Run a named plugin."""
    return _run_plugin(args.plugin, args.roe, args.dry_run)


def _run_plugin(plugin_name: str, roe_path: str, dry_run: bool) -> int:
    """Common plugin execution logic."""
    orch = Orchestrator()

    try:
        orch.load_engagement(roe_path)
    except PolicyDeniedException as e:
        print(f"[POLICY DENIED] {e}")
        return 2

    if not dry_run:
        # Check activation
        activation = ActivationEngine()
        if not activation.is_configured:
            print("[!] No activation code set. Run 'redcheck activate --set' first.")
            return 3

        import getpass

        code = getpass.getpass("[?] Enter activation code: ")
        if not orch.activate(code):
            print("[DENIED] Invalid activation code.")
            return 3

    try:
        result = orch.run_plugin(plugin_name, dry_run=dry_run)
    except PolicyDeniedException as e:
        print(f"[POLICY DENIED] {e}")
        return 2

    # Output results
    print(f"\n{'=' * 60}")
    print(f"Plugin: {result.plugin_name}")
    print(f"Success: {result.success}")
    if result.findings:
        print(f"Findings ({len(result.findings)}):")
        for f in result.findings:
            print(f"  - [{f.get('type', '?')}] {f.get('target', '?')}: {f.get('detail', '')}")
    if result.errors:
        print("Errors:")
        for e in result.errors:
            print(f"  ! {e}")
    if result.metadata:
        print(f"Metadata: {json.dumps(result.metadata, indent=2)}")
    print(f"{'=' * 60}")

    orch.shutdown()
    return 0 if result.success else 1


def cmd_list_plugins(args: argparse.Namespace) -> int:
    """List all registered plugins."""
    plugins = PluginRegistry.list_plugins()
    if not plugins:
        print("[!] No plugins registered.")
        return 1

    print(f"\nRegistered Plugins ({len(plugins)}):")
    print(f"{'Name':<25} {'Version':<10} {'Category':<15} {'Auth':<6} Description")
    print("-" * 90)
    for p in plugins:
        auth = "YES" if p["requires_authorization"] else "NO"
        print(
            f"{p['name']:<25} {p['version']:<10} {p['category']:<15} {auth:<6} {p['description']}"
        )
    return 0


def cmd_verify_roe(args: argparse.Namespace) -> int:
    """Validate an RoE file."""
    from redcheck.security.roe_validator import validate_roe_file

    valid, message, data = validate_roe_file(args.file)
    if valid:
        print(f"[OK] {message}")
        print(f"  Engagement: {data.get('engagement_id', '?')}")
        print(f"  Authorizer: {data.get('authorizer', '?')}")
        print(f"  Targets: {len(data.get('authorized_targets', []))}")
        print(f"  Tests: {', '.join(data.get('allowed_tests', []))}")
        return 0
    else:
        print(f"[FAIL] {message}")
        return 1


def cmd_activate(args: argparse.Namespace) -> int:
    """Set or verify activation code."""
    import getpass

    engine = ActivationEngine()

    if args.set_code:
        code = getpass.getpass("[?] Enter new activation code: ")
        confirm = getpass.getpass("[?] Confirm activation code: ")
        if code != confirm:
            print("[!] Codes do not match.")
            return 1
        ok, msg = engine.set_code(code)
        if ok:
            print(f"[OK] {msg}")
        else:
            print(f"[FAIL] {msg}")
            return 1
        return 0

    if args.verify_code:
        code = getpass.getpass("[?] Enter activation code to verify: ")
        if engine.verify_code(code):
            print("[OK] Activation code verified.")
        else:
            print("[FAIL] Invalid activation code.")
            return 1
        return 0

    # Default: show status
    if engine.is_configured:
        print("[OK] Activation code is configured.")
    else:
        print("[!] No activation code set. Use 'redcheck activate --set'.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show framework status."""
    print(f"\nRedCheck246 v{__version__}")
    print(f"{'=' * 40}")

    # Activation
    engine = ActivationEngine()
    act_status = "CONFIGURED" if engine.is_configured else "NOT SET"
    print(f"Activation: {act_status}")

    # Plugins
    plugins = PluginRegistry.list_plugins()
    print(f"Plugins:    {len(plugins)} registered")

    # Policy engine
    policy = get_policy_engine()
    print(f"Policy:     {policy.__class__.__name__} loaded")

    # Audit
    audit = get_audit_logger()
    log_path = Path(audit.log_path) if hasattr(audit, "log_path") else Path("logs/audit.log")
    print(f"Audit log:  {log_path} ({'exists' if log_path.exists() else 'not found'})")

    print(f"{'=' * 40}")
    return 0


def main() -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "init": cmd_init,
        "recon": cmd_recon,
        "run": cmd_run,
        "list-plugins": cmd_list_plugins,
        "verify-roe": cmd_verify_roe,
        "activate": cmd_activate,
        "status": cmd_status,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
