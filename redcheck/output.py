"""RedCheck246 CLI output formatting — Rich tables, panels, progress bars.

All user-facing output goes through this module so that ``--format json``
and ``--format text`` (colored) are consistent across every command.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(stderr=True)

# Banner shown once on startup in interactive mode
_BANNER = r"""
[bold red] ____          _  ____ _               _    ____  _  _    __
[bold red]|  _ \ ___  __| |/ ___| |__   ___  ___| | _|___ \| || |  / /_
[bold red]| |_) / _ \/ _` | |   | '_ \ / _ \/ __| |/ / __) | || |_| '_ \
[bold red]|  _ <  __/ (_| | |___| | | |  __/ (__|   < / __/|__   _| (_) |
[bold red]|_| \_\___|\__,_|\____|_| |_|\___|\___|_|\_\_____|  |_|  \___/
[dim]Policy-gated security assessment framework[/dim]
"""


def print_banner(version: str) -> None:
    console.print(_BANNER)
    console.print(f"  [dim]v{version}[/dim]\n")


def format_findings_table(findings: list[dict[str, Any]]) -> Table:
    """Build a Rich table from a list of finding dicts."""
    table = Table(title="Findings", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Type", width=20)
    table.add_column("Target", width=25)
    table.add_column("Detail", min_width=30)

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity", "info")).lower()
        color = severity_colors.get(sev, "white")
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            str(f.get("finding_type", f.get("type", "?"))),
            str(f.get("target", "?")),
            str(f.get("detail", "")),
        )
    return table


def format_plugin_list(plugins: list[dict[str, Any]]) -> Table:
    """Build a Rich table of registered plugins."""
    table = Table(title="Registered Plugins")
    table.add_column("Name", style="bold")
    table.add_column("Version")
    table.add_column("Category")
    table.add_column("Capability")
    table.add_column("Auth")
    table.add_column("Description")

    for p in plugins:
        auth = "[green]YES[/green]" if p.get("requires_authorization") else "[dim]NO[/dim]"
        cap = str(p.get("capability", "passive")).upper()
        cap_color = {"PASSIVE": "green", "ACTIVE": "yellow", "DESTRUCTIVE": "red"}.get(cap, "white")
        table.add_row(
            p.get("name", "?"),
            p.get("version", "?"),
            p.get("category", "?"),
            f"[{cap_color}]{cap}[/{cap_color}]",
            auth,
            p.get("description", ""),
        )
    return table


def format_scan_result(result: dict[str, Any], fmt: str = "text") -> None:
    """Print a PluginResult dict as text or JSON."""
    if fmt == "json":
        console.print_json(json.dumps(result, indent=2, default=str))
        return

    panel_lines = [
        f"[bold]Plugin:[/bold] {result.get('plugin_name', '?')}",
        "[bold]Success:[/bold] {}".format(
            "[green]YES[/green]" if result.get("success") else "[red]NO[/red]"
        ),
        f"[bold]Mode:[/bold] {result.get('mode', 'live')}",
    ]
    if result.get("duration_ms"):
        panel_lines.append(f"[bold]Duration:[/bold] {result['duration_ms']:.0f} ms")

    console.print(Panel("\n".join(panel_lines), title="Scan Result", border_style="blue"))

    findings = result.get("findings", [])
    if findings:
        console.print(format_findings_table(findings))
    else:
        console.print("[dim]No findings.[/dim]")

    errors = result.get("errors", [])
    if errors:
        console.print("\n[bold red]Errors:[/bold red]")
        for e in errors:
            console.print(f"  [red]✗[/red] {e}")


def format_status(status: dict[str, Any], fmt: str = "text") -> None:
    """Print framework status as text or JSON."""
    if fmt == "json":
        console.print_json(json.dumps(status, indent=2, default=str))
        return

    table = Table(title="Framework Status", show_lines=False)
    table.add_column("Component", style="bold")
    table.add_column("Status")
    for k, v in status.items():
        table.add_row(k, str(v))
    console.print(table)
