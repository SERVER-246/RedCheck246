"""RedCheck246 — Mode Separation (Phase E).

Classifies and segregates findings by execution mode so that simulated
results are never presented alongside real observations in executive
summaries.  Three categories:

* **real** — Plugin made actual network requests / system calls.
* **simulated** — Plugin ran in TEST mode with synthetic data.
* **dry_run** — Plugin produced an execution plan only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from redcheck.models import Finding, PluginResult

log = structlog.get_logger(__name__)

# Valid execution modes recognised by the separator.
_MODES = frozenset({"real", "simulated", "dry_run"})

# Simulation fidelity levels.
FIDELITY_HIGH = "high"
FIDELITY_MEDIUM = "medium"
FIDELITY_LOW = "low"


# ---------------------------------------------------------------------------
# Finding classification
# ---------------------------------------------------------------------------


def classify_finding(finding: Finding) -> str:
    """Return the execution mode of a finding: 'real', 'simulated', or 'dry_run'."""
    mode = finding.metadata.get("execution_mode", "real")
    if mode in _MODES:
        return mode
    return "real"


# ---------------------------------------------------------------------------
# Simulation metadata stamping
# ---------------------------------------------------------------------------


def stamp_simulation_metadata(
    result: PluginResult,
    *,
    fidelity: str = FIDELITY_MEDIUM,
) -> None:
    """Mark all findings in *result* as simulated with TEST‑mode metadata.

    Called by the orchestrator when ``runtime_mode == TEST`` and the result
    did not originate from a dry‑run.  Each finding receives:

    * ``simulation_flag = True``
    * ``execution_mode = "simulated"``
    * ``simulation_fidelity`` — caller‑supplied or 'medium'
    * ``simulated_input`` — target from the finding itself
    * ``expected_real_behavior`` — descriptive placeholder
    """
    result.metadata["execution_mode"] = "simulated"

    for finding in result.findings:
        finding.metadata["simulation_flag"] = True
        finding.metadata["execution_mode"] = "simulated"
        finding.metadata["simulation_fidelity"] = fidelity
        finding.metadata.setdefault(
            "simulated_input",
            finding.target,
        )
        finding.metadata.setdefault(
            "expected_real_behavior",
            f"Live execution against {finding.target} would produce "
            f"real network evidence for finding type '{finding.finding_type}'.",
        )


# ---------------------------------------------------------------------------
# Report‑ready segregation
# ---------------------------------------------------------------------------


class SegregatedFindings:
    """Findings split by execution mode, ready for report rendering."""

    __slots__ = ("real", "simulated", "dry_run")

    def __init__(
        self,
        real: list[Finding],
        simulated: list[Finding],
        dry_run: list[Finding],
    ) -> None:
        self.real = real
        self.simulated = simulated
        self.dry_run = dry_run

    @property
    def total(self) -> int:
        return len(self.real) + len(self.simulated) + len(self.dry_run)

    def to_dict(self) -> dict[str, Any]:
        """Emit the mode_breakdown dict used in report summaries."""
        return {
            "real": len(self.real),
            "simulated": len(self.simulated),
            "dry_run": len(self.dry_run),
        }


def segregate_findings(findings: list[Finding]) -> SegregatedFindings:
    """Split a flat list of findings into mode‑based buckets."""
    real: list[Finding] = []
    simulated: list[Finding] = []
    dry_run: list[Finding] = []

    for f in findings:
        mode = classify_finding(f)
        if mode == "simulated":
            simulated.append(f)
        elif mode == "dry_run":
            dry_run.append(f)
        else:
            real.append(f)

    return SegregatedFindings(real=real, simulated=simulated, dry_run=dry_run)
