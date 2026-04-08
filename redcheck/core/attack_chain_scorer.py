"""RedCheck246 — Attack Chain Scorer (Phase D).

Combines cross-plugin findings into scored multi-step attack paths
with quantitative risk ratings.

Uses ``AttackPathCorrelator`` to build graph from pipeline findings,
then applies the risk scoring formula from the improvement plan:

    risk_score = impact × composite_likelihood
                 × (exploitability / 10) × (1 − detection_probability)

Scale: 0.0 (no risk) to 10.0 (critical risk).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from redcheck.core.attack_path_correlator import AttackPathCorrelator
from redcheck.models import AttackerClass

if TYPE_CHECKING:
    from redcheck.plugins.base_plugin import PluginResult

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Impact scores for final-step finding types (CIA triad)
# ---------------------------------------------------------------------------

_IMPACT_SCORES: dict[str, float] = {  # nosec B105 — not passwords
    "sqli_timing": 9.0,
    "xss_reflected": 7.0,
    "breached_password": 8.5,
    "weak_credentials": 8.5,
    "idor_accessible": 7.5,
    "supply_chain_vulnerability": 8.0,
    "dast_sensitive_path": 5.0,
    "dast_weak_tls": 6.0,
    "session_fixation": 8.0,
    "csrf_missing": 6.5,
    "cookie_scope_issue": 5.5,
}

_DEFAULT_IMPACT: float = 5.0

# ---------------------------------------------------------------------------
# Edge-type → exploitability score mapping
# ---------------------------------------------------------------------------

_EXPLOITABILITY: dict[str, float] = {  # nosec B105 — not passwords
    "exploit_public": 8.0,
    "misconfig": 7.0,
    "authz_bypass": 7.5,
    "idor": 6.5,
    "token_reuse": 6.0,
    "privesc": 5.5,
    "api_chain": 5.0,
    "trust_boundary": 4.5,
    "lateral": 4.0,
    "exfil_indicator": 3.5,
}

_DEFAULT_EXPLOITABILITY: float = 5.0

# ---------------------------------------------------------------------------
# Cross-plugin correlation rules (upstream finding → downstream attack step)
# ---------------------------------------------------------------------------

CORRELATION_RULES: list[dict[str, str]] = [
    {
        "upstream": "open_port",
        "condition": "no_tls",
        "enables": "mitm_downgrade",
        "mitre": "T1557",
        "description": "Open port with no TLS enables MitM / downgrade attack",
    },
    {
        "upstream": "dast_weak_tls",
        "condition": "missing_hsts",
        "enables": "session_hijack",
        "mitre": "T1539",
        "description": "Missing HSTS enables session hijacking via insecure redirect",
    },
    {
        "upstream": "weak_credentials",
        "condition": "hardcoded",
        "enables": "auth_bypass",
        "mitre": "T1078",
        "description": "Hardcoded credentials enable direct authentication bypass",
    },
    {
        "upstream": "supply_chain_vulnerability",
        "condition": "known_cve",
        "enables": "exploit_known",
        "mitre": "T1190",
        "description": "Known CVE in dependency enables public exploit",
    },
    {
        "upstream": "idor_accessible",
        "condition": "enumerable",
        "enables": "data_exfil",
        "mitre": "T1530",
        "description": "IDOR with enumerable IDs enables mass data exfiltration",
    },
    {
        "upstream": "csrf_missing",
        "condition": "auth_form",
        "enables": "account_takeover",
        "mitre": "T1185",
        "description": "Missing CSRF on auth form enables account takeover via browser pivot",
    },
    {
        "upstream": "session_fixation",
        "condition": "no_rotation",
        "enables": "session_hijack",
        "mitre": "T1539",
        "description": "Session fixation enables pre-authenticated session hijacking",
    },
]


# ---------------------------------------------------------------------------
# Risk rating tiers
# ---------------------------------------------------------------------------


def _risk_rating(score: float) -> str:
    """Map a 0-10 risk score to a rating label."""
    if score >= 7.0:
        return "CRITICAL"
    if score >= 4.0:
        return "HIGH"
    if score >= 2.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ChainRiskScore:
    """Quantitative risk assessment for a single attack chain."""

    impact: float
    exploitability: float
    composite_likelihood: float
    detection_difficulty: float
    risk_score: float
    rating: str
    path_length: int
    weakest_link: float
    strongest_link: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "impact": round(self.impact, 2),
            "exploitability": round(self.exploitability, 2),
            "composite_likelihood": round(self.composite_likelihood, 4),
            "detection_difficulty": round(self.detection_difficulty, 2),
            "risk_score": round(self.risk_score, 2),
            "rating": self.rating,
            "path_length": self.path_length,
            "weakest_link": round(self.weakest_link, 4),
            "strongest_link": round(self.strongest_link, 4),
        }


@dataclass
class ScoredAttackChain:
    """A ranked attack path with quantitative risk scoring."""

    path_id: str
    entry_point: str
    final_target: str
    steps: list[dict[str, Any]]
    scoring: ChainRiskScore
    mitre_techniques: list[str]
    correlation_rules_matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "entry_point": self.entry_point,
            "final_target": self.final_target,
            "steps": self.steps,
            "scoring": self.scoring.to_dict(),
            "mitre_techniques": self.mitre_techniques,
            "correlation_rules_matched": self.correlation_rules_matched,
        }


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------


class AttackChainScorer:
    """Scores cross-plugin attack paths with quantitative risk metrics.

    Parameters
    ----------
    attacker_class:
        Scopes graph traversal depth and allowed edge types.
    detection_coverage:
        Dict mapping MITRE technique IDs to detection probability (0-1).
        Sourced from detection-coverage plugin results.
    max_chains:
        Maximum number of scored chains to return (default 10).
    """

    def __init__(
        self,
        attacker_class: AttackerClass = AttackerClass.AC2,
        detection_coverage: dict[str, float] | None = None,
        max_chains: int = 10,
    ) -> None:
        self._ac = attacker_class
        self._detection_coverage = detection_coverage or {}
        self._max_chains = max_chains

    def score(
        self,
        results: dict[str, PluginResult],
    ) -> list[ScoredAttackChain]:
        """Score attack chains from pipeline results.

        1. Feeds results into AttackPathCorrelator to build graph
        2. Extracts ranked paths via correlator.correlate()
        3. Scores each path with the risk formula
        4. Applies cross-plugin correlation rules
        5. Returns top-N scored chains sorted by risk_score desc
        """
        correlator = AttackPathCorrelator(
            attacker_class=self._ac,
            chain_mode=False,
            allow_exploit_validation=False,
        )
        correlator.ingest_findings(results)
        correlation = correlator.correlate()
        ranked_paths: list[dict[str, Any]] = correlation.get("ranked_paths", [])

        # Also build finding-type index for correlation rules
        finding_types: set[str] = set()
        for pr in results.values():
            for f in pr.findings:
                finding_types.add(f.finding_type)

        # Match correlation rules
        matched_rules = self._match_correlation_rules(finding_types)

        scored: list[ScoredAttackChain] = []
        for i, path_dict in enumerate(ranked_paths[: self._max_chains]):
            chain = self._score_path(path_dict, i + 1, matched_rules)
            scored.append(chain)

        # Sort by risk_score descending
        scored.sort(key=lambda c: c.scoring.risk_score, reverse=True)

        # Re-rank after sort
        for rank, chain in enumerate(scored, 1):
            chain.path_id = f"AC-{rank:03d}"

        log.info(
            "attack_chains_scored",
            total_paths=len(ranked_paths),
            scored_chains=len(scored),
            top_rating=scored[0].scoring.rating if scored else "N/A",
        )

        return scored

    def score_summary(
        self,
        results: dict[str, PluginResult],
    ) -> dict[str, Any]:
        """Return a summary dict suitable for embedding in reports."""
        chains = self.score(results)
        if not chains:
            return {
                "attack_chains": [],
                "chain_count": 0,
                "highest_risk_score": 0.0,
                "highest_risk_rating": "N/A",
                "ratings_breakdown": {},
            }

        ratings: dict[str, int] = {}
        for c in chains:
            ratings[c.scoring.rating] = ratings.get(c.scoring.rating, 0) + 1

        return {
            "attack_chains": [c.to_dict() for c in chains],
            "chain_count": len(chains),
            "highest_risk_score": round(chains[0].scoring.risk_score, 2),
            "highest_risk_rating": chains[0].scoring.rating,
            "ratings_breakdown": ratings,
        }

    # -- private -----------------------------------------------------------

    def _score_path(
        self,
        path_dict: dict[str, Any],
        rank: int,
        matched_rules: list[str],
    ) -> ScoredAttackChain:
        """Apply the risk scoring formula to a single ranked path."""
        edges = path_dict.get("edges", [])
        nodes = path_dict.get("nodes", [])
        agg_prob = path_dict.get("aggregate_probability", 0.0)

        # Build steps from edges
        steps: list[dict[str, Any]] = []
        edge_probs: list[float] = []
        mitre_techniques: list[str] = []
        edge_types: list[str] = []

        for step_num, edge in enumerate(edges, 1):
            prob = edge.get("probability", 0.2)
            edge_probs.append(prob)
            mitre = edge.get("mitre_technique", "")
            if mitre and mitre not in mitre_techniques:
                mitre_techniques.append(mitre)
            et = edge.get("edge_type", "exploit_public")
            edge_types.append(et)

            steps.append(
                {
                    "step": step_num,
                    "source": edge.get("source", ""),
                    "target": edge.get("target", ""),
                    "technique": mitre,
                    "edge_type": et,
                    "probability": round(prob, 4),
                    "description": edge.get("description", ""),
                }
            )

        # Composite likelihood = product of step probabilities
        composite_likelihood = agg_prob if agg_prob > 0 else 1.0
        for p in edge_probs:
            if agg_prob == 0:
                composite_likelihood *= p

        # Impact: based on the final edge's finding type (extracted from description)
        impact = self._compute_impact(edges)

        # Exploitability: weighted average of edge types
        exploitability = self._compute_exploitability(edge_types)

        # Detection difficulty: based on MITRE technique coverage
        detection_prob = self._compute_detection_probability(mitre_techniques)

        # Risk formula:
        # risk = impact × likelihood × (exploitability/10) × (1 - detection_prob)
        risk_score = (
            impact * composite_likelihood * (exploitability / 10.0) * (1.0 - detection_prob)
        )
        # Clamp to 0..10
        risk_score = max(0.0, min(10.0, risk_score))

        weakest = min(edge_probs) if edge_probs else 0.0
        strongest = max(edge_probs) if edge_probs else 0.0

        scoring = ChainRiskScore(
            impact=impact,
            exploitability=exploitability,
            composite_likelihood=composite_likelihood,
            detection_difficulty=1.0 - detection_prob,
            risk_score=risk_score,
            rating=_risk_rating(risk_score),
            path_length=len(steps),
            weakest_link=weakest,
            strongest_link=strongest,
        )

        entry = nodes[0] if nodes else (edges[0]["source"] if edges else "unknown")
        final = nodes[-1] if nodes else (edges[-1]["target"] if edges else "unknown")

        return ScoredAttackChain(
            path_id=f"AC-{rank:03d}",
            entry_point=entry,
            final_target=final,
            steps=steps,
            scoring=scoring,
            mitre_techniques=mitre_techniques,
            correlation_rules_matched=matched_rules,
        )

    def _compute_impact(self, edges: list[dict[str, Any]]) -> float:
        """Derive impact score from the final edge's finding type."""
        if not edges:
            return _DEFAULT_IMPACT

        # Extract finding type from last edge description
        last_edge = edges[-1]
        desc = last_edge.get("description", "")
        edge_type = last_edge.get("edge_type", "")

        # Check each known finding type in the description
        for ft, score in _IMPACT_SCORES.items():
            if ft in desc:
                return score

        # Fallback: edge type heuristic
        if edge_type in ("exploit_public", "authz_bypass"):
            return 8.0
        if edge_type in ("idor", "token_reuse"):
            return 7.0
        if edge_type == "misconfig":
            return 5.5

        return _DEFAULT_IMPACT

    def _compute_exploitability(self, edge_types: list[str]) -> float:
        """Weighted average exploitability across path edges."""
        if not edge_types:
            return _DEFAULT_EXPLOITABILITY
        total = sum(_EXPLOITABILITY.get(et, _DEFAULT_EXPLOITABILITY) for et in edge_types)
        return total / len(edge_types)

    def _compute_detection_probability(self, techniques: list[str]) -> float:
        """Average detection probability from detection-coverage data."""
        if not techniques or not self._detection_coverage:
            return 0.0  # No detection data → assume undetected
        probs = [self._detection_coverage.get(t, 0.0) for t in techniques]
        return sum(probs) / len(probs)

    @staticmethod
    def _match_correlation_rules(finding_types: set[str]) -> list[str]:
        """Check which cross-plugin correlation rules are triggered."""
        matched: list[str] = []
        for rule in CORRELATION_RULES:
            if rule["upstream"] in finding_types:
                matched.append(rule["description"])
        return matched
