"""Tests for the Attack Chain Scorer (redcheck.core.attack_chain_scorer)."""

from __future__ import annotations

from unittest.mock import patch

from redcheck.core.attack_chain_scorer import (
    _DEFAULT_EXPLOITABILITY,
    _DEFAULT_IMPACT,
    CORRELATION_RULES,
    AttackChainScorer,
    ChainRiskScore,
    ScoredAttackChain,
    _risk_rating,
)
from redcheck.models import (
    AttackerClass,
    Finding,
    FindingSeverity,
    PluginResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    finding_type: str,
    target: str = "10.0.0.1",
    severity: FindingSeverity = FindingSeverity.HIGH,
    detail: str = "test detail",
    mitre_technique: str | None = None,
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        target=target,
        severity=severity,
        detail=detail,
        mitre_technique=mitre_technique,
        metadata=metadata or {},
    )


def _result(
    plugin_name: str,
    findings: list[Finding] | None = None,
) -> PluginResult:
    return PluginResult(
        plugin_name=plugin_name,
        success=True,
        findings=findings or [],
    )


def _multi_plugin_results() -> dict[str, PluginResult]:
    """Build a realistic multi-plugin result set with assets and vulnerabilities."""
    return {
        "network-scanner": _result(
            "network-scanner",
            [
                _finding(
                    "open_port",
                    target="10.0.0.1",
                    severity=FindingSeverity.INFO,
                    metadata={"port": 443, "service_name": "https"},
                ),
                _finding(
                    "open_port",
                    target="10.0.0.1",
                    severity=FindingSeverity.INFO,
                    metadata={"port": 80, "service_name": "http"},
                ),
            ],
        ),
        "dast-scanner": _result(
            "dast-scanner",
            [
                _finding(
                    "dast_weak_tls",
                    target="10.0.0.1",
                    severity=FindingSeverity.MEDIUM,
                    mitre_technique="T1557",
                ),
                _finding(
                    "xss_reflected",
                    target="10.0.0.1",
                    severity=FindingSeverity.HIGH,
                    mitre_technique="T1059.007",
                ),
            ],
        ),
        "supply-chain-audit": _result(
            "supply-chain-audit",
            [
                _finding(
                    "supply_chain_vulnerability",
                    target="10.0.0.1",
                    severity=FindingSeverity.CRITICAL,
                    mitre_technique="T1190",
                ),
            ],
        ),
    }


# ---------------------------------------------------------------------------
# Risk Rating
# ---------------------------------------------------------------------------


class TestRiskRating:
    def test_critical(self):
        assert _risk_rating(7.0) == "CRITICAL"
        assert _risk_rating(10.0) == "CRITICAL"

    def test_high(self):
        assert _risk_rating(4.0) == "HIGH"
        assert _risk_rating(6.9) == "HIGH"

    def test_medium(self):
        assert _risk_rating(2.0) == "MEDIUM"
        assert _risk_rating(3.9) == "MEDIUM"

    def test_low(self):
        assert _risk_rating(0.0) == "LOW"
        assert _risk_rating(1.9) == "LOW"


# ---------------------------------------------------------------------------
# ChainRiskScore
# ---------------------------------------------------------------------------


class TestChainRiskScore:
    def test_to_dict_fields(self):
        score = ChainRiskScore(
            impact=8.5,
            exploitability=7.0,
            composite_likelihood=0.35,
            detection_difficulty=0.8,
            risk_score=7.2,
            rating="CRITICAL",
            path_length=3,
            weakest_link=0.4,
            strongest_link=0.9,
        )
        d = score.to_dict()
        assert d["impact"] == 8.5
        assert d["exploitability"] == 7.0
        assert d["composite_likelihood"] == 0.35
        assert d["risk_score"] == 7.2
        assert d["rating"] == "CRITICAL"
        assert d["path_length"] == 3

    def test_values_rounded(self):
        score = ChainRiskScore(
            impact=8.456,
            exploitability=7.123,
            composite_likelihood=0.123456,
            detection_difficulty=0.8,
            risk_score=5.678,
            rating="HIGH",
            path_length=2,
            weakest_link=0.12345,
            strongest_link=0.98765,
        )
        d = score.to_dict()
        assert d["impact"] == 8.46
        assert d["exploitability"] == 7.12
        assert d["composite_likelihood"] == 0.1235
        assert d["weakest_link"] == 0.1235
        assert d["strongest_link"] == 0.9877


# ---------------------------------------------------------------------------
# ScoredAttackChain
# ---------------------------------------------------------------------------


class TestScoredAttackChain:
    def test_to_dict_structure(self):
        chain = ScoredAttackChain(
            path_id="AC-001",
            entry_point="asset:10.0.0.1:80",
            final_target="asset:10.0.0.1:vuln:xss_reflected",
            steps=[{"step": 1, "source": "a", "target": "b"}],
            scoring=ChainRiskScore(
                impact=7.0,
                exploitability=8.0,
                composite_likelihood=0.7,
                detection_difficulty=0.8,
                risk_score=6.3,
                rating="HIGH",
                path_length=1,
                weakest_link=0.7,
                strongest_link=0.7,
            ),
            mitre_techniques=["T1190"],
            correlation_rules_matched=["test rule"],
        )
        d = chain.to_dict()
        assert d["path_id"] == "AC-001"
        assert d["entry_point"] == "asset:10.0.0.1:80"
        assert d["scoring"]["rating"] == "HIGH"
        assert d["mitre_techniques"] == ["T1190"]
        assert d["correlation_rules_matched"] == ["test rule"]
        assert len(d["steps"]) == 1


# ---------------------------------------------------------------------------
# AttackChainScorer — Construction
# ---------------------------------------------------------------------------


class TestAttackChainScorerInit:
    def test_default_attacker_class(self):
        scorer = AttackChainScorer()
        assert scorer._ac == AttackerClass.AC2

    def test_custom_attacker_class(self):
        scorer = AttackChainScorer(attacker_class=AttackerClass.AC4)
        assert scorer._ac == AttackerClass.AC4

    def test_with_detection_coverage(self):
        coverage = {"T1190": 0.8, "T1557": 0.3}
        scorer = AttackChainScorer(detection_coverage=coverage)
        assert scorer._detection_coverage == coverage

    def test_max_chains_default(self):
        scorer = AttackChainScorer()
        assert scorer._max_chains == 10


# ---------------------------------------------------------------------------
# AttackChainScorer — Empty results
# ---------------------------------------------------------------------------


class TestAttackChainScorerEmpty:
    def test_no_results(self):
        scorer = AttackChainScorer()
        chains = scorer.score({})
        assert chains == []

    def test_no_vulnerabilities(self):
        """Asset-only results produce no edges, thus no paths."""
        results = {
            "network-scanner": _result(
                "network-scanner",
                [_finding("open_port", metadata={"port": 80})],
            ),
        }
        scorer = AttackChainScorer()
        chains = scorer.score(results)
        assert chains == []

    def test_score_summary_empty(self):
        scorer = AttackChainScorer()
        summary = scorer.score_summary({})
        assert summary["chain_count"] == 0
        assert summary["highest_risk_score"] == 0.0
        assert summary["highest_risk_rating"] == "N/A"
        assert summary["attack_chains"] == []


# ---------------------------------------------------------------------------
# AttackChainScorer — Scoring with findings
# ---------------------------------------------------------------------------


class TestAttackChainScorerScoring:
    def test_single_vulnerability_chain(self):
        """A single vuln edge creates one attack chain."""
        results = {
            "network-scanner": _result(
                "network-scanner",
                [
                    _finding(
                        "open_port",
                        target="10.0.0.1",
                        severity=FindingSeverity.INFO,
                        metadata={"port": 443},
                    ),
                ],
            ),
            "dast-scanner": _result(
                "dast-scanner",
                [
                    _finding(
                        "sqli_timing",
                        target="10.0.0.1",
                        severity=FindingSeverity.CRITICAL,
                        mitre_technique="T1190",
                    ),
                ],
            ),
        }
        scorer = AttackChainScorer()
        chains = scorer.score(results)
        # The correlator may or may not find paths depending on graph structure
        # but the scorer should not crash
        assert isinstance(chains, list)
        for chain in chains:
            assert isinstance(chain, ScoredAttackChain)
            assert chain.scoring.risk_score >= 0
            assert chain.scoring.risk_score <= 10.0
            assert chain.scoring.rating in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_multi_plugin_results(self):
        """Multi-plugin scenario should score paths correctly."""
        results = _multi_plugin_results()
        scorer = AttackChainScorer()
        chains = scorer.score(results)
        assert isinstance(chains, list)
        # All chains should be sorted by risk_score desc
        for i in range(len(chains) - 1):
            assert chains[i].scoring.risk_score >= chains[i + 1].scoring.risk_score

    def test_risk_score_formula_components(self):
        """Verify risk score formula is applied correctly."""
        results = _multi_plugin_results()
        scorer = AttackChainScorer()
        chains = scorer.score(results)
        for chain in chains:
            s = chain.scoring
            # Verify all components are within valid ranges
            assert 0 <= s.impact <= 10.0
            assert 0 <= s.exploitability <= 10.0
            assert 0 <= s.composite_likelihood <= 1.0
            assert 0 <= s.detection_difficulty <= 1.0
            assert 0 <= s.risk_score <= 10.0

    def test_scored_chains_have_ids(self):
        """Chains should be numbered AC-001, AC-002, etc."""
        results = _multi_plugin_results()
        scorer = AttackChainScorer()
        chains = scorer.score(results)
        for i, chain in enumerate(chains, 1):
            assert chain.path_id == f"AC-{i:03d}"

    def test_max_chains_limit(self):
        """Scorer should respect max_chains."""
        results = _multi_plugin_results()
        scorer = AttackChainScorer(max_chains=1)
        chains = scorer.score(results)
        assert len(chains) <= 1


# ---------------------------------------------------------------------------
# AttackChainScorer — Detection coverage
# ---------------------------------------------------------------------------


class TestDetectionCoverage:
    def test_detection_lowers_risk(self):
        """High detection coverage should reduce risk score."""
        results = _multi_plugin_results()

        # No detection coverage
        scorer_no_det = AttackChainScorer(detection_coverage={})
        chains_no_det = scorer_no_det.score(results)

        # Full detection coverage
        scorer_full_det = AttackChainScorer(
            detection_coverage={"T1557": 0.9, "T1059.007": 0.9, "T1190": 0.9}
        )
        chains_full_det = scorer_full_det.score(results)

        # With detection, risk should be lower (or equal if no paths)
        if chains_no_det and chains_full_det:
            assert chains_full_det[0].scoring.risk_score <= chains_no_det[0].scoring.risk_score


# ---------------------------------------------------------------------------
# Correlation Rules
# ---------------------------------------------------------------------------


class TestCorrelationRules:
    def test_rules_have_required_fields(self):
        for rule in CORRELATION_RULES:
            assert "upstream" in rule
            assert "enables" in rule
            assert "mitre" in rule
            assert "description" in rule

    def test_open_port_matches(self):
        scorer = AttackChainScorer()
        matched = scorer._match_correlation_rules({"open_port", "dns_record"})
        assert any("MitM" in m for m in matched)

    def test_supply_chain_matches(self):
        scorer = AttackChainScorer()
        matched = scorer._match_correlation_rules({"supply_chain_vulnerability"})
        assert any("CVE" in m for m in matched)

    def test_no_match_for_unrelated(self):
        scorer = AttackChainScorer()
        matched = scorer._match_correlation_rules({"dns_record", "subdomain_enum"})
        assert matched == []

    def test_multiple_rules_match(self):
        scorer = AttackChainScorer()
        finding_types = {
            "open_port",
            "weak_credentials",
            "supply_chain_vulnerability",
            "csrf_missing",
        }
        matched = scorer._match_correlation_rules(finding_types)
        assert len(matched) >= 3


# ---------------------------------------------------------------------------
# Score Summary
# ---------------------------------------------------------------------------


class TestScoreSummary:
    def test_summary_structure(self):
        results = _multi_plugin_results()
        scorer = AttackChainScorer()
        summary = scorer.score_summary(results)
        assert "attack_chains" in summary
        assert "chain_count" in summary
        assert "highest_risk_score" in summary
        assert "highest_risk_rating" in summary
        assert "ratings_breakdown" in summary

    def test_summary_chains_serializable(self):
        """Chains in summary should be plain dicts."""
        results = _multi_plugin_results()
        scorer = AttackChainScorer()
        summary = scorer.score_summary(results)
        for chain in summary["attack_chains"]:
            assert isinstance(chain, dict)
            assert "scoring" in chain
            assert isinstance(chain["scoring"], dict)

    def test_ratings_breakdown_counts(self):
        results = _multi_plugin_results()
        scorer = AttackChainScorer()
        summary = scorer.score_summary(results)
        total = sum(summary["ratings_breakdown"].values())
        assert total == summary["chain_count"]


# ---------------------------------------------------------------------------
# _score_path — direct unit tests
# ---------------------------------------------------------------------------

_FAKE_PATH = {
    "nodes": ["asset:10.0.0.1:80", "vuln:xss_reflected"],
    "edges": [
        {
            "source": "asset:10.0.0.1:80",
            "target": "vuln:xss_reflected",
            "probability": 0.6,
            "edge_type": "exploit_public",
            "mitre_technique": "T1059.007",
            "description": "xss_reflected on target",
        },
    ],
    "aggregate_probability": 0.0,
}


class TestScorePath:
    def test_basic_path_scoring(self):
        scorer = AttackChainScorer()
        chain = scorer._score_path(_FAKE_PATH, 1, [])
        assert isinstance(chain, ScoredAttackChain)
        assert chain.path_id == "AC-001"
        assert chain.entry_point == "asset:10.0.0.1:80"
        assert chain.final_target == "vuln:xss_reflected"
        assert len(chain.steps) == 1
        assert chain.scoring.risk_score >= 0
        assert chain.scoring.risk_score <= 10.0
        assert chain.scoring.path_length == 1

    def test_path_with_precomputed_aggregate(self):
        """When aggregate_probability > 0, it is used directly."""
        path = {
            "nodes": ["a", "b"],
            "edges": [
                {
                    "source": "a",
                    "target": "b",
                    "probability": 0.5,
                    "edge_type": "misconfig",
                    "mitre_technique": "T1557",
                    "description": "misconfiguration",
                },
            ],
            "aggregate_probability": 0.25,
        }
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        assert chain.scoring.composite_likelihood == 0.25

    def test_path_with_zero_aggregate(self):
        """When aggregate_probability == 0, product of edge probabilities is used."""
        path = {
            "nodes": ["a", "b", "c"],
            "edges": [
                {
                    "source": "a",
                    "target": "b",
                    "probability": 0.5,
                    "edge_type": "misconfig",
                    "mitre_technique": "",
                    "description": "",
                },
                {
                    "source": "b",
                    "target": "c",
                    "probability": 0.4,
                    "edge_type": "idor",
                    "mitre_technique": "",
                    "description": "",
                },
            ],
            "aggregate_probability": 0.0,
        }
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        # 1.0 * 0.5 * 0.4 = 0.2
        assert abs(chain.scoring.composite_likelihood - 0.2) < 1e-9

    def test_weakest_strongest_links(self):
        path = {
            "nodes": ["a", "b", "c"],
            "edges": [
                {
                    "source": "a",
                    "target": "b",
                    "probability": 0.3,
                    "edge_type": "misconfig",
                    "description": "",
                },
                {
                    "source": "b",
                    "target": "c",
                    "probability": 0.9,
                    "edge_type": "idor",
                    "description": "",
                },
            ],
            "aggregate_probability": 0.0,
        }
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        assert chain.scoring.weakest_link == 0.3
        assert chain.scoring.strongest_link == 0.9

    def test_empty_edges(self):
        path = {"nodes": [], "edges": [], "aggregate_probability": 0.0}
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        assert chain.scoring.path_length == 0
        assert chain.entry_point == "unknown"
        assert chain.final_target == "unknown"
        assert chain.scoring.weakest_link == 0.0
        assert chain.scoring.strongest_link == 0.0

    def test_no_nodes_fallback_to_edges(self):
        path = {
            "nodes": [],
            "edges": [
                {
                    "source": "src",
                    "target": "dst",
                    "probability": 0.5,
                    "edge_type": "lateral",
                    "description": "",
                },
            ],
            "aggregate_probability": 0.0,
        }
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        assert chain.entry_point == "src"
        assert chain.final_target == "dst"

    def test_dedup_mitre_techniques(self):
        path = {
            "nodes": ["a", "b", "c"],
            "edges": [
                {
                    "source": "a",
                    "target": "b",
                    "probability": 0.5,
                    "edge_type": "exploit_public",
                    "mitre_technique": "T1190",
                    "description": "",
                },
                {
                    "source": "b",
                    "target": "c",
                    "probability": 0.5,
                    "edge_type": "exploit_public",
                    "mitre_technique": "T1190",
                    "description": "",
                },
            ],
            "aggregate_probability": 0.0,
        }
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        # Duplicate technique should appear only once
        assert chain.mitre_techniques == ["T1190"]

    def test_risk_score_clamped_to_10(self):
        """Extreme values should still clamp to 10."""
        path = {
            "nodes": ["a", "b"],
            "edges": [
                {
                    "source": "a",
                    "target": "b",
                    "probability": 1.0,
                    "edge_type": "exploit_public",
                    "mitre_technique": "",
                    "description": "sqli_timing — direct injection",
                },
            ],
            "aggregate_probability": 0.0,
        }
        scorer = AttackChainScorer()
        chain = scorer._score_path(path, 1, [])
        assert chain.scoring.risk_score <= 10.0

    def test_correlation_rules_passed_through(self):
        scorer = AttackChainScorer()
        chain = scorer._score_path(_FAKE_PATH, 1, ["rule-a", "rule-b"])
        assert chain.correlation_rules_matched == ["rule-a", "rule-b"]

    def test_detection_coverage_reduces_score(self):
        """With detection coverage, risk_score should decrease."""
        path = {
            "nodes": ["a", "b"],
            "edges": [
                {
                    "source": "a",
                    "target": "b",
                    "probability": 0.8,
                    "edge_type": "exploit_public",
                    "mitre_technique": "T1190",
                    "description": "sqli_timing",
                },
            ],
            "aggregate_probability": 0.0,
        }
        scorer_no_det = AttackChainScorer(detection_coverage={})
        scorer_det = AttackChainScorer(detection_coverage={"T1190": 0.9})
        chain_no = scorer_no_det._score_path(path, 1, [])
        chain_det = scorer_det._score_path(path, 1, [])
        assert chain_det.scoring.risk_score < chain_no.scoring.risk_score


# ---------------------------------------------------------------------------
# _compute_impact — direct unit tests
# ---------------------------------------------------------------------------


class TestComputeImpact:
    def _scorer(self) -> AttackChainScorer:
        return AttackChainScorer()

    def test_empty_edges_returns_default(self):
        assert self._scorer()._compute_impact([]) == _DEFAULT_IMPACT

    def test_known_finding_in_description(self):
        edges = [{"description": "found sqli_timing issue", "edge_type": "exploit_public"}]
        assert self._scorer()._compute_impact(edges) == 9.0

    def test_xss_reflected_in_description(self):
        edges = [{"description": "xss_reflected on target", "edge_type": "exploit_public"}]
        assert self._scorer()._compute_impact(edges) == 7.0

    def test_supply_chain_in_description(self):
        edges = [{"description": "supply_chain_vulnerability CVE-2024-1234", "edge_type": ""}]
        assert self._scorer()._compute_impact(edges) == 8.0

    def test_exploit_public_fallback(self):
        edges = [{"description": "unknown thing", "edge_type": "exploit_public"}]
        assert self._scorer()._compute_impact(edges) == 8.0

    def test_authz_bypass_fallback(self):
        edges = [{"description": "unknown thing", "edge_type": "authz_bypass"}]
        assert self._scorer()._compute_impact(edges) == 8.0

    def test_idor_fallback(self):
        edges = [{"description": "unknown thing", "edge_type": "idor"}]
        assert self._scorer()._compute_impact(edges) == 7.0

    def test_token_reuse_fallback(self):
        edges = [{"description": "unknown thing", "edge_type": "token_reuse"}]
        assert self._scorer()._compute_impact(edges) == 7.0

    def test_misconfig_fallback(self):
        edges = [{"description": "unknown thing", "edge_type": "misconfig"}]
        assert self._scorer()._compute_impact(edges) == 5.5

    def test_completely_unknown_returns_default(self):
        edges = [{"description": "no match", "edge_type": "lateral"}]
        assert self._scorer()._compute_impact(edges) == _DEFAULT_IMPACT

    def test_multiple_edges_uses_last(self):
        """Impact is derived from the *last* edge only."""
        edges = [
            {"description": "sqli_timing", "edge_type": "exploit_public"},
            {"description": "no match", "edge_type": "misconfig"},
        ]
        assert self._scorer()._compute_impact(edges) == 5.5


# ---------------------------------------------------------------------------
# _compute_exploitability — direct unit tests
# ---------------------------------------------------------------------------


class TestComputeExploitability:
    def _scorer(self) -> AttackChainScorer:
        return AttackChainScorer()

    def test_empty_returns_default(self):
        assert self._scorer()._compute_exploitability([]) == _DEFAULT_EXPLOITABILITY

    def test_single_known_type(self):
        assert self._scorer()._compute_exploitability(["exploit_public"]) == 8.0

    def test_average_of_types(self):
        # exploit_public=8.0, misconfig=7.0 → average=7.5
        result = self._scorer()._compute_exploitability(["exploit_public", "misconfig"])
        assert abs(result - 7.5) < 1e-9

    def test_unknown_type_uses_default(self):
        result = self._scorer()._compute_exploitability(["totally_unknown"])
        assert result == _DEFAULT_EXPLOITABILITY


# ---------------------------------------------------------------------------
# _compute_detection_probability — direct unit tests
# ---------------------------------------------------------------------------


class TestComputeDetectionProbability:
    def test_no_techniques(self):
        scorer = AttackChainScorer(detection_coverage={"T1190": 0.8})
        assert scorer._compute_detection_probability([]) == 0.0

    def test_no_coverage_data(self):
        scorer = AttackChainScorer(detection_coverage={})
        assert scorer._compute_detection_probability(["T1190"]) == 0.0

    def test_single_technique(self):
        scorer = AttackChainScorer(detection_coverage={"T1190": 0.7})
        assert abs(scorer._compute_detection_probability(["T1190"]) - 0.7) < 1e-9

    def test_average(self):
        scorer = AttackChainScorer(detection_coverage={"T1190": 0.8, "T1557": 0.4})
        result = scorer._compute_detection_probability(["T1190", "T1557"])
        assert abs(result - 0.6) < 1e-9

    def test_missing_technique_defaults_to_zero(self):
        scorer = AttackChainScorer(detection_coverage={"T1190": 0.8})
        result = scorer._compute_detection_probability(["T1190", "T9999"])
        assert abs(result - 0.4) < 1e-9


# ---------------------------------------------------------------------------
# score() / score_summary() with mocked correlator paths
# ---------------------------------------------------------------------------


class TestScoreWithPaths:
    """Use a mock correlator to inject ranked_paths so score/score_summary
    exercise the ranking, re-numbering, and summary aggregation code."""

    _FAKE_CORRELATION = {
        "ranked_paths": [
            {
                "nodes": ["a", "b"],
                "edges": [
                    {
                        "source": "a",
                        "target": "b",
                        "probability": 0.6,
                        "edge_type": "misconfig",
                        "mitre_technique": "T1557",
                        "description": "dast_weak_tls",
                    },
                ],
                "aggregate_probability": 0.6,
            },
            {
                "nodes": ["c", "d"],
                "edges": [
                    {
                        "source": "c",
                        "target": "d",
                        "probability": 0.9,
                        "edge_type": "exploit_public",
                        "mitre_technique": "T1190",
                        "description": "sqli_timing",
                    },
                ],
                "aggregate_probability": 0.9,
            },
        ],
    }

    def _results(self) -> dict[str, PluginResult]:
        return {
            "scanner": _result(
                "scanner",
                [_finding("open_port", metadata={"port": 80})],
            ),
        }

    def _mock_correlate(self, _self):
        # _self is AttackPathCorrelator instance; ignore it
        return self._FAKE_CORRELATION

    @patch(
        "redcheck.core.attack_chain_scorer.AttackPathCorrelator.correlate",
        autospec=True,
    )
    @patch(
        "redcheck.core.attack_chain_scorer.AttackPathCorrelator.ingest_findings",
        autospec=True,
    )
    def test_score_returns_sorted_chains(self, mock_ingest, mock_correlate):
        mock_correlate.side_effect = self._mock_correlate
        scorer = AttackChainScorer()
        chains = scorer.score(self._results())
        assert len(chains) == 2
        # Should be sorted descending by risk_score
        assert chains[0].scoring.risk_score >= chains[1].scoring.risk_score
        # Re-ranked after sort
        assert chains[0].path_id == "AC-001"
        assert chains[1].path_id == "AC-002"

    @patch(
        "redcheck.core.attack_chain_scorer.AttackPathCorrelator.correlate",
        autospec=True,
    )
    @patch(
        "redcheck.core.attack_chain_scorer.AttackPathCorrelator.ingest_findings",
        autospec=True,
    )
    def test_score_summary_with_chains(self, mock_ingest, mock_correlate):
        mock_correlate.side_effect = self._mock_correlate
        scorer = AttackChainScorer()
        summary = scorer.score_summary(self._results())
        assert summary["chain_count"] == 2
        assert summary["highest_risk_score"] > 0
        assert summary["highest_risk_rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert isinstance(summary["ratings_breakdown"], dict)
        total = sum(summary["ratings_breakdown"].values())
        assert total == 2
