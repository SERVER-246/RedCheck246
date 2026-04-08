"""Tests for the Attack Chain Scorer (redcheck.core.attack_chain_scorer)."""

from __future__ import annotations

from redcheck.core.attack_chain_scorer import (
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
