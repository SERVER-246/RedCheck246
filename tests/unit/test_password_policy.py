"""Tests for redcheck.plugins.crypto.password_policy — PasswordEntropyScorer.

Coverage: entropy calculation, weak pattern detection, policy evaluation,
plugin execution, dry run.
"""

from __future__ import annotations

from redcheck.plugins.crypto.password_policy import (
    PasswordEntropyScorer,
    calculate_entropy,
    check_weak_patterns,
    evaluate_policy,
)

# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------


class TestCalculateEntropy:
    def test_empty_password(self):
        assert calculate_entropy("") == 0.0

    def test_all_lowercase(self):
        entropy = calculate_entropy("abcdefgh")
        # 8 chars * log2(26) ≈ 37.6
        assert 37 < entropy < 38

    def test_mixed_case_higher(self):
        lower = calculate_entropy("abcdefgh")
        mixed = calculate_entropy("Abcdefgh")
        assert mixed > lower

    def test_with_digits(self):
        no_digit = calculate_entropy("abcdefgh")
        with_digit = calculate_entropy("abcdefg1")
        assert with_digit > no_digit

    def test_with_symbols(self):
        entropy = calculate_entropy("P@ssw0rd!")
        # Uses all 4 classes → charset=95
        assert entropy > 50

    def test_longer_is_stronger(self):
        short = calculate_entropy("abcd")
        long_ = calculate_entropy("abcdefghijklmnop")
        assert long_ > short


# ---------------------------------------------------------------------------
# Weak pattern detection
# ---------------------------------------------------------------------------


class TestCheckWeakPatterns:
    def test_sequential_digits(self):
        patterns = check_weak_patterns("pass123word")
        assert "sequential_digits" in patterns

    def test_repeated_chars(self):
        patterns = check_weak_patterns("aaabbb")
        assert "repeated_chars" in patterns

    def test_keyboard_walk(self):
        patterns = check_weak_patterns("qwerty123")
        assert "keyboard_walk" in patterns

    def test_common_word(self):
        patterns = check_weak_patterns("password123")
        assert "common_word" in patterns

    def test_strong_password_no_patterns(self):
        patterns = check_weak_patterns("X9$mK2!pL7@n")
        assert len(patterns) == 0


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


class TestEvaluatePolicy:
    def test_strong_policy(self):
        policy = {
            "min_length": 12,
            "require_uppercase": True,
            "require_digits": True,
            "require_symbols": True,
            "max_age_days": 90,
            "mfa_required": True,
        }
        result = evaluate_policy(policy)
        assert result["rating"] == "strong"
        assert result["score"] >= 80

    def test_weak_policy(self):
        policy = {"min_length": 4}
        result = evaluate_policy(policy)
        assert result["rating"] in ("weak", "critical")
        assert len(result["issues"]) > 0

    def test_moderate_policy(self):
        policy = {
            "min_length": 8,
            "require_uppercase": True,
            "require_digits": True,
        }
        result = evaluate_policy(policy)
        assert result["rating"] in ("moderate", "weak")

    def test_issues_list(self):
        policy = {}
        result = evaluate_policy(policy)
        assert isinstance(result["issues"], list)
        assert len(result["issues"]) > 0

    def test_mfa_adds_score(self):
        without = evaluate_policy({"min_length": 8})
        with_mfa = evaluate_policy({"min_length": 8, "mfa_required": True})
        assert with_mfa["score"] > without["score"]


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------


class TestPasswordEntropyPlugin:
    def test_analyze_passwords(self):
        plugin = PasswordEntropyScorer()
        result = plugin.execute({"passwords": ["abc", "X9$mK2!pL7@nQ"]})
        assert result.success
        assert len(result.findings) == 2
        # First password is very short → critical entropy
        weak = result.findings[0]
        assert weak["severity"] in ("critical", "high")

    def test_analyze_policies(self):
        plugin = PasswordEntropyScorer()
        result = plugin.execute(
            {
                "password_policies": [
                    {
                        "min_length": 12,
                        "require_uppercase": True,
                        "require_digits": True,
                        "require_symbols": True,
                        "max_age_days": 90,
                        "mfa_required": True,
                    },
                ]
            }
        )
        assert result.success
        assert any(f["finding_type"] == "password_policy" for f in result.findings)

    def test_empty_input(self):
        plugin = PasswordEntropyScorer()
        result = plugin.execute({})
        assert result.success is True
        assert result.metadata.get("mode") == "no-input"

    def test_metadata_counts(self):
        plugin = PasswordEntropyScorer()
        result = plugin.execute(
            {
                "passwords": ["test"],
                "password_policies": [{"min_length": 8}],
            }
        )
        assert result.metadata["passwords_analyzed"] == 1
        assert result.metadata["policies_analyzed"] == 1

    def test_password_preview_masked(self):
        plugin = PasswordEntropyScorer()
        result = plugin.execute({"passwords": ["secretpassword"]})
        preview = result.findings[0]["password_preview"]
        assert "secretpassword" not in preview
        assert preview.startswith("se")

    def test_dry_run(self):
        plugin = PasswordEntropyScorer()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_plugin_name(self):
        assert PasswordEntropyScorer.name == "password-entropy-scorer"

    def test_passive_capability(self):
        from redcheck.models import PluginCapability

        assert PasswordEntropyScorer.capability == PluginCapability.PASSIVE
