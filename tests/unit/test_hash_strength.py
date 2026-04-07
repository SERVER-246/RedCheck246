"""Tests for redcheck.plugins.crypto.hash_strength — OfflineHashStrengthAnalyzer.

Coverage: hash identification, crack time estimation, plugin execution,
dry run, edge cases.
"""

from __future__ import annotations

from redcheck.plugins.crypto.hash_strength import (
    OfflineHashStrengthAnalyzer,
    estimate_crack_time,
    identify_hash,
)

# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------


class TestIdentifyHash:
    def test_md5(self):
        result = identify_hash("5d41402abc4b2a76b9719d911017c592")
        assert result is not None
        assert result["name"] == "MD5"
        assert result["rating"] == "critical"

    def test_sha1(self):
        result = identify_hash("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        assert result is not None
        assert result["name"] == "SHA-1"

    def test_sha256(self):
        h = "a" * 64
        result = identify_hash(h)
        assert result is not None
        assert result["name"] == "SHA-256"

    def test_sha512(self):
        h = "b" * 128
        result = identify_hash(h)
        assert result is not None
        assert result["name"] == "SHA-512"

    def test_bcrypt(self):
        h = "$2b$12$" + "a" * 53
        result = identify_hash(h)
        assert result is not None
        assert result["name"] == "bcrypt"
        assert result["rating"] == "low"

    def test_argon2(self):
        result = identify_hash("$argon2id$v=19$m=65536,t=3,p=4$abcdefgh$hash")
        assert result is not None
        assert result["name"] == "argon2"

    def test_pbkdf2(self):
        result = identify_hash("pbkdf2:sha256:260000$salt$hash")
        assert result is not None
        assert result["name"] == "PBKDF2"

    def test_unrecognized(self):
        result = identify_hash("not-a-hash")
        assert result is None

    def test_empty_string(self):
        result = identify_hash("")
        assert result is None

    def test_ntlm_with_context(self):
        result = identify_hash("5d41402abc4b2a76b9719d911017c592", "ntlm")
        assert result is not None
        assert result["name"] == "NTLM"

    def test_whitespace_stripped(self):
        result = identify_hash("  5d41402abc4b2a76b9719d911017c592  ")
        assert result is not None
        assert result["name"] == "MD5"


# ---------------------------------------------------------------------------
# Crack time estimation
# ---------------------------------------------------------------------------


class TestEstimateCrackTime:
    def test_md5_is_moderate_at_8chars(self):
        info = identify_hash("5d41402abc4b2a76b9719d911017c592")
        assert info is not None
        result = estimate_crack_time(info, charset_size=95, password_length=8)
        assert result["feasibility"] in ("trivial", "easy", "moderate")

    def test_md5_is_trivial_at_6chars(self):
        info = identify_hash("5d41402abc4b2a76b9719d911017c592")
        assert info is not None
        result = estimate_crack_time(info, charset_size=95, password_length=6)
        assert result["feasibility"] in ("trivial", "easy")

    def test_bcrypt_is_hard(self):
        h = "$2b$12$" + "a" * 53
        info = identify_hash(h)
        assert info is not None
        result = estimate_crack_time(info, charset_size=95, password_length=8)
        assert result["feasibility"] in ("hard", "infeasible")

    def test_argon2_is_infeasible(self):
        info = identify_hash("$argon2id$v=19$m=65536,t=3,p=4$abcdefgh$hash")
        assert info is not None
        result = estimate_crack_time(info, charset_size=95, password_length=8)
        assert result["feasibility"] in ("hard", "infeasible")

    def test_short_password_faster(self):
        info = identify_hash("5d41402abc4b2a76b9719d911017c592")
        assert info is not None
        short = estimate_crack_time(info, password_length=4)
        long_ = estimate_crack_time(info, password_length=12)
        assert short["estimated_seconds"] < long_["estimated_seconds"]

    def test_result_structure(self):
        info = {"name": "test", "crackable_per_second_gpu": 1_000_000}
        result = estimate_crack_time(info, charset_size=26, password_length=6)
        assert "keyspace" in result
        assert "rate_per_second" in result
        assert "estimated_seconds" in result
        assert "human_readable" in result
        assert "feasibility" in result


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------


class TestHashStrengthPlugin:
    def test_no_hashes(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute({"hashes": []})
        assert result.success is True
        assert result.metadata.get("mode") == "no-input"

    def test_no_hashes_key(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute({})
        assert result.success is True
        assert result.metadata.get("mode") == "no-input"

    def test_analyze_md5(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute({"hashes": ["5d41402abc4b2a76b9719d911017c592"]})
        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0]["algorithm"] == "MD5"
        assert result.findings[0]["severity"] == "critical"

    def test_analyze_bcrypt(self):
        plugin = OfflineHashStrengthAnalyzer()
        h = "$2b$12$" + "a" * 53
        result = plugin.execute({"hashes": [h]})
        assert result.success
        assert result.findings[0]["algorithm"] == "bcrypt"
        assert result.findings[0]["severity"] == "low"

    def test_unrecognized_hash_error(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute({"hashes": ["not-a-hash"]})
        assert result.success
        assert len(result.errors) == 1

    def test_dict_entry_with_context(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute(
            {"hashes": [{"hash": "5d41402abc4b2a76b9719d911017c592", "context": "ntlm"}]}
        )
        assert result.success
        assert result.findings[0]["algorithm"] == "NTLM"

    def test_multiple_hashes(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute(
            {
                "hashes": [
                    "5d41402abc4b2a76b9719d911017c592",
                    "$2b$12$" + "a" * 53,
                ]
            }
        )
        assert len(result.findings) == 2

    def test_metadata_count(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.execute({"hashes": ["a" * 64]})
        assert result.metadata["hashes_analyzed"] == 1

    def test_dry_run(self):
        plugin = OfflineHashStrengthAnalyzer()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"
        assert "supported_algorithms" in result.metadata

    def test_plugin_name(self):
        assert OfflineHashStrengthAnalyzer.name == "hash-strength-analyzer"

    def test_passive_capability(self):
        from redcheck.models import PluginCapability

        assert OfflineHashStrengthAnalyzer.capability == PluginCapability.PASSIVE
