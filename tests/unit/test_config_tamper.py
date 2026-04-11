"""Tests for config tamper detection (Phase O)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from redcheck.config import RedCheckConfig, hmac_compare
from redcheck.exceptions import ConfigTamperError


@pytest.fixture
def config_yaml(tmp_path: Path) -> Path:
    cfg = {"runtime_mode": "research", "log_level": "DEBUG"}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(cfg), encoding="utf-8")
    return path


class TestHmacCompare:
    def test_equal_strings(self):
        assert hmac_compare("abc", "abc") is True

    def test_unequal_strings(self):
        assert hmac_compare("abc", "xyz") is False


class TestFromYamlVerified:
    def test_valid_hash_loads(self, config_yaml: Path):
        raw = config_yaml.read_bytes()
        expected = hashlib.sha256(raw).hexdigest()
        cfg = RedCheckConfig.from_yaml_verified(config_yaml, expected)
        assert cfg.log_level == "DEBUG"

    def test_invalid_hash_raises(self, config_yaml: Path):
        with pytest.raises(ConfigTamperError):
            RedCheckConfig.from_yaml_verified(config_yaml, "badhash")

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            RedCheckConfig.from_yaml_verified(tmp_path / "missing.yaml", "abc123")


class TestPluginAllowlist:
    def test_default_is_none(self):
        cfg = RedCheckConfig()
        assert cfg.plugin_allowlist is None

    def test_can_set_allowlist(self):
        cfg = RedCheckConfig(plugin_allowlist=["passive-recon", "sast-scanner"])
        assert cfg.plugin_allowlist == ["passive-recon", "sast-scanner"]
