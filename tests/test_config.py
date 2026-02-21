"""Tests for RedCheckConfig — defaults, YAML loading, env vars, round-trip."""

import pytest

from redcheck.config import RedCheckConfig, get_config, reset_config


class TestConfigDefaults:
    """Default configuration value tests."""

    def test_default_values(self):
        cfg = RedCheckConfig()
        assert cfg.log_level == "INFO"
        assert cfg.log_format == "text"
        assert cfg.max_concurrent_plugins == 1
        assert cfg.require_signed_roe is True
        assert cfg.require_activation_code is True
        assert cfg.default_mode == "dry-run"
        assert cfg.encryption_algorithm == "AES-256-GCM"

    def test_default_runtime_mode(self):
        from redcheck.models import RuntimeMode

        cfg = RedCheckConfig()
        assert cfg.runtime_mode == RuntimeMode.DEV

    def test_resolved_paths_relative_to_project_root(self, tmp_path):
        cfg = RedCheckConfig(project_root=tmp_path)
        assert cfg.resolved_engagements_dir == tmp_path / "engagements"
        assert cfg.resolved_logs_dir == tmp_path / "logs"
        assert cfg.resolved_evidence_dir == tmp_path / "evidence"


class TestConfigFromYAML:
    """YAML loading tests."""

    def test_load_from_yaml(self, config_yaml):
        cfg = RedCheckConfig.from_yaml(config_yaml)
        assert cfg.log_level == "DEBUG"
        assert cfg.log_format == "json"
        assert cfg.max_concurrent_plugins == 4

    def test_missing_yaml_uses_defaults(self, tmp_path):
        cfg = RedCheckConfig.from_yaml(tmp_path / "nonexistent.yaml")
        assert cfg.log_level == "INFO"

    def test_yaml_round_trip(self, tmp_path):
        original = RedCheckConfig(
            project_root=tmp_path,
            log_level="WARNING",
            max_concurrent_plugins=3,
        )
        path = tmp_path / "out.yaml"
        original.to_yaml(path)
        loaded = RedCheckConfig.from_yaml(path)
        assert loaded.log_level == "WARNING"
        assert loaded.max_concurrent_plugins == 3


class TestConfigEnvVars:
    """Environment variable override tests."""

    def test_env_prefix_override(self, monkeypatch):
        monkeypatch.setenv("REDCHECK_LOG_LEVEL", "ERROR")
        monkeypatch.setenv("REDCHECK_MAX_CONCURRENT_PLUGINS", "7")
        cfg = RedCheckConfig()
        assert cfg.log_level == "ERROR"
        assert cfg.max_concurrent_plugins == 7

    def test_runtime_mode_from_env(self, monkeypatch):
        from redcheck.models import RuntimeMode

        monkeypatch.setenv("REDCHECK_RUNTIME_MODE", "production")
        cfg = RedCheckConfig()
        assert cfg.runtime_mode == RuntimeMode.PRODUCTION


class TestConfigValidation:
    """Validation constraint tests."""

    def test_max_concurrent_plugins_bounds(self):
        with pytest.raises(Exception):  # noqa: B017, PT011
            RedCheckConfig(max_concurrent_plugins=0)
        with pytest.raises(Exception):  # noqa: B017, PT011
            RedCheckConfig(max_concurrent_plugins=99)

    def test_request_timeout_bounds(self):
        with pytest.raises(Exception):  # noqa: B017, PT011
            RedCheckConfig(request_timeout_seconds=0)


class TestConfigSingleton:
    """Global config singleton tests."""

    def test_get_config_returns_instance(self):
        reset_config()
        cfg = get_config()
        assert isinstance(cfg, RedCheckConfig)
        # Same instance returned
        cfg2 = get_config()
        assert cfg is cfg2

    def test_reset_config_creates_new(self):
        cfg1 = get_config()
        reset_config()
        cfg2 = get_config()
        assert cfg1 is not cfg2
