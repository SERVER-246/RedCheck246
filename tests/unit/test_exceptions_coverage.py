"""Tests for exception hierarchy — to_dict() serialisation and constructors."""

from __future__ import annotations

from redcheck.exceptions import (
    ActivationError,
    ChainModeError,
    ConfigurationError,
    ContextValidationError,
    CryptoError,
    IsolationError,
    NetworkError,
    OffensiveControlError,
    PluginError,
    PluginNotFoundError,
    PolicyDeniedException,
    RateLimitExceededError,
    RedCheckError,
    RoEValidationError,
    ScanTimeoutError,
    ScopeViolationError,
    TenantIsolationError,
)


class TestRedCheckErrorToDict:
    def test_base_error_to_dict(self) -> None:
        err = RedCheckError("boom", engagement_id="ENG-1")
        d = err.to_dict()
        assert d["error_type"] == "RedCheckError"
        assert d["message"] == "boom"
        assert d["engagement_id"] == "ENG-1"

    def test_base_error_no_engagement(self) -> None:
        err = RedCheckError("fail")
        d = err.to_dict()
        assert d["engagement_id"] is None


class TestPolicyDeniedException:
    def test_to_dict(self) -> None:
        err = PolicyDeniedException("scanner", "not allowed", engagement_id="E1")
        d = err.to_dict()
        assert d["plugin_name"] == "scanner"
        assert d["reason"] == "not allowed"
        assert "scanner" in str(err)


class TestRoEValidationError:
    def test_to_dict(self) -> None:
        err = RoEValidationError("bad roe", roe_path="/tmp/roe.yml")
        d = err.to_dict()
        assert d["roe_path"] == "/tmp/roe.yml"
        assert d["error_type"] == "RoEValidationError"


class TestPluginError:
    def test_to_dict(self) -> None:
        err = PluginError("my-plugin", "crashed")
        d = err.to_dict()
        assert d["plugin_name"] == "my-plugin"
        assert "crashed" in d["message"]


class TestPluginNotFoundError:
    def test_constructor(self) -> None:
        err = PluginNotFoundError("missing-plugin")
        assert "missing-plugin" in str(err)
        assert err.plugin_name == "missing-plugin"


class TestContextValidationError:
    def test_constructor(self) -> None:
        err = ContextValidationError("plug", "bad context")
        assert err.reason == "bad context"


class TestNetworkError:
    def test_to_dict(self) -> None:
        err = NetworkError("timeout", target="10.0.0.1")
        d = err.to_dict()
        assert d["target"] == "10.0.0.1"


class TestScanTimeoutError:
    def test_constructor(self) -> None:
        err = ScanTimeoutError("scanner", 30.0, target="host")
        assert err.plugin_name == "scanner"
        assert err.timeout_seconds == 30.0
        assert "30.0s" in str(err)


class TestScopeViolationError:
    def test_constructor(self) -> None:
        err = ScopeViolationError("plug", "OUTOFSCOPE-TARGET")
        assert err.target == "OUTOFSCOPE-TARGET"
        assert "OUTOFSCOPE-TARGET" in str(err)


class TestOffensiveControlError:
    def test_to_dict(self) -> None:
        err = OffensiveControlError("plug", ["ctrl_a", "ctrl_b"])
        d = err.to_dict()
        assert d["missing_controls"] == ["ctrl_a", "ctrl_b"]


class TestChainModeError:
    def test_default_reason(self) -> None:
        err = ChainModeError("plug")
        assert "chain_mode" in str(err)


class TestIsolationError:
    def test_to_dict(self) -> None:
        err = IsolationError("plug")
        d = err.to_dict()
        assert d["plugin_name"] == "plug"
        assert "Docker" in str(err)


class TestRateLimitExceededError:
    def test_to_dict(self) -> None:
        err = RateLimitExceededError("plug", 5.0)
        d = err.to_dict()
        assert d["plugin_name"] == "plug"
        assert d["rate_limit_rps"] == 5.0


class TestTenantIsolationError:
    def test_to_dict(self) -> None:
        err = TenantIsolationError("tenant-b", "tenant-a")
        d = err.to_dict()
        assert d["requested_tenant"] == "tenant-b"
        assert d["current_tenant"] == "tenant-a"


class TestActivationError:
    def test_constructor(self) -> None:
        err = ActivationError("locked out", attempts_remaining=0)
        assert err.attempts_remaining == 0


class TestConfigurationError:
    def test_is_redcheck_error(self) -> None:
        err = ConfigurationError("bad config")
        assert isinstance(err, RedCheckError)


class TestCryptoError:
    def test_is_redcheck_error(self) -> None:
        err = CryptoError("decrypt fail")
        assert isinstance(err, RedCheckError)
