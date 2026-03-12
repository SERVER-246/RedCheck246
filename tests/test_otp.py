"""Tests for the OTP Engine (redcheck.core.otp_engine)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from redcheck.core.otp_engine import (
    OTPChallenge,
    OTPEngine,
    get_otp_engine,
    reset_otp_engine,
)
from redcheck.exceptions import (
    OTPCancelledError,
    OTPExpiredError,
    OTPVerificationError,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset OTP engine singleton between tests."""
    reset_otp_engine()
    yield
    reset_otp_engine()


@pytest.fixture
def engine() -> OTPEngine:
    return OTPEngine(
        smtp_host="localhost",
        smtp_port=587,
        otp_length=6,
        otp_expiry_seconds=300,
        otp_max_attempts=3,
    )


class TestOTPGeneration:
    def test_generate_returns_challenge_and_code(self, engine: OTPEngine):
        challenge, code = engine.generate_otp("eng-1", "test-plugin")
        assert isinstance(challenge, OTPChallenge)
        assert isinstance(code, str)
        assert len(code) == 6
        assert code.isdigit()

    def test_code_hash_matches_sha256(self, engine: OTPEngine):
        challenge, code = engine.generate_otp("eng-1", "test-plugin")
        expected = hashlib.sha256(code.encode("utf-8")).hexdigest()
        assert challenge.code_hash == expected

    def test_challenge_fields(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "scanner")
        assert challenge.engagement_id == "eng-1"
        assert challenge.plugin_name == "scanner"
        assert challenge.attempts_remaining == 3
        assert challenge.challenge_id  # non-empty UUID

    def test_challenge_expiry_is_future(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "x")
        now = datetime.now(timezone.utc)
        assert challenge.expires_at > now

    def test_challenge_is_frozen(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "x")
        with pytest.raises(AttributeError):
            challenge.attempts_remaining = 0  # type: ignore[misc]


class TestOTPVerification:
    def test_verify_correct_code(self, engine: OTPEngine):
        challenge, code = engine.generate_otp("eng-1", "plugin-a")
        result = engine.verify_otp(challenge, code)
        assert result is True

    def test_verify_wrong_code_raises(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "plugin-a")
        with pytest.raises(OTPVerificationError) as exc_info:
            engine.verify_otp(challenge, "000000")
        assert exc_info.value.attempts_remaining == 2

    def test_verify_decrements_attempts(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "plugin-a")
        for expected_remaining in (2, 1, 0):
            with pytest.raises(OTPVerificationError) as exc_info:
                engine.verify_otp(challenge, "wrong!")
            assert exc_info.value.attempts_remaining == expected_remaining
            # Get updated challenge for next iteration
            if expected_remaining > 0:
                challenge = engine._active_challenges[challenge.challenge_id]

    def test_verify_expired_raises(self, engine: OTPEngine):
        challenge, code = engine.generate_otp("eng-1", "plugin-a")
        expired = OTPChallenge(
            code_hash=challenge.code_hash,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
            attempts_remaining=3,
            engagement_id="eng-1",
            plugin_name="plugin-a",
            challenge_id=challenge.challenge_id,
        )
        engine._active_challenges[expired.challenge_id] = expired
        with pytest.raises(OTPExpiredError):
            engine.verify_otp(expired, code)

    def test_verify_strips_whitespace(self, engine: OTPEngine):
        challenge, code = engine.generate_otp("eng-1", "p")
        assert engine.verify_otp(challenge, f"  {code}  ") is True

    def test_verify_zero_attempts_raises_immediately(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "p")
        exhausted = OTPChallenge(
            code_hash=challenge.code_hash,
            expires_at=challenge.expires_at,
            attempts_remaining=0,
            engagement_id="eng-1",
            plugin_name="p",
            challenge_id=challenge.challenge_id,
        )
        engine._active_challenges[exhausted.challenge_id] = exhausted
        with pytest.raises(OTPVerificationError) as exc_info:
            engine.verify_otp(exhausted, "anything")
        assert exc_info.value.attempts_remaining == 0


class TestOTPSend:
    @patch("redcheck.core.otp_engine.smtplib.SMTP")
    def test_send_success(self, mock_smtp_class, engine: OTPEngine):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        challenge, code = engine.generate_otp("eng-1", "plug")
        result = engine.send_otp(challenge, "user@example.com", code)
        assert result is True

    @patch("redcheck.core.otp_engine.smtplib.SMTP")
    def test_send_smtp_failure(self, mock_smtp_class, engine: OTPEngine):
        import smtplib

        mock_smtp_class.return_value.__enter__ = MagicMock(
            side_effect=smtplib.SMTPException("connection refused")
        )
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        challenge, code = engine.generate_otp("eng-1", "plug")
        result = engine.send_otp(challenge, "user@example.com", code)
        assert result is False


class TestOTPCancel:
    def test_cancel_raises(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "plugin-a")
        with pytest.raises(OTPCancelledError):
            engine.cancel_challenge(challenge)

    def test_cancel_removes_active_challenge(self, engine: OTPEngine):
        challenge, _ = engine.generate_otp("eng-1", "plugin-a")
        with pytest.raises(OTPCancelledError):
            engine.cancel_challenge(challenge)
        assert challenge.challenge_id not in engine._active_challenges


class TestEmailMasking:
    @pytest.mark.parametrize(
        ("email", "expected"),
        [
            ("user@example.com", "u***@example.com"),
            ("a@b.io", "*@b.io"),
            ("x", "***"),
            ("", "***"),
        ],
    )
    def test_mask_email(self, email: str, expected: str):
        assert OTPEngine._mask_email(email) == expected


class TestSingleton:
    def test_get_returns_same_instance(self):
        a = get_otp_engine()
        b = get_otp_engine()
        assert a is b

    def test_reset_clears_instance(self):
        a = get_otp_engine()
        reset_otp_engine()
        b = get_otp_engine()
        assert a is not b
