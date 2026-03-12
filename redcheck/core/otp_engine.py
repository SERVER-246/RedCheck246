"""RedCheck246 — OTP Authorization Engine.

Email-based One-Time Password verification for Test Mode high-risk actions.
The plaintext OTP code is never stored — only its SHA-256 hash is kept
in the OTPChallenge dataclass.
"""

from __future__ import annotations

import hashlib
import secrets
import smtplib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

import structlog

from redcheck.constants import OTP_CODE_LENGTH, OTP_EXPIRY_SECONDS, OTP_MAX_ATTEMPTS
from redcheck.core.audit import get_audit_logger
from redcheck.exceptions import OTPCancelledError, OTPExpiredError, OTPVerificationError

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class OTPChallenge:
    """Immutable OTP state — code is NEVER stored in plaintext."""

    code_hash: str
    expires_at: datetime
    attempts_remaining: int
    engagement_id: str
    plugin_name: str
    challenge_id: str


class OTPEngine:
    """Email-based OTP verification for Test Mode high-risk actions."""

    def __init__(
        self,
        *,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        smtp_use_tls: bool = True,
        sender_email: str = "redcheck@localhost",
        otp_length: int = OTP_CODE_LENGTH,
        otp_expiry_seconds: int = OTP_EXPIRY_SECONDS,
        otp_max_attempts: int = OTP_MAX_ATTEMPTS,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._smtp_user = smtp_user
        self._smtp_password = smtp_password
        self._smtp_use_tls = smtp_use_tls
        self._sender_email = sender_email
        self._otp_length = otp_length
        self._otp_expiry_seconds = otp_expiry_seconds
        self._otp_max_attempts = otp_max_attempts
        self._audit = get_audit_logger()
        self._active_challenges: dict[str, OTPChallenge] = {}

    @staticmethod
    def _hash_code(code: str) -> str:
        """SHA-256 hash of the OTP code."""
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @staticmethod
    def _mask_email(email: str) -> str:
        """Mask email for audit logs: u***@domain.com."""
        parts = email.split("@", 1)
        if len(parts) != 2:  # noqa: PLR2004
            return "***"
        local = parts[0]
        domain = parts[1]
        masked = "*" if len(local) <= 1 else local[0] + "***"
        return f"{masked}@{domain}"

    def generate_otp(
        self,
        engagement_id: str,
        plugin_name: str,
    ) -> tuple[OTPChallenge, str]:
        """Generate an OTP challenge.

        Returns (challenge, plaintext_code). The caller must send the
        plaintext code via send_otp() and then discard it.
        """
        upper = 10**self._otp_length
        code_int = secrets.randbelow(upper)
        code = str(code_int).zfill(self._otp_length)

        code_hash = self._hash_code(code)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._otp_expiry_seconds)
        challenge_id = str(uuid.uuid4())

        challenge = OTPChallenge(
            code_hash=code_hash,
            expires_at=expires_at,
            attempts_remaining=self._otp_max_attempts,
            engagement_id=engagement_id,
            plugin_name=plugin_name,
            challenge_id=challenge_id,
        )

        self._active_challenges[challenge_id] = challenge

        log.info(
            "otp_generated",
            challenge_id=challenge_id,
            plugin_name=plugin_name,
            engagement_id=engagement_id,
        )
        self._audit.log(
            action="OTP_GENERATED",
            details=f"OTP generated for plugin '{plugin_name}'",
            engagement_id=engagement_id,
        )

        return challenge, code

    def send_otp(
        self,
        challenge: OTPChallenge,
        recipient_email: str,
        plaintext_code: str,
    ) -> bool:
        """Send the OTP code via email.

        Returns True if sent successfully, False on SMTP failure.
        The caller should discard plaintext_code after calling this.
        """
        msg = EmailMessage()
        msg["Subject"] = f"RedCheck OTP — {challenge.plugin_name}"
        msg["From"] = self._sender_email
        msg["To"] = recipient_email
        msg.set_content(
            f"Your RedCheck OTP code is: {plaintext_code}\n\n"
            f"Engagement: {challenge.engagement_id}\n"
            f"Plugin: {challenge.plugin_name}\n"
            f"Challenge ID: {challenge.challenge_id}\n\n"
            f"This code expires in {self._otp_expiry_seconds} seconds."
        )

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30) as server:
                if self._smtp_use_tls:
                    server.starttls()
                if self._smtp_user:
                    server.login(self._smtp_user, self._smtp_password)
                server.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            log.error(
                "otp_send_failed",
                challenge_id=challenge.challenge_id,
                error=str(exc),
            )
            self._audit.log(
                action="OTP_SEND_FAILED",
                details=f"SMTP error: {exc}",
                engagement_id=challenge.engagement_id,
                level="ERROR",
            )
            return False

        masked = self._mask_email(recipient_email)
        log.info("otp_sent", challenge_id=challenge.challenge_id, recipient=masked)
        self._audit.log(
            action="OTP_SENT",
            details=f"OTP sent to {masked}",
            engagement_id=challenge.engagement_id,
        )
        return True

    def verify_otp(self, challenge: OTPChallenge, user_input: str) -> bool:
        """Verify a user-provided OTP code against the challenge.

        Raises OTPExpiredError if the challenge has expired.
        Raises OTPVerificationError if the code is wrong and attempts remain.
        Returns True on successful verification.
        """
        now = datetime.now(timezone.utc)
        expires = challenge.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        if now > expires:
            log.warning("otp_expired", challenge_id=challenge.challenge_id)
            self._audit.log(
                action="OTP_EXPIRED",
                details=f"Challenge {challenge.challenge_id} expired",
                engagement_id=challenge.engagement_id,
                level="WARN",
            )
            self._active_challenges.pop(challenge.challenge_id, None)
            raise OTPExpiredError(
                "OTP challenge has expired",
                challenge_id=challenge.challenge_id,
                engagement_id=challenge.engagement_id,
            )

        if challenge.attempts_remaining <= 0:
            self._active_challenges.pop(challenge.challenge_id, None)
            raise OTPVerificationError(
                attempts_remaining=0,
                challenge_id=challenge.challenge_id,
                engagement_id=challenge.engagement_id,
            )

        # Decrement attempts via replacing the frozen challenge
        updated = OTPChallenge(
            code_hash=challenge.code_hash,
            expires_at=challenge.expires_at,
            attempts_remaining=challenge.attempts_remaining - 1,
            engagement_id=challenge.engagement_id,
            plugin_name=challenge.plugin_name,
            challenge_id=challenge.challenge_id,
        )
        self._active_challenges[challenge.challenge_id] = updated

        input_hash = self._hash_code(user_input.strip())
        match = secrets.compare_digest(input_hash, challenge.code_hash)

        if match:
            log.info("otp_verify_success", challenge_id=challenge.challenge_id)
            self._audit.log(
                action="OTP_VERIFY_SUCCESS",
                details=f"Challenge {challenge.challenge_id} verified",
                engagement_id=challenge.engagement_id,
            )
            self._active_challenges.pop(challenge.challenge_id, None)
            return True

        log.warning(
            "otp_verify_failed",
            challenge_id=challenge.challenge_id,
            attempts_remaining=updated.attempts_remaining,
        )
        self._audit.log(
            action="OTP_VERIFY_FAILED",
            details=(
                f"Challenge {challenge.challenge_id} failed, "
                f"{updated.attempts_remaining} attempts remaining"
            ),
            engagement_id=challenge.engagement_id,
            level="WARN",
        )

        if updated.attempts_remaining <= 0:
            self._active_challenges.pop(challenge.challenge_id, None)

        raise OTPVerificationError(
            attempts_remaining=updated.attempts_remaining,
            challenge_id=challenge.challenge_id,
            engagement_id=challenge.engagement_id,
        )

    def cancel_challenge(self, challenge: OTPChallenge) -> None:
        """Cancel an active OTP challenge."""
        self._active_challenges.pop(challenge.challenge_id, None)
        log.info("otp_cancelled", challenge_id=challenge.challenge_id)
        self._audit.log(
            action="OTP_CANCELLED",
            details=f"Challenge {challenge.challenge_id} cancelled",
            engagement_id=challenge.engagement_id,
        )
        raise OTPCancelledError(
            "OTP challenge cancelled by operator",
            challenge_id=challenge.challenge_id,
            engagement_id=challenge.engagement_id,
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_otp_engine: OTPEngine | None = None


def get_otp_engine(**kwargs: Any) -> OTPEngine:
    """Get or create the global OTPEngine instance."""
    global _otp_engine  # noqa: PLW0603
    if _otp_engine is None:
        _otp_engine = OTPEngine(**kwargs)
    return _otp_engine


def reset_otp_engine() -> None:
    """Reset global OTPEngine — for test isolation only."""
    global _otp_engine  # noqa: PLW0603
    _otp_engine = None
