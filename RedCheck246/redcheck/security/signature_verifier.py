"""
RedCheck246 — Signature Verifier

Verifies digital signatures on RoE documents and evidence files.
Uses HMAC-SHA256 for shared-secret mode (default).
Can be extended to RSA/ECDSA for PKI-based verification.
"""

import hashlib
import hmac
import json
from pathlib import Path

import yaml


class SignatureVerifier:
    """Verify signatures on RoE and evidence documents."""

    def __init__(self, secret: str | None = None):
        """
        Args:
            secret: Shared secret for HMAC-based signing/verification.
                    If None, signature verification is disabled.
        """
        self._secret = secret

    @property
    def is_configured(self) -> bool:
        return self._secret is not None and len(self._secret) > 0

    def sign_roe(self, roe_path: str | Path) -> str:
        """Generate HMAC-SHA256 signature for an RoE file.

        Signs the canonical content (all fields except 'signature').

        Args:
            roe_path: Path to the RoE YAML file.

        Returns: Hex-encoded HMAC-SHA256 signature.
        """
        if not self.is_configured:
            raise RuntimeError("SignatureVerifier not configured — no secret set")

        canonical = self._canonical_roe_content(roe_path)
        return self._hmac_sha256(canonical)

    def verify_roe(self, roe_path: str | Path) -> tuple[bool, str]:
        """Verify the signature on an RoE file.

        Args:
            roe_path: Path to the RoE YAML file.

        Returns: (valid, message)
        """
        if not self.is_configured:
            return False, "Signature verifier not configured — no secret set"

        path = Path(roe_path)
        if not path.exists():
            return False, f"RoE file not found: {path}"

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        stored_sig = data.get("signature", "")
        if not stored_sig:
            return False, "No signature field in RoE"

        canonical = self._canonical_roe_content(roe_path)
        expected = self._hmac_sha256(canonical)

        if hmac.compare_digest(stored_sig, expected):
            return True, "Signature verified"
        else:
            return False, "Signature mismatch — RoE may have been tampered with"

    def sign_evidence(self, data: bytes) -> str:
        """Sign evidence data, returning HMAC-SHA256 hex signature."""
        if not self.is_configured:
            raise RuntimeError("SignatureVerifier not configured")
        return self._hmac_sha256(data)

    def verify_evidence(self, data: bytes, signature: str) -> bool:
        """Verify evidence data against a signature."""
        if not self.is_configured:
            return False
        expected = self._hmac_sha256(data)
        return hmac.compare_digest(signature, expected)

    def _hmac_sha256(self, data: bytes) -> str:
        """Compute HMAC-SHA256 with the configured secret."""
        return hmac.new(
            self._secret.encode("utf-8"),
            data,
            hashlib.sha256,
        ).hexdigest()

    def _canonical_roe_content(self, roe_path: str | Path) -> bytes:
        """Extract canonical content from RoE (all fields except 'signature'),
        serialized as sorted JSON for deterministic hashing.
        """
        with open(roe_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Remove signature for canonical form
        canonical = {k: v for k, v in data.items() if k != "signature"}

        # Convert datetimes to ISO strings for JSON serialization
        for key, value in canonical.items():
            if hasattr(value, "isoformat"):
                canonical[key] = value.isoformat()

        return json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")
