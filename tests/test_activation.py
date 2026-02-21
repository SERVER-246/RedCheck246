"""Tests for ActivationEngine — code complexity, hashing, and verification."""

import pytest

from redcheck.core.activation_engine import ActivationEngine


@pytest.fixture
def engine(tmp_path):
    """Fresh activation engine with isolated storage."""
    return ActivationEngine(base_dir=str(tmp_path))


class TestActivationEngine:
    """Activation engine tests."""

    def test_set_and_verify_code(self, engine):
        ok, msg = engine.set_code("Str0ng!Pass#2024")
        assert ok is True
        assert engine.is_configured
        assert engine.verify_code("Str0ng!Pass#2024")

    def test_wrong_code_fails(self, engine):
        engine.set_code("Correct@Pass1")
        assert not engine.verify_code("WrongPass123!")

    def test_code_requires_special_chars(self, engine):
        ok, msg = engine.set_code("NoSpecialChars1")
        assert ok is False
        assert "special" in msg.lower() or "complexity" in msg.lower()

    def test_code_requires_digits(self, engine):
        ok, msg = engine.set_code("NoDigits!Here@")
        assert ok is False

    def test_code_requires_letters(self, engine):
        ok, msg = engine.set_code("12345!@#$%")
        assert ok is False

    def test_code_minimum_length(self, engine):
        ok, msg = engine.set_code("Ab1!")
        assert ok is False
        assert "length" in msg.lower() or "short" in msg.lower() or "8" in msg

    def test_clear_code(self, engine):
        engine.set_code("Valid@Code123")
        assert engine.is_configured
        engine.clear()
        assert not engine.is_configured

    def test_not_configured_by_default(self, engine):
        assert not engine.is_configured
        assert not engine.verify_code("anything")

    def test_different_codes_produce_different_hashes(self, engine):
        """Verify salted hashing produces unique outputs."""
        engine.set_code("First@Code111")
        import json

        with open(engine._path) as f:
            hash1 = json.load(f)["hash"]

        engine.set_code("Second@Code222")
        with open(engine._path) as f:
            hash2 = json.load(f)["hash"]

        assert hash1 != hash2
