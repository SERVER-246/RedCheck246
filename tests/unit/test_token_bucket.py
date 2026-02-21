"""Tests for TokenBucket rate limiter."""

from __future__ import annotations

import asyncio
import time

import pytest

from redcheck.core.token_bucket import TokenBucket


class TestTokenBucketInit:
    """Initialization and argument validation."""

    def test_basic_init(self):
        tb = TokenBucket(rate=10.0)
        assert tb.rate == 10.0
        assert tb.burst == 20  # rate * 2

    def test_custom_burst(self):
        tb = TokenBucket(rate=10.0, burst=5)
        assert tb.burst == 5

    def test_zero_rate_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            TokenBucket(rate=0)

    def test_negative_rate_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            TokenBucket(rate=-1)


class TestTryAcquire:
    """Non-blocking acquire attempts."""

    def test_immediate_acquire(self):
        tb = TokenBucket(rate=10.0, burst=5)
        assert tb.try_acquire(1) is True

    def test_burst_acquire(self):
        tb = TokenBucket(rate=10.0, burst=10)
        assert tb.try_acquire(10) is True

    def test_exceed_burst_fails(self):
        tb = TokenBucket(rate=10.0, burst=5)
        # Consume all burst
        assert tb.try_acquire(5) is True
        # No more tokens
        assert tb.try_acquire(1) is False

    def test_tokens_refill_over_time(self):
        tb = TokenBucket(rate=100.0, burst=100)
        assert tb.try_acquire(100) is True
        assert tb.try_acquire(1) is False
        time.sleep(0.05)  # wait for ~5 tokens
        assert tb.try_acquire(1) is True

    def test_zero_tokens_rejected(self):
        tb = TokenBucket(rate=10.0)
        with pytest.raises(ValueError, match="must be >= 1"):
            tb.try_acquire(0)


class TestAsyncAcquire:
    """Async blocking acquire."""

    @pytest.mark.asyncio
    async def test_acquire_immediate(self):
        tb = TokenBucket(rate=100.0, burst=10)
        await tb.acquire(1)
        # Should succeed immediately

    @pytest.mark.asyncio
    async def test_acquire_blocks_until_available(self):
        tb = TokenBucket(rate=100.0, burst=1)
        await tb.acquire(1)
        # Now bucket is empty; next acquire should block briefly
        start = time.monotonic()
        await tb.acquire(1)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # should refill quickly at rate=100

    @pytest.mark.asyncio
    async def test_acquire_exceeds_burst_raises(self):
        tb = TokenBucket(rate=10.0, burst=5)
        with pytest.raises(ValueError, match="burst"):
            await tb.acquire(10)

    @pytest.mark.asyncio
    async def test_acquire_zero_tokens_raises(self):
        tb = TokenBucket(rate=10.0)
        with pytest.raises(ValueError, match="must be >= 1"):
            await tb.acquire(0)

    @pytest.mark.asyncio
    async def test_rate_enforcement(self):
        """10 requests at rate=100 should complete in ~0.1s."""
        tb = TokenBucket(rate=100.0, burst=1)
        # Drain initial burst
        await tb.acquire(1)
        start = time.monotonic()
        for _ in range(9):
            await tb.acquire(1)
        elapsed = time.monotonic() - start
        # Should take roughly 9/100 = 0.09s, allow tolerance
        assert elapsed < 1.0


class TestAvailableTokens:
    """available_tokens property."""

    def test_initial_tokens(self):
        tb = TokenBucket(rate=10.0, burst=5)
        assert tb.available_tokens == pytest.approx(5.0, abs=0.5)

    def test_tokens_decrease_after_acquire(self):
        tb = TokenBucket(rate=10.0, burst=10)
        tb.try_acquire(3)
        assert tb.available_tokens < 10


class TestConcurrentAccess:
    """Thread safety under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_async_acquire(self):
        """Multiple concurrent acquires should not corrupt state."""
        tb = TokenBucket(rate=1000.0, burst=100)

        async def worker():
            for _ in range(10):
                await tb.acquire(1)

        await asyncio.gather(*(worker() for _ in range(5)))
        # 50 total acquires at rate=1000 with burst=100 should complete
