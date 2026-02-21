"""RedCheck246 — Token Bucket Rate Limiter.

Thread-safe, async-aware token bucket with configurable rate and burst.
Used by the orchestrator to enforce per-plugin rate limits.
"""

from __future__ import annotations

import asyncio
import threading
import time


class TokenBucket:
    """Thread-safe token bucket rate limiter with async support.

    Args:
        rate: Tokens per second (sustained rate).
        burst: Maximum tokens available at once.  Defaults to ``int(rate * 2)``.
    """

    def __init__(self, rate: float, burst: int | None = None) -> None:
        if rate <= 0:
            msg = "rate must be positive"
            raise ValueError(msg)
        self.rate = rate
        self.burst = burst if burst is not None else int(rate * 2)
        if self.burst < 1:
            self.burst = 1
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking acquire attempt.

        Returns ``True`` if tokens were acquired, ``False`` otherwise.
        """
        if tokens < 1:
            msg = "tokens must be >= 1"
            raise ValueError(msg)
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, blocking (async) until available.

        Raises ``ValueError`` if ``tokens`` exceeds burst capacity.
        """
        if tokens < 1:
            msg = "tokens must be >= 1"
            raise ValueError(msg)
        if tokens > self.burst:
            msg = f"Cannot acquire {tokens} tokens (burst={self.burst})"
            raise ValueError(msg)

        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Calculate wait time until enough tokens available
                deficit = tokens - self._tokens
                wait_time = deficit / self.rate

            # Sleep outside lock
            await asyncio.sleep(min(wait_time, 0.1))

    @property
    def available_tokens(self) -> float:
        """Current number of available tokens (approximate)."""
        with self._lock:
            self._refill()
            return self._tokens
