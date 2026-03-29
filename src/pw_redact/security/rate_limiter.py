# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact

"""In-memory token bucket rate limiter with stale-bucket cleanup."""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..config import settings

MAX_BUCKETS = 10_000
CLEANUP_INTERVAL = 300.0  # 5 minutes
STALE_AGE = 1800.0  # 30 minutes


@dataclass
class _Bucket:
    """Token bucket for a single key."""

    tokens: float
    last_refill: float
    rpm: int
    burst: int

    def consume(self) -> tuple[bool, float]:
        """Try to consume a token. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        refill_rate = self.rpm / 60.0
        self.tokens = min(self.burst, self.tokens + elapsed * refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0.0

        wait = (1.0 - self.tokens) / refill_rate
        return False, round(wait, 1)


class RateLimiter:
    """In-memory per-key token bucket rate limiter."""

    def __init__(
        self,
        rpm: int | None = None,
        burst: int | None = None,
    ) -> None:
        self.rpm = rpm or settings.rate_limit_rpm
        self.burst = burst or settings.rate_limit_burst
        self._buckets: dict[str, _Bucket] = {}
        self._last_cleanup = time.monotonic()

    def check(self, key: str) -> tuple[bool, float]:
        """Check if request is allowed for the given key.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.monotonic()

        # Periodic cleanup of stale buckets
        if now - self._last_cleanup > CLEANUP_INTERVAL:
            self._cleanup(now)
            self._last_cleanup = now

        # Reject new keys when at capacity (prevents memory exhaustion)
        if key not in self._buckets:
            if len(self._buckets) >= MAX_BUCKETS:
                return False, 60.0
            self._buckets[key] = _Bucket(
                tokens=float(self.burst),
                last_refill=now,
                rpm=self.rpm,
                burst=self.burst,
            )

        return self._buckets[key].consume()

    def _cleanup(self, now: float) -> None:
        """Remove buckets unused for > STALE_AGE seconds."""
        stale = [k for k, v in self._buckets.items() if now - v.last_refill > STALE_AGE]
        for k in stale:
            del self._buckets[k]
