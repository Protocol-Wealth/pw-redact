# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""In-memory token bucket rate limiter."""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..config import settings


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
        # Refill at rpm/60 tokens per second
        refill_rate = self.rpm / 60.0
        self.tokens = min(self.burst, self.tokens + elapsed * refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0.0

        # How long until 1 token is available
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

    def check(self, key: str) -> tuple[bool, float]:
        """Check if request is allowed for the given key.

        Returns:
            (allowed, retry_after_seconds)
        """
        if key not in self._buckets:
            self._buckets[key] = _Bucket(
                tokens=float(self.burst),
                last_refill=time.monotonic(),
                rpm=self.rpm,
                burst=self.burst,
            )
        return self._buckets[key].consume()
