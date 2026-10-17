"""Simple cooldown-based rate limiter for alert notifications.

Prevents notification storms when the same rule/channel combination fires
repeatedly across collection cycles.
"""
from __future__ import annotations

import time
from typing import Callable, Optional


class RateLimiter:
    """Allow an event per ``key`` at most once every ``cooldown`` seconds."""

    def __init__(
        self,
        cooldown: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cooldown = float(cooldown)
        self._clock = clock
        self._last_seen: dict[str, float] = {}

    def allow(self, key: str) -> bool:
        """Return ``True`` if ``key`` may fire now (and record the firing)."""
        now = self._clock()
        last = self._last_seen.get(key)
        if last is not None and (now - last) < self.cooldown:
            return False
        self._last_seen[key] = now
        return True

    def remaining(self, key: str) -> float:
        """Seconds until ``key`` is allowed again (0 if allowed now)."""
        last = self._last_seen.get(key)
        if last is None:
            return 0.0
        left = self.cooldown - (self._clock() - last)
        return max(0.0, left)

    def prune(self, max_age: Optional[float] = None) -> int:
        """Drop stale entries; returns number removed."""
        cutoff = self._clock() - (max_age if max_age is not None else self.cooldown)
        stale = [k for k, ts in self._last_seen.items() if ts < cutoff]
        for k in stale:
            del self._last_seen[k]
        return len(stale)
