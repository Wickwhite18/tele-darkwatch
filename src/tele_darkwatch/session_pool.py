"""Telegram session-pool management with anti-friction rate control.

Telegram bans accounts that join too many channels or pull too much data too
fast. :class:`SessionPool` cycles through a set of ``.session`` files, caps
per-account message throughput, and injects randomized organic delays between
requests so no single account behaves like a scraping node.

Sessions are treated as opaque credential files; the pool never logs their
contents. Rotation is round-robin with per-session token-bucket throttling.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tele_darkwatch.logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class SessionSlot:
    """One Telegram account in the pool."""

    path: Path
    max_per_minute: int = 30
    _tokens: float = field(default=30.0, repr=False)
    _last_refill: float = field(default_factory=time.monotonic, repr=False)
    last_used: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.max_per_minute)

    @property
    def name(self) -> str:
        return self.path.stem

    def refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(float(self.max_per_minute),
                           self._tokens + elapsed * (self.max_per_minute / 60.0))
        self._last_refill = now

    def try_acquire(self) -> bool:
        """Consume one request token if this account is under its cap."""
        self.refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class SessionPool:
    """Round-robin pool of Telegram sessions with throttling + jitter.

    Usage::

        pool = SessionPool(Path("sessions"), max_per_minute=25)
        slot = pool.acquire()          # blocks until some account is free
        ...use slot.path for Telethon/Pyrogram...
        pool.report_success(slot)      # or report_failure to quarantine
    """

    def __init__(
        self,
        directory: Path | str,
        max_per_minute: int = 30,
        jitter: tuple[float, float] = (5.0, 15.0),
        quarantine_after: int = 3,
    ) -> None:
        self.directory = Path(directory)
        self.jitter = jitter
        self.quarantine_after = quarantine_after
        self.slots: list[SessionSlot] = []
        self._cursor = 0
        self._failures: dict[str, int] = {}
        self._quarantined: set[str] = set()
        if self.directory.is_dir():
            for p in sorted(self.directory.glob("*.session")):
                self.slots.append(SessionSlot(p, max_per_minute=max_per_minute))

    # ------------------------------------------------------------------ state
    def healthy_slots(self) -> list[SessionSlot]:
        return [s for s in self.slots if s.name not in self._quarantined]

    def add_session(self, path: Path | str, max_per_minute: int = 30) -> SessionSlot:
        path = Path(path)
        for existing in self.slots:
            if existing.path == path or existing.name == path.stem:
                return existing
        slot = SessionSlot(path, max_per_minute=max_per_minute)
        self.slots.append(slot)
        log.info("registered session %s (%d total)", slot.name, len(self.slots))
        return slot

    # --------------------------------------------------------------- rotation
    def acquire(self, timeout: float = 60.0) -> Optional[SessionSlot]:
        """Return the next usable session, waiting out throttle windows.

        Applies randomized delay between picks to mimic organic behavior.
        Returns ``None`` when every session is quarantined or timeout expires.
        """
        healthy = self.healthy_slots()
        if not healthy:
            log.warning("no healthy telegram sessions available")
            return None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for _ in range(len(healthy)):
                slot = healthy[self._cursor % len(healthy)]
                self._cursor += 1
                if slot.try_acquire():
                    slot.last_used = time.monotonic()
                    time.sleep(random.uniform(*self.jitter))
                    return slot
            time.sleep(0.5)
        log.warning("session pool exhausted (all accounts at rate cap)")
        return None

    # ------------------------------------------------------------ health ops
    def report_success(self, slot: SessionSlot) -> None:
        self._failures[slot.name] = 0

    def report_failure(self, slot: SessionSlot) -> None:
        n = self._failures.get(slot.name, 0) + 1
        self._failures[slot.name] = n
        if n >= self.quarantine_after:
            self._quarantined.add(slot.name)
            log.error("quarantining session %s after %d failures", slot.name, n)

    def unquarantine(self, name: str) -> None:
        self._quarantined.discard(name)
        self._failures[name] = 0

    def status(self) -> dict:
        return {
            "total": len(self.slots),
            "healthy": len(self.healthy_slots()),
            "quarantined": sorted(self._quarantined),
            "per_minute_cap": self.slots[0].max_per_minute if self.slots else 0,
        }
