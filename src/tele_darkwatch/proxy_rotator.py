"""Residential/datacenter proxy rotation middleware for scraper requests.

Datacenter IPs get blacklisted instantly on underground sites. This module
provides a small, dependency-free rotation layer that any httpx/aiohttp based
collector can wrap around: it maintains a pool of proxy URLs, tracks success /
failure per proxy, temporarily mutes failing endpoints, and hands out the next
proxy in weighted round-robin order.

Proxy list comes from ``DW_PROXY_POOL`` (comma-separated) or a file.
Example::

    rotator = ProxyRotator.from_settings(settings)
    client = httpx.Client(proxy=rotator.next(), timeout=20)
    try:
        r = client.get(url); rotator.report(r.url, ok=(r.status_code < 500))
    except Exception as exc:
        rotator.report(None, ok=False, exc=exc)
"""
from __future__ import annotations

import itertools
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from tele_darkwatch.logging_setup import get_logger

log = get_logger(__name__)

#: seconds a failing proxy stays muted before retry eligibility
MUTE_SECONDS = 120.0


@dataclass
class ProxyEntry:
    url: str
    weight: int = 1
    failures: int = 0
    successes: int = 0
    muted_until: float = 0.0

    @property
    def available(self) -> bool:
        return time.monotonic() >= self.muted_until


class ProxyRotator:
    """Weighted round-robin proxy pool with failure-based muting."""

    def __init__(self, proxies: Iterable[str], mute_seconds: float = MUTE_SECONDS) -> None:
        urls = [p.strip() for p in proxies if p and p.strip()]
        if not urls:
            raise ValueError("ProxyRotator requires at least one proxy URL")
        self.entries = [ProxyEntry(url=u) for u in urls]
        self.mute_seconds = mute_seconds
        self._cycle = itertools.cycle(self.entries)
        log.info("proxy rotator ready with %d endpoints", len(self.entries))

    # ------------------------------------------------------------- factories
    @classmethod
    def from_settings(cls, settings) -> Optional["ProxyRotator"]:
        raw = getattr(settings, "proxy_pool", "") or ""
        urls = [u for u in raw.split(",") if u.strip()]
        path = getattr(settings, "proxy_pool_file", "") or ""
        if path and Path(path).is_file():
            urls += [ln.strip() for ln in Path(path).read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")]
        return cls(urls) if urls else None

    # ----------------------------------------------------------------- usage
    def next(self) -> str:
        """Return the next available proxy URL (random fallback if all muted)."""
        for _ in range(len(self.entries) * 3):
            entry = next(self._cycle)
            if entry.available:
                return entry.url
        # everything is muted — take the soonest-to-recover one anyway
        entry = min(self.entries, key=lambda e: e.muted_until)
        log.warning("all proxies muted; forcing %s", entry.url)
        return entry.url

    def report(self, url: Optional[str], ok: bool) -> None:
        for e in self.entries:
            if url is None or e.url == url:
                if ok:
                    e.successes += 1
                    e.failures = max(0, e.failures - 1)
                else:
                    e.failures += 1
                    if e.failures >= 3:
                        e.muted_until = time.monotonic() + self.mute_seconds
                        e.failures = 0
                        log.info("muted proxy %s for %.0fs", e.url, self.mute_seconds)

    def jitter_sleep(self, low: float = 1.0, high: float = 6.0) -> None:
        """Randomized pause between fetches to reduce crawler fingerprint."""
        time.sleep(random.uniform(low, high))

    def status(self) -> dict:
        return {
            "count": len(self.entries),
            "available": sum(1 for e in self.entries if e.available),
            "muted": [e.url for e in self.entries if not e.available],
        }
