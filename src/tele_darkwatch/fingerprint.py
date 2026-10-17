"""Browser-like request fingerprints to evade TLS/header-based bot detection.

Underground sites and Cloudflare-fronted leak blogs fingerprint the TLS
handshake and header order of ``requests``/``httpx`` defaults. Full TLS
impersonation requires native tooling (curl-impersonate / tls-client); this
module provides the pure-Python layer that works on top of any HTTP stack:

* rotating User-Agent pools for Chrome/Firefox/Edge on common platforms,
* realistic header sets (Accept, Accept-Language, Sec-Fetch-*),
* per-session sticky identity so headers don't change mid-navigation.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

USER_AGENTS: dict[str, list[str]] = {
    "chrome": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "firefox": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) "
        "Gecko/20100101 Firefox/129.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) "
        "Gecko/20100101 Firefox/128.0",
    ],
    "edge": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    ],
}

_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.95"]


@dataclass
class BrowserProfile:
    """A sticky pseudo-browser identity for one scraping session."""

    name: str
    user_agent: str
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": random.choice(_LANGS),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }


def random_profile(browser: str | None = None) -> BrowserProfile:
    browser = browser or random.choice(list(USER_AGENTS))
    ua = random.choice(USER_AGENTS[browser])
    return BrowserProfile(name=browser, user_agent=ua)


class FingerprintRotator:
    """Hand out a fresh (or sticky) browser profile per request/session."""

    def __init__(self, sticky: bool = True) -> None:
        self.sticky = sticky
        self._current: BrowserProfile | None = None

    def next(self) -> BrowserProfile:
        if self.sticky and self._current is not None:
            return self._current
        self._current = random_profile()
        return self._current
