"""Telegram channel sourcing (discovery engine).

Threat actors constantly rotate channels and cross-advertise new invite links.
This module scans stored message text for ``t.me`` handles, registers unseen
candidates in a *pending* pool, tracks verification status, and can auto-verify
a candidate by sampling its public RSS feed (reusing the Telegram collector's
transport so no extra network code is needed).

Workflow: ``discover_from_store`` -> candidates land as ``pending`` ->
``verify_candidate`` fetches a sample and classifies it with keyword scoring ->
verified channels become ``active`` and are returned by
:func:`ChannelDiscovery.active_channels` (ready for DW_TELEGRAM_CHANNELS).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

import httpx
from pydantic import BaseModel, Field

from tele_darkwatch.storage.message_store import MessageStore

#: t.me public links and joinchat invites found in leak chatter.
TG_LINK_RE = re.compile(
    r"(?:https?://)?t\.me/(?:joinchat/|s/)?(?P<name>[A-Za-z][A-Za-z0-9_]{3,31})",
    re.IGNORECASE,
)

#: Keywords that mark a channel as relevant to breach/stealer monitoring.
INTEL_KEYWORDS = (
    "logs", "stealer", "combo", "combolist", "dump", "breach", "compromised",
    "redline", "lumma", "mars", "vidar", "mimic", "mrg",
    "cc fullz", "credentials", "base", "database",
)

RSS_URL = "https://t.me/s/{channel}"


class ChannelStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REJECTED = "rejected"
    DEAD = "dead"


class DiscoveredChannel(BaseModel):
    name: str
    status: ChannelStatus = ChannelStatus.PENDING
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_checked: Optional[datetime] = None
    score: float = 0.0
    samples: int = 0
    origin_channel: str = ""


def extract_channel_names(text: str) -> list[str]:
    """Pull unique lowercase channel names from t.me links/handles in text."""
    out: list[str] = []
    seen: set[str] = set()
    for m in TG_LINK_RE.finditer(text):
        name = m.group("name").lower()
        # Skip obvious non-channel paths
        if name in {"s", "joinchat", "share", "addstickers", "proxy", "iv"}:
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def classify_text(text: str, keywords=INTEL_KEYWORDS) -> float:
    """Cheap local NLP triage: fraction of intel keywords present (0..1)."""
    lowered = text.lower()
    hits = sum(1 for kw in keywords if kw in lowered)
    return round(hits / max(len(keywords), 1), 4)


class ChannelDiscovery:
    """Persistent pending/active/rejected pool stored in the meta table."""

    _META_KEY = "discovered_channels"

    def __init__(self, store: MessageStore,
                 transport: Optional[httpx.BaseTransport] = None,
                 threshold: float = 0.08) -> None:
        self.store = store
        self.transport = transport
        self.threshold = threshold
        self._channels: dict[str, DiscoveredChannel] = {}
        raw = store.get_meta(self._META_KEY)
        if raw:
            import json
            for item in json.loads(raw).values():
                ch = DiscoveredChannel(**item)
                self._channels[ch.name] = ch

    # ------------------------------------------------------------------ state
    def _persist(self) -> None:
        import json
        self.store.set_meta(self._META_KEY, json.dumps(
            {k: v.model_dump(mode="json") for k, v in self._channels.items()}))

    @property
    def all_channels(self) -> list[DiscoveredChannel]:
        return sorted(self._channels.values(), key=lambda c: c.name)

    def pending(self) -> list[DiscoveredChannel]:
        return [c for c in self.all_channels if c.status == ChannelStatus.PENDING]

    def active_channels(self) -> list[str]:
        return [c.name for c in self.all_channels if c.status == ChannelStatus.ACTIVE]

    # --------------------------------------------------------------- discover
    def discover_from_text(self, text: str, origin: str = "") -> int:
        """Register every new channel mentioned in *text*; returns count added."""
        added = 0
        for name in extract_channel_names(text):
            if name in self._channels:
                continue
            self._channels[name] = DiscoveredChannel(name=name, origin_channel=origin)
            added += 1
        if added:
            self._persist()
            self.store.events.record("discovery", added=added, origin=origin)
        return added

    def discover_from_store(self, limit: int = 500) -> int:
        """Recursive link scraping over recent archived messages."""
        total = 0
        for msg in self.store.recent(limit=limit):
            total += self.discover_from_text(msg.content, origin=msg.channel)
        return total

    # ----------------------------------------------------------------- verify
    def verify_candidate(self, name: str, client: Optional[httpx.Client] = None
                         ) -> DiscoveredChannel:
        """Sample the channel public page and classify; update status.

        Network failures mark the channel DEAD (it may be banned/wiped) rather
        than raising, so batch triage loops keep going.
        """
        ch = self._channels.get(name) or DiscoveredChannel(name=name)
        own_client = client is None
        client = client or httpx.Client(transport=self.transport, timeout=15,
                                        follow_redirects=True)
        try:
            resp = client.get(RSS_URL.format(channel=name))
            if resp.status_code != 200:
                ch.status = ChannelStatus.DEAD
            else:
                body = resp.text
                ch.score = classify_text(body)
                ch.samples = body.count("tgme_widget_message")
                ch.status = (ChannelStatus.ACTIVE if ch.score >= self.threshold
                             else ChannelStatus.REJECTED)
        except httpx.HTTPError:
            ch.status = ChannelStatus.DEAD
        finally:
            if own_client:
                client.close()
        ch.last_checked = datetime.now(timezone.utc)
        self._channels[name] = ch
        self._persist()
        return ch

    def verify_pending(self, max_candidates: int = 10) -> dict[str, int]:
        """Triage up to *max_candidates* pending channels; returns tallies."""
        tally = {"active": 0, "rejected": 0, "dead": 0}
        for ch in self.pending()[:max_candidates]:
            result = self.verify_candidate(ch.name)
            tally[result.status.value] = tally.get(result.status.value, 0) + 1
        self.store.events.record("discovery_verify", **tally)
        return tally
