"""Enterprise watchlist — flag exposures that concern *your* organization.

Given a list of owned domains (``DW_CORPORATE_DOMAINS=acme.com,acme.co.uk``),
every archived message or parsed leak is checked for emails belonging to those
domains. Hits raise high-severity alerts (P1 when paired with a password or a
live session cookie). Also exposes :func:`profile_for` — lightweight entity
resolution: everything we know about one identity across all sources.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from tele_darkwatch.entities import Entity, EntityType, extract_all
from tele_darkwatch.models import Alert
from tele_darkwatch.storage.message_store import MessageStore


def corporate_hits(text: str, domains: Iterable[str]) -> list[Entity]:
    """Email entities whose domain matches one of the watched domains."""
    wanted = [d.lower().lstrip(".") for d in domains if d]
    hits: list[Entity] = []
    if not wanted:
        return hits
    for ent in extract_all(text):
        if ent.type is not EntityType.EMAIL:
            continue
        domain = ent.value.rsplit("@", 1)[-1]
        if any(domain == w or domain.endswith("." + w) for w in wanted):
            hits.append(ent)
    return hits


def scan_message_for_watchlist(store: MessageStore, content: str, channel: str,
                               domains: Iterable[str],
                               source_ref: Optional[int] = None) -> list[Alert]:
    """Raise P1/P2 alerts for every corporate hit; dedup via alert history."""
    raised: list[Alert] = []
    for ent in corporate_hits(content, domains):
        has_password = bool(ent.attributes.get("password"))
        severity = 1 if has_password else 2
        rule = "corporate_credential_leak" if has_password else "corporate_email_exposed"
        # Don't re-page for the same identity+channel combination.
        if store.alert_exists(rule=rule, channel=channel,
                              needle=ent.value):
            continue
        alert = Alert(
            rule=rule,
            channel=channel,
            message_content=f"{ent.value}"
                            + (" with password" if has_password else ""),
            metadata={"severity": severity, "entity_hash": ent.entity_hash,
                      "domain": ent.value.rsplit("@", 1)[-1]},
        )
        store.save_alert(alert)
        raised.append(alert)
    if raised:
        store.events.record("watchlist", channel=channel, hits=len(raised))
    return raised


def profile_for(store: MessageStore, identity: str) -> dict:
    """Cross-vector correlation: all known channels/entities around an identity.

    Answers: where has ``jane@acme.com`` (or just ``jane``) shown up, and what
    other entities co-occur in those same messages? The result approximates an
    "infected device profile" without a graph database.
    """
    rows = store.entities.find_by_value(identity)
    channels: set[str] = set()
    seen_count = 0
    for r in rows:
        channels.update(r["channels"])
        seen_count += r["seen_count"]
    co_entities: dict[str, int] = defaultdict(int)
    for msg in store.search_like(identity):
        for ent in extract_all(msg.content):
            if ent.value.lower() != identity.lower():
                co_entities[f"{ent.type.value}:{ent.value}"] += 1
    return {
        "identity": identity,
        "known_records": len(rows),
        "total_sightings": seen_count,
        "channels": sorted(channels),
        "co_occurring_entities": dict(sorted(co_entities.items(),
                                             key=lambda kv: -kv[1])[:25]),
    }
