"""In-process ingestion pipeline: extract → dedupe → enrich → alert.

Every collected message flows through :func:`process_new_messages` after a
collection cycle. The pipeline:

1. pulls only messages not yet processed (tracked via a ``meta`` watermark),
2. runs the regex entity extractors (:mod:`tele_darkwatch.entities`),
3. records entities in the persistent index — brand-new values are flagged as
   *first-seen*, repeats get their ``seen_count`` bumped (repackaged-leak
   deduplication),
4. raises alerts for high-value findings (API keys, credential pairs) while
   suppressing dummy/test identities (false-positive filtering),
5. advances the watermark atomically.
"""
from __future__ import annotations

from typing import Iterable, Optional

from tele_darkwatch.alerts.regex_engine import RegexAlertEngine, default_regex_rules
from tele_darkwatch.entities import (
    EntityType,
    extract_all,
    filter_dummies,
    summarize,
)
from tele_darkwatch.logging_setup import get_logger
from tele_darkwatch.health import HealthMonitor
from tele_darkwatch.models import Alert
from tele_darkwatch.storage.message_store import MessageStore
from tele_darkwatch.watchlist import scan_message_for_watchlist

log = get_logger(__name__)

_WATERMARK_KEY = "pipeline_last_message_id"

#: Entity types that always escalate when they are genuinely new.
CRITICAL_TYPES = {EntityType.API_KEY}


class PipelineResult(dict):
    """Counter bag: ``processed``, ``entities``, ``new_entities``, ``alerts``…"""


def process_new_messages(
    store: MessageStore,
    batch_size: int = 500,
    raise_alerts: bool = True,
    include_dummies: bool = False,
    corporate_domains: Optional[Iterable[str]] = None,
) -> PipelineResult:
    """Run the extraction pipeline over all messages added since last time."""
    result = PipelineResult(processed=0, entities=0, new_entities=0,
                            alerts=0, by_type={})
    health = HealthMonitor(store)
    watermark = int(store.get_meta(_WATERMARK_KEY) or 0)

    while True:
        messages = store.messages_since(watermark, limit=batch_size)
        if not messages:
            break
        for msg in messages:
            watermark = max(watermark, msg.id or 0)
            result["processed"] += 1
            entities = extract_all(msg.content)
            if not include_dummies:
                from tele_darkwatch.entities import is_dummy_email
                dropped = [e for e in entities if is_dummy_email(e)]
                entities = [e for e in entities if not is_dummy_email(e)]
                if dropped:
                    log.debug("suppressed %d dummy entities in msg %s",
                              len(dropped), msg.id)
            new_count = store.entities.record_many(
                entities, message_id=msg.id, channel=msg.channel)
            result["entities"] += len(entities)
            result["new_entities"] += new_count

            if raise_alerts and new_count:
                result["alerts"] += _alert_for_entities(store, msg, entities)

            if raise_alerts and corporate_domains:
                wl = scan_message_for_watchlist(
                    store, msg.content, msg.channel, corporate_domains)
                result["alerts"] += len(wl)
                result["watchlist_hits"] = result.get("watchlist_hits", 0) + len(wl)

            health.beat(msg.channel)

        store.set_meta(_WATERMARK_KEY, str(watermark))

    result["by_type"] = store.entities.counts_by_type()
    if result["processed"]:
        store.events.record("pipeline", **{k: v for k, v in result.items()
                                           if k != "by_type"})
    return result


def _alert_for_entities(store: MessageStore, msg, entities) -> int:
    """Escalate first-seen critical entities; P1 for API keys, P2 creds."""
    raised = 0
    seen_now: set[str] = set()
    for ent in entities:
        if ent.entity_hash in seen_now:
            continue
        seen_now.add(ent.entity_hash)
        existing = store.entities.find_by_value(ent.value)
        is_new = bool(existing) and existing[0]["seen_count"] <= 1
        if not is_new:
            continue
        severity: Optional[int] = None
        rule_name: Optional[str] = None
        if ent.type in CRITICAL_TYPES:
            severity, rule_name = 1, f"new_{ent.type.value}"
        elif ent.type is EntityType.EMAIL and ent.attributes.get("password"):
            severity, rule_name = 2, "new_credential_pair"
        if severity is None:
            continue
        alert = Alert(
            rule=rule_name or "new_entity",
            channel=msg.channel,
            message_content=f"{ent.type.value}: {ent.value}"
                            f"{' (with password)' if ent.attributes.get('password') else ''}",
            metadata={"severity": severity, "entity_hash": ent.entity_hash,
                      **ent.attributes},
        )
        store.save_alert(alert)
        raised += 1
    return raised


def run_regex_iocs(store: MessageStore, limit: int = 200) -> list[Alert]:
    """Convenience wrapper used by the daemon to combine IOC regex scanning."""
    engine = RegexAlertEngine(store, default_regex_rules())
    return engine.scan_recent(limit=limit)
