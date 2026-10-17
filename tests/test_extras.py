"""Tests for rate limiting, export, retention, logging and the daemon cycle."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from tele_darkwatch.alerts.rate_limiter import RateLimiter
from tele_darkwatch.config import Settings
from tele_darkwatch.daemon import Daemon
from tele_darkwatch.export import export_messages
from tele_darkwatch.logging_setup import configure_logging, get_logger
from tele_darkwatch.models import Alert, Message, SourceType
from tele_darkwatch.retention import prune
from tele_darkwatch.storage.message_store import MessageStore


# ---------------------------------------------------------------- rate limiter
class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_rate_limiter_blocks_within_cooldown():
    clock = FakeClock()
    limiter = RateLimiter(cooldown=60.0, clock=clock)
    assert limiter.allow("rule|chan") is True
    assert limiter.allow("rule|chan") is False
    clock.now = 59.0
    assert limiter.allow("rule|chan") is False
    clock.now = 61.0
    assert limiter.allow("rule|chan") is True


def test_rate_limiter_remaining_and_prune():
    clock = FakeClock()
    limiter = RateLimiter(cooldown=30.0, clock=clock)
    limiter.allow("a")
    assert limiter.remaining("a") == 30.0
    assert limiter.remaining("never-seen") == 0.0
    clock.now = 100.0
    assert limiter.prune() == 1


# ---------------------------------------------------------------------- export
@pytest.fixture()
def messages():
    return [
        Message(
            content="missile launch detected",
            channel="dcg345",
            source_type=SourceType.TELEGRAM,
            url="https://t.me/dcg345/1",
            metadata={"collector": "telegram-rss"},
        ),
        Message(
            content='he said "exploit, then leak"',
            channel="onion.example",
            source_type=SourceType.DARKWEB,
        ),
    ]


def test_export_json_roundtrip(messages):
    data = json.loads(export_messages(messages, fmt="json"))
    assert len(data) == 2
    assert data[0]["content"] == "missile launch detected"


def test_export_ndjson(messages):
    lines = export_messages(messages, fmt="ndjson").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["channel"] == "onion.example"


def test_export_csv_quotes_commas(messages):
    text = export_messages(messages, fmt="csv")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][0] == "id"
    assert len(rows) == 3
    assert rows[2][-2] == 'he said "exploit, then leak"'  # quoted properly


def test_export_rejects_unknown_format(messages):
    with pytest.raises(ValueError):
        export_messages(messages, fmt="xml")


# ------------------------------------------------------------------- retention
def test_prune_removes_old_messages(store):
    now = datetime.now(timezone.utc)
    store.add_message(
        Message(content="fresh", channel="c", source_type=SourceType.MANUAL, timestamp=now)
    )
    store.add_message(
        Message(
            content="ancient",
            channel="c",
            source_type=SourceType.MANUAL,
            timestamp=now - timedelta(days=90),
        )
    )
    removed = prune(store, older_than_days=30.0)
    assert removed["messages"] == 1
    contents = [m.content for m in store.recent(limit=10)]
    assert contents == ["fresh"]


def test_prune_can_delete_alerts(store):
    old = datetime.now(timezone.utc) - timedelta(days=60)
    store.save_alert(
        Alert(rule="r", channel="c", message_content="x", created_at=old)
    )
    removed = prune(store, older_than_days=30.0, keep_alerts=False)
    assert removed["alerts"] == 1


# --------------------------------------------------------------------- logging
def test_configure_logging_idempotent():
    configure_logging("DEBUG", force=True)
    log = get_logger("tests")
    assert log.name.startswith("tele_darkwatch")
    configure_logging("INFO")  # second call should not raise / duplicate handlers
    root = get_logger("tele_darkwatch")
    assert len(root.handlers) >= 1


# ---------------------------------------------------------------------- daemon
def test_daemon_run_cycle_with_alerts(tmp_path, monkeypatch):
    db = tmp_path / "dw.db"
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{"pattern": "missile", "name": "strike"}]}))

    settings = Settings(
        db_path=str(db),
        rules_path=str(rules),
        telegram_channels="",  # no network in tests
        alert_cooldown=3600,
    )
    store = MessageStore(db)
    store.add_message(
        Message(content="missile inbound", channel="testchan", source_type=SourceType.MANUAL)
    )
    daemon = Daemon(settings, store=store)
    stats = daemon.run_cycle()
    assert stats["alerts"] == 1
    assert stats["notified"] == 1  # console notifier counts as delivered
    assert store.pending_alerts() == []

    # Second cycle re-raises the alert but the rate limiter suppresses notification.
    stats2 = daemon.run_cycle()
    assert stats2["alerts"] == 1
    assert stats2["notified"] == 0
    store.close()
