from datetime import datetime, timezone

from tele_darkwatch.models import Message, SourceType
from tele_darkwatch.storage.message_store import MessageStore


def _msg(content="hello world", channel="testchan"):
    return Message(
        content=content,
        channel=channel,
        source_type=SourceType.TELEGRAM,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_add_and_retrieve(store):
    mid = store.add_message(_msg())
    assert mid is not None
    got = store.get_message(mid)
    assert got.content == "hello world"
    assert got.source_type == SourceType.TELEGRAM


def test_dedup(store):
    assert store.add_message(_msg()) is not None
    assert store.add_message(_msg()) is None  # duplicate suppressed
    assert store.count() == 1


def test_bulk_and_channels(store):
    n = store.add_messages([_msg("a"), _msg("b", channel="other"), _msg("a")])
    assert n == 2
    assert set(store.channels()) == {"testchan", "other"}


def test_recent_ordering(store):
    m1 = Message(
        content="old",
        channel="c",
        source_type=SourceType.MANUAL,
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    m2 = _msg("new")
    m2.timestamp = datetime(2026, 6, 1, tzinfo=timezone.utc)
    store.add_messages([m1, m2])
    recent = store.recent(limit=10)
    assert recent[0].content == "new"


def test_alert_roundtrip(store):
    from tele_darkwatch.models import Alert

    store.save_alert(Alert(rule="r1", channel="c", message_content="boom"))
    pending = store.pending_alerts()
    assert len(pending) == 1
    store.mark_alert_notified("r1", "c")
    assert store.pending_alerts() == []
