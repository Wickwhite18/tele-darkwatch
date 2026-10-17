"""Tests for entity extraction, the ingestion pipeline and dedup."""
from __future__ import annotations

import pytest

from tele_darkwatch.entities import (
    EntityType,
    extract_all,
    extract_api_keys,
    extract_crypto_addresses,
    extract_emails,
    is_dummy_email,
)
from tele_darkwatch.models import Message, SourceType
from tele_darkwatch.pipeline import process_new_messages
from tele_darkwatch.storage.message_store import MessageStore


@pytest.fixture()
def store(tmp_path):
    s = MessageStore(tmp_path / "t.sqlite3")
    yield s
    s.close()


def _msg(content, channel="chan"):
    return Message(content=content, channel=channel, source_type=SourceType.TELEGRAM)


class TestExtraction:
    def test_emails_with_password(self):
        ents = extract_emails("leak: jane@acme.com:hunter2 more")
        assert ents and ents[0].value == "jane@acme.com"
        assert ents[0].attributes["password"] == "hunter2"

    def test_ip_not_mistaken_for_email(self):
        # 1.2.3.4 matches the loose email regex; extractor must drop it.
        assert not any(e.type == EntityType.EMAIL for e in extract_all("host 1.2.3.4 up"))

    def test_api_keys(self):
        text = ("AKIAIOSFODNN7EXAMPLE sk-ant-api03-" + "x" * 30 +
                " sk-proj-" + "y" * 25)
        types = {e.attributes["key_type"] for e in extract_api_keys(text)}
        assert {"aws_access_key_id", "anthropic_api_key", "openai_api_key"} <= types

    def test_crypto(self):
        btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        eth = "0x" + "a" * 40
        found = {e.type for e in extract_crypto_addresses(f"{btc} {eth}")}
        assert EntityType.BTC_ADDRESS in found and EntityType.ETH_ADDRESS in found

    def test_dummy_detection(self):
        ents = extract_all("test@test.com admin@acme.com")
        dummies = [e for e in ents if is_dummy_email(e)]
        assert len(dummies) == 1


class TestPipeline:
    def test_first_run_extracts_and_dedups(self, store):
        store.add_message(_msg("victim@corp.io:S3cret posted at https://x.onion/a"))
        res = process_new_messages(store)
        assert res["processed"] == 1
        assert res["entities"] >= 2
        # second call: watermark means nothing new to do
        res2 = process_new_messages(store)
        assert res2["processed"] == 0

    def test_repackaged_leak_bumps_seen_count(self, store):
        line = "reuse@corp.io:pw"
        store.add_message(_msg(line, channel="a"))
        process_new_messages(store)
        store.add_message(_msg(line, channel="b"))
        res = process_new_messages(store)
        assert res["new_entities"] == 0  # known value → no fresh alert
        rows = store.entities.find_by_value("reuse@corp.io")
        assert rows and rows[0]["seen_count"] == 2
        assert set(rows[0]["channels"]) == {"a", "b"}

    def test_api_key_raises_p1_alert(self, store):
        store.add_message(_msg("token AKIAIOSFODNN7EXAMPLE live"))
        res = process_new_messages(store)
        assert res["alerts"] >= 1
        alerts = store.pending_alerts()
        assert any(a.rule.startswith("new_") for a in alerts)

    def test_watchlist_hit_alerts(self, store):
        store.add_message(_msg("sale: bob@acme.com:pass99 on market"))
        res = process_new_messages(store, corporate_domains=["acme.com"])
        assert res.get("watchlist_hits", 0) == 1
        rules = {a.rule for a in store.pending_alerts()}
        assert "corporate_credential_leak" in rules

    def test_watchlist_dedup_no_double_page(self, store):
        for ch in ("a", "b"):
            store.add_message(_msg("bob@acme.com:pass99", channel=ch))
            process_new_messages(store, corporate_domains=["acme.com"])
        again = process_new_messages(store, corporate_domains=["acme.com"])
        assert again.get("watchlist_hits", 0) == 0
