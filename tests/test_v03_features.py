"""Tests for regex IOC engine, event log, schema migration and new CLI commands."""
from __future__ import annotations

import json
import sqlite3

import pytest

from tele_darkwatch.alerts.regex_engine import (
    RegexAlertEngine,
    RegexRule,
    default_regex_rules,
)
from tele_darkwatch.cli import main
from tele_darkwatch.models import Alert, Message, SourceType
from tele_darkwatch.storage.event_log import EventLog
from tele_darkwatch.storage.message_store import MessageStore


def _msg(content: str, channel: str = "testchan") -> Message:
    return Message(content=content, channel=channel, source_type=SourceType.MANUAL)


# ---------------------------------------------------------------- regex rules
class TestRegexEngine:
    def test_cve_extraction(self, store):
        engine = RegexAlertEngine(store, default_regex_rules())
        alerts = engine.check_message(
            _msg("Critical vuln CVE-2024-34567 exploited in the wild")
        )
        cve_alerts = [a for a in alerts if a.rule == "cve"]
        assert len(cve_alerts) == 1
        assert cve_alerts[0].metadata["cve"] == "CVE-2024-34567"
        assert cve_alerts[0].metadata["severity"] == 3

    def test_onion_and_email_extraction(self, store):
        engine = RegexAlertEngine(store, default_regex_rules())
        alerts = engine.check_message(
            _msg("mirror at abcdefghijklmnop.onion contact ops@example.com")
        )
        by_rule = {a.rule: a for a in alerts}
        assert "onion_address" in by_rule
        assert by_rule["onion_address"].metadata["onion"] == "abcdefghijklmnop.onion"
        assert "email" in by_rule
        assert by_rule["email"].metadata["email"] == "ops@example.com"

    def test_no_match_no_alert(self, store):
        engine = RegexAlertEngine(store, default_regex_rules())
        assert engine.check_message(_msg("nothing interesting here")) == []

    def test_custom_rule_from_file(self, store, tmp_path):
        rules_file = tmp_path / "ioc.json"
        rules_file.write_text(json.dumps({
            "rules": [{"name": "wallet", "pattern": r"(?P<w>bc1[a-z0-9]{27,68})", "severity": 5}]
        }))
        engine = RegexAlertEngine.from_file(store, rules_file)
        alerts = engine.check_message(_msg("pay to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 now"))
        assert len(alerts) == 1
        assert alerts[0].rule == "wallet"
        assert alerts[0].metadata["severity"] == 5

    def test_case_sensitive_flag(self):
        rule = RegexRule(name="exact", pattern=r"(?P<x>FOO)", flags_ignorecase=False)
        assert rule.extract("has FOO here") == {"x": "FOO"}
        assert rule.extract("has foo here") is None

    def test_alert_metadata_roundtrip(self, store):
        alert = Alert(rule="r", channel="c", message_content="m",
                      metadata={"cve": "CVE-2024-1"})
        store.save_alert(alert)
        pending = store.pending_alerts()
        assert pending[0].metadata == {"cve": "CVE-2024-1"}


# ------------------------------------------------------------------ event log
class TestEventLog:
    def test_record_and_recent(self, store):
        store.events.record("cycle", telegram=5, alerts=1)
        store.events.record("notify", dispatched=1)
        all_events = store.events.recent()
        assert store.events.count() == 2
        cats = {e["category"] for e in all_events}
        assert cats == {"cycle", "notify"}
        cycle = [e for e in all_events if e["category"] == "cycle"][0]
        assert cycle["detail"]["telegram"] == 5

    def test_filter_by_category(self, store):
        store.events.record("a", x=1)
        store.events.record("b", y=2)
        only_b = store.events.recent(category="b")
        assert len(only_b) == 1 and only_b[0]["detail"] == {"y": 2}

    def test_purge_before(self, store):
        store.events.record("keep", x=1)
        assert store.events.purge_before(days=-0.001) == 1  # cutoff in the future
        assert store.events.count() == 0

    def test_daemon_cycle_records_event(self, store):
        from tele_darkwatch.config import Settings
        from tele_darkwatch.daemon import Daemon

        settings = Settings(db_path=store.path, telegram_channels="", darkweb_urls="")
        Daemon(settings, store=store).run_cycle()
        events = store.events.recent(category="cycle")
        assert len(events) == 1


# ------------------------------------------------------------------- meta KV
class TestMetaAndMigration:
    def test_set_get_meta(self, store):
        assert store.get_meta("schema_version") is None
        store.set_meta("schema_version", "3")
        assert store.get_meta("schema_version") == "3"
        store.set_meta("schema_version", "4")  # upsert
        assert store.get_meta("schema_version") == "4"

    def test_migration_adds_metadata_column(self, tmp_path):
        """An old DB without alerts.metadata must upgrade transparently."""
        db = tmp_path / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " dedup_key TEXT UNIQUE NOT NULL, content TEXT NOT NULL,"
            " channel TEXT NOT NULL, source_type TEXT NOT NULL, timestamp TEXT NOT NULL,"
            " url TEXT, metadata TEXT NOT NULL DEFAULT '{}');"
            "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " rule TEXT NOT NULL, channel TEXT NOT NULL, message_content TEXT NOT NULL,"
            " created_at TEXT NOT NULL, notified INTEGER NOT NULL DEFAULT 0);"
        )
        conn.execute(
            "INSERT INTO alerts (rule, channel, message_content, created_at)"
            " VALUES ('legacy', 'ch', 'body', '2024-01-01T00:00:00+00:00')"
        )
        conn.commit()
        conn.close()

        upgraded = MessageStore(db)
        pending = upgraded.pending_alerts()
        assert len(pending) == 1
        assert pending[0].rule == "legacy"
        assert pending[0].metadata == {}
        upgraded.save_alert(Alert(rule="new", channel="ch",
                                  message_content="x", metadata={"k": "v"}))
        metas = {a.rule: a.metadata for a in upgraded.pending_alerts()}
        assert metas["new"] == {"k": "v"}
        upgraded.close()


# ------------------------------------------------------------------------ CLI
class TestNewCliCommands:
    def test_add_command(self, store, capsys):
        rc = main(["--db", store.path, "add", "exploit leaked at CVE-2024-9999",
                   "--channel", "manual"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Stored message id=" in out
        assert "alert(s) raised" in out
        assert store.count() == 1

    def test_add_duplicate_suppressed(self, store, capsys):
        main(["--db", store.path, "add", "same text"])
        main(["--db", store.path, "add", "same text"])
        assert store.count() == 1
        assert "duplicate" in capsys.readouterr().out.lower()

    def test_ioc_scan_command(self, store, capsys):
        store.add_message(_msg("target 192.168.1.10 uses deadbeefdeadbeef.onion"))
        rc = main(["--db", store.path, "ioc-scan"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "IOC alert(s) raised" in out
        assert "onion_address" in out or "ipv4" in out

    def test_events_and_stats(self, store, capsys):
        store.events.record("test", value=42)
        assert main(["--db", store.path, "events"]) == 0
        out = capsys.readouterr().out
        assert '"category": "test"' in out
        assert main(["--db", store.path, "stats"]) == 0
        assert '"events": 1' in capsys.readouterr().out
