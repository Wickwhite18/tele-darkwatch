"""Tests for the v0.6 layer: entity graph, SOAR playbooks, NLP triage,
and the optional async/userbot collectors (import-safety only)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from tele_darkwatch.graph import EntityGraph, build_graph
from tele_darkwatch.models import Alert, Message, SourceType
from tele_darkwatch.nlp_classify import classify, should_index, summarize
from tele_darkwatch.soar import SOAREngine, process_pending_alerts
from tele_darkwatch.storage.message_store import MessageStore


# ---------------------------------------------------------------------------
# nlp_classify
# ---------------------------------------------------------------------------

class TestNLPClassify:
    def test_credential_dump_label(self):
        res = classify("fresh combo UserPass.txt base64 dXNlcjpwYXNz lumma logs")
        assert res.label == "valid_credential_dump"
        assert res.confidence > 0.3

    def test_ransomware_victim_label(self):
        res = classify("we have breached Acme Corp, data will be published on leak site")
        assert res.label == "ransomware_victim"

    def test_scam_or_ad_dropped(self):
        res = classify("premium logs mega sale paypal accepted proof of payment vip sellers only")
        assert res.label in {"log_advertisement", "scam_or_ad"}
        assert should_index(res, threshold=0.5) is False

    def test_general_kept(self):
        res = classify("hello everyone how are you today")
        assert res.label == "general"
        assert should_index(res) is True

    def test_custom_model_fn_override(self):
        def fake_model(text: str) -> dict[str, float]:
            return {"malware_source": 0.9}

        res = classify("anything at all", model_fn=fake_model)
        assert res.label == "malware_source"
        assert res.source == "model"

    def test_summarize(self):
        results = [classify(t) for t in ("combo UserPass.txt lumma", "hi there")]
        s = summarize(results)
        assert sum(s.values()) == 2


# ---------------------------------------------------------------------------
# graph (entity resolution)
# ---------------------------------------------------------------------------

def _seed_graph(store: MessageStore):
    # one message grafting a corporate email + personal email + name
    store.add_message(Message(
        content="john@acme-corp.com also uses john@gmail.com - John Doe creds attached",
        channel="breach-chat", source_type=SourceType.TELEGRAM,
    ))
    # second unrelated breach reusing the personal email
    store.add_message(Message(
        content="dump: john@gmail.com password reuse confirmed in market leak",
        channel="market-x", source_type=SourceType.DARKWEB,
    ))


class TestEntityGraph:
    def test_cluster_links_across_breaches(self, store):
        _seed_graph(store)
        g = build_graph(store)
        cluster = g.cluster("email:john@gmail.com", max_hops=2)
        values = {n["value"] for n in cluster}
        assert "john@acme-corp.com" in values  # cross-breach graft found

    def test_risk_score_flags_corporate_exposure(self, store):
        _seed_graph(store)
        g = build_graph(store)
        score = g.risk_score("john@gmail.com")
        assert score["found"] is True
        assert score["score"] > 0
        # personal + corporate emails grafted across two channels
        assert score["cluster_size"] >= 2
        assert len(score["channels"]) >= 1

    def test_unknown_identity_zero_risk(self, store):
        g = EntityGraph(store)
        score = g.risk_score("nobody@example.org")
        assert score["score"] == 0


# ---------------------------------------------------------------------------
# SOAR engine
# ---------------------------------------------------------------------------

def _save_alert(store: MessageStore, hint: str = "admin@acme-corp.com") -> Alert:
    alert = Alert(
        rule="leak-watch", channel="chat",
        message_content=f"{hint}:Password1 leaked",
        metadata={"match_value": hint},
    )
    alert.id = store.save_alert(alert)
    return alert


class TestSOAR:
    def test_ticket_opened_and_persisted(self, store):
        alert = _save_alert(store)
        engine = SOAREngine(store, webhook_url="")  # no network
        result = engine.run_playbook(alert)
        assert result["severity"].startswith("P")
        assert result["delivered"] is False  # no webhook configured
        tickets = engine.list_tickets()
        assert len(tickets) == 1
        assert tickets[0]["alert_id"] == alert.id

    def test_run_playbook_with_live_validator(self, store):
        alert = _save_alert(store, hint="token@sso.bigcorp.com")
        engine = SOAREngine(store, webhook_url="")
        result = engine.run_playbook(alert, session_validator=lambda hint: True)
        assert result["session_live"] is True
        assert result["severity"] == "P0"

    def test_live_enterprise_session_escalates_to_p0(self, store):
        alert = _save_alert(store, hint="user@company.okta.com")
        engine = SOAREngine(store, webhook_url="", enrich=False)
        sev = engine.decide_severity(alert, {"score": 0}, session_live=True)
        assert sev == "P0"

    def test_expired_session_downgrades(self, store):
        alert = _save_alert(store)
        engine = SOAREngine(store, webhook_url="", enrich=False)
        sev_live = engine.decide_severity(alert, {"score": 0}, session_live=True)
        sev_dead = engine.decide_severity(alert, {"score": 0}, session_live=False)
        assert sev_dead > sev_live  # P-number grows as priority drops

    def test_process_pending_alerts_idempotent(self, store):
        _save_alert(store)
        first = process_pending_alerts(store, None)
        assert len(first) == 1
        second = process_pending_alerts(store, None)
        assert second == []  # already-ticketed alert not re-processed


# ---------------------------------------------------------------------------
# Optional-dependency collectors: must import cleanly and fail gracefully
# ---------------------------------------------------------------------------

class TestOptionalCollectors:
    def test_userbot_requires_telethon(self):
        from tele_darkwatch.collectors import telegram_userbot as tub

        if tub.telethon_available():
            pytest.skip("telethon installed; skip graceful-degradation check")
        with pytest.raises(Exception):
            tub._require_telethon()

    def test_message_to_model_shape(self):
        from datetime import datetime, timezone

        from tele_darkwatch.collectors.telegram_userbot import message_to_model

        class FakeMsg:
            id = 7
            raw_text = "leak detected"
            date = datetime(2026, 10, 17, tzinfo=timezone.utc)
            file = None
            photo = None

        msg = message_to_model(FakeMsg(), "testchan")
        assert msg.channel == "testchan"
        assert msg.content == "leak detected"

    def test_async_crawler_import_safe(self):
        from tele_darkwatch.collectors import darkweb_async as da

        assert callable(da.crawl_async)
        assert callable(da.crawl_blocking)

    def test_to_message_parses_html(self):
        from tele_darkwatch.collectors.darkweb_async import _to_message

        html = ("<html><body><h1>Ransomware leak</h1>"
                "<p>victim acme-corp data</p></body></html>")
        msg = _to_message("http://abc.onion/leaks", html)
        assert msg is not None
        assert "Ransomware leak" in msg.content


# ---------------------------------------------------------------------------
# CLI wiring smoke tests (subprocess against the installed console entry)
# ---------------------------------------------------------------------------

def _run_cli(args, db):
    return subprocess.run(
        [sys.executable, "-m", "tele_darkwatch.cli", *args, "--db", db],
        capture_output=True, text=True, timeout=60,
    )


class TestCLIv06:
    def test_classify_command(self, tmp_path):
        r = _run_cli(["classify", "combo UserPass.txt lumma fresh logs"], tmp_path / "c.db")
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["label"] == "valid_credential_dump"

    def test_risk_command(self, tmp_path):
        db = tmp_path / "r.db"
        store = MessageStore(db)
        _seed_graph(store)
        store.close()
        r = _run_cli(["risk", "john@gmail.com"], db)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["score"] > 0

    def test_soar_run_and_tickets(self, tmp_path):
        db = tmp_path / "s.db"
        store = MessageStore(db)
        _save_alert(store)
        store.close()
        r = _run_cli(["soar-run"], db)
        assert r.returncode == 0, r.stderr
        r2 = _run_cli(["tickets"], db)
        assert r2.returncode == 0, r2.stderr
        tickets = json.loads(r2.stdout)
        assert len(tickets) == 1
