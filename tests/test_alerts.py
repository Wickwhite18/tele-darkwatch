import json

from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import ConsoleNotifier, dispatch_pending
from tele_darkwatch.models import MatchRule, Message, SourceType


def _msg(content):
    return Message(content=content, channel="chan", source_type=SourceType.TELEGRAM)


def test_rule_matches_and_persists(store):
    engine = AlertEngine(store, [MatchRule(pattern="missile", name="kinetic")])
    alerts = engine.check_message(_msg("A MISSILE was launched"))
    assert len(alerts) == 1
    assert alerts[0].rule == "kinetic"
    assert store.pending_alerts()


def test_case_sensitive(store):
    engine = AlertEngine(store, [MatchRule(pattern="ABC", case_sensitive=True)])
    assert engine.check_message(_msg("abc")) == []
    assert len(engine.check_message(_msg("ABC"))) == 1


def test_from_file(store, tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": [{"pattern": "exploit"}]}))
    engine = AlertEngine.from_file(store, p)
    assert engine.rules[0].pattern == "exploit"


def test_scan_recent(store):
    engine = AlertEngine(store, [MatchRule(pattern="leak")])
    store.add_message(_msg("data leak discovered"))
    found = engine.scan_recent()
    assert len(found) == 1


def test_dispatch_marks_notified(store):
    store.save_alert(
        __import__("tele_darkwatch.models", fromlist=["Alert"]).Alert(
            rule="r", channel="c", message_content="x"
        )
    )
    sent = dispatch_pending(store, [ConsoleNotifier()])
    assert sent == 1
    assert store.pending_alerts() == []
