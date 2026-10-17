"""End-to-end CLI coverage for the v0.4 analysis commands."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from tele_darkwatch.cli import main


def run_cli(argv, db):
    """Invoke the CLI in-process against a temp DB; return captured stdout."""
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--db", str(db), *argv])
    assert rc == 0, f"CLI failed: {argv} -> rc={rc}"
    return buf.getvalue()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db = tmp_path / "dw.sqlite3"
    monkeypatch.setenv("DW_DB_PATH", str(db))
    return tmp_path, db


def _seed(db, content: str, channel="testchan"):
    from tele_darkwatch.storage.message_store import MessageStore
    store = MessageStore(db)
    from tele_darkwatch.models import Message, SourceType
    store.add_message(Message(content=content, channel=channel,
                              source_type=SourceType.TELEGRAM))
    store.close()


class TestPipelineCLI:
    def test_pipeline_and_entities(self, env):
        _, db = env
        _seed(db, "leak dump jane@corp.io:S3cret and AKIAIOSFODNN7EXAMPLE here")
        out = run_cli(["pipeline"], db)
        result = json.loads(out)
        assert result["processed"] == 1 and result["entities"] >= 2
        out = run_cli(["entities"], db)
        counts = json.loads(out)
        assert counts["counts_by_type"].get("email") == 1
        assert counts["counts_by_type"].get("api_key") == 1
        out = run_cli(["entities", "jane", "--type", "email"], db)
        rows = json.loads(out)
        assert rows[0]["value"] == "jane@corp.io"
        assert rows[0]["attributes"]["password"] == "S3cret"

    def test_stats_includes_entities(self, env):
        _, db = env
        _seed(db, "x y z plain text")
        run_cli(["pipeline"], db)
        stats = json.loads(run_cli(["stats"], db))
        assert "entities" in stats

    def test_watchlist_profile(self, env, monkeypatch):
        _, db = env
        monkeypatch.setenv("DW_CORPORATE_DOMAINS", "acme.com")
        _seed(db, "selling bob@acme.com:P@ssw0rd fresh combo")
        res = json.loads(run_cli(["pipeline"], db))
        assert res.get("watchlist_hits") == 1
        prof = json.loads(run_cli(["profile", "bob@acme.com"], db))
        assert prof["total_sightings"] >= 1
        assert "testchan" in prof["channels"]


class TestArchiveAndCookies:
    def test_parse_archive(self, env):
        tmp, db = env
        zp = tmp / "dump.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("Userpass.txt", "victim@mail.com:pw99\nhttps://t.me/NewLogs24\n")
            zf.writestr("evil.exe", "MZfake")
        out = json.loads(run_cli(["parse-archive", str(zp)], db))
        assert out["dropped_executables"] == 1
        assert out["entity_counts"].get("email") == 1

    def test_parse_cookies(self, env):
        tmp, db = env
        exp = int((datetime.now(timezone.utc) + timedelta(days=2)).timestamp())
        cf = tmp / "cookies.txt"
        cf.write_text(
            ".microsoftonline.com\tTRUE\t/\tTRUE\t"
            f"{exp}\tsid\tlive-token\n")
        out = json.loads(run_cli(["parse-cookies", str(cf)], db))
        assert out["critical_live_sessions"] == 1


class TestDiscoveryCLI:
    def test_discover_channels_list(self, env):
        _, db = env
        _seed(db, "new base advertised: t.me/StealerHub_99 join now")
        out = run_cli(["discover"], db)
        assert "1 new channel candidate" in out
        rows = json.loads(run_cli(["channels"], db))
        assert rows[0]["name"] == "stealerhub_99"
        assert rows[0]["status"] == "pending"


class TestSanitizeHealthCLI:
    def test_sanitize(self, env, monkeypatch):
        _, db = env
        monkeypatch.setenv("DW_CORPORATE_DOMAINS", "acme.com")
        _seed(db, "outsider@random.xyz:Secret123 leaked")
        _seed(db, "alice@acme.com:KeepThis99 internal", channel="internal")
        res = json.loads(run_cli(["sanitize"], db))
        assert res["masked"] == 1
        from tele_darkwatch.storage.message_store import MessageStore
        store = MessageStore(db)
        msgs = {m.channel: m.content for m in store.recent(limit=10)}
        store.close()
        assert "Secret123" not in msgs["testchan"]
        assert "KeepThis99" in msgs["internal"]

    def test_health_json_and_prom(self, env):
        _, db = env
        snap = json.loads(run_cli(["health"], db))
        assert "stale_channels" in snap and "failing_endpoints" in snap
        out = run_cli(["health", "--prometheus"], db)
        assert "darkwatch_messages_total" in out


class TestDaemonIntegration:
    def test_daemon_cycle_runs_pipeline(self, env, monkeypatch):
        tmp, db = env
        monkeypatch.delenv("DW_TELEGRAM_CHANNELS", raising=False)
        monkeypatch.delenv("DW_DARKWEB_URLS", raising=False)
        monkeypatch.setenv("DW_ALERT_WEBHOOK_URL", "")
        # seed a message so the pipeline has work after collectors add nothing
        _seed(db, "daemon-seed joe@widgets.co:pw5 on list")
        monkeypatch.setenv("DW_CORPORATE_DOMAINS", "widgets.co")
        import inspect
        from tele_darkwatch import daemon as daemon_mod
        cls = next(v for k, v in vars(daemon_mod).items()
                   if isinstance(v, type) and hasattr(v, "run_cycle"))

        class _NoopNotifier:
            def notify(self, alert):
                return True

        daemon = cls(notifiers=[_NoopNotifier()])
        stats = daemon.run_cycle()
        assert stats["pipeline_processed"] == 1
        alerts = daemon.store.all_alerts()
        assert any(a.rule == "corporate_credential_leak" for a in alerts)
        daemon.shutdown()
