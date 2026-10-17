"""Tests for in-memory archive parsing, cookie triage and sanitization."""
from __future__ import annotations

import io
import json
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tele_darkwatch.channel_discovery import (
    ChannelDiscovery,
    ChannelStatus,
    classify_text,
    extract_channel_names,
)
from tele_darkwatch.cookies import parse_any, triage
from tele_darkwatch.health import HealthMonitor
from tele_darkwatch.leak_parser import parse_archive_bytes, parse_userpass_text
from tele_darkwatch.sanitize import mask_text, sanitize_store
from tele_darkwatch.session_check import validate_token
from tele_darkwatch.storage.message_store import MessageStore
from tele_darkwatch.models import Message, SourceType


@pytest.fixture()
def store(tmp_path):
    s = MessageStore(tmp_path / "t.sqlite3")
    yield s
    s.close()


def _zip(members: dict[str, bytes]) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return bio.getvalue()


class TestLeakParser:
    def test_extracts_entities_in_memory(self):
        blob = _zip({"Userpass.txt": b"bob@site.com:pw123\nhttps://t.me/NewBase42\n",
                     "systeminfo.txt": b"PC-NAME; ip 8.8.8.8"})
        report = parse_archive_bytes(blob)
        values = {e.value for e in report.entities}
        assert "bob@site.com" in values and "8.8.8.8" in values
        assert report.dropped_executables == 0

    def test_drops_executables_by_magic_and_extension(self):
        blob = _zip({"evil.exe": b"MZ\x90\x03 fake pe",
                     "shell.bin": b"\x7fELF binary",
                     "ok.txt": b"safe content"})
        report = parse_archive_bytes(blob)
        assert report.dropped_executables == 2
        assert report.members_parsed == 1

    def test_zip_bomb_budget(self):
        blob = _zip({f"f{i}.txt": b"x" * 1000 + f"a@{i}.com ".encode()
                     for i in range(10)})
        report = parse_archive_bytes(blob, max_total_bytes=2500)
        assert report.truncated is True

    def test_tar_support(self):
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:gz") as tf:
            data = b"victim@mail.com:hunter2"
            info = tarfile.TarInfo("logs/Userpass.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        report = parse_archive_bytes(bio.getvalue())
        assert any(e.value == "victim@mail.com" for e in report.entities)

    def test_userpass_lines(self):
        recs = parse_userpass_text("# comment\nu1:secret1\nplainline\na@b.co:x-y-z")
        assert {"username": "u1", "password": "secret1"} in recs


class TestCookies:
    NETSCAPE = (
        "# Netscape HTTP Cookie File\n"
        ".microsoftonline.com\tTRUE\t/\tTRUE\t{exp}\tsessionid\tabc123\n"
        ".example-gaming.net\tFALSE\t/\tFALSE\t0\tpref\tdark\n"
    )

    def test_live_high_value_is_critical(self):
        exp = int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())
        cookies = parse_any(self.NETSCAPE.format(exp=exp))
        assert len(cookies) == 2
        t = triage(cookies)
        assert t["critical_live_sessions"] == 1
        assert t["live_domains"] == [".microsoftonline.com"]

    def test_expired_downgrades(self):
        exp = int((datetime.now(timezone.utc) - timedelta(days=5)).timestamp())
        t = triage(parse_any(self.NETSCAPE.format(exp=exp)))
        assert t["critical_live_sessions"] == 0
        assert t["expired_high_value"] == 1

    def test_json_format(self):
        payload = json.dumps([{"domain": ".okta.com", "name": "sid",
                               "value": "v", "expirationDate": None}])
        cookies = parse_any(payload)
        assert cookies[0].high_value and not cookies[0].is_expired


class TestDiscovery:
    def test_extract_names(self):
        names = extract_channel_names("see https://t.me/s/BreachDump or "
                                      "t.me/joinchat/Stealer_Logs x")
        assert "breachdump" in names and "stealer_logs" in names

    def test_classify_score(self):
        hot = "fresh stealer logs combos dumped breach database"
        assert classify_text(hot) > classify_text("hello everyone good morning")

    def test_verify_flow_with_mock_transport(self, store):
        def handler(request: httpx.Request) -> httpx.Response:
            if "leakybase" in str(request.url):
                return httpx.Response(200, text="stealer logs combos breach dump database")
            if "deadchan" in str(request.url):
                return httpx.Response(404)
            return httpx.Response(200, text="cute cat pictures daily")

        transport = httpx.MockTransport(handler)
        disc = ChannelDiscovery(store, transport=transport)
        disc.discover_from_text("check t.me/leakybase and t.me/catpics and t.me/deadchan",
                                origin="src")
        assert len(disc.pending()) == 3
        tally = disc.verify_pending(max_candidates=5)
        assert tally["active"] == 1 and tally["rejected"] == 1 and tally["dead"] == 1
        assert disc.active_channels() == ["leakybase"]

        # persistence across instances
        disc2 = ChannelDiscovery(store, transport=transport)
        assert disc2.active_channels() == ["leakybase"]


class TestHealth:
    def test_heartbeat_and_stale(self, store):
        h = HealthMonitor(store)
        h.beat("live-chan")
        # simulate old beat by rewriting meta
        import json as _json
        old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
        store.set_meta("health_channel_last_seen",
                       _json.dumps({"live-chan": old}))
        stale = h.stale_channels(max_silence_hours=24)
        assert [s["channel"] for s in stale] == ["live-chan"]

    def test_endpoint_failures(self, store):
        h = HealthMonitor(store)
        url = "http://xyz.onion/leaks"
        for _ in range(3):
            h.endpoint_fail(url, "504 Gateway Timeout")
        failing = h.failing_endpoints(threshold=3)
        assert failing and failing[0]["failures"] == 3
        h.endpoint_ok(url, items=10)
        assert h.failing_endpoints(threshold=3) == []

    def test_prometheus_output(self, store):
        store.add_message(Message(content="hi there", channel="c1",
                                  source_type=SourceType.TELEGRAM))
        HealthMonitor(store).beat("c1")
        text = HealthMonitor(store).prometheus_text()
        assert "darkwatch_messages_total 1" in text
        assert 'darkwatch_channel_stale_hours' in text


class TestSanitize:
    def test_masks_non_corporate(self):
        out = mask_text("bob@other.com:S3cret! card 4111 1111 1111 1111")
        assert "S3cret!" not in out
        assert "XXXX-XXXX-XXXX-1111" in out
        assert "sha256:" in out

    def test_keeps_corporate_verbatim(self):
        line = "alice@acme.com:KeepMe123"
        assert mask_text(line, protect_domains=["acme.com"]) == line

    def test_sanitize_store_rewrites(self, store):
        msg = Message(content="zed@mall.com:Passw0rd!", channel="ch",
                      source_type=SourceType.DARKWEB)
        mid = store.add_message(msg)
        res = sanitize_store(store)
        assert res["masked"] == 1
        assert "Passw0rd!" not in store.get_message(mid).content


class TestSessionCheck:
    def _client(self, status: int) -> httpx.Client:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "api.github.com/user" in str(request.url)
            assert request.headers["Authorization"].startswith("token ")
            return httpx.Response(status)
        return httpx.Client(transport=httpx.MockTransport(handler))

    def test_live_token_escalates_p1(self):
        res = validate_token("ghp_" + "a" * 36, client=self._client(200))
        assert res.status == "live" and res.severity == 1

    def test_dead_token_downgrades(self):
        res = validate_token("ghp_" + "a" * 36, client=self._client(401))
        assert res.status == "dead" and res.severity == 5

    def test_unsupported_provider_no_ping(self):
        res = validate_token("AKIAIOSFODNN7EXAMPLE")
        assert res.status == "unsupported"
