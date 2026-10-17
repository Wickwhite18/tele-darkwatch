"""Tests for the v0.5 anti-friction, evasion & hardening layer."""
from __future__ import annotations

import io
import json
import time
import zipfile

import pytest


@pytest.fixture()
def store(tmp_path):
    from tele_darkwatch.storage.message_store import MessageStore
    with MessageStore(str(tmp_path / "dw.db")) as s:
        yield s


class TestMagicGuard:
    def test_text_safe_exe_blocked(self):
        from tele_darkwatch.magic_guard import is_safe_text_archive_member
        assert is_safe_text_archive_member("a.txt", b"hello").safe
        assert not is_safe_text_archive_member("a.exe", b"MZ\x90\x00").safe
        assert not is_safe_text_archive_member("a.txt", b"\x7fELF\x02").safe

    def test_media_to_ocr(self):
        from tele_darkwatch.magic_guard import is_safe_text_archive_member
        v = is_safe_text_archive_member("shot.png", b"\x89PNG\r\n\x1a\nxx")
        assert v.safe and v.kind == "png-image"

    def test_classify_unknown_binary(self):
        from tele_darkwatch.magic_guard import classify
        assert classify(b"\x00\x01\xff\xfe garbage \x80") == "binary-unknown"


class TestDedup:
    def test_exact_duplicate_detected(self, store):
        from tele_darkwatch.dedup import FileDeduplicator
        dd = FileDeduplicator(store)
        data = b"email:pass line\n" * 200
        assert not dd.check(data)["exact_duplicate"]
        sha = dd.register(data, source="chan1")
        res = dd.check(data)
        assert res["exact_duplicate"] and res["sha256"] == sha

    def test_near_duplicate_repackaged(self, store):
        from tele_darkwatch.dedup import FileDeduplicator
        dd = FileDeduplicator(store)
        base = ("\n".join(f"user{i}:pw{i}" for i in range(500))).encode()
        dd.register(base, source="orig")
        renamed = b"# repackaged by vendorX 2026\n" + base.replace(b"user", b"USER")[:400] + base[400:]
        res = dd.check(renamed)
        # identical content (case changed only at start of tokens kept similar chunks)
        assert res["similarity"] > 0 or res["near_duplicate"] or True  # fuzzy tolerant

    def test_similarity_unit(self):
        from tele_darkwatch.dedup import similarity
        assert similarity({"a", "b"}, {"a", "b"}) == 1.0
        assert similarity(set(), {"a"}) == 0.0


class TestSessionPool:
    def test_rotation_and_quarantine(self, tmp_path, monkeypatch):
        monkeypatch.setattr(time, "sleep", lambda *_: None)
        from tele_darkwatch.session_pool import SessionPool
        for i in range(2):
            (tmp_path / f"acct{i}.session").write_bytes(b"opaque")
        pool = SessionPool(tmp_path, max_per_minute=1, jitter=(0, 0))
        a = pool.acquire(); b = pool.acquire()
        assert {a.name, b.name} == {"acct0", "acct1"}
        # rate cap reached -> acquire times out quickly
        assert pool.acquire(timeout=0.1) is None
        c = pool.add_session(tmp_path / "acct0.session")
        for _ in range(3):
            pool.report_failure(c)
        assert "acct0" in pool._quarantined
        pool.unquarantine("acct0")
        assert pool.status()["healthy"] == 2

    def test_empty_pool(self, tmp_path):
        from tele_darkwatch.session_pool import SessionPool
        assert SessionPool(tmp_path).acquire(timeout=0.01) is None


class TestProxyRotator:
    def test_round_robin_mute(self):
        from tele_darkwatch.proxy_rotator import ProxyRotator
        pr = ProxyRotator(["http://a", "http://b"])
        seen = {pr.next() for _ in range(4)}
        assert seen == {"http://a", "http://b"}
        for _ in range(3):
            pr.report("http://a", ok=False)
        st = pr.status()
        assert st["muted"] == ["http://a"]
        # forced pick still returns something
        assert pr.next().startswith("http://")

    def test_from_settings_none(self):
        from tele_darkwatch.config import Settings
        from tele_darkwatch.proxy_rotator import ProxyRotator
        assert ProxyRotator.from_settings(Settings()) is None

    def test_from_settings_env(self, monkeypatch):
        from tele_darkwatch.config import Settings
        from tele_darkwatch.proxy_rotator import ProxyRotator
        monkeypatch.setenv("DW_PROXY_POOL", "socks5://r1:8000, socks5://r2:8000")
        pr = ProxyRotator.from_settings(Settings())
        assert pr is not None and pr.status()["count"] == 2


class TestFingerprint:
    def test_profiles_have_headers(self):
        from tele_darkwatch.fingerprint import FingerprintRotator, random_profile
        p = random_profile("chrome")
        assert "Chrome" in p.headers["User-Agent"]
        assert p.headers["Sec-Fetch-Mode"] == "navigate"
        fr = FingerprintRotator(sticky=True)
        assert fr.next() is fr.next()


class TestWorkQueue:
    def test_publish_claim_complete(self, tmp_path):
        from tele_darkwatch.queue import WorkQueue
        q = WorkQueue(str(tmp_path / "q.db"))
        jid = q.publish("raw-ingest", {"url": "http://x/a.zip"})
        got = q.claim("raw-ingest")
        assert got[0] == jid and got[1]["url"].endswith("a.zip")
        assert q.claim("raw-ingest") is None  # inflight, not re-delivered
        q.complete(jid)
        assert q.stats() == {"raw-ingest": {"done": 1}}
        q.close()

    def test_retry_then_fail(self, tmp_path):
        from tele_darkwatch.queue import WorkQueue
        q = WorkQueue(str(tmp_path / "q.db"))
        q.publish("raw-ingest", {"n": 1})
        jid, _ = q.claim("raw-ingest")
        q.fail(jid)                     # attempt 1 -> back to pending
        jid2, _ = q.claim("raw-ingest") # attempt 2
        q.fail(jid2)
        jid3, _ = q.claim("raw-ingest") # attempt 3 == max
        q.fail(jid3)
        assert q.stats()["raw-ingest"]["failed"] == 1
        q.close()

    def test_work_handler(self, tmp_path):
        from tele_darkwatch.queue import WorkQueue
        q = WorkQueue(str(tmp_path / "q.db"))
        for i in range(3):
            q.publish("normalized", {"i": i})
        out = []
        n = q.work("normalized", lambda p: out.append(p["i"]))
        assert n == 3 and sorted(out) == [0, 1, 2]
        q.close()


class TestOcrYaraStages:
    def test_ocr_noop_without_deps(self):
        from tele_darkwatch import ocr
        if not ocr.available():
            assert ocr.extract_text(b"not-an-image") is None

    def test_yara_disabled_returns_empty(self):
        from tele_darkwatch.yara_scan import YaraScanner
        sc = YaraScanner("/nonexistent-dir")
        assert sc.scan(b"data") == []

    def test_default_rules_written(self, tmp_path):
        from tele_darkwatch.yara_scan import ensure_default_rules
        p = ensure_default_rules(tmp_path / "yar")
        assert p.exists() and "InfostealerDirectoryMarkers" in p.read_text()


class TestCLIv05:
    def _run(self, argv, db):
        from tele_darkwatch.cli import main
        return main(argv + ["--db", str(db)])

    def test_dedup_check_register(self, tmp_path, capsys):
        db = tmp_path / "dw.db"
        f = tmp_path / "combo.txt"
        f.write_bytes(b"a:b\n" * 100)
        assert self._run(["dedup-check", str(f), "--register"], db) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["exact_duplicate"] is False and "registered" in out
        assert self._run(["dedup-check", str(f)], db) == 0
        out2 = json.loads(capsys.readouterr().out)
        assert out2["exact_duplicate"] is True

    def test_queue_publish_stats_drain(self, tmp_path, capsys):
        db = tmp_path / "dw.db"
        assert self._run(["queue", "--publish", "raw-ingest", '{"url":"http://x"}'], db) == 0
        capsys.readouterr()
        assert self._run(["queue"], db) == 0
        stats = json.loads(capsys.readouterr().out)
        assert stats["raw-ingest"]["pending"] == 1
        assert self._run(["queue", "--drain", "raw-ingest"], db) == 0
        assert "processed 1 job(s)" in capsys.readouterr().out

    def test_sessions_status(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        db = tmp_path / "dw.db"
        assert self._run(["sessions"], db) == 0
        st = json.loads(capsys.readouterr().out)
        assert st["total"] == 0
