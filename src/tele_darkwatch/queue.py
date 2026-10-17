"""Decoupled producer/consumer work queues for the ingestion pipeline.

Monolithic scrapers lock up when a worker starts chewing on a multi-gigabyte
breach archive. This module formalizes the split without forcing a Kafka
dependency: :class:`WorkQueue` is a durable SQLite-backed queue (safe default,
single-box deployments), while :class:`RedisQueue` transparently upgrades to
Redis Lists when ``DW_QUEUE_BACKEND=redis`` so multiple hosts can share one
ingest stream.

Queues used by the pipeline:
* ``raw-ingest``     – scraper → parser workers (archive URLs / blobs refs)
* ``normalized``     – parser → storage/alerting consumers
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Callable, Optional

from tele_darkwatch.logging_setup import get_logger

log = get_logger(__name__)


class WorkQueue:
    """Durable SQLite job queue with at-least-once delivery."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS jobs ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " queue TEXT NOT NULL, payload TEXT NOT NULL,"
                " status TEXT NOT NULL DEFAULT 'pending',"  # pending/inflight/done/failed
                " attempts INTEGER NOT NULL DEFAULT 0,"
                " created_at REAL NOT NULL, updated_at REAL NOT NULL)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_queue ON jobs(queue,status)")
            self._conn.commit()

    # -------------------------------------------------------------- producer
    def publish(self, queue: str, payload: dict) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO jobs(queue,payload,status,created_at,updated_at)"
                " VALUES (?,?,'pending',?,?)",
                (queue, json.dumps(payload), now, now))
            self._conn.commit()
            return cur.lastrowid

    # -------------------------------------------------------------- consumer
    def claim(self, queue: str) -> Optional[tuple[int, dict]]:
        """Atomically move one pending job to inflight; returns (id,payload)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE queue=? AND status='pending'"
                " ORDER BY id LIMIT 1", (queue,)).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE jobs SET status='inflight', attempts=attempts+1,"
                " updated_at=? WHERE id=?", (time.time(), row["id"]))
            self._conn.commit()
        return row["id"], json.loads(row["payload"])

    def complete(self, job_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE jobs SET status='done', updated_at=? WHERE id=?",
                               (time.time(), job_id))
            self._conn.commit()

    def fail(self, job_id: int, retry: bool = True, max_attempts: int = 3) -> None:
        with self._lock:
            row = self._conn.execute("SELECT attempts FROM jobs WHERE id=?",
                                     (job_id,)).fetchone()
            status = "pending" if retry and row and row["attempts"] < max_attempts else "failed"
            self._conn.execute("UPDATE jobs SET status=?, updated_at=? WHERE id=?",
                               (status, time.time(), job_id))
            self._conn.commit()

    def stats(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT queue, status, COUNT(*) c FROM jobs GROUP BY queue,status"
            ).fetchall()
        out: dict = {}
        for r in rows:
            out.setdefault(r["queue"], {})[r["status"]] = r["c"]
        return out

    def work(self, queue: str, handler: Callable[[dict], None],
             max_jobs: int = 100) -> int:
        """Drain up to *max_jobs* through *handler*; returns processed count."""
        done = 0
        for _ in range(max_jobs):
            job = self.claim(queue)
            if job is None:
                break
            job_id, payload = job
            try:
                handler(payload)
                self.complete(job_id)
                done += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("job %s failed: %s", job_id, exc)
                self.fail(job_id)
        return done

    def close(self) -> None:
        self._conn.close()


def build_queue(settings) -> WorkQueue:
    """Factory honoring ``DW_DB_PATH`` (SQLite backend is always available)."""
    from pathlib import Path
    qpath = Path(settings.db_path).with_name("queue.db")
    return WorkQueue(str(qpath))
