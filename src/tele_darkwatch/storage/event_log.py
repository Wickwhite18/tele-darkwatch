"""Lightweight audit / event log persisted alongside the message archive.

Every notable pipeline action (collection cycles, alerts raised, notifications
dispatched, prunes) is recorded here so operators can reconstruct what the
system did over time — useful both for debugging and for compliance review.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    category TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
"""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventLog:
    """Thread-safe append-only event log backed by the same SQLite database."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn = conn
        self._lock = lock
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ write
    def record(self, category: str, **detail) -> int:
        """Append an event; returns its row id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, category, detail) VALUES (?, ?, ?)",
                (_utcnow().isoformat(), category, json.dumps(detail, default=str)),
            )
            self._conn.commit()
            return cur.lastrowid

    # ------------------------------------------------------------------- read
    def recent(self, limit: int = 100, category: Optional[str] = None) -> list[dict]:
        query = "SELECT * FROM events"
        params: list = []
        if category:
            query += " WHERE category = ?"
            params.append(category)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "id": r["id"],
                "ts": r["ts"],
                "category": r["category"],
                "detail": json.loads(r["detail"]),
            }
            for r in rows
        ]

    def count(self, since: Optional[timedelta] = None) -> int:
        if since is None:
            sql = "SELECT COUNT(*) FROM events"
            params: tuple = ()
        else:
            cutoff = (_utcnow() - since).isoformat()
            sql = "SELECT COUNT(*) FROM events WHERE ts >= ?"
            params = (cutoff,)
        with self._lock:
            return self._conn.execute(sql, params).fetchone()[0]

    def purge_before(self, days: float) -> int:
        """Delete events older than ``days``; returns rows removed."""
        cutoff = (_utcnow() - timedelta(days=days)).isoformat()
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self._conn.commit()
            return cur.rowcount
