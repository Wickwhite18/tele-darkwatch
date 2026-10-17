"""Entity index persisted alongside the message archive.

Stores every extracted indicator with a stable ``entity_hash`` so the same
credential re-shared across channels or breach packs is recognised instantly
(hash deduplication) instead of firing fresh alerts. Also supports *cross-
vector correlation*: look up which messages/channels an email appeared in.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Iterable, Optional

from tele_darkwatch.entities import Entity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    entity_hash TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_message_id INTEGER,
    channels TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
"""


class EntityStore:
    """Thread-safe SQLite index of extracted entities."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn = conn
        self._lock = lock
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ write
    def record(self, entity: Entity, message_id: Optional[int] = None,
               channel: str = "") -> bool:
        """Insert or update an entity; returns True when it was never seen."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT seen_count, channels FROM entities WHERE entity_hash = ?",
                (entity.entity_hash,),
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO entities (entity_hash, type, value, attributes,"
                    " first_seen, last_seen, seen_count, first_message_id, channels)"
                    " VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                    (entity.entity_hash, entity.type.value, entity.value,
                     json.dumps(entity.attributes), now, now, message_id,
                     json.dumps([channel] if channel else [])),
                )
                self._conn.commit()
                return True
            channels: list[str] = json.loads(row["channels"])
            if channel and channel not in channels:
                channels.append(channel)
            self._conn.execute(
                "UPDATE entities SET last_seen = ?, seen_count = seen_count + 1,"
                " channels = ?, attributes = ? WHERE entity_hash = ?",
                (now, json.dumps(channels), json.dumps(entity.attributes),
                 entity.entity_hash),
            )
            self._conn.commit()
            return False

    def record_many(self, entities: Iterable[Entity], message_id: Optional[int] = None,
                    channel: str = "") -> int:
        """Bulk-record; returns the number of *new* entities."""
        return sum(1 for e in entities if self.record(e, message_id, channel))

    # ------------------------------------------------------------------- read
    def find_by_value(self, value: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM entities WHERE value = ? COLLATE NOCASE",
                (value,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def search(self, substring: str, etype: Optional[str] = None,
               limit: int = 50) -> list[dict]:
        query = "SELECT * FROM entities WHERE value LIKE ?"
        params: list = [f"%{substring}%"]
        if etype:
            query += " AND type = ?"
            params.append(etype)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def top(self, etype: Optional[str] = None, limit: int = 20) -> list[dict]:
        query = "SELECT * FROM entities"
        params: list = []
        if etype:
            query += " WHERE type = ?"
            params.append(etype)
        query += " ORDER BY seen_count DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def counts_by_type(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT type, COUNT(*) AS n FROM entities GROUP BY type"
            ).fetchall()
        return {r["type"]: r["n"] for r in rows}

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["attributes"] = json.loads(d.get("attributes") or "{}")
        d["channels"] = json.loads(d.get("channels") or "[]")
        return d
