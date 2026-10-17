"""SQLite-backed storage for collected messages, rules and alerts."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from tele_darkwatch.models import Alert, Message, SourceType
from tele_darkwatch.storage.entity_store import EntityStore
from tele_darkwatch.storage.event_log import EventLog

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT UNIQUE NOT NULL,
    content TEXT NOT NULL,
    channel TEXT NOT NULL,
    source_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    url TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    channel TEXT NOT NULL,
    message_content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    notified INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class MessageStore:
    """Thread-safe SQLite store with duplicate suppression."""

    def __init__(self, path: str | Path = "darkwatch.db") -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._migrate_raw()
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()
        self.events = EventLog(self._conn, self._lock)
        self.entities = EntityStore(self._conn, self._lock)

    def _migrate_raw(self) -> None:
        """Pre-schema fix: add columns that ``_SCHEMA`` references on old DBs."""
        cols = {
            r["name"]
            for r in self._conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        if cols and "metadata" not in cols:
            self._conn.execute(
                "ALTER TABLE alerts ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'"
            )

    def _migrate(self) -> None:
        """Bring an existing database up to the current schema (idempotent)."""
        pass

    # ------------------------------------------------------------------- meta
    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def meta_keys(self, prefix: str = "") -> list[str]:
        """All meta keys starting with *prefix* (for namespaced indexes)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key FROM meta WHERE key LIKE ?", (prefix + "%",)
            ).fetchall()
        return [r["key"] for r in rows]

    # ------------------------------------------------------------------ write
    def add_message(self, message: Message) -> Optional[int]:
        """Insert a message; returns its row id or ``None`` if it was a duplicate."""
        import json

        with self._lock:
            try:
                cur = self._conn.execute(
                    "INSERT INTO messages (dedup_key, content, channel, source_type,"
                    " timestamp, url, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        message.dedup_key,
                        message.content,
                        message.channel,
                        message.source_type.value,
                        message.timestamp.isoformat(),
                        message.url,
                        json.dumps(message.metadata),
                    ),
                )
                self._conn.commit()
                return cur.lastrowid
            except sqlite3.IntegrityError:
                return None

    def add_messages(self, messages: Iterable[Message]) -> int:
        """Bulk insert; returns the number of *new* rows stored."""
        return sum(1 for m in messages if self.add_message(m) is not None)

    # ------------------------------------------------------------------- read
    def get_message(self, message_id: int) -> Optional[Message]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
        return self._row_to_message(row) if row else None

    def recent(self, limit: int = 50, channel: Optional[str] = None) -> list[Message]:
        query = "SELECT * FROM messages"
        params: list = []
        if channel:
            query += " WHERE channel = ?"
            params.append(channel)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_message(r) for r in rows]

    def messages_since(self, last_id: int, limit: int = 500) -> list[Message]:
        """Messages with row id greater than ``last_id`` (pipeline watermark)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE id > ? ORDER BY id LIMIT ?",
                (last_id, limit),
            ).fetchall()
        return [self._row_to_message(r) for r in rows]

    def update_message_content(self, message_id: int, content: str) -> None:
        """Rewrite a stored message's content (used by sanitization)."""
        import hashlib

        new_key = hashlib.sha256(
            f"{self._channel_of(message_id)}|{content.strip().lower()}".encode()
        ).hexdigest()
        with self._lock:
            self._conn.execute(
                "UPDATE messages SET content = ?, dedup_key = ? WHERE id = ?",
                (content, new_key, message_id),
            )
            self._conn.commit()

    def _channel_of(self, message_id: int) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT channel FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
        return row["channel"] if row else ""

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    def channels(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT channel FROM messages ORDER BY channel"
            ).fetchall()
        return [r["channel"] for r in rows]

    # ----------------------------------------------------------------- alerts
    def save_alert(self, alert: Alert) -> int:
        import json

        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (rule, channel, message_content, created_at,"
                " notified, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    alert.rule,
                    alert.channel,
                    alert.message_content,
                    alert.created_at.isoformat(),
                    int(alert.notified),
                    json.dumps(alert.metadata),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def all_alerts(self, limit: int = 100) -> list[Alert]:
        """Every stored alert (notified or not), newest first."""
        import json

        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_alert(r) for r in rows]

    @staticmethod
    def _row_to_alert(r) -> Alert:
        import json

        try:
            meta = json.loads(r["metadata"]) if r["metadata"] else {}
        except (ValueError, TypeError):
            meta = {}
        return Alert(
            id=r["id"],
            rule=r["rule"],
            channel=r["channel"],
            message_content=r["message_content"],
            created_at=datetime.fromisoformat(r["created_at"]),
            notified=bool(r["notified"]),
            metadata=meta,
        )

    def pending_alerts(self, limit: int = 100) -> list[Alert]:
        import json

        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts WHERE notified = 0 ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            Alert(
                id=r["id"],
                rule=r["rule"],
                channel=r["channel"],
                message_content=r["message_content"],
                created_at=_parse_dt(r["created_at"]),
                notified=bool(r["notified"]),
                metadata=json.loads(r["metadata"]) if "metadata" in r.keys() else {},
            )
            for r in rows
        ]

    def alert_exists(self, rule: str, channel: str, needle: str) -> bool:
        """True if an alert for rule/channel already mentions *needle*."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM alerts WHERE rule = ? AND channel = ?"
                " AND message_content LIKE ? LIMIT 1",
                (rule, channel, f"%{needle}%"),
            ).fetchone()
        return row is not None

    def search_like(self, substring: str, limit: int = 50) -> list[Message]:
        """Case-insensitive substring scan over stored messages."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE content LIKE ?"
                " ORDER BY id DESC LIMIT ?",
                (f"%{substring}%", limit),
            ).fetchall()
        return [self._row_to_message(r) for r in rows]

    def mark_alert_notified(self, rule: str, channel: str,
                            alert_id: Optional[int] = None) -> None:
        """Mark an alert as notified.

        When ``alert_id`` is given only that row is updated; otherwise every
        pending alert for the ``(rule, channel)`` pair is marked (legacy
        behaviour used by callers without row ids).
        """
        with self._lock:
            if alert_id is not None:
                self._conn.execute(
                    "UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,)
                )
            else:
                self._conn.execute(
                    "UPDATE alerts SET notified = 1 WHERE rule = ? AND channel = ?",
                    (rule, channel),
                )
            self._conn.commit()

    # ------------------------------------------------------------------ misc
    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> Message:
        import json

        return Message(
            id=row["id"],
            content=row["content"],
            channel=row["channel"],
            source_type=SourceType(row["source_type"]),
            timestamp=_parse_dt(row["timestamp"]),
            url=row["url"],
            metadata=json.loads(row["metadata"]),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "MessageStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
