"""Full-text search over stored messages using SQLite FTS5 with LIKE fallback."""
from __future__ import annotations

import sqlite3
from typing import Optional

from tele_darkwatch.storage.message_store import MessageStore


class SearchEngine:
    """Query the message store by keyword, channel and source type."""

    def __init__(self, store: MessageStore) -> None:
        self.store = store
        self._fts_ready = False
        try:
            with store._lock:
                store._conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5("
                    "content, content='messages', content_rowid='id')"
                )
                store._conn.execute(
                    "CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages"
                    " BEGIN INSERT INTO messages_fts(rowid, content)"
                    " VALUES (new.id, new.content); END;"
                )
                store._conn.commit()
            self._fts_ready = True
        except sqlite3.OperationalError:
            self._fts_ready = False

    def search(
        self,
        query: str,
        channel: Optional[str] = None,
        limit: int = 50,
    ):
        """Return matching messages, newest first."""
        if self._fts_ready and len(query.split()) > 0:
            rows = self._fts_search(query, channel, limit)
            if rows is not None:
                return rows
        return self._like_search(query, channel, limit)

    # ------------------------------------------------------------------ impl
    def _fts_search(self, query: str, channel: Optional[str], limit: int):
        sql = (
            "SELECT m.* FROM messages m JOIN messages_fts f ON m.id = f.rowid"
            " WHERE messages_fts MATCH ?"
        )
        params: list = [query]
        if channel:
            sql += " AND m.channel = ?"
            params.append(channel)
        sql += " ORDER BY m.timestamp DESC LIMIT ?"
        params.append(limit)
        try:
            with self.store._lock:
                rows = self.store._conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return None  # bad FTS syntax -> fall back to LIKE
        return [MessageStore._row_to_message(r) for r in rows]

    def _like_search(self, query: str, channel: Optional[str], limit: int):
        sql = "SELECT * FROM messages WHERE content LIKE ?"
        params: list = [f"%{query}%"]
        if channel:
            sql += " AND channel = ?"
            params.append(channel)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self.store._lock:
            rows = self.store._conn.execute(sql, params).fetchall()
        return [MessageStore._row_to_message(r) for r in rows]
