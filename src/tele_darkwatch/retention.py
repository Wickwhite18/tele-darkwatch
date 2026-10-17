"""Data-retention helpers: prune old messages/alerts and vacuum the database."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from tele_darkwatch.storage.message_store import MessageStore


def prune(
    store: MessageStore,
    *,
    older_than_days: float = 30.0,
    before: Optional[datetime] = None,
    keep_alerts: bool = True,
) -> dict[str, int]:
    """Delete messages older than the cutoff; returns counts of rows removed.

    :param older_than_days: retention window in days.
    :param before: override the "now" reference (useful for tests).
    :param keep_alerts: when False, also delete alerts older than the cutoff.
    """
    ref = before or datetime.now(timezone.utc)
    cutoff = (ref - timedelta(days=older_than_days)).isoformat()

    with store._lock:
        cur = store._conn.execute("DELETE FROM messages WHERE timestamp < ?", (cutoff,))
        removed_messages = cur.rowcount
        removed_alerts = 0
        if not keep_alerts:
            cur = store._conn.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,))
            removed_alerts = cur.rowcount
        store._conn.commit()

    return {"messages": removed_messages, "alerts": removed_alerts}


def vacuum(store: MessageStore) -> None:
    """Reclaim space after large deletions."""
    with store._lock:
        store._conn.execute("VACUUM")
