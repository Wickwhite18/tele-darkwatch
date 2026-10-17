"""Operational health monitoring & deadman switches.

Dark-web endpoints rotate or get seized daily; Telegram channels get banned or
quiet. This module turns "no news" into explicit signal:

* ``channel_heartbeat`` — last activity per source channel; silent channels
  past the threshold are reported (possible ban/wipe).
* ``endpoint_status`` — last collection result per dark-web URL; persistent
  failures (504/timeouts) are reported so operators can re-source onions.
* :func:`snapshot` — a Prometheus-style text exposition plus JSON summary,
  written to a file for scrapers/Grafana.

State lives in the SQLite ``meta`` table, so any process (CLI, daemon, cron)
can update and read it.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from tele_darkwatch.storage.message_store import MessageStore

_HEARTBEAT_KEY = "health_channel_last_seen"
_ENDPOINT_KEY = "health_endpoint_status"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class HealthMonitor:
    def __init__(self, store: MessageStore) -> None:
        self.store = store

    # ------------------------------------------------------------- heartbeat
    def _load(self, key: str) -> dict:
        raw = self.store.get_meta(key)
        return json.loads(raw) if raw else {}

    def beat(self, channel: str) -> None:
        """Record that *channel* produced data right now."""
        data = self._load(_HEARTBEAT_KEY)
        data[channel] = _utcnow().isoformat()
        self.store.set_meta(_HEARTBEAT_KEY, json.dumps(data))

    def stale_channels(self, max_silence_hours: float = 24.0) -> list[dict]:
        cutoff = _utcnow() - timedelta(hours=max_silence_hours)
        out = []
        for channel, ts in self._load(_HEARTBEAT_KEY).items():
            last = datetime.fromisoformat(ts)
            if last < cutoff:
                out.append({"channel": channel,
                            "last_seen": ts,
                            "silence_hours": round(
                                (_utcnow() - last).total_seconds() / 3600, 1)})
        return sorted(out, key=lambda d: d["silence_hours"], reverse=True)

    # -------------------------------------------------------------- endpoints
    def endpoint_ok(self, url: str, items: int = 0) -> None:
        self._update_endpoint(url, status="up", error=None, items=items)

    def endpoint_fail(self, url: str, error: str) -> None:
        state = self._update_endpoint(url, status=None, error=error)
        # keep previous consecutive-failure count via status field below
        return state

    def _update_endpoint(self, url: str, status: Optional[str],
                         error: Optional[str], items: int = 0) -> dict:
        data = self._load(_ENDPOINT_KEY)
        entry = data.get(url, {"failures": 0})
        if status == "up":
            entry.update(status="up", failures=0, last_ok=_utcnow().isoformat(),
                         last_error=None)
        else:
            entry["failures"] = entry.get("failures", 0) + 1
            entry["status"] = "down" if entry["failures"] >= 3 else "degraded"
            entry["last_error"] = error
        entry["last_items"] = items
        entry["last_check"] = _utcnow().isoformat()
        data[url] = entry
        self.store.set_meta(_ENDPOINT_KEY, json.dumps(data))
        return entry

    def failing_endpoints(self, threshold: int = 3) -> list[dict]:
        return [{"url": u, **e}
                for u, e in self._load(_ENDPOINT_KEY).items()
                if e.get("failures", 0) >= threshold]

    # ---------------------------------------------------------------- report
    def snapshot(self, max_silence_hours: float = 24.0,
                 failure_threshold: int = 3) -> dict:
        return {
            "generated_at": _utcnow().isoformat(),
            "messages": self.store.count(),
            "pending_alerts": len(self.store.pending_alerts()),
            "entities": self.store.entities.count(),
            "stale_channels": self.stale_channels(max_silence_hours),
            "failing_endpoints": self.failing_endpoints(failure_threshold),
            "endpoints": self._load(_ENDPOINT_KEY),
        }

    def prometheus_text(self, max_silence_hours: float = 24.0) -> str:
        snap = self.snapshot(max_silence_hours)
        lines = [
            "# HELP darkwatch_messages_total Stored messages.",
            "# TYPE darkwatch_messages_total gauge",
            f"darkwatch_messages_total {snap['messages']}",
            "# HELP darkwatch_pending_alerts Undispatched alerts.",
            "# TYPE darkwatch_pending_alerts gauge",
            f"darkwatch_pending_alerts {snap['pending_alerts']}",
            "# HELP darkwatch_entities_total Indexed entities.",
            "# TYPE darkwatch_entities_total gauge",
            f"darkwatch_entities_total {snap['entities']}",
            "# HELP darkwatch_channel_stale_hours Silence per channel.",
            "# TYPE darkwatch_channel_stale_hours gauge",
        ]
        for row in snap["stale_channels"]:
            safe = row["channel"].replace('"', "")
            lines.append(
                f'darkwatch_channel_stale_hours{{channel="{safe}"}} '
                f'{row["silence_hours"]}')
        lines += ["# HELP darkwatch_endpoint_failures Consecutive failures.",
                  "# TYPE darkwatch_endpoint_failures gauge"]
        for url, entry in snap["endpoints"].items():
            safe = url.replace('"', "")
            lines.append(
                f'darkwatch_endpoint_failures{{url="{safe}"}} '
                f'{entry.get("failures", 0)}')
        return "\n".join(lines) + "\n"

    def write_promfile(self, path: str, max_silence_hours: float = 24.0) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.prometheus_text(max_silence_hours))
