"""Continuous monitoring daemon.

Runs collection → alert-scan → notification cycles forever (until stopped
with Ctrl-C / SIGTERM), optionally pruning old data according to the
retention policy. Designed to be the entrypoint of a systemd service or
Docker container::

    darkwatch daemon
"""
from __future__ import annotations

import signal
import threading
from pathlib import Path
from typing import Optional

from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import WebhookNotifier, dispatch_pending
from tele_darkwatch.alerts.rate_limiter import RateLimiter
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.logging_setup import get_logger
from tele_darkwatch.retention import prune
from tele_darkwatch.storage.message_store import MessageStore

log = get_logger(__name__)


class Daemon:
    """Long-running poll loop tying collectors, alerts and notifiers together."""

    def __init__(
        self,
        settings: Settings,
        store: Optional[MessageStore] = None,
        engine: Optional[AlertEngine] = None,
    ) -> None:
        self.settings = settings
        self._owns_store = store is None
        self.store = store or MessageStore(settings.db_path)
        if engine is not None:
            self.engine = engine
        elif Path(settings.rules_path).exists():
            self.engine = AlertEngine.from_file(self.store, settings.rules_path)
        else:
            self.engine = AlertEngine(self.store)
        self.notifiers = []
        if settings.webhook_url:
            self.notifiers.append(WebhookNotifier(settings.webhook_url))
        self.rate_limiter = RateLimiter(cooldown=float(settings.alert_cooldown))
        self._stop = threading.Event()

    # ------------------------------------------------------------------ cycle
    def run_cycle(self) -> dict:
        """One collect → scan → notify pass; returns per-stage counters."""
        stats = {"telegram": 0, "darkweb": 0, "alerts": 0, "notified": 0, "pruned": 0}

        if self.settings.channels:
            monitor = TelegramMonitor(self.store, self.settings.channels)
            try:
                stats["telegram"] = monitor.run_once()
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("Telegram collection failed: %s", exc)

        if self.settings.urls:
            monitor = DarkWebMonitor(
                self.store, self.settings.urls, socks_proxy=self.settings.tor_proxy
            )
            try:
                stats["darkweb"] = monitor.run_once()
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("Dark-web collection failed: %s", exc)

        new_msgs = stats["telegram"] + stats["darkweb"]
        # Always scan recent messages; repeat notifications are suppressed by
        # the rate limiter inside dispatch_pending().
        stats["alerts"] = len(self.engine.scan_recent(limit=max(new_msgs, 50)))

        stats["notified"] = dispatch_pending(
            self.store, self.notifiers or None, self.rate_limiter
        )

        if self.settings.retention_days > 0:
            removed = prune(self.store, older_than_days=self.settings.retention_days)
            stats["pruned"] = removed["messages"]

        self.store.events.record("cycle", **stats)
        log.info("cycle complete: %s", stats)
        return stats

    # ------------------------------------------------------------------- loop
    def run_forever(self) -> None:
        interval = max(5, int(self.settings.poll_interval))
        log.info(
            "daemon started (interval=%ss, channels=%s, urls=%s)",
            interval,
            self.settings.channels,
            self.settings.urls,
        )
        self._install_signal_handlers()
        while not self._stop.is_set():
            try:
                self.run_cycle()
            except Exception as exc:  # keep the loop alive on unexpected errors
                log.error("cycle error: %s", exc)
            self._stop.wait(interval)
        self.shutdown()

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        if self._owns_store:
            self.store.close()

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_: self.stop())
            except ValueError:
                # Not on the main thread (e.g. under tests); caller stops us.
                pass
