"""Alert notifiers — console by default, webhook optional."""
from __future__ import annotations

import sys
from typing import Optional

import httpx

from tele_darkwatch.alerts.engine import AlertEngine  # noqa: F401 (type hints)
from tele_darkwatch.models import Alert
from tele_darkwatch.storage.message_store import MessageStore


class ConsoleNotifier:
    def notify(self, alert: Alert) -> None:
        print(
            f"[ALERT] rule={alert.rule!r} channel={alert.channel} "
            f"content={alert.message_content[:120]!r}",
            file=sys.stderr,
        )


class WebhookNotifier:
    """POSTs the alert as JSON to a Slack-compatible webhook URL."""

    def __init__(self, url: str, client: Optional[httpx.Client] = None) -> None:
        self.url = url
        self._client = client or httpx.Client(timeout=10.0)

    def notify(self, alert: Alert) -> None:
        payload = {
            "text": (
                f":rotating_light: *{alert.rule}* on `{alert.channel}`:\n"
                f"{alert.message_content[:400]}"
            )
        }
        self._client.post(self.url, json=payload)


def dispatch_pending(
    store: MessageStore,
    notifiers: Optional[list] = None,
) -> int:
    """Send every pending alert through the notifiers; returns count sent."""
    notifiers = notifiers or [ConsoleNotifier()]
    pending = store.pending_alerts()
    sent = 0
    for alert in pending:
        for notifier in notifiers:
            try:
                notifier.notify(alert)
            except Exception:
                continue
        store.mark_alert_notified(alert.rule, alert.channel)
        sent += 1
    return sent
