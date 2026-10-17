"""Alert notifiers — console by default, webhook/email optional."""
from __future__ import annotations

import smtplib
import sys
from email.message import EmailMessage
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


class EmailNotifier:
    """Sends alerts via SMTP.

    ``use_tls`` selects STARTTLS (port 587); otherwise implicit TLS (port 465)
    is used. Credentials should come from environment/settings, never hardcoded.
    """

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients = list(recipients)
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def notify(self, alert: Alert) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[darkwatch] {alert.rule} on {alert.channel}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(alert.message_content)

        cls = smtplib.SMTP_SSL if not self.use_tls else smtplib.SMTP
        with cls(self.host, self.port, timeout=15) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.send_message(msg)


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
    rate_limiter=None,
) -> int:
    """Send every pending alert through the notifiers; returns count sent.

    When a :class:`~tele_darkwatch.alerts.rate_limiter.RateLimiter` is given,
    alerts whose ``rule|channel`` key is still in cooldown are left pending
    (not marked as notified) so they can be retried later.
    """
    notifiers = notifiers or [ConsoleNotifier()]
    pending = store.pending_alerts()
    sent = 0
    for alert in pending:
        if rate_limiter is not None:
            key = f"{alert.rule}|{alert.channel}"
            if not rate_limiter.allow(key):
                continue
        delivered = False
        for notifier in notifiers:
            try:
                notifier.notify(alert)
                delivered = True
            except Exception:
                continue
        if delivered:
            store.mark_alert_notified(alert.rule, alert.channel,
                                      alert_id=getattr(alert, "id", None))
            sent += 1
    return sent
