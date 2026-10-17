"""Keyword alerting: scan stored messages against rules and emit alerts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from tele_darkwatch.models import Alert, MatchRule, Message
from tele_darkwatch.storage.message_store import MessageStore


class AlertEngine:
    """Evaluates match rules against new messages and persists alerts."""

    def __init__(self, store: MessageStore, rules: Optional[Iterable[MatchRule]] = None):
        self.store = store
        self.rules: list[MatchRule] = list(rules or [])

    # --------------------------------------------------------------- loading
    @classmethod
    def from_file(cls, store: MessageStore, path: str | Path) -> "AlertEngine":
        data = json.loads(Path(path).read_text())
        rules = [MatchRule(**item) for item in data.get("rules", data)]
        return cls(store, rules)

    def add_rule(self, rule: MatchRule) -> None:
        self.rules.append(rule)

    # ---------------------------------------------------------------- checks
    def check_message(self, message: Message) -> list[Alert]:
        """Return (and persist) alerts for every rule matching this message."""
        alerts = []
        for rule in self.rules:
            name = rule.name or rule.pattern
            if rule.matches(message.content):
                alert = Alert(
                    rule=name,
                    channel=message.channel,
                    message_content=message.content[:500],
                )
                self.store.save_alert(alert)
                alerts.append(alert)
        return alerts

    def scan_recent(self, limit: int = 200) -> list[Alert]:
        """Run all rules over the most recent stored messages."""
        found: list[Alert] = []
        for msg in self.store.recent(limit=limit):
            found.extend(self.check_message(msg))
        return found
