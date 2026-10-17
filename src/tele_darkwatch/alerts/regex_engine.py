"""Regex-based alert rules with named-capture extraction.

Extends the simple keyword engine with :class:`RegexRule` patterns that can
pull structured data (CVE IDs, onion addresses, emails, IPs…) out of matched
messages and attach it to the resulting alert.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Optional

from pydantic import BaseModel, Field

from tele_darkwatch.models import Alert, Message
from tele_darkwatch.storage.message_store import MessageStore


class RegexRule(BaseModel):
    """A compiled regular-expression rule with an optional severity."""

    name: str
    pattern: str
    severity: int = Field(default=2, ge=1, le=5)
    flags_ignorecase: bool = True

    def _compiled(self) -> re.Pattern:
        flags = re.IGNORECASE if self.flags_ignorecase else 0
        return re.compile(self.pattern, flags)

    def extract(self, text: str) -> Optional[dict]:
        """Return the named groups of the first match, or ``None``."""
        m = self._compiled().search(text)
        if not m:
            return None
        return dict(m.groupdict()) or {"match": m.group(0)}


class RegexAlertEngine:
    """Evaluate :class:`RegexRule`s over stored messages, persisting alerts."""

    def __init__(self, store: MessageStore, rules: Optional[Iterable[RegexRule]] = None):
        self.store = store
        self.rules: list[RegexRule] = list(rules or [])

    @classmethod
    def from_file(cls, store: MessageStore, path: str | Path) -> "RegexAlertEngine":
        data = json.loads(Path(path).read_text())
        rules = [RegexRule(**item) for item in data.get("rules", data)]
        return cls(store, rules)

    def add_rule(self, rule: RegexRule) -> None:
        self.rules.append(rule)

    def check_message(self, message: Message) -> list[Alert]:
        """Return (and persist) one alert per matching regex rule."""
        alerts: list[Alert] = []
        for rule in self.rules:
            extracted = rule.extract(message.content)
            if extracted is None:
                continue
            alert = Alert(
                rule=rule.name,
                channel=message.channel,
                message_content=message.content[:500],
                metadata={**extracted, "severity": rule.severity},
            )
            self.store.save_alert(alert)
            alerts.append(alert)
        return alerts

    def scan_recent(self, limit: int = 200) -> list[Alert]:
        found: list[Alert] = []
        for msg in self.store.recent(limit=limit):
            found.extend(self.check_message(msg))
        return found


# ------------------------------------------------------------------ built-ins
COMMON_PATTERNS: dict[str, str] = {
    "cve": r"(?P<cve>CVE-\d{4}-\d{4,7})",
    "onion_address": r"(?P<onion>[a-z2-7]{16,59}\.onion)",
    "ipv4": (
        r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    ),
    "email": r"(?P<email>[\w.+-]+@[\w-]+\.[\w.-]+)",
    "bitcoin_address": r"(?P<btc>\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{27,68}\b)",
}


def default_regex_rules() -> list[RegexRule]:
    """IOC-extraction rules suitable for most intel feeds."""
    severities = {"cve": 3, "onion_address": 2, "ipv4": 1, "email": 1, "bitcoin_address": 3}
    return [
        RegexRule(name=name, pattern=pattern, severity=severities.get(name, 2))
        for name, pattern in COMMON_PATTERNS.items()
    ]
