"""Core data models shared across collectors, storage, search and alerts."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SourceType(str, Enum):
    """Where a message was collected from."""

    TELEGRAM = "telegram"
    DARKWEB = "darkweb"
    MANUAL = "manual"


class Message(BaseModel):
    """A single normalized intelligence item collected by any source."""

    content: str
    channel: str
    source_type: SourceType
    timestamp: datetime = Field(default_factory=_utcnow)
    url: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    id: Optional[int] = None

    @property
    def dedup_key(self) -> str:
        """Stable hash used to detect duplicate messages across imports."""
        raw = f"{self.channel}|{self.content.strip().lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class MatchRule(BaseModel):
    """A keyword pattern that triggers an alert when seen in a message."""

    pattern: str
    name: str = ""
    case_sensitive: bool = False

    def matches(self, text: str) -> bool:
        haystack = text if self.case_sensitive else text.lower()
        needle = self.pattern if self.case_sensitive else self.pattern.lower()
        return needle in haystack


class Alert(BaseModel):
    """A notification emitted when a rule matches a stored message."""

    rule: str
    channel: str
    message_content: str
    created_at: datetime = Field(default_factory=_utcnow)
    notified: bool = False
