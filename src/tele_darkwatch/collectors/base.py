"""Base collector interface shared by Telegram and dark-web monitors."""
from __future__ import annotations

import abc
from typing import Iterable

from tele_darkwatch.models import Message
from tele_darkwatch.storage.message_store import MessageStore


class BaseCollector(abc.ABC):
    """A collector fetches raw items and persists normalized messages."""

    def __init__(self, store: MessageStore) -> None:
        self.store = store

    @abc.abstractmethod
    def collect(self) -> Iterable[Message]:
        """Return newly collected messages (implementation-dependent)."""

    def run_once(self) -> int:
        """Collect once and store new messages; returns count of new rows."""
        return self.store.add_messages(self.collect())
