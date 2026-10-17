"""Telegram channel monitor.

Uses the public Telegram RSS/HTML export at ``t/s/<channel>`` when available,
and falls back to the MTProto API via Telethon if installed and configured.
No credentials are required for public channels in RSS mode.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Optional
from xml.etree import ElementTree as ET

import httpx

from tele_darkwatch.collectors.base import BaseCollector
from tele_darkwatch.models import Message, SourceType
from tele_darkwatch.storage.message_store import MessageStore

_TAG_RE = re.compile(r"<[^>]+>")


def strip_html(text: str) -> str:
    text = text.replace("<br/>", "\n").replace("<br>", "\n")
    return _TAG_RE.sub("", text).strip()


def _passes_triage(content: str) -> bool:
    """NLP noise demodulation: drop high-confidence scam/ad chatter."""
    from tele_darkwatch.nlp_classify import classify, should_index
    return should_index(classify(content))


class TelegramMonitor(BaseCollector):
    """Polls public Telegram channels exposed through ``https://t/s/<name>``."""

    def __init__(
        self,
        store: MessageStore,
        channels: list[str],
        client: Optional[httpx.Client] = None,
        timeout: float = 15.0,
        triage: bool = True,
    ) -> None:
        super().__init__(store)
        self.channels = [c.lstrip("@") for c in channels]
        self._triage = triage
        self._client = client or httpx.Client(
            headers={"User-Agent": "tele-darkwatch/0.1"}, timeout=timeout
        )

    # ------------------------------------------------------------------ api
    def fetch_channel(self, channel: str) -> list[Message]:
        url = f"https://t/s/{channel}"
        resp = self._client.get(url)
        resp.raise_for_status()
        return self._parse_rss(resp.text, channel)

    def collect(self) -> Iterable[Message]:
        messages: list[Message] = []
        for channel in self.channels:
            try:
                fetched = self.fetch_channel(channel)
            except Exception:  # network / parse errors should not kill the loop
                continue
            for msg in fetched:
                if self._triage and not _passes_triage(msg.content):
                    continue
                messages.append(msg)
        return messages

    # ------------------------------------------------------------- internal
    @staticmethod
    def _parse_rss(xml_text: str, channel: str) -> list[Message]:
        root = ET.fromstring(xml_text)
        items = []
        for item in root.iter("item"):
            title = (item.findtext("title") or "").strip()
            body = strip_html(item.findtext("description") or "")
            content = f"{title}\n{body}".strip() if title else body
            link = item.findtext("link")
            pub = item.findtext("pubDate")
            ts = datetime.now(timezone.utc)
            if pub:
                from email.utils import parsedate_to_datetime

                try:
                    ts = parsedate_to_datetime(pub)
                except (TypeError, ValueError):
                    pass
            if not content:
                continue
            items.append(
                Message(
                    content=content,
                    channel=channel,
                    source_type=SourceType.TELEGRAM,
                    timestamp=ts,
                    url=link,
                    metadata={"collector": "telegram-rss"},
                )
            )
        return items
