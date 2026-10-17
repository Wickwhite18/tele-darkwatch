"""Dark-web (onion) monitor.

Fetches .onion pages through a Tor SOCKS5 proxy (default ``127.0.0.1:9050``).
If Tor is not reachable the collector degrades gracefully and returns no
messages instead of crashing the pipeline. Scraped HTML is converted to plain
text before being stored.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Optional

import httpx

from tele_darkwatch.collectors.base import BaseCollector
from tele_darkwatch.models import Message, SourceType
from tele_darkwatch.storage.message_store import MessageStore

_WS_RE = re.compile(r"\s+")
_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)


def html_to_text(html: str) -> str:
    html = _TAG_RE.sub(" ", html)
    text = re.sub(r"<[^>]+>", " ", html)
    return _WS_RE.sub(" ", text).strip()


class DarkWebMonitor(BaseCollector):
    """Scrapes configured onion URLs over Tor."""

    def __init__(
        self,
        store: MessageStore,
        urls: list[str],
        socks_proxy: str = "socks5h://127.0.0.1:9050",
        client: Optional[httpx.Client] = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(store)
        self.urls = urls
        self.socks_proxy = socks_proxy
        self._client = client or httpx.Client(
            proxy=socks_proxy,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (tor-browser)"},
            verify=False,  # onion services commonly use self-signed certs
        )

    def fetch(self, url: str) -> Optional[Message]:
        resp = self._client.get(url, follow_redirects=True)
        resp.raise_for_status()
        text = html_to_text(resp.text)
        if not text:
            return None
        channel = re.sub(r"^https?://", "", url).split("/")[0]
        return Message(
            content=text[:20000],
            channel=channel,
            source_type=SourceType.DARKWEB,
            timestamp=datetime.now(timezone.utc),
            url=url,
            metadata={"collector": "tor-http"},
        )

    def collect(self) -> Iterable[Message]:
        messages: list[Message] = []
        for url in self.urls:
            try:
                msg = self.fetch(url)
                if msg:
                    messages.append(msg)
            except Exception:
                # Tor not running / site offline — skip this source.
                continue
        return messages
