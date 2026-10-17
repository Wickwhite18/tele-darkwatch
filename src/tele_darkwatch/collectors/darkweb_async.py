"""Async dark-web crawler: aiohttp over Tor with Playwright fallback.

Complements the synchronous :class:`DarkWebMonitor` for *scale*: hundreds of
.onion leak sites can be fetched concurrently through a single Tor SOCKS5
endpoint without blocking threads.

* Primary path: ``aiohttp`` + ``aiohttp-socks`` (optional deps — install with
  ``pip install "tele-darkwatch[darkweb]"``).
* JS-heavy or Cloudflare-gated sites: optional ``playwright`` fallback driven
  through the same proxy (browser automation mimics real TLS/JS fingerprints;
  see :mod:`tele_darkwatch.fingerprint`).
* Per-site failure isolation, randomized pacing between batches, and
  graceful degradation when Tor is unreachable.
"""
from __future__ import annotations

import asyncio
import random
import re
from datetime import datetime, timezone
from typing import Iterable, Optional

from tele_darkwatch.collectors.darkweb_monitor import html_to_text
from tele_darkwatch.models import Message, SourceType


def _channel_of(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/")[0]


def _to_message(url: str, html: str) -> Optional[Message]:
    text = html_to_text(html)
    if not text:
        return None
    return Message(
        content=text[:20000],
        channel=_channel_of(url),
        source_type=SourceType.DARKWEB,
        timestamp=datetime.now(timezone.utc),
        url=url,
        metadata={"collector": "aiohttp-tor"},
    )


async def _fetch_one_aiohttp(session, url: str) -> Optional[Message]:
    async with session.get(url, ssl=False, allow_redirects=True) as resp:
        if resp.status >= 400:
            return None
        return _to_message(url, await resp.text())


async def crawl_async(urls: Iterable[str], socks_proxy: str = "127.0.0.1:9050",
                      concurrency: int = 8, timeout: float = 30.0,
                      jitter: tuple[float, float] = (0.5, 2.0)) -> list[Message]:
    """Concurrently fetch onion URLs via aiohttp+Tor. Returns parsed messages."""
    try:
        import aiohttp
        from aiohttp_socks import ProxyConnector
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            'Async crawling needs aiohttp & aiohttp-socks: '
            'pip install "tele-darkwatch[darkweb]"') from exc

    urls = list(urls)
    connector = ProxyConnector.from_url(f"socks5h://{socks_proxy}")
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers={"User-Agent": "Mozilla/5.0 (Tor Browser)"},
    ) as session:

        async def worker(url: str):
            async with sem:
                await asyncio.sleep(random.uniform(*jitter))  # organic pacing
                try:
                    return await _fetch_one_aiohttp(session, url)
                except Exception:
                    return None

        results = await asyncio.gather(*(worker(u) for u in urls))
    return [m for m in results if m is not None]


async def render_with_playwright(urls: Iterable[str],
                                 proxy: str = "http://127.0.0.1:9150") -> list[Message]:
    """Headless-browser pass for JS-rendered / fingerprint-gated pages."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            'Playwright fallback needs: pip install "tele-darkwatch[playwright]" '
            "&& playwright install chromium") from exc
    messages: list[Message] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(proxy={"server": proxy})
        page = await (await browser.new_context()).new_page()
        for url in urls:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
                msg = _to_message(url, await page.content())
                if msg:
                    msg.metadata["collector"] = "playwright-tor"
                    messages.append(msg)
            except Exception:
                continue
        await browser.close()
    return messages


def crawl_blocking(urls, **kwargs) -> list[Message]:
    """Sync wrapper for CLI/daemon use."""
    return asyncio.run(crawl_async(urls, **kwargs))
