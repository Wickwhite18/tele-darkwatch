"""Optional Telethon-based Telegram userbot collector.

Standard bots cannot read private/restricted channels, so serious monitoring
uses a *userbot* (a real account session) over the MTProto API with Telethon.
Telethon is an **optional dependency** — install with::

    pip install "tele-darkwatch[telegram]"

and configure ``api_id``/``api_hash`` from https://my.telegram.org plus a
pool of ``.session`` files (see :mod:`tele_darkwatch.session_pool`).

Design notes
------------
* The whole module imports lazily; without Telethon installed every function
  raises a clear RuntimeError instead of an ImportError at package import.
* ``run_userbot`` owns a single asyncio loop and fans out across channels
  concurrently — no blocking calls in the event loop.
* Anti-friction: randomized delays between history pulls and per-account
  rate caps delegated to the session pool keep Telegram's spam heuristics
  from flagging the accounts (join/read pacing).
"""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone
from typing import Iterable, Optional

from tele_darkwatch.models import Message, SourceType

TELETHON_INSTALL_HINT = (
    "Telethon is required for the userbot collector. "
    'Install with: pip install "tele-darkwatch[telegram]"'
)


def telethon_available() -> bool:
    try:
        import telethon  # noqa: F401
        return True
    except ImportError:
        return False


def _require_telethon():
    if not telethon_available():
        raise RuntimeError(TELETHON_INSTALL_HINT)
    from telethon import TelegramClient
    return TelegramClient


def message_to_model(raw, channel: str) -> Message:
    """Convert a Telethon Message into our storage model."""
    text = getattr(raw, "raw_text", None) or getattr(raw, "text", "") or ""
    date = getattr(raw, "date", None) or datetime.now(timezone.utc)
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    media_kind = None
    if getattr(raw, "photo", None):
        media_kind = "photo"
    elif getattr(raw, "document", None):
        media_kind = "document"
    return Message(
        content=(text or f"[{media_kind}]" if media_kind else text)[:20000],
        channel=channel,
        source_type=SourceType.TELEGRAM,
        timestamp=date,
        metadata={
            "collector": "telethon",
            "message_id": getattr(raw, "id", None),
            "media": media_kind,
        },
    )


async def fetch_history(client, channel: str, limit: int = 50) -> list[Message]:
    """Pull recent history for one channel through a connected client."""
    messages: list[Message] = []
    async for raw in client.iter_messages(channel, limit=limit):
        messages.append(message_to_model(raw, channel))
    return messages


async def run_userbot(
    api_id: int,
    api_hash: str,
    sessions: Iterable[str],
    channels: Iterable[str],
    *,
    proxy=None,
    limit_per_channel: int = 50,
    delay_range: tuple[float, float] = (2.0, 8.0),
    download_media_dir: Optional[str] = None,
) -> list[Message]:
    """Cycle a pool of sessions across channels with organic pacing.

    Returns all fetched messages. Each session gets its own client; channels
    are partitioned round-robin over the pool so no single account reads more
    than its share, and a randomized sleep between pulls mimics human speed.
    """
    TelegramClient = _require_telethon()
    sessions = list(sessions)
    channels = list(channels)
    if not sessions or not channels:
        raise ValueError("sessions and channels must both be non-empty")

    results: list[Message] = []
    clients = [TelegramClient(s, api_id, api_hash, proxy=proxy) for s in sessions]
    try:
        for client in clients:
            await client.connect()
        # Round-robin: channel i handled by client i % len(clients)
        tasks = []
        for idx, channel in enumerate(channels):
            client = clients[idx % len(clients)]
            tasks.append(_paced_fetch(client, channel, limit_per_channel,
                                      delay_range, download_media_dir))
        for chunk in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(chunk, list):
                results.extend(chunk)
    finally:
        for client in clients:
            try:
                await client.disconnect()
            except Exception:
                pass
    return results


async def _paced_fetch(client, channel, limit, delay_range, media_dir):
    await asyncio.sleep(random.uniform(*delay_range))
    messages: list[Message] = []
    async for raw in client.iter_messages(channel, limit=limit):
        msg = message_to_model(raw, channel)
        if media_dir and getattr(raw, "media", None):
            try:  # keep artefacts on tmpfs-backed paths only (see Dockerfile)
                await client.download_media(raw, file=media_dir)
                msg.metadata["downloaded"] = True
            except Exception:
                pass
        messages.append(msg)
    return messages


def collect_blocking(**kwargs) -> list[Message]:
    """Synchronous wrapper used by the CLI/daemon (owns the event loop)."""
    return asyncio.run(run_userbot(**kwargs))
