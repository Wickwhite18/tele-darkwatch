"""Input validation helpers for CLI arguments.

Every validator raises :class:`ValidationError` with a human-friendly message
so the CLI can print a red ✖ line and exit(2) instead of dumping a traceback.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")  # Telegram-style
URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)


class ValidationError(ValueError):
    """Raised when user input fails validation."""


def require_nonempty(value: str | None, name: str, *, max_len: int = 100_000) -> str:
    if value is None or not str(value).strip():
        raise ValidationError(f"{name} must be a non-empty string")
    v = str(value).strip()
    if len(v) > max_len:
        raise ValidationError(f"{name} too long ({len(v)} chars, max {max_len})")
    return v


def valid_channel(name: str) -> str:
    name = require_nonempty(name, "channel", max_len=64)
    if not CHANNEL_RE.match(name):
        raise ValidationError(
            f"invalid channel name {name!r}: use letters/digits/_/-, 3-64 chars"
        )
    return name


def valid_channels(names: list[str]) -> list[str]:
    seen: list[str] = []
    for n in names or []:
        c = valid_channel(n)
        if c not in seen:
            seen.append(c)
    return seen


def valid_url(url: str) -> str:
    url = require_nonempty(url, "url", max_len=2048)
    if not URL_RE.match(url):
        raise ValidationError(f"invalid url {url!r}: must start with http:// or https://")
    return url


def valid_urls(urls: list[str]) -> list[str]:
    return [valid_url(u) for u in (urls or [])]


def valid_int(value: int, name: str, *, minimum: int, maximum: int) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be an integer, got {value!r}") from None
    if not minimum <= ivalue <= maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}, got {ivalue}")
    return ivalue


def valid_float(value: float, name: str, *, minimum: float, maximum: float) -> float:
    try:
        fvalue = float(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be a number, got {value!r}") from None
    if not minimum <= fvalue <= maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}, got {fvalue}")
    return fvalue


def valid_path(path: str, name: str, *, must_exist: bool = False,
                is_dir: bool = False) -> Path:
    p = Path(require_nonempty(path, name, max_len=1024)).expanduser()
    if must_exist and not p.exists():
        raise ValidationError(f"{name} path does not exist: {p}")
    if is_dir and p.exists() and not p.is_dir():
        raise ValidationError(f"{name} expected a directory, got file: {p}")
    return p


def valid_json(text: str, name: str = "json") -> dict | list:
    import json as _json

    try:
        obj = _json.loads(text)
    except _json.JSONDecodeError as exc:
        raise ValidationError(f"{name} is not valid JSON: {exc}") from None
    if not isinstance(obj, (dict, list)):
        raise ValidationError(f"{name} must be a JSON object or array")
    return obj


def valid_log_level(level: str) -> str:
    level = require_nonempty(level, "log-level", max_len=10).upper()
    allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if level not in allowed:
        raise ValidationError(f"log-level must be one of {sorted(allowed)}, got {level!r}")
    return level


def valid_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps like ``2026-01-31`` or ``2026-01-31T09:30``."""
    value = require_nonempty(value, "timestamp", max_len=40)
    dt: datetime | None = None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S",
               "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            break
        except ValueError:
            continue
    if dt is None:
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            raise ValidationError(
                f"invalid timestamp {value!r}; expected ISO-8601 e.g. 2026-01-31T09:30"
            ) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if dt > now:
        raise ValidationError("timestamp cannot be in the future")
    return dt
