"""Browser-cookie parsing & session-longevity triage.

Infostealer drops contain Chromium/Firefox cookie dumps as Netscape text or
JSON arrays. This module normalizes both formats, flags high-value enterprise
domains, and escalates **unexpired** sessions (session-replay risk) so the
alert pipeline can trigger P1 incident response while the token is still live.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Iterable, Optional

from pydantic import BaseModel, Field

#: Domains whose live sessions justify immediate incident response.
HIGH_VALUE_DOMAINS = {
    "microsoftonline.com", "office.com", "office365.com", "outlook.com",
    "okta.com", "salesforce.com", "google.com", "github.com", "gitlab.com",
    "amazon.com", "aws.amazon.com", "console.aws.amazon.com", "slack.com",
    "zoom.us", "dropbox.com", "sharepoint.com", "linkedin.com", "stripe.com",
}

_NETSCAPE_LINE = re.compile(
    r"^(?P<domain>\S+)\s+(?P<flag>T|TRUE|F|FALSE)\s+(?P<path>\S+)\s+"
    r"(?P<secure>\S+)\s+(?P<expiry>\d+)\s+(?P<name>\S+)\s+(?P<value>\S+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


class Cookie(BaseModel):
    domain: str
    name: str
    value: str = Field(repr=False)
    path: str = "/"
    secure: bool = False
    expires: Optional[datetime] = None

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False  # session cookie — treat as live
        return self.expires < datetime.now(timezone.utc)

    @property
    def high_value(self) -> bool:
        d = self.domain.lstrip(".").lower()
        return any(d == hv or d.endswith("." + hv) for hv in HIGH_VALUE_DOMAINS)


def parse_netscape(text: str) -> list[Cookie]:
    """Parse Mozilla/Netscape ``cookies.txt`` format."""
    out: list[Cookie] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _NETSCAPE_LINE.match(line)
        if not m:
            continue
        expiry_ts = int(m.group("expiry"))
        expires = (datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
                   if expiry_ts > 0 else None)
        out.append(Cookie(
            domain=m.group("domain"),
            path=m.group("path"),
            secure=m.group("secure").upper() in {"TRUE", "T"},
            expires=expires,
            name=m.group("name"),
            value=m.group("value"),
        ))
    return out


def parse_json_cookies(text: str) -> list[Cookie]:
    """Parse JSON cookie arrays (EditThisCookie / browser extension exports)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = data.get("cookies", [])
    out: list[Cookie] = []
    for item in data:
        if not isinstance(item, dict) or "name" not in item:
            continue
        exp = item.get("expirationDate") or item.get("expires")
        expires = None
        if isinstance(exp, (int, float)) and exp > 0:
            expires = datetime.fromtimestamp(exp, tz=timezone.utc)
        out.append(Cookie(
            domain=str(item.get("domain", "")),
            path=str(item.get("path", "/")),
            secure=bool(item.get("secure", False)),
            expires=expires,
            name=str(item["name"]),
            value=str(item.get("value", "")),
        ))
    return out


def parse_any(text: str) -> list[Cookie]:
    """Auto-detect format (JSON array vs Netscape) and parse cookies."""
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        return parse_json_cookies(text)
    return parse_netscape(text)


def live_high_value_cookies(cookies: Iterable[Cookie]) -> list[Cookie]:
    """The dangerous subset: unexpired cookies on enterprise domains."""
    return [c for c in cookies if c.high_value and not c.is_expired]


def triage(cookies: Iterable[Cookie]) -> dict:
    """Severity buckets used by the alerting layer.

    * P1 — live session cookie on a high-value domain (replay risk now),
    * P2 — expired high-value cookie (historical exposure),
    * P3 — everything else.
    """
    p1, p2, p3 = [], [], []
    for c in cookies:
        if c.high_value and not c.is_expired:
            p1.append(c)
        elif c.high_value:
            p2.append(c)
        else:
            p3.append(c)
    return {
        "critical_live_sessions": len(p1),
        "expired_high_value": len(p2),
        "other": len(p3),
        "live_domains": sorted({c.domain for c in p1}),
    }
