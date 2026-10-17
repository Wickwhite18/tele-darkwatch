"""Entity extraction from raw leak text.

Turns noisy breach/infostealer dumps into structured, deduplicated entities:
emails (with credential pairs), URLs, IPv4 addresses, cryptocurrency wallet
addresses and API keys (AWS, OpenAI, Anthropic, GitHub, Google, Slack, Stripe).

All extractors are pure functions over strings so they can be unit-tested and
reused by the pipeline, the CLI and the alert engines alike.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from enum import Enum
from typing import Iterable

from pydantic import BaseModel


class EntityType(str, Enum):
    EMAIL = "email"
    URL = "url"
    IPV4 = "ipv4"
    BTC_ADDRESS = "btc_address"
    ETH_ADDRESS = "eth_address"
    API_KEY = "api_key"


#: Well-known throwaway / example identities that must never escalate an alert.
DUMMY_EMAILS = {
    "test@test.com", "test@example.com", "admin@admin.com", "user@user.com",
    "me@example.org", "email@example.com", "test@test.org", "a@a.com",
}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]}]+")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                     r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{27,68})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

API_KEY_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "openai_api_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "anthropic_api_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_key": re.compile(r"\b(?:sk|pk|rk|wh)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
}


class Entity(BaseModel):
    """A single extracted indicator with a stable identity hash."""

    type: EntityType
    value: str
    #: Extra context, e.g. ``{"password": "...", "key_type": "aws_access_key_id"}``
    attributes: dict = {}

    @property
    def entity_hash(self) -> str:
        return hashlib.sha256(
            f"{self.type.value}|{self.value.lower()}".encode()
        ).hexdigest()


def _looks_like_email_address(token: str) -> bool:
    """Reject bare IPs that the loose email regex would happily match."""
    return IPV4_RE.fullmatch(token) is None


def extract_emails(text: str) -> list[Entity]:
    """Extract emails; attaches adjacent passwords when the line looks like
    a leaked credential pair (``user:pass``, ``user - pass``, CSV rows…)."""
    entities: list[Entity] = []
    for line in text.splitlines():
        for email in EMAIL_RE.findall(line):
            if not _looks_like_email_address(email):
                continue
            attrs: dict = {}
            # Try to pull a password belonging to *this* email out of the line.
            escaped = re.escape(email)
            m = re.search(rf"{escaped}\s*[:;,|\t-]\s*(\S{{3,}})", line, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip("\"'")
                if not EMAIL_RE.fullmatch(candidate):
                    attrs["password"] = candidate
            entities.append(Entity(type=EntityType.EMAIL, value=email.lower(),
                                   attributes=attrs))
    # Whole-text scan too (catches emails on lines we already handled — dedup below)
    return entities


def extract_urls(text: str) -> list[Entity]:
    return [Entity(type=EntityType.URL, value=u.rstrip(".,;:!"))
            for u in URL_RE.findall(text)]


def extract_ipv4(text: str) -> list[Entity]:
    return [Entity(type=EntityType.IPV4, value=ip) for ip in IPV4_RE.findall(text)]


def extract_crypto_addresses(text: str) -> list[Entity]:
    out = [Entity(type=EntityType.BTC_ADDRESS, value=a) for a in BTC_RE.findall(text)]
    out += [Entity(type=EntityType.ETH_ADDRESS, value=a) for a in ETH_RE.findall(text)]
    return out


def extract_api_keys(text: str) -> list[Entity]:
    out: list[Entity] = []
    for key_type, pattern in API_KEY_PATTERNS.items():
        for match in pattern.findall(text):
            out.append(Entity(type=EntityType.API_KEY, value=match,
                              attributes={"key_type": key_type}))
    return out


_EXTRACTORS = (
    extract_emails,
    extract_urls,
    extract_ipv4,
    extract_crypto_addresses,
    extract_api_keys,
)


def extract_all(text: str) -> list[Entity]:
    """Run every extractor and return deduplicated entities (first seen wins)."""
    seen: set[str] = set()
    out: list[Entity] = []
    for extractor in _EXTRACTORS:
        for ent in extractor(text):
            if ent.entity_hash in seen:
                continue
            seen.add(ent.entity_hash)
            out.append(ent)
    return out


def is_dummy_email(entity: Entity) -> bool:
    """Contextual validation: obvious test/example accounts are noise."""
    if entity.type is not EntityType.EMAIL:
        return False
    value = entity.value.lower()
    if value in DUMMY_EMAILS:
        return True
    domain = value.rsplit("@", 1)[-1]
    return domain in {"example.com", "example.org", "example.net", "test.com"}


def filter_dummies(entities: Iterable[Entity]) -> list[Entity]:
    return [e for e in entities if not is_dummy_email(e)]


def summarize(entities: Iterable[Entity]) -> dict[str, int]:
    """Counts per entity type — handy for stats output and alert metadata."""
    return dict(Counter(e.type.value for e in entities))
