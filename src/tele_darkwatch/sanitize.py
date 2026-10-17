"""Data sanitization / masking for compliance (GDPR/CCPA posture).

Plaintext PII should not sit in the archive unless it belongs to a protected
corporate domain that the analyst explicitly owns. Two operations:

* :func:`mask_text` — masks passwords and credit-card numbers in free text
  while leaving corporate-domain emails untouched.
* :func:`sanitize_store` — one-shot batch rewrite of historic messages
  (used by ``darkwatch sanitize``).
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, Optional

from tele_darkwatch.entities import EMAIL_RE
from tele_darkwatch.storage.message_store import MessageStore

#: ``user:pass`` style pairs — password portion becomes an irreversible hash.
_CRED_PAIR_RE = re.compile(
    r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    r"\s*[:;,|\t-]\s*(\S{3,})"
)
#: 13–19 digit groups possibly separated by spaces/dashes → credit cards.
_CC_RE = re.compile(r"(?<![\w.])(?:\d[ -]?){15,18}\d(?![\w.])")


def _hash_password(pw: str) -> str:
    return "sha256:" + hashlib.sha256(pw.encode("utf-8")).hexdigest()[:32]


def _mask_cc(match: re.Match) -> str:
    digits = re.sub(r"[ -]", "", match.group(0))
    if not (13 <= len(digits) <= 19):
        return match.group(0)
    return f"XXXX-XXXX-XXXX-{digits[-4:]}"


def mask_text(text: str, protect_domains: Iterable[str] = ()) -> str:
    """Mask credential-pair passwords and card numbers outside protected domains."""
    protected = {d.lower().lstrip(".") for d in protect_domains if d}

    def cred_sub(m: re.Match) -> str:
        email, secret = m.group(1), m.group(2)
        domain = email.rsplit("@", 1)[-1].lower()
        if domain in protected:
            return m.group(0)  # keep verbatim for owned corporate assets
        return f"{email}:{_hash_password(secret)}"

    masked = _CRED_PAIR_RE.sub(cred_sub, text)
    masked = _CC_RE.sub(_mask_cc, masked)
    return masked


def find_corporate_emails(text: str, domains: Iterable[str]) -> list[str]:
    """Return emails matching any of the protected corporate domains."""
    wanted = [d.lower().lstrip(".") for d in domains if d]
    out = []
    for email in EMAIL_RE.findall(text):
        lower = email.lower()
        if any(lower.endswith("@" + d) or f".{d}" in lower.split("@")[-1]
               for d in wanted):
            out.append(email)
    return sorted(set(out))


def sanitize_store(
    store: MessageStore,
    protect_domains: Iterable[str] = (),
    limit: int = 100000,
) -> dict:
    """Rewrite stored messages with masked PII; returns counters."""
    changed = 0
    scanned = 0
    for msg in store.recent(limit=limit):
        scanned += 1
        masked = mask_text(msg.content, protect_domains)
        if masked != msg.content:
            store.update_message_content(msg.id, masked)
            changed += 1
    store.events.record("sanitize", scanned=scanned, changed=changed,
                        protect_domains=list(protect_domains))
    return {"scanned": scanned, "masked": changed}
