"""Lightweight NLP noise-demodulation classifier for incoming chatter.

Cybercrime feeds are flooded with scam ads, repacks and boilerplate spam.
Indexing all of it turns the datastore into a dump yard. This module labels
every message *before* ingestion using fast, deterministic heuristics — no
GPU, no model download, fully offline:

  valid_credential_dump   user:pass combos, stealer-log filenames
  ransomware_victim       leak-site style victim announcements
  malware_source          repo/gist drops claiming source code
  log_advertisement       "premium logs", payment proofs, vendor ads
  scam_or_ad              giveaway/crypto-spam/affiliate noise (drop)
  general                 everything else (keep, low priority)

Scores from ``classify`` sum to 1.0; anything at or above ``threshold`` for a
drop-class label is rejected by :func:`should_index`. A pluggable
``model_fn`` lets teams swap in a fine-tuned Hugging Face transformer later
without touching call-sites.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

LABEL_CRED = "valid_credential_dump"
LABEL_RANSOM = "ransomware_victim"
LABEL_MALWARE = "malware_source"
LABEL_AD = "log_advertisement"
LABEL_SCAM = "scam_or_ad"
LABEL_GENERAL = "general"

DROP_LABELS = {LABEL_SCAM, LABEL_AD}


@dataclass
class Classification:
    label: str
    scores: dict[str, float] = field(default_factory=dict)
    source: str = "heuristic"

    @property
    def confidence(self) -> float:
        return self.scores.get(self.label, 0.0)


# ---------------------------------------------------------------- patterns
_PATTERNS: dict[str, list[re.Pattern]] = {
    LABEL_CRED: [
        re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+[:;]\s*\S{4,}", re.I),      # email:pass
        re.compile(r"\buser(?:name)?[:=]\s*\S+\s*,?\s*pass(?:word)?[:=]", re.I),
        re.compile(r"(UserPass|Passwords?|Combo|CCFull)\.txt", re.I),
        re.compile(r"\blumma|stealc|redline|vidar|racoon\b", re.I),
    ],
    LABEL_RANSOM: [
        re.compile(r"\bransomware\b|\bleak site\b|\bvictim count\b", re.I),
        re.compile(r"\bwe (?:have )?(?:breached|attacked|encrypted)\b", re.I),
        re.compile(r"\bdata (?:has been|will be) (?:published|leaked)\b", re.I),
    ],
    LABEL_MALWARE: [
        re.compile(r"\b(source code|full src)\b.*\b(botnet|stealer|loader|rat)\b", re.I),
        re.compile(r"\b(github\.com|gist\.github\.com)/\S+", re.I),
        re.compile(r"\bc\+\+|rust|go source|panel source\b", re.I),
    ],
    LABEL_AD: [
        re.compile(r"\bpremium logs?\b|\bfresh dumps?\b|\bchecking service\b", re.I),
        re.compile(r"\b(selling|buying)\b.*\b(logs|dumps|combos|cc|base)\b", re.I),
        re.compile(r"\bescrow recommended\b|\bfeedback \d+\b|\btop seller\b", re.I),
    ],
    LABEL_SCAM: [
        re.compile(r"\bfree (?:steam|nitro|discord|gift card)s?\b", re.I),
        re.compile(r"\bincrease your (?:bitcoin|crypto)\b|\bdoubler\b", re.I),
        re.compile(r"\bjoin my (?:channel|casino)\b|\bsend \d+ get \d+ back\b", re.I),
    ],
}

_WEIGHTS = {LABEL_CRED: 2.0, LABEL_RANSOM: 1.6, LABEL_MALWARE: 1.2,
            LABEL_AD: 1.4, LABEL_SCAM: 1.8}


def classify(text: str,
             model_fn: Optional[Callable[[str], dict[str, float]]] = None
             ) -> Classification:
    """Label one message. ``model_fn`` (transformer etc.) wins when supplied."""
    if model_fn is not None:
        scores = model_fn(text)
        label = max(scores, key=scores.get) if scores else LABEL_GENERAL
        return Classification(label=label, scores=scores, source="model")

    raw: dict[str, float] = {}
    hits = 0
    for label, pats in _PATTERNS.items():
        score = sum(1 for p in pats if p.search(text)) * _WEIGHTS[label]
        if score:
            raw[label] = round(score, 3)
            hits += 1
    total = sum(raw.values())
    if not raw:
        return Classification(LABEL_GENERAL, {LABEL_GENERAL: 1.0})
    scores = {k: round(v / total, 3) for k, v in sorted(raw.items(), key=lambda kv: -kv[1])}
    if not hits:  # pragma: no cover - defensive
        return Classification(LABEL_GENERAL, {LABEL_GENERAL: 1.0})
    top = max(scores, key=scores.get)
    return Classification(top, scores)


def should_index(result: Classification, threshold: float = 0.5) -> bool:
    """Drop high-confidence scam/ad content before it reaches storage."""
    return not (result.label in DROP_LABELS and result.confidence >= threshold)


def summarize(results: list[Classification]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        out[r.label] = out.get(r.label, 0) + 1
    return out
