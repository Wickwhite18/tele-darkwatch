"""File-level hash deduplication for re-packaged breach archives.

Cybercriminals constantly re-upload the same combo lists under new names to
build marketplace reputation. Before a downloaded leak archive is parsed, its
SHA-256 and a lightweight fuzzy signature (context-chunk hashes) are checked
against history:

* exact SHA-256 hit  -> discard immediately (known leak),
* Jaccard similarity of chunk sets >= threshold -> probable repackaged copy,
  flagged but still stored for provenance (never re-alerted).

The pure-Python fuzzy signature approximates ssdeep-style rolling chunks
without native dependencies.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

CHUNK_SIZE = 48          # bytes per rolling window (small => sensitive)
FUZZY_THRESHOLD = 0.75   # default Jaccard cutoff for "same leak, renamed"


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fuzzy_signature(data: bytes, chunk_size: int = CHUNK_SIZE) -> frozenset[str]:
    """Set of hashes over fixed chunks — order-tolerant fingerprint."""
    sig: set[str] = set()
    for start in range(0, max(len(data) - chunk_size, 1), chunk_size // 2):
        block = data[start:start + chunk_size]
        if len(block) < chunk_size // 2:
            break
        sig.add(hashlib.blake2b(block, digest_size=8).hexdigest())
    return frozenset(sig)


def similarity(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


class FileDeduplicator:
    """Store-backed dedup index (table ``file_hashes`` via store meta API)."""

    _PREFIX = "filededup:"

    def __init__(self, store) -> None:
        self.store = store

    # ------------------------------------------------------------------ api
    def check(self, data: bytes) -> dict:
        """Classify a blob: new / exact-duplicate / near-duplicate."""
        digest = sha256_of(data)
        known_exact = self.store.get_meta(self._PREFIX + digest) is not None
        result = {"sha256": digest, "exact_duplicate": known_exact,
                  "near_duplicate": False, "similarity": 0.0,
                  "matched_sha": None}
        if known_exact:
            return result
        sig = fuzzy_signature(data)
        best_sim, best_key = 0.0, None
        for key in self.store.meta_keys(self._PREFIX):
            other = self.store.get_meta(key)
            if not other:
                continue
            stored = frozenset(other.split(","))
            sim = similarity(sig, stored)
            if sim > best_sim:
                best_sim, best_key = sim, key
        if best_sim >= FUZZY_THRESHOLD and best_key:
            result.update(near_duplicate=True, similarity=round(best_sim, 3),
                          matched_sha=best_key.removeprefix(self._PREFIX))
        return result

    def register(self, data: bytes, source: str = "") -> str:
        digest = sha256_of(data)
        sig = fuzzy_signature(data)
        self.store.set_meta(self._PREFIX + digest, ",".join(sorted(sig)))
        self.store.events.record("file_registered", sha256=digest,
                                 source=source, size=len(data))
        return digest
