"""Infostealer-log archive parser (defensive, ephemeral).

Handles the typical RedLine/Lumma/Stealc drop format: zip/tar archives packed
with ``Userpass.txt``, ``Cookies/``, autofill and system-info text files.

Safety properties (OpSec):
* Archives are decompressed **in memory** (``io.BytesIO``) — nothing is ever
  written to disk; there is no extraction path at all.
* Member names are validated against zip-slip / path traversal.
* Files whose magic bytes match known executable formats (PE/MZ, ELF, script
  shebangs…) are **dropped**, never stored or scanned.
* Total uncompressed output is capped to stop zip-bombs.
"""
from __future__ import annotations

import io
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Iterator, Optional

from tele_darkwatch.entities import Entity, extract_all, summarize

#: Refuse to inflate more than this many bytes of text content per archive.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB
#: Skip individual members larger than this (raw log texts are small).
MAX_MEMBER_BYTES = 8 * 1024 * 1024    # 8 MiB

#: Magic-byte signatures of payloads we must never touch storage.
EXECUTABLE_MAGICS: tuple[bytes, ...] = (
    b"MZ",                    # PE / DOS
    b"\x7fELF",               # Linux ELF
    b"\xfe\xed\xfa",          # Mach-O (big-endian variants omitted for brevity)
    b"\xca\xfe\xba\xbe",      # Mach-O fat
    b"#!/bin/", b"#!/usr/",   # script shebangs
    b"@echo ",                # batch
)
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".vbs", ".lnk", ".bat", ".cmd",
                        ".ps1", ".dll", ".jar", ".msi", ".com", ".pif"}


def is_executable(data: bytes) -> bool:
    """Magic-byte analysis: does this blob look like runnable code?"""
    head = data[:8]
    if any(head.startswith(magic) for magic in EXECUTABLE_MAGICS):
        return True
    name_ext = ""
    return False


def _safe_member_name(name: str) -> bool:
    """Reject absolute paths and traversal (zip-slip)."""
    return not (name.startswith("/") or ".." in name.split("/")
                or re.match(r"^[A-Za-z]:[\\/]", name))


@dataclass
class ParseReport:
    """Outcome of parsing one archive."""

    members_seen: int = 0
    members_parsed: int = 0
    dropped_executables: int = 0
    skipped_large: int = 0
    truncated: bool = False
    entities: list[Entity] = field(default_factory=list)
    credential_lines: int = 0

    @property
    def entity_counts(self) -> dict[str, int]:
        return summarize(self.entities)


_TEXT_FILE_HINTS = ("userpass", "password", "credential", "combo", "login",
                    "cookies", "autofill", "history", "cc:", "screenshot")


def _looks_like_log_text(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(".txt") or lowered.endswith(".csv"):
        return True
    return any(h in lowered for h in _TEXT_FILE_HINTS)


def iter_archive_members(blob: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield ``(name, data)`` for every regular file in a zip or tar blob."""
    bio = io.BytesIO(blob)
    try:
        with zipfile.ZipFile(bio) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if not _safe_member_name(info.filename):
                    continue
                with zf.open(info) as fh:
                    yield info.filename, fh.read(MAX_MEMBER_BYTES + 1)
            return
    except zipfile.BadZipFile:
        pass
    bio.seek(0)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not _safe_member_name(member.name):
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                yield member.name, fh.read(MAX_MEMBER_BYTES + 1)
    except tarfile.TarError:
        return


def parse_archive_bytes(
    blob: bytes,
    max_total_bytes: int = DEFAULT_MAX_BYTES,
    scan_binaries: bool = False,
) -> ParseReport:
    """Unpack an infostealer archive **in memory** and extract entities.

    Executable members are dropped before they ever reach storage. Text
    members are decoded lossily and fed through the entity extractors.
    """
    report = ParseReport()
    budget = max_total_bytes
    for name, data in iter_archive_members(blob):
        report.members_seen += 1
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS or (not scan_binaries and
                                           is_executable(data)):
            report.dropped_executables += 1
            continue
        if len(data) > MAX_MEMBER_BYTES:
            report.skipped_large += 1
            continue
        if len(data) > budget:
            data = data[:budget]
            report.truncated = True
        budget -= len(data)
        if budget <= 0:
            report.truncated = True
            break
        text = data.decode("utf-8", errors="replace")
        report.members_parsed += 1
        if _looks_like_log_text(name):
            report.credential_lines += sum(
                1 for line in text.splitlines() if ":" in line or "@" in line)
        report.entities.extend(extract_all(text))
    return report


def parse_file(path: str, **kwargs) -> ParseReport:
    """Convenience wrapper that reads an archive from disk into memory."""
    with open(path, "rb") as fh:
        return parse_archive_bytes(fh.read(), **kwargs)


# ------------------------------------------------------------- loose text files
_USERPASS_RE = re.compile(
    r"^(?P<user>[^\s:,@]+(?:@[^\s:,@]+)?)(?:\s*[:;,|]\s*(?P<secret>\S+))?\s*$"
)


def parse_userpass_text(text: str) -> list[dict]:
    """Parse loose ``Userpass.txt``/``Passwords.txt`` style lines.

    Returns one record per recognizable ``identity:secret`` line:
    ``{"username": ..., "password": ...}`` (email usernames also surface as
    email entities via :func:`tele_darkwatch.entities.extract_all`).
    """
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith("#"):
            continue
        m = _USERPASS_RE.match(line)
        if not m or not m.group("secret"):
            continue
        records.append({"username": m.group("user"),
                        "password": m.group("secret")})
    return records
