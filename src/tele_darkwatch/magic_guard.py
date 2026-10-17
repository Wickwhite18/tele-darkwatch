"""Malware-detonation guard: magic-byte validation before files touch disk.

Infostealer log archives sometimes carry bait executables aimed at the
researcher's parser. :func:`classify` inspects only the first bytes of a
buffer (no external deps) and :func:`is_safe_text_archive_member` decides
whether an archive member may be extracted & parsed. Executables, scripts and
office droppers are rejected by policy — never written to storage volumes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

#: magic-number prefix -> human label (checked case-sensitively on raw bytes)
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "windows-pe-executable"),
    (b"\x7fELF", "elf-binary"),
    (b"#!\n", "shebang-script"),
    (b"\xde\xad\xbe\xef", "java-class-or-macho-fat"),
    (b"PK\x03\x04", "zip-archive"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"Rar!\x1a\x07", "rar-archive"),
    (b"%PDF", "pdf-document"),
    (b"\xff\xd8\xff", "jpeg-image"),
    (b"\x89PNG\r\n\x1a\n", "png-image"),
]

#: extensions that must never be extracted from untrusted leak archives
BLOCKED_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".lnk", ".bat", ".cmd", ".com", ".pif",
    ".js", ".jse", ".wsf", ".ps1", ".msi", ".dll", ".jar", ".hta",
}


@dataclass(frozen=True)
class FileVerdict:
    kind: str          # detected type or "text"/"unknown"
    safe: bool         # OK to extract/parse
    reason: str


def classify(head: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES:
        if head.startswith(magic):
            return label
    try:
        head[:512].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary-unknown"


def is_safe_text_archive_member(name: str, head: bytes) -> FileVerdict:
    """Policy check for one member inside an untrusted leak archive."""
    ext = PurePosixPath(name).suffix.lower()
    kind = classify(head)
    if ext in BLOCKED_EXTENSIONS:
        return FileVerdict(kind, False, f"blocked extension {ext}")
    if kind == "windows-pe-executable" or kind == "elf-binary":
        return FileVerdict(kind, False, "executable payload")
    if kind.endswith("-archive"):
        # nested archives are re-checked recursively by the leak parser;
        # treat as unsafe here unless caller opts into recursion depth.
        return FileVerdict(kind, False, "nested archive")
    if kind == "text":
        return FileVerdict(kind, True, "plain text")
    if kind in ("png-image", "jpeg-image", "pdf-document"):
        return FileVerdict(kind, True, "media routed to OCR pipeline")
    return FileVerdict(kind, False, "unrecognized binary")
