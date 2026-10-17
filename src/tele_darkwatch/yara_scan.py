"""Optional YARA binary/log pattern matching stage.

Regex misses structured hits inside corrupted binaries or memory dumps. When
``yara-python`` is installed and a rules directory is configured
(``DW_YARA_RULES_PATH``), every parsed leak file gets compiled-rule scans and
matches become metadata on the resulting alert. No native dep => graceful
no-op, consistent with the OCR stage.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from tele_darkwatch.logging_setup import get_logger

log = get_logger(__name__)

try:  # pragma: no cover
    import yara
    _HAVE_YARA = True
except Exception:  # noqa: BLE001
    yara = None
    _HAVE_YARA = False


def available() -> bool:
    return _HAVE_YARA


class YaraScanner:
    def __init__(self, rules_path: Path | str) -> None:
        self.rules_path = Path(rules_path)
        self._rules = None
        if not _HAVE_YARA:
            log.info("yara-python not installed; scanner disabled")
            return
        if not self.rules_path.is_dir():
            log.warning("YARA rules dir missing: %s", self.rules_path)
            return
        files = {p.stem: str(p) for p in self.rules_path.glob("*.yar")}
        if not files:
            log.warning("no .yar files found in %s", self.rules_path)
            return
        try:
            self._rules = yara.compile(filenames=files)
            log.info("compiled %d YARA rule files", len(files))
        except Exception as exc:  # noqa: BLE001
            log.error("YARA compile failed: %s", exc)

    def scan(self, data: bytes) -> list[str]:
        """Return names of rules matching *data* (empty when disabled)."""
        if self._rules is None:
            return []
        try:
            return [m.rule for m in self._rules.match(data=data)]
        except Exception as exc:  # noqa: BLE001
            log.warning("YARA scan error: %s", exc)
            return []

    def scan_file(self, path: Path | str) -> list[str]:
        if self._rules is None:
            return []
        try:
            return [m.rule for m in self._rules.match(str(path))]
        except Exception:  # noqa: BLE001
            return self.scan(Path(path).read_bytes())


DEFAULT_RULE_TEXT = '''rule InfostealerDirectoryMarkers
{
    meta:
        author = "tele-darkwatch"
        description = "Common folder names inside Lumma/Stealc/RedLine drops"
    strings:
        $s1 = "Passwords.txt" ascii wide
        $s2 = "Userpass.txt" ascii wide
        $s3 = "Cookies/" ascii wide
        $s4 = "cc-log.txt" ascii wide
    condition:
        any of them
}
'''


def ensure_default_rules(directory: Path | str) -> Path:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    target = d / "infostealer_markers.yar"
    if not target.exists():
        target.write_text(DEFAULT_RULE_TEXT)
    return target
