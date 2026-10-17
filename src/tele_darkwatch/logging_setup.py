"""Centralized logging configuration for tele-darkwatch.

Usage::

    from tele_darkwatch.logging_setup import configure_logging, get_logger

    configure_logging(level="INFO", log_file="darkwatch.log")
    log = get_logger(__name__)
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_configured = False


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str | Path] = None,
    *,
    force: bool = False,
) -> None:
    """Configure the ``tele_darkwatch`` logger once (idempotent).

    :param level: one of DEBUG/INFO/WARNING/ERROR/CRITICAL.
    :param log_file: optional path; when given, logs are also appended there.
    :param force: re-configure even if already set up.
    """
    global _configured
    if _configured and not force:
        return

    root = logging.getLogger("tele_darkwatch")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(_FORMAT)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file:
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``tele_darkwatch`` namespace."""
    if not name.startswith("tele_darkwatch"):
        name = f"tele_darkwatch.{name}"
    return logging.getLogger(name)
