"""Optional OCR stage for image leaks (screenshots of DB dumps, panels).

Threat actors post images instead of text constantly. When ``pytesseract``
(and the tesseract binary) are present, media messages are run through it to
recover searchable text before entity extraction. Without the dependency the
stage degrades to a no-op so the core pipeline never breaks.

Preprocessing (grayscale/threshold via Pillow) improves capture rates on
dark-panel screenshots dramatically compared to raw input.
"""
from __future__ import annotations

import io
from typing import Optional

from tele_darkwatch.logging_setup import get_logger

log = get_logger(__name__)

try:  # pragma: no cover - exercised only when deps installed
    import pytesseract
    from PIL import Image, ImageOps
    _HAVE_OCR = True
except Exception:  # noqa: BLE001
    pytesseract = None
    Image = None
    _HAVE_OCR = False


def available() -> bool:
    if not _HAVE_OCR:
        return False
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:  # noqa: BLE001
        return False


def preprocess(png_bytes: bytes) -> bytes:
    """Grayscale + autocontrast; returns PNG bytes ready for Tesseract."""
    img = Image.open(io.BytesIO(png_bytes)).convert("L")
    img = ImageOps.autocontrast(img)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def extract_text(image_bytes: bytes) -> Optional[str]:
    """OCR an in-memory image; ``None`` when unavailable or on failure."""
    if not available():
        log.debug("OCR requested but tesseract/pytesseract missing")
        return None
    try:
        clean = preprocess(image_bytes)
        text = pytesseract.image_to_string(Image.open(io.BytesIO(clean)))
        return text.strip() or None
    except Exception as exc:  # noqa: BLE001
        log.warning("OCR failed: %s", exc)
        return None
