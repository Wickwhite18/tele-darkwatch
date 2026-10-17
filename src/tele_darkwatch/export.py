"""Export stored intelligence to JSON / CSV / newline-delimited NDJSON."""
from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from tele_darkwatch.models import Message

_COLUMNS = ("id", "timestamp", "source_type", "channel", "url", "content", "metadata")


def messages_to_json(messages: Iterable[Message], indent: int = 2) -> str:
    payload = [m.model_dump(mode="json") for m in messages]
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def messages_to_ndjson(messages: Iterable[Message]) -> str:
    return "\n".join(
        json.dumps(m.model_dump(mode="json"), ensure_ascii=False) for m in messages
    )


def messages_to_csv(messages: Iterable[Message]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_COLUMNS)
    for m in messages:
        d = m.model_dump(mode="json")
        row = [d.get(col) for col in _COLUMNS[:-1]] + [json.dumps(d["metadata"], ensure_ascii=False)]
        writer.writerow(row)
    return buf.getvalue()


def export_messages(messages: Iterable[Message], fmt: str = "json") -> str:
    """Serialize ``messages`` using ``fmt`` in {json, csv, ndjson}."""
    fmt = fmt.lower()
    if fmt == "json":
        return messages_to_json(messages)
    if fmt == "csv":
        return messages_to_csv(messages)
    if fmt == "ndjson":
        return messages_to_ndjson(messages)
    raise ValueError(f"Unsupported export format: {fmt!r} (use json|csv|ndjson)")
