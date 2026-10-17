"""Rich terminal UI layer for tele-darkwatch.

Provides color-coded output, progress bars, spinners, tables, banners, and an
accessibility-aware plain-text fallback.  All helpers degrade gracefully when
the ``rich`` package is not installed so the CLI keeps working in minimal
environments (and inside tests).

Environment adaptability
------------------------
* ``DW_NO_COLOR=1`` / ``NO_COLOR``  -> disable all ANSI color (accessibility,
  piping to files, screen-reader friendly logs).
* ``DW_UI=plain``                    -> force the plain-text fallback even when
  rich is available.
* Non-TTY stdout                     -> automatically falls back to plain text.
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterable, Optional

try:  # optional dependency – graceful degradation
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
        MofNCompleteColumn,
    )
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
except Exception:  # pragma: no cover - exercised via monkeypatch in tests
    _HAS_RICH = False


# ---------------------------------------------------------------------------
# Severity / status colour maps (consistent across every command)
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[int, str] = {
    1: "green",       # informational
    2: "yellow",      # low
    3: "orange3",     # medium
    4: "red",         # high
    5: "bold red",    # critical
}

STATUS_ICONS: dict[str, tuple[str, str]] = {
    # status -> (icon, colour)
    "ok":        ("✔", "green"),
    "success":   ("✔", "green"),
    "pass":      ("✔", "green"),
    "running":   ("▶", "cyan"),
    "pending":   ("…", "yellow"),
    "warn":      ("⚠", "yellow"),
    "warning":   ("⚠", "yellow"),
    "error":     ("✖", "red"),
    "fail":      ("✖", "red"),
    "quarantine":("⛔", "bold red"),
    "dropped":   ("⊘", "dim"),
    "new":       ("＋", "blue"),
}

_SEV_WORDS = {
    1: "INFO", 2: "LOW", 3: "MED", 4: "HIGH", 5: "CRIT",
}


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class UI:
    """Central rendering facade.  One instance per process (see :func:`get_ui`)."""

    def __init__(self, force_plain: Optional[bool] = None) -> None:
        self.plain = (
            not _HAS_RICH
            if force_plain is None
            else force_plain
        ) or _env_truthy("DW_UI_PLAIN") or _env_truthy("NO_COLOR") or _env_truthy("DW_NO_COLOR")
        if not self.plain and not sys.stdout.isatty():
            # keep logs clean when piped; still no ANSI codes
            self.plain = True
        self.console: Optional["Console"] = None
        if not self.plain:
            self.console = Console(highlight=False, soft_wrap=False)

    # -- basic printing ----------------------------------------------------
    def print(self, msg: str = "", style: Optional[str] = None) -> None:
        if self.plain:
            print(msg)
        else:
            self.console.print(msg, style=style)

    def rule(self, title: str = "") -> None:
        if self.plain:
            print(f"--- {title} ---" if title else "---")
        else:
            self.console.rule(title)

    def banner(self, title: str, subtitle: str = "") -> None:
        head = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            head += f"\n[dim]{subtitle}[/dim]"
        if self.plain:
            print(f"== {title} ==")
            if subtitle:
                print(subtitle)
        else:
            self.console.print(Panel(head, box=box.DOUBLE, border_style="cyan"))

    # -- status indicators ---------------------------------------------------
    def status_line(self, status: str, label: str, detail: str = "") -> None:
        icon, color = STATUS_ICONS.get(status.lower(), ("•", "white"))
        if self.plain:
            line = f"[{status.upper()}] {label}"
            print(f"{line}: {detail}" if detail else line)
        else:
            line = f"[{color}]{icon}[/] [{color} bold]{label}[/]"
            if detail:
                line += f" [dim]{detail}[/]"
            self.console.print(line)

    def severity_tag(self, severity: int) -> str:
        sev = max(1, min(5, int(severity)))
        word = _SEV_WORDS[sev]
        color = SEVERITY_COLORS[sev]
        if self.plain:
            return f"[{word}]"
        return f"[{color} on bright_black] {word} [/]"

    def kv(self, key: str, value: Any, style: Optional[str] = None) -> None:
        if self.plain:
            print(f"{key:<22}{value}")
        else:
            self.console.print(f"[bold]{key:<22}[/][/]{''}", end="")
            self.console.print(str(value), style=style, end="")
            self.console.print("")

    # -- tables --------------------------------------------------------------
    def table(self, title: str, columns: Iterable[str], rows: Iterable[Iterable[Any]],
              styles: Optional[Iterable[str]] = None) -> None:
        cols = list(columns)
        row_list = [list(r) for r in rows]
        if self.plain:
            widths = [len(str(c)) for c in cols]
            for r in row_list:
                for i, cell in enumerate(r):
                    if i < len(widths):
                        widths[i] = max(widths[i], len(str(cell)))
            header = "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cols))
            print(header)
            print("  ".join("-" * w for w in widths))
            for r in row_list:
                print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))
            return
        t = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold cyan",
                  title_style="bold", border_style="dim")
        for c in cols:
            t.add_column(str(c))
        style_list = list(styles) if styles else []
        for idx, r in enumerate(row_list):
            st = style_list[idx] if idx < len(style_list) else None
            cells = [x if isinstance(x, (Text,)) or hasattr(x, "__rich_console__")
                     else str(x) for x in r]
            while len(cells) < len(cols):
                cells.append("")
            t.add_row(*cells[: len(cols)], style=st)
        self.console.print(t)

    # -- progress bars ---------------------------------------------------------
    @contextmanager
    def progress_task(self, description: str, total: Optional[float] = None):
        """Context manager yielding a callback ``cb(increment=1)`` plus a live bar."""
        if self.plain:
            start = time.monotonic()
            state = {"done": 0}

            def cb(increment: int = 1, **_kw) -> None:
                state["done"] += increment
                n = state["done"]
                if total:
                    pct = int(100 * n / total)
                    sys.stdout.write(f"\r{description}: {n}/{total} ({pct}%)")
                else:
                    sys.stdout.write(f"\r{description}: {n}")
                sys.stdout.flush()

            try:
                yield cb
            finally:
                elapsed = time.monotonic() - start
                sys.stdout.write(f"\r{description}: done ({state['done']} items, "
                                 f"{elapsed:.1f}s)\n")
                sys.stdout.flush()
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,
        ) as prog:
            task_id = prog.add_task(description, total=total)

            def cb(increment: int = 1, description: Optional[str] = None,
                   completed: Optional[float] = None) -> None:
                if description is not None:
                    prog.update(task_id, description=description)
                if completed is not None:
                    prog.update(task_id, completed=completed)
                else:
                    prog.advance(task_id, advance=increment)

            yield cb

    @contextmanager
    def spinner(self, label: str):
        if self.plain:
            print(f"... {label}")
            yield
            return
        with self.console.status(f"[cyan]{label}") as st:
            yield st

    # -- feedback helpers ------------------------------------------------------
    def success(self, msg: str) -> None:
        self.status_line("ok", msg)

    def warn(self, msg: str) -> None:
        self.status_line("warn", msg)

    def error(self, msg: str) -> None:
        if self.plain:
            print(f"[ERROR] {msg}", file=sys.stderr)
        else:
            self.console.print(f"[bold red]✖ ERROR[/] [red]{msg}[/]", style=None)

    def timer(self, label: str):
        return _Timer(self, label)


class _Timer:
    def __init__(self, ui: UI, label: str) -> None:
        self.ui = ui
        self.label = label
        self.start = 0.0

    def __enter__(self) -> "_Timer":
        self.start = time.monotonic()
        return self

    def __exit__(self, *exc) -> None:
        elapsed = time.monotonic() - self.start
        self.ui.print(f"[dim]⏱ {self.label} finished in {elapsed:.2f}s[/]"
                      if not self.ui.plain else f"{self.label}: {elapsed:.2f}s")


_UI: Optional[UI] = None


def get_ui() -> UI:
    global _UI
    if _UI is None:
        _UI = UI()
    return _UI
