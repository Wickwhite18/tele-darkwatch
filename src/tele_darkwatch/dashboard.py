"""Interactive terminal dashboard for tele-darkwatch (``darkwatch dashboard``).

A lightweight, dependency-optional menu loop: pick numbered actions to run
collection cycles, search, review alerts, dispatch notifications, inspect the
queue/sessions/health, and open SOAR tickets — all with color-coded feedback.

Works without ``rich`` (plain text) and is fully scriptable: pass
``commands="5,8,q"`` (or stdin lines) so tests / SSH sessions can drive it
non-interactively.
"""
from __future__ import annotations

import json
import sys
from typing import Callable, Optional

from tele_darkwatch.config import Settings
from tele_darkwatch.ui import get_ui


def _menu_items() -> list[tuple[str, str, str]]:
    """(key, label, status-icon-status) triples."""
    return [
        ("1", "Collect Telegram channels (RSS)",            "running"),
        ("2", "Collect dark-web .onion sites (Tor)",        "running"),
        ("3", "Search stored messages",                     "pending"),
        ("4", "Run keyword alert rules",                    "pending"),
        ("5", "Run regex IOC scan (CVEs/onions/crypto)",    "pending"),
        ("6", "Dispatch pending alerts to notifiers",       "new"),
        ("7", "Pipeline: entity extraction + watchlist",    "running"),
        ("8", "SOAR playbooks → incident tickets",          "warn"),
        ("9", "Storage & pipeline statistics",              "ok"),
        ("h", "Health snapshot (silence detection)",        "ok"),
        ("q", "Work-queue status",                          "pending"),
        ("s", "Telegram session pool status",               "pending"),
        ("e", "Recent audit events",                        "ok"),
        ("x", "Export archive (JSON file)",                 "new"),
        ("c", "Configuration summary",                      "ok"),
        ("?", "Show this menu",                             "ok"),
    ]


class Dashboard:
    def __init__(self, settings: Settings, store, actions: dict[str, Callable[[], None]],
                 ui=None) -> None:
        self.settings = settings
        self.store = store
        self.actions = actions
        self.ui = ui or get_ui()

    def render_header(self) -> None:
        from tele_darkwatch import __version__

        counts = {
            "messages": self.store.count(),
            "pending alerts": len(self.store.pending_alerts()),
        }
        self.ui.banner(
            f"tele-darkwatch v{__version__} — threat-intel dashboard",
            subtitle=f"db={self.settings.db_path}  "
                     + "  ".join(f"{k}={v}" for k, v in counts.items()),
        )

    def render_menu(self) -> None:
        rows = []
        for key, label, status in _menu_items():
            icon = "✔" if key in self.actions else "⚠"
            rows.append([key, label, "ready" if key in self.actions else "missing handler"])
        self.ui.table("Actions", ["#", "Command", "State"], rows,
                      styles=["cyan"] * len(rows))

    def run(self, commands: Optional[list[str]] = None) -> int:
        """Main loop.  ``commands`` (if given) are consumed instead of stdin."""
        queue = list(commands or [])
        idx = 0
        self.render_header()
        self.render_menu()
        while True:
            if idx < len(queue):
                choice = queue[idx]
                idx += 1
                print(f"> {choice}")
            else:
                try:
                    choice = input("darkwatch> ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    self.ui.print("\n[dim]bye[/]")
                    return 0
            if choice in {"", "?"}:
                self.render_menu()
                continue
            if choice in {"q", "quit", "exit"}:
                self.ui.success("Session ended.")
                return 0
            if choice == "r":
                self.render_header()
                continue
            action = self.actions.get(choice)
            if action is None:
                self.ui.warn(f"Unknown action {choice!r}. Press ? for the menu.")
                continue
            with self.ui.timer(f"action {choice}"):
                try:
                    action()
                except Exception as exc:  # keep dashboard alive on errors
                    self.ui.error(f"{type(exc).__name__}: {exc}")


def build_actions(settings: Settings, store, cli_main: Callable[[list[str]], int]) -> dict:
    """Map menu keys to closures that reuse the existing CLI machinery."""

    def run(*argv: str) -> None:
        rc = cli_main(list(argv))
        if rc != 0:
            raise SystemExit(rc)

    actions: dict[str, Callable[[], None]] = {
        "1": lambda: run("--db", settings.db_path, "collect"),
        "2": lambda: run("--db", settings.db_path, "collect-darkweb"),
        "4": lambda: run("--db", settings.db_path, "alerts"),
        "5": lambda: run("--db", settings.db_path, "ioc-scan"),
        "6": lambda: run("--db", settings.db_path, "notify"),
        "7": lambda: run("--db", settings.db_path, "pipeline"),
        "8": lambda: run("--db", settings.db_path, "soar-run"),
        "h": lambda: run("--db", settings.db_path, "health"),
        "e": lambda: run("--db", settings.db_path, "events", "--limit", "15"),
        "x": lambda: run("--db", settings.db_path, "export", "--format", "json",
                         "--output", "dashboard-export.json"),
    }

    def _search() -> None:
        q = input("query> ").strip()
        if q:
            run("--db", settings.db_path, "search", q, "--limit", "10")

    def _stats() -> None:
        ui = get_ui()
        info = {
            "messages": store.count(),
            "channels": len(store.channels()),
            "pending_alerts": len(store.pending_alerts()),
            "entities": store.entities.count(),
            "events": store.events.count(),
        }
        ui.table("Statistics", ["Metric", "Value"],
                 [[k, v] for k, v in info.items()])

    def _queue() -> None:
        from pathlib import Path as _P

        from tele_darkwatch.queue import WorkQueue

        ui = get_ui()
        q = WorkQueue(str(_P(settings.db_path).with_name("queue.db")))
        stats = q.stats()  # {queue_name: {status: count}}
        q.close()
        rows = [
            [name, counts.get("pending", 0), counts.get("done", 0),
             counts.get("failed", 0)]
            for name, counts in sorted(stats.items())
        ] or [(("(empty)", "", "", ""))]
        ui.table("Work queues", ["Queue", "Pending", "Done", "Failed"],
                 [list(r) for r in rows])

    def _sessions() -> None:
        from pathlib import Path as _P

        from tele_darkwatch.session_pool import SessionPool

        ui = get_ui()
        pool = SessionPool(_P(settings.session_dir),
                           max_per_minute=settings.session_rate_per_min,
                           jitter=(settings.jitter_min, settings.jitter_max))
        status = pool.status()  # {total, healthy, quarantined, per_minute_cap}
        rows = [
            ["total sessions", status["total"]],
            ["healthy", status["healthy"]],
            ["quarantined", len(status["quarantined"])],
            ["per-minute cap", status["per_minute_cap"]],
        ]
        for q in status["quarantined"]:
            rows.append([f"⛔ {q}", "QUARANTINED"])
        ui.table("Telegram session pool", ["Metric", "Value"], rows,
                 styles=["green", "green", "red" if status["quarantined"] else "dim",
                         "cyan"] + ["bold red"] * len(status["quarantined"]))

    def _config() -> None:
        ui = get_ui()
        dump = settings.model_dump()
        secret_keys = {"telegram_api_hash", "smtp_password"}
        rows = []
        for k, v in sorted(dump.items()):
            if v in (None, "", [], {}):
                continue
            shown = "***" if k in secret_keys and v else v
            rows.append([k, str(shown)])
        ui.table("Configuration (Settings)", ["Key", "Value"], rows)

    actions.update({
        "3": _search,
        "9": _stats,
        "q": _queue,
        "s": _sessions,
        "c": _config,
    })
    return actions
