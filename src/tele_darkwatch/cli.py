"""Command-line interface for tele-darkwatch.

Usage examples::

    darkwatch collect --channels dcg345 bellingcat
    darkwatch collect-darkweb --urls http://exampleonionx.onion
    darkwatch search "drone strike" --channel dcg345
    darkwatch alerts --rules rules.json
    darkwatch notify
    darkwatch stats
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import WebhookNotifier, dispatch_pending
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.search.engine import SearchEngine
from tele_darkwatch.storage.message_store import MessageStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="darkwatch", description=__doc__)
    parser.add_argument("--db", default=None, help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("collect", help="Poll Telegram channels and store messages")
    p.add_argument("--channels", nargs="*", default=None)

    p = sub.add_parser("collect-darkweb", help="Scrape onion URLs over Tor")
    p.add_argument("--urls", nargs="*", default=None)
    p.add_argument("--tor-proxy", default=None)

    p = sub.add_parser("search", help="Full-text search stored messages")
    p.add_argument("query")
    p.add_argument("--channel", default=None)
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("alerts", help="Run alert rules over recent messages")
    p.add_argument("--rules", default=None, help="Path to rules JSON file")
    p.add_argument("--limit", type=int, default=200)

    sub.add_parser("notify", help="Dispatch pending alerts to notifiers")

    sub.add_parser("stats", help="Show storage statistics")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings()
    db_path = args.db or settings.db_path

    with MessageStore(db_path) as store:
        if args.command == "collect":
            channels = args.channels or settings.channels
            if not channels:
                print("No channels given (--channels or DW_TELEGRAM_CHANNELS).")
                return 1
            monitor = TelegramMonitor(store, channels)
            new = monitor.run_once()
            engine = _engine(settings, store)
            engine.scan_recent(limit=new or 50)
            print(f"Stored {new} new Telegram messages.")

        elif args.command == "collect-darkweb":
            urls = args.urls or settings.urls
            if not urls:
                print("No URLs given (--urls or DW_DARKWEB_URLS).")
                return 1
            proxy = args.tor_proxy or settings.tor_proxy
            monitor = DarkWebMonitor(store, urls, socks_proxy=proxy)
            new = monitor.run_once()
            print(f"Stored {new} new dark-web messages.")

        elif args.command == "search":
            engine = SearchEngine(store)
            results = engine.search(args.query, channel=args.channel, limit=args.limit)
            print(json.dumps([m.model_dump(mode="json") for m in results], indent=2))

        elif args.command == "alerts":
            engine = _engine(settings, store, rules_path=args.rules)
            found = engine.scan_recent(limit=args.limit)
            print(f"{len(found)} alert(s) raised.")

        elif args.command == "notify":
            notifiers = []
            if settings.webhook_url:
                notifiers.append(WebhookNotifier(settings.webhook_url))
            sent = dispatch_pending(store, notifiers or None)
            print(f"Dispatched {sent} alert(s).")

        elif args.command == "stats":
            info = {
                "messages": store.count(),
                "channels": store.channels(),
                "pending_alerts": len(store.pending_alerts()),
            }
            print(json.dumps(info, indent=2))

    return 0


def _engine(settings: Settings, store: MessageStore, rules_path: str | None = None):
    path = rules_path or settings.rules_path
    if Path(path).exists():
        return AlertEngine.from_file(store, path)
    return AlertEngine(store)


if __name__ == "__main__":
    sys.exit(main())
