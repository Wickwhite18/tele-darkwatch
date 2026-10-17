"""Command-line interface for tele-darkwatch.

Usage examples::

    darkwatch collect --channels dcg345 bellingcat
    darkwatch collect-darkweb --urls http://exampleonionx.onion
    darkwatch search "drone strike" --channel dcg345
    darkwatch alerts --rules rules.json
    darkwatch notify
    darkwatch export --format csv --output messages.csv
    darkwatch prune --older-than-days 30
    darkwatch daemon
    darkwatch stats
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import WebhookNotifier, dispatch_pending
from tele_darkwatch.alerts.rate_limiter import RateLimiter
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.export import export_messages
from tele_darkwatch.logging_setup import configure_logging, get_logger
from tele_darkwatch.retention import prune, vacuum
from tele_darkwatch.search.engine import SearchEngine
from tele_darkwatch.storage.message_store import MessageStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="darkwatch", description=__doc__)
    parser.add_argument("--db", default=None, help="SQLite database path")
    parser.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING/ERROR")
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

    p = sub.add_parser("export", help="Export stored messages (json|csv|ndjson)")
    p.add_argument("--format", choices=["json", "csv", "ndjson"], default="json")
    p.add_argument("--channel", default=None)
    p.add_argument("--limit", type=int, default=10000)
    p.add_argument("--output", default=None, help="Write to file instead of stdout")

    p = sub.add_parser("prune", help="Delete messages older than N days")
    p.add_argument("--older-than-days", type=float, default=30.0)
    p.add_argument("--include-alerts", action="store_true",
                   help="Also delete alerts older than the cutoff")
    p.add_argument("--vacuum", action="store_true", help="Reclaim disk space after pruning")

    p = sub.add_parser("daemon", help="Run continuous collect/alert/notify loop")
    p.add_argument("--interval", type=int, default=None, help="Seconds between cycles")

    sub.add_parser("stats", help="Show storage statistics")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings()
    if args.log_level:
        settings.log_level = args.log_level
    configure_logging(settings.log_level, settings.log_file or None)
    log = get_logger("cli")
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
            limiter = RateLimiter(cooldown=float(settings.alert_cooldown))
            sent = dispatch_pending(store, notifiers or None, limiter)
            print(f"Dispatched {sent} alert(s).")

        elif args.command == "export":
            messages = store.recent(limit=args.limit, channel=args.channel)
            data = export_messages(messages, fmt=args.format)
            if args.output:
                Path(args.output).write_text(data, encoding="utf-8")
                print(f"Exported {len(messages)} message(s) to {args.output}")
            else:
                print(data)

        elif args.command == "prune":
            removed = prune(
                store,
                older_than_days=args.older_than_days,
                keep_alerts=not args.include_alerts,
            )
            if args.vacuum:
                vacuum(store)
            print(json.dumps(removed, indent=2))

        elif args.command == "daemon":
            from tele_darkwatch.daemon import Daemon

            if args.interval:
                settings.poll_interval = args.interval
            log.info("starting daemon on %s", db_path)
            Daemon(settings, store=store).run_forever()

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
