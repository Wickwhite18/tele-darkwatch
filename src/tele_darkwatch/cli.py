"""Command-line interface for tele-darkwatch.

Usage examples::

    darkwatch collect --channels dcg345 bellingcat
    darkwatch collect-darkweb --urls http://exampleonionx.onion
    darkwatch search "drone strike" --channel dcg345
    darkwatch alerts --rules rules.json
    darkwatch ioc-scan            # regex IOC extraction (CVEs, onion addr…)
    darkwatch notify
    darkwatch export --format csv --output messages.csv
    darkwatch prune --older-than-days 30
    darkwatch events             # audit log of pipeline activity
    darkwatch add "text" --channel manual
    darkwatch daemon
    darkwatch stats
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import (
    ConsoleNotifier,
    EmailNotifier,
    WebhookNotifier,
    dispatch_pending,
)
from tele_darkwatch.alerts.rate_limiter import RateLimiter
from tele_darkwatch.alerts.regex_engine import RegexAlertEngine, default_regex_rules
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.export import export_messages
from tele_darkwatch.logging_setup import configure_logging, get_logger
from tele_darkwatch.models import Message, SourceType
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

    p = sub.add_parser(
        "ioc-scan",
        help="Regex IOC scan (CVEs, onion addresses, IPs, emails, BTC)",
    )
    p.add_argument("--rules", default=None,
                   help="Path to RegexRule JSON file (default: built-in patterns)")
    p.add_argument("--limit", type=int, default=200)

    sub.add_parser("notify", help="Dispatch pending alerts to notifiers")

    p = sub.add_parser("add", help="Manually insert a message into the archive")
    p.add_argument("text")
    p.add_argument("--channel", default="manual")

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

    p = sub.add_parser("pipeline", help="Extract entities from new messages (dedup + watchlist)")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--no-alerts", action="store_true")

    p = sub.add_parser("entities", help="Search the entity index")
    p.add_argument("query", nargs="?", default=None)
    p.add_argument("--type", default=None,
                   help="email|url|ipv4|btc_address|eth_address|api_key")
    p.add_argument("--top", action="store_true", help="Show most-repeated entities")
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("profile", help="Cross-source profile for an identity (entity resolution)")
    p.add_argument("identity")

    p = sub.add_parser("parse-archive", help="In-memory infostealer archive parse (zip/tar)")
    p.add_argument("path")
    p.add_argument("--json", action="store_true", help="Dump full entity list")

    p = sub.add_parser("parse-cookies", help="Parse Netscape/JSON cookie file & triage sessions")
    p.add_argument("path")

    p = sub.add_parser("discover", help="Scan stored chatter for new t.me channels")
    p.add_argument("--limit", type=int, default=500)

    p = sub.add_parser("verify-channels", help="Triage pending discovered channels (network)")
    p.add_argument("--max", type=int, default=10)

    sub.add_parser("channels", help="List discovered channels and their status")

    p = sub.add_parser("sanitize", help="Mask PII (passwords/cards) in stored messages")
    p.add_argument("--domains", nargs="*", default=None,
                   help="Corporate domains to keep verbatim (default: DW_CORPORATE_DOMAINS)")

    p = sub.add_parser("check-token", help="Read-only liveness ping for a leaked token")
    p.add_argument("token")

    p = sub.add_parser("health", help="Pipeline health snapshot / Prometheus text")
    p.add_argument("--prometheus", action="store_true")
    p.add_argument("--hours", type=float, default=24.0)
    p.add_argument("--output", default=None, help="Write metrics to file")

    p = sub.add_parser("daemon", help="Run continuous collect/alert/notify loop")
    p.add_argument("--interval", type=int, default=None, help="Seconds between cycles")

    p = sub.add_parser("events", help="Show the audit/event log")
    p.add_argument("--category", default=None)
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("dedup-check", help="Hash-check a leak file against history (SHA-256 + fuzzy)")
    p.add_argument("file", help="Path to archive/combo list")
    p.add_argument("--register", action="store_true", help="Record the file in the dedup index")

    p = sub.add_parser("queue", help="Inspect or drain the durable work queue")
    p.add_argument("--drain", default=None, metavar="QUEUE", help="Process pending jobs in QUEUE")
    p.add_argument("--publish", nargs=2, metavar=("QUEUE", "JSON"), help="Publish a job")
    p.add_argument("--stats", action="store_true", help="Show queue statistics")

    p = sub.add_parser("sessions", help="Telegram session-pool status")
    p.add_argument("--add", default=None, metavar="SESSION_FILE", help="Register a .session file")

    sub.add_parser("stats", help="Show storage statistics")
    return parser


def _extract_global_flags(parser, argv):
    """Pull --db/--log-level out of *argv* wherever they appear.

    Returns (remaining_argv, overrides_dict). Handles both
    `darkwatch --db x sub ...` and `darkwatch sub ... --db x`.
    """
    if argv is None:
        argv = sys.argv[1:]
    remaining: list[str] = []
    overrides: dict[str, str] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("--db", "--log-level") and i + 1 < len(argv):
            key = "db" if tok == "--db" else "log_level"
            overrides[key] = argv[i + 1]
            i += 2
            continue
        if tok.startswith("--db=") or tok.startswith("--log-level="):
            flag, _, val = tok.partition("=")
            key = "db" if flag == "--db" else "log_level"
            overrides[key] = val
            i += 1
            continue
        remaining.append(tok)
        i += 1
    return remaining, overrides


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    # Global flags may be supplied after the subcommand (e.g. `queue --publish ... --db x`);
    # split them out so argparse doesn't reject them as unrecognized.
    argv, global_overrides = _extract_global_flags(parser, argv)
    args = parser.parse_args(argv)
    for key, value in global_overrides.items():
        setattr(args, key, value)
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

        elif args.command == "ioc-scan":
            regex_engine = _regex_engine(settings, store, rules_path=args.rules)
            found = regex_engine.scan_recent(limit=args.limit)
            print(json.dumps(
                [a.model_dump(mode="json") for a in found], indent=2))
            print(f"{len(found)} IOC alert(s) raised.")

        elif args.command == "notify":
            notifiers = [ConsoleNotifier()]
            if settings.webhook_url:
                notifiers.append(WebhookNotifier(settings.webhook_url))
            if settings.smtp_host and settings.email_to:
                notifiers.append(EmailNotifier(
                    host=settings.smtp_host,
                    port=settings.smtp_port,
                    sender=settings.email_sender,
                    recipients=[e.strip() for e in settings.email_to.split(",") if e.strip()],
                    username=settings.smtp_user or None,
                    password=settings.smtp_password or None,
                    use_tls=settings.smtp_starttls,
                ))
            limiter = RateLimiter(cooldown=float(settings.alert_cooldown))
            sent = dispatch_pending(store, notifiers, limiter)
            store.events.record("notify", dispatched=sent)
            print(f"Dispatched {sent} alert(s).")

        elif args.command == "add":
            message = Message(
                content=args.text,
                channel=args.channel,
                source_type=SourceType.MANUAL,
                timestamp=datetime.now(timezone.utc),
            )
            row_id = store.add_message(message)
            if row_id is None:
                print("Message already exists (duplicate suppressed).")
            else:
                engine = _engine(settings, store)
                alerts = engine.check_message(message.model_copy(update={"id": row_id}))
                print(f"Stored message id={row_id}, {len(alerts)} alert(s) raised.")

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

        elif args.command == "pipeline":
            from tele_darkwatch.pipeline import process_new_messages

            result = process_new_messages(
                store, batch_size=args.limit, raise_alerts=not args.no_alerts,
                corporate_domains=settings.protect_domains or None)
            print(json.dumps(result, indent=2))

        elif args.command == "entities":
            if args.top:
                rows = store.entities.top(etype=args.type, limit=args.limit)
            elif args.query:
                rows = store.entities.search(args.query, etype=args.type,
                                             limit=args.limit)
            else:
                rows = {"counts_by_type": store.entities.counts_by_type(),
                        "total": store.entities.count()}
            print(json.dumps(rows, indent=2, default=str))

        elif args.command == "profile":
            from tele_darkwatch.watchlist import profile_for

            print(json.dumps(profile_for(store, args.identity), indent=2))

        elif args.command == "parse-archive":
            from tele_darkwatch.leak_parser import parse_file

            report = parse_file(args.path)
            summary = {
                "members_seen": report.members_seen,
                "members_parsed": report.members_parsed,
                "dropped_executables": report.dropped_executables,
                "truncated": report.truncated,
                "credential_lines": report.credential_lines,
                "entity_counts": report.entity_counts,
            }
            if args.json:
                summary["entities"] = [e.model_dump(mode="json")
                                       for e in report.entities]
                new_count = store.entities.record_many(report.entities,
                                                       channel="archive")
                summary["new_entities_indexed"] = new_count
            print(json.dumps(summary, indent=2))

        elif args.command == "parse-cookies":
            from tele_darkwatch.cookies import parse_any, triage

            cookies = parse_any(Path(args.path).read_text(encoding="utf-8",
                                                           errors="replace"))
            print(json.dumps({"parsed": len(cookies), **triage(cookies)},
                             indent=2))

        elif args.command == "discover":
            from tele_darkwatch.channel_discovery import ChannelDiscovery

            disc = ChannelDiscovery(store)
            added = disc.discover_from_store(limit=args.limit)
            print(f"{added} new channel candidate(s); "
                  f"{len(disc.pending())} pending total.")

        elif args.command == "verify-channels":
            from tele_darkwatch.channel_discovery import ChannelDiscovery

            disc = ChannelDiscovery(store, threshold=settings.discovery_threshold)
            print(json.dumps(disc.verify_pending(max_candidates=args.max),
                             indent=2))

        elif args.command == "channels":
            from tele_darkwatch.channel_discovery import ChannelDiscovery

            disc = ChannelDiscovery(store)
            print(json.dumps([c.model_dump(mode="json")
                              for c in disc.all_channels], indent=2))

        elif args.command == "sanitize":
            from tele_darkwatch.sanitize import sanitize_store

            domains = args.domains or settings.protect_domains
            print(json.dumps(sanitize_store(store, protect_domains=domains),
                             indent=2))

        elif args.command == "check-token":
            from tele_darkwatch.session_check import validate_token

            res = validate_token(args.token)
            print(json.dumps({"provider": res.provider, "status": res.status,
                              "http_status": res.http_status,
                              "severity": res.severity}, indent=2))

        elif args.command == "health":
            from tele_darkwatch.health import HealthMonitor

            monitor = HealthMonitor(store)
            if args.prometheus:
                text = monitor.prometheus_text(max_silence_hours=args.hours)
                if args.output:
                    Path(args.output).write_text(text, encoding="utf-8")
                    print(f"Wrote metrics to {args.output}")
                else:
                    print(text)
            else:
                snap = monitor.snapshot(max_silence_hours=args.hours)
                if args.output:
                    Path(args.output).write_text(
                        json.dumps(snap, indent=2), encoding="utf-8")
                print(json.dumps(snap, indent=2))

        elif args.command == "daemon":
            from tele_darkwatch.daemon import Daemon

            if args.interval:
                settings.poll_interval = args.interval
            log.info("starting daemon on %s", db_path)
            Daemon(settings, store=store).run_forever()

        elif args.command == "events":
            events = store.events.recent(limit=args.limit, category=args.category)
            print(json.dumps(events, indent=2))

        elif args.command == "dedup-check":
            from pathlib import Path as _P
            from tele_darkwatch.dedup import FileDeduplicator
            data = _P(args.file).read_bytes()
            dd = FileDeduplicator(store)
            verdict = dd.check(data)
            if args.register:
                sha = dd.register(data, source=args.file)
                verdict["registered"] = sha
            print(json.dumps(verdict, indent=2))

        elif args.command == "queue":
            from pathlib import Path as _P
            from tele_darkwatch.queue import WorkQueue
            q = WorkQueue(str(_P(db_path).with_name("queue.db")))
            if args.publish:
                jid = q.publish(args.publish[0], json.loads(args.publish[1]))
                print(f"published job {jid} to {args.publish[0]}")
            elif args.drain:
                def _handler(payload):  # demo consumer: log the job
                    log.info("queue job: %s", payload)
                n = q.work(args.drain, _handler)
                print(f"processed {n} job(s) from {args.drain}")
            else:
                print(json.dumps(q.stats(), indent=2))
            q.close()

        elif args.command == "sessions":
            from pathlib import Path as _P
            from tele_darkwatch.session_pool import SessionPool
            pool = SessionPool(_P(settings.session_dir),
                               max_per_minute=settings.session_rate_per_min,
                               jitter=(settings.jitter_min, settings.jitter_max))
            if args.add:
                pool.add_session(args.add, max_per_minute=settings.session_rate_per_min)
            print(json.dumps(pool.status(), indent=2))

        elif args.command == "stats":
            info = {
                "messages": store.count(),
                "channels": store.channels(),
                "pending_alerts": len(store.pending_alerts()),
                "entities": store.entities.count(),
                "entity_types": store.entities.counts_by_type(),
                "events": store.events.count(),
            }
            print(json.dumps(info, indent=2))

    return 0


def _engine(settings: Settings, store: MessageStore, rules_path: str | None = None):
    path = rules_path or settings.rules_path
    if Path(path).exists():
        return AlertEngine.from_file(store, path)
    return AlertEngine(store)


def _regex_engine(settings: Settings, store: MessageStore, rules_path: str | None = None):
    """Regex IOC engine — loads custom patterns from file, else built-ins."""
    path = rules_path or settings.regex_rules_path
    if path and Path(path).exists():
        return RegexAlertEngine.from_file(store, path)
    return RegexAlertEngine(store, default_regex_rules())


if __name__ == "__main__":
    sys.exit(main())
