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
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from tele_darkwatch import __version__
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
from tele_darkwatch.ui import get_ui, SEVERITY_COLORS
from tele_darkwatch.validation import ValidationError


def SEV_STYLE(severity: int) -> str:
    """Map an alert severity (1-5) to a rich colour name."""
    try:
        return SEVERITY_COLORS.get(int(severity), "white")
    except (TypeError, ValueError):
        return "white"


def _alert_sev(alert) -> int:
    """Best-effort severity for an Alert (metadata wins, default 3)."""
    meta = getattr(alert, "metadata", None) or {}
    for key in ("severity", "sev"):
        try:
            return max(1, min(5, int(meta.get(key, 3))))
        except (TypeError, ValueError):
            pass
    return 3


def _validate_channels(names):
    from tele_darkwatch.validation import valid_channels

    return valid_channels(names)


def _validate_urls(urls):
    from tele_darkwatch.validation import valid_urls

    return valid_urls(urls)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="darkwatch", description=__doc__)
    parser.add_argument("--db", default=None, help="SQLite database path")
    parser.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING/ERROR")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Machine-readable output for compatible commands "
                             "(also honored by subcommands of the same name)")
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
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Print summary line instead of table (compat)")

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
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Raw JSON output")
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

    # ---- v0.6: graph resolution / SOAR / NLP triage -----------------------
    p = sub.add_parser("graph", help="Entity co-occurrence cluster around an identity")
    p.add_argument("identity")
    p.add_argument("--hops", type=int, default=2)

    p = sub.add_parser("risk", help="Graph-based blast-radius risk score for an identity")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Suppress severity banner; print only JSON")
    p.add_argument("identity")

    p = sub.add_parser("soar-run", help="Execute SOAR playbooks over unprocessed alerts")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Raw JSON output of playbook results")
    p.add_argument("--webhook", default=None, help="Override DW_SOAR_WEBHOOK_URL")

    p = sub.add_parser("tickets", help="List incident tickets opened by the SOAR engine")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Raw JSON output")

    p = sub.add_parser("classify", help="NLP-triage a text (label + scores)")
    p.add_argument("text")

    p = sub.add_parser("collect-userbot", help="Telethon userbot collection (optional dep)")
    p.add_argument("--api-id", type=int, default=None)
    p.add_argument("--api-hash", default=None)
    p.add_argument("--channels", nargs="*", default=None)

    p = sub.add_parser("crawl-async", help="Concurrent aiohttp-over-Tor crawl (optional dep)")
    p.add_argument("--urls", nargs="*", default=None)
    p.add_argument("--tor-proxy", default=None, help="host:port SOCKS5 (default 127.0.0.1:9050)")

    p = sub.add_parser("stats", help="Show storage statistics")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Raw JSON output")

    p = sub.add_parser("dashboard", help="Interactive color-coded menu dashboard")
    p.add_argument("--commands", default=None,
                   help="Comma-separated action keys to run non-interactively (e.g. '9,h,q')")

    parser.add_argument("--version", action="version",
                        version=f"darkwatch {__version__}")
    return parser


def _extract_global_flags(parser, argv):
    """Pull --db/--log-level out of *argv* wherever they appear.

    Returns (remaining_argv, overrides_dict). Handles both
    `darkwatch --db x sub ...` and `darkwatch sub ... --db x`.
    """
    if argv is None:
        argv = sys.argv[1:]
    remaining: list[str] = []
    overrides: dict[str, object] = {}
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
        if tok == "--json":
            # Machine-readable mode is a global switch; subcommands that define
            # their own --json keep working, and ones that don't inherit it here.
            overrides["json_output"] = True
            i += 1
            continue
        remaining.append(tok)
        i += 1
    return remaining, overrides


def _machine_mode() -> bool:
    """True when stdout is not an interactive terminal or a machine-readable
    mode is requested (DW_UI_PLAIN / DW_JSON).  In that case commands emit
    stable, parseable output instead of decorative tables."""
    if os.environ.get("DW_UI_PLAIN") or os.environ.get("DW_JSON"):
        return True
    try:
        return not sys.stdout.isatty()
    except Exception:
        return True


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    # Global flags may be supplied after the subcommand (e.g. `queue --publish ... --db x`);
    # split them out so argparse doesn't reject them as unrecognized.
    argv, global_overrides = _extract_global_flags(parser, argv)
    args = parser.parse_args(argv)
    for key, value in global_overrides.items():
        setattr(args, key, value)
    if _machine_mode():
        args.json_output = True
    ui = get_ui()
    settings = Settings()
    if args.log_level:
        try:
            from tele_darkwatch.validation import valid_log_level

            settings.log_level = valid_log_level(args.log_level)
        except ValidationError as exc:
            ui.error(str(exc))
            return 2
    configure_logging(settings.log_level, settings.log_file or None)
    log = get_logger("cli")
    db_path = args.db or settings.db_path

    try:
        return _dispatch(args, settings, db_path, ui, log, main)
    except ValidationError as exc:
        ui.error(f"input error: {exc}")
        return 2
    except SystemExit:
        raise
    except KeyboardInterrupt:
        ui.warn("Interrupted.")
        return 130
    except Exception as exc:  # comprehensive top-level guard
        log.exception("unhandled error in %s", args.command)
        ui.error(f"{type(exc).__name__}: {exc}")
        return 1


def _dispatch(args, settings: Settings, db_path: str, ui, log, cli_main) -> int:
    with MessageStore(db_path) as store:
        if args.command == "collect":
            channels = _validate_channels(args.channels or settings.channels)
            if not channels:
                ui.warn("No channels given (--channels or DW_TELEGRAM_CHANNELS).")
                return 1
            monitor = TelegramMonitor(store, channels)
            with ui.spinner("Polling Telegram channels…"):
                new = monitor.run_once()
            engine = _engine(settings, store)
            engine.scan_recent(limit=new or 50)
            ui.success(f"Stored {new} new Telegram message(s).")

        elif args.command == "collect-darkweb":
            urls = _validate_urls(args.urls or settings.urls)
            if not urls:
                ui.warn("No URLs given (--urls or DW_DARKWEB_URLS).")
                return 1
            proxy = args.tor_proxy or settings.tor_proxy
            monitor = DarkWebMonitor(store, urls, socks_proxy=proxy)
            with ui.spinner("Scraping onion sites over Tor…"):
                new = monitor.run_once()
            ui.success(f"Stored {new} new dark-web message(s).")

        elif args.command == "search":
            from tele_darkwatch.validation import require_nonempty as _rne

            _rne(args.query, "query", max_len=512)
            engine = SearchEngine(store)
            results = engine.search(args.query, channel=args.channel, limit=args.limit)
            ui.table(f"Search results — {len(results)} hit(s)",
                     ["ID", "Time", "Channel", "Content"],
                     [[m.id, m.timestamp.strftime("%Y-%m-%d %H:%M"),
                       m.channel, (m.content[:70] + "…") if len(m.content) > 70 else m.content]
                      for m in results])

        elif args.command == "alerts":
            engine = _engine(settings, store, rules_path=args.rules)
            found = engine.scan_recent(limit=args.limit)
            if getattr(args, "json_output", False):
                # Compat/machine mode: summary line + JSON payload on stdout
                print(f"{len(found)} alert(s) raised")
                if found:
                    print(json.dumps([a.model_dump(mode="json") for a in found],
                                     indent=2, default=str))
            elif found:
                ui.table(f"{len(found)} alert(s) raised",
                         ["Sev", "Rule", "Channel", "Message"],
                         [[ui.severity_tag(_alert_sev(a)), a.rule, a.channel,
                           (a.message_content or "")[:60]] for a in found],
                         styles=[SEV_STYLE(_alert_sev(a)) for a in found])
            else:
                ui.success("0 alerts raised.")

        elif args.command == "ioc-scan":
            regex_engine = _regex_engine(settings, store, rules_path=args.rules)
            found = regex_engine.scan_recent(limit=args.limit)
            if getattr(args, "json_output", False):
                print(json.dumps([a.model_dump(mode="json") for a in found],
                                 indent=2, default=str))
            elif found:
                ui.table(f"{len(found)} IOC alert(s) raised",
                         ["Sev", "Rule", "Match", "Channel"],
                         [[ui.severity_tag(_alert_sev(a)), a.rule,
                           str((a.metadata or {}).get("match_value", ""))[:40],
                           a.channel] for a in found],
                         styles=[SEV_STYLE(_alert_sev(a)) for a in found])
            else:
                ui.success("0 IOC alerts raised.")
                return 0
            # Keep the human summary visible even in table/json modes.
            print(f"{len(found)} IOC alert(s) raised")

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
            ui.success(f"Dispatched {sent} alert(s) to {len(notifiers)} notifier(s).")

        elif args.command == "add":
            from tele_darkwatch.validation import require_nonempty, valid_channel

            text = require_nonempty(args.text, "message text", max_len=65536)
            channel = valid_channel(args.channel)
            message = Message(
                content=text,
                channel=channel,
                source_type=SourceType.MANUAL,
                timestamp=datetime.now(timezone.utc),
            )
            row_id = store.add_message(message)
            if row_id is None:
                ui.warn("Message already exists (duplicate suppressed).")
            else:
                engine = _engine(settings, store)
                alerts = engine.check_message(message.model_copy(update={"id": row_id}))
                ui.success(f"Stored message id={row_id}, {len(alerts)} alert(s) raised.")

        elif args.command == "export":
            messages = store.recent(limit=args.limit, channel=args.channel)
            data = export_messages(messages, fmt=args.format)
            if args.output:
                with ui.progress_task(f"Exporting {len(messages)} message(s)",
                                      total=max(len(messages), 1)) as cb:
                    Path(args.output).write_text(data, encoding="utf-8")
                    cb(completed=len(messages))
                ui.success(f"Exported {len(messages)} message(s) to {args.output}")
            else:
                print(data)

        elif args.command == "prune":
            from tele_darkwatch.validation import valid_float

            days = valid_float(args.older_than_days, "older-than-days",
                               minimum=0.001, maximum=36500)
            removed = prune(store, older_than_days=days,
                            keep_alerts=not args.include_alerts)
            if args.vacuum:
                vacuum(store)
            ui.table("Prune results", ["Table", "Rows removed"],
                     [[k, v] for k, v in removed.items()])
            if args.vacuum:
                ui.status_line("ok", "VACUUM complete")

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
            ui.success(f"{added} new channel candidate(s); "
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
                    ui.success(f"Wrote health snapshot to {args.output}")
                if getattr(args, "json_output", False):
                    print(json.dumps(snap, indent=2, default=str))
                    return 0
                rows = []
                styles = []
                for k, v in snap.items():
                    bad = isinstance(v, list) and v or "silence" in str(v).lower() and v not in (None, [], {}, 0)
                    rows.append([k, json.dumps(v, default=str)[:90]])
                    styles.append("red" if bad else "green")
                ui.table("Health snapshot", ["Check", "Result"], rows, styles=styles)

        elif args.command == "daemon":
            from tele_darkwatch.daemon import Daemon

            if args.interval:
                settings.poll_interval = args.interval
            log.info("starting daemon on %s", db_path)
            Daemon(settings, store=store).run_forever()

        elif args.command == "events":
            events = store.events.recent(limit=args.limit, category=args.category)
            if getattr(args, "json_output", False):
                print(json.dumps(events, indent=2, default=str))
            else:
                cat_style = {"notify": "yellow", "alert": "red", "collect": "cyan",
                             "prune": "dim", "error": "bold red"}
                ui.table(f"Audit events ({len(events)})",
                         ["Time", "Category", "Detail"],
                         [[e["ts"][:19].replace("T", " "), e["category"],
                           json.dumps(e["detail"])[:80]] for e in events],
                         styles=[cat_style.get(e["category"], "white") for e in events])

        elif args.command == "dedup-check":
            from pathlib import Path as _P
            from tele_darkwatch.dedup import FileDeduplicator
            data = _P(args.file).read_bytes()
            dd = FileDeduplicator(store)
            verdict = dd.check(data)
            if args.register:
                sha = dd.register(data, source=args.file)
                verdict["registered"] = sha
            dup = bool(verdict.get("duplicate")) or bool(verdict.get("known")) \
                or bool(verdict.get("fuzzy_match"))
            if getattr(args, "json_output", False):
                print(json.dumps(verdict, indent=2, default=str))
            else:
                ui.status_line("warn" if dup else "new", "dedup verdict",
                               json.dumps(verdict))

        elif args.command == "queue":
            from pathlib import Path as _P
            from tele_darkwatch.queue import WorkQueue
            q = WorkQueue(str(_P(db_path).with_name("queue.db")))
            if args.publish:
                from tele_darkwatch.validation import valid_json

                jid = q.publish(args.publish[0], valid_json(args.publish[1], "job payload"))
                if getattr(args, "json_output", False):
                    print(json.dumps({"published": jid, "topic": args.publish[0]}))
                else:
                    ui.success(f"Published job {jid} to {args.publish[0]!r}")
            elif args.drain:
                def _handler(payload):  # demo consumer: log the job
                    log.info("queue job: %s", str(payload))
                n = q.work(args.drain, _handler)
                if getattr(args, "json_output", False):
                    print(json.dumps({"drained": n, "topic": args.drain}))
                    print(f"processed {n} job(s)")  # stable lowercase compat line
                else:
                    ui.success(f"Processed {n} job(s) from {args.drain!r}")
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
                pool.add_session(args.add, max_per_minute=getattr(settings, "session_rate_per_min", 30))
            print(json.dumps(pool.status(), indent=2))

        elif args.command == "graph":
            from tele_darkwatch.graph import build_graph

            g = build_graph(store)
            cluster = g.cluster(args.identity, max_hops=args.hops)
            ui.rule(f"Entity graph around {args.identity!r}")
            members = cluster.get("members") or cluster.get("entities") or cluster
            if isinstance(members, dict):
                print(json.dumps(cluster, indent=2))
            else:
                ui.table(f"{len(members)} linked entity(ies)", ["Entity"],
                         [[m] for m in members])

        elif args.command == "risk":
            from tele_darkwatch.graph import build_graph

            g = build_graph(store)
            score = g.risk_score(args.identity)
            if getattr(args, "json_output", False):
                print(json.dumps(score, indent=2, default=str))
                return 0
            val = score.get("score", 0) if isinstance(score, dict) else score
            try:
                sev = 5 if float(val) >= 80 else 4 if float(val) >= 60 \
                    else 3 if float(val) >= 40 else 2 if float(val) >= 20 else 1
            except (TypeError, ValueError):
                sev = 3
            ui.print(f"{ui.severity_tag(sev)} blast-radius risk for "
                     f"[bold]{args.identity}[/]" if not ui.plain else
                     f"[SEV{sev}] blast-radius risk for {args.identity}")
            print(json.dumps(score, indent=2, default=str))

        elif args.command == "soar-run":
            from tele_darkwatch.soar import SOAREngine, process_pending_alerts

            if args.webhook is not None:
                settings.soar_webhook_url = args.webhook
            with ui.spinner("Running SOAR playbooks…"):
                results = process_pending_alerts(store, settings)
            if getattr(args, "json_output", False):
                print(json.dumps(results, indent=2, default=str))
                return 0
            for r in results:
                sev_word = str(r["severity"]).upper()
                sev_num = {"P0": 5, "P1": 4, "P2": 3, "P3": 2, "P4": 1}.get(sev_word, 3)
                ui.print(f"{ui.severity_tag(sev_num)} {r['alert']} -> ticket {r['ticket']}"
                         f" [dim](webhook delivered: {r['delivered']})[/]"
                         if not ui.plain else
                         f"[{sev_word}] {r['alert']} -> ticket {r['ticket']} "
                         f"(webhook delivered: {r['delivered']})")
            ui.success(f"{len(results)} playbook run(s).")

        elif args.command == "tickets":
            from tele_darkwatch.soar import SOAREngine

            tickets = SOAREngine(store).list_tickets()
            if getattr(args, "json_output", False):
                print(json.dumps(tickets, indent=2, default=str))
            elif tickets:
                ui.table(f"Incident tickets ({len(tickets)})",
                         ["ID", "Severity", "Alert", "Status"],
                         [[t.get("id", "?"), t.get("severity", "?"),
                           str(t.get("alert", ""))[:50], t.get("status", "open")]
                          for t in tickets],
                         styles=[SEV_STYLE(
                             {"P0": 5, "P1": 4, "P2": 3, "P3": 2}.get(
                                 str(t.get("severity", "")).upper(), 2))
                             for t in tickets])
            else:
                ui.success("No incident tickets.")

        elif args.command == "classify":
            from tele_darkwatch.nlp_classify import classify, should_index

            res = classify(args.text)
            keep = should_index(res, settings.nlp_drop_threshold)
            label_color = {"valid_credential_dump": "bold red",
                           "ransomware_victim": "red",
                           "malware_source": "orange3",
                           "scam_or_ad": "dim"}.get(res.label, "cyan")
            if ui.plain:
                print(json.dumps({"label": res.label, "scores": res.scores,
                                  "index": keep}, indent=2))
            else:
                ui.console.print(f"[bold {label_color}]{res.label}[/]  "
                                 f"{'[green]INDEX[/]' if keep else '[dim]DROP[/]'}")
                ui.table("NLP scores", ["Label", "Score"],
                         sorted(res.scores.items(), key=lambda kv: -kv[1]))

        elif args.command == "collect-userbot":
            from pathlib import Path as _P

            from tele_darkwatch.collectors.telegram_userbot import collect_blocking

            api_id = args.api_id or settings.telegram_api_id
            api_hash = args.api_hash or settings.telegram_api_hash
            channels = _validate_channels(args.channels or settings.channels)
            sessions = sorted(str(p) for p in _P(settings.session_dir).glob("*.session"))
            if not (api_id and api_hash and sessions and channels):
                ui.warn("Need api_id/api_hash, *.session files in DW_SESSION_DIR,"
                        " and channels (--channels or DW_TELEGRAM_CHANNELS).")
                return 1
            with ui.spinner(f"Userbot collection across {len(sessions)} session(s)…"):
                msgs = collect_blocking(api_id=api_id, api_hash=api_hash,
                                        sessions=sessions, channels=channels)
            new = store.add_messages(msgs)
            ui.success(f"Fetched {len(msgs)} message(s); stored {new} new.")

        elif args.command == "crawl-async":
            from tele_darkwatch.collectors.darkweb_async import crawl_blocking

            urls = _validate_urls(args.urls or settings.urls)
            if not urls:
                ui.warn("No URLs given (--urls or DW_DARKWEB_URLS).")
                return 1
            proxy = (args.tor_proxy or settings.tor_proxy).removeprefix("socks5h://")
            with ui.progress_task(f"Crawling {len(urls)} onion site(s)", total=len(urls)):
                msgs = crawl_blocking(urls, socks_proxy=proxy)
            new = store.add_messages(msgs)
            ui.success(f"Crawled {len(urls)} onion URL(s); stored {new} new message(s).")

        elif args.command == "stats":
            info = {
                "messages": store.count(),
                "channels": store.channels(),
                "pending_alerts": len(store.pending_alerts()),
                "entities": store.entities.count(),
                "entity_types": store.entities.counts_by_type(),
                "events": store.events.count(),
            }
            if getattr(args, "json_output", False):
                print(json.dumps(info, indent=2, default=str))
                return 0
            rows = [["messages", info["messages"]],
                    ["entities", info["entities"]],
                    ["pending alerts", info["pending_alerts"]],
                    ["audit events", info["events"]],
                    ["channels", len(info["channels"])]]
            ui.table("Storage statistics", ["Metric", "Value"], rows)
            # Compat/machine-readable key counts (grep-friendly)
            for k, v in info.items():
                if isinstance(v, dict):
                    continue  # already printed inside the JSON dump above
                print(f'"{k}": {json.dumps(v, default=str)}')
            if info["channels"]:
                ui.table("Top channels", ["Channel", "Latest count"],
                         [[c, "—"] for c in list(info["channels"])[:10]])
            if info["entity_types"]:
                ui.table("Entity breakdown", ["Type", "Count"],
                         [[k, v] for k, v in sorted(info["entity_types"].items())])

        elif args.command == "dashboard":
            from tele_darkwatch.dashboard import Dashboard, build_actions

            cmds = [c.strip() for c in args.commands.split(",")] if args.commands else None
            dash = Dashboard(settings, store, build_actions(settings, store, cli_main), ui)
            try:
                return dash.run(commands=cmds)
            except SystemExit as exc:  # nested CLI requested exit
                return int(exc.code or 0)

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
