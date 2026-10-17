# tele-darkwatch

Telegram and dark-web monitoring and search project with collectors, storage, and alerts.

## Architecture

```
src/tele_darkwatch/
├── models.py                  # Message / MatchRule / Alert (pydantic)
├── config.py                  # Settings via DW_* env vars or .env
├── cli.py                     # `darkwatch` command-line entry point
├── daemon.py                  # Continuous collect → alert → notify loop
├── logging_setup.py           # Centralized console/file logging
├── export.py                  # JSON / CSV / NDJSON exports
├── retention.py               # Pruning + vacuum of old data
├── collectors/
│   ├── base.py                # BaseCollector interface
│   ├── telegram_monitor.py    # Public Telegram channels via t/s RSS export
│   └── darkweb_monitor.py     # .onion scraping over a Tor SOCKS5 proxy
├── search/
│   └── engine.py              # FTS5 full-text search (LIKE fallback)
├── storage/
│   ├── message_store.py       # Thread-safe SQLite store with dedup + migrations
│   └── event_log.py           # Persistent audit log of pipeline activity
└── alerts/
    ├── engine.py              # Keyword rules -> persisted alerts
    ├── regex_engine.py        # Regex IOC rules (CVE/onion/IP/email/BTC) + severity
    ├── notifiers.py           # Console / webhook / email dispatch
    └── rate_limiter.py        # Cooldown suppression for repeat alerts
```

## Install

```bash
pip install -e ".[dev]"
```

Requires Python ≥ 3.10. Dependencies: httpx (+ socksio for Tor), pydantic, pydantic-settings.

## Usage

```bash
# Collect from public Telegram channels (no API key needed — uses t/s RSS export)
darkwatch collect --channels dcg345 bellingcat

# Scrape onion sites (requires a running Tor daemon on 127.0.0.1:9050)
darkwatch collect-darkweb --urls http://example.onion/feed

# Search everything collected so far
darkwatch search "drone strike" --channel dcg345

# Run keyword alert rules over recent messages
cp rules.example.json rules.json
darkwatch alerts --rules rules.json

# Send pending alerts to console (and DW_WEBHOOK_URL / SMTP email if configured)
darkwatch notify

# Manually insert an item into the archive (dedup + keyword rules applied)
darkwatch add "new CVE-2025-1234 exploit published" --channel analyst-note

# Regex IOC scan — extracts CVEs, .onion addresses, IPs, emails, BTC wallets
# into alert metadata (custom patterns via regex_rules.example.json / DW_REGEX_RULES_PATH)
darkwatch ioc-scan

# Audit trail of daemon cycles and dispatches
darkwatch events --limit 20

# Export the archive (json | csv | ndjson), stdout or file
darkwatch export --format csv --output messages.csv

# Delete messages older than 30 days (optionally vacuum the DB)
darkwatch prune --older-than-days 30 --vacuum

# Continuous monitoring: collect → alert → notify loop (Ctrl-C to stop)
darkwatch daemon --interval 120

# Storage statistics
darkwatch stats
```

Configuration can live in a `.env` file (see `.env.example`), all variables prefixed `DW_`.

## Docker / deployment

A `Dockerfile` bundles Tor so dark-web collection works out of the box, and
`docker-compose.yml` runs the daemon continuously with a persistent `./data`
volume for the SQLite database and `rules.json`:

```bash
cp rules.example.json data/rules.json
docker compose up -d --build
docker compose logs -f darkwatch
```

`.github/workflows/ci.yml` runs lint + tests on Python 3.10–3.13 and builds
the image on `main`. A `Makefile` provides shortcuts (`make install`,
`make test`, `make lint`, `make docker-up`, …).

## Architecture details

- **Daemon** (`daemon.py`) — signal-safe poll loop combining collectors, the
  alert engine and dispatch; per-cycle stats are logged via the centralized
  `logging_setup` (stderr + optional `DW_LOG_FILE`).
- **Rate limiting** (`alerts/rate_limiter.py`) — repeat notifications for the
  same `rule|channel` are suppressed during `DW_ALERT_COOLDOWN` seconds; the
  alert stays pending and is retried on the next cycle.
- **Retention** (`retention.py`) — `prune()` deletes rows older than
  `DW_RETENTION_DAYS` (automatic inside the daemon loop) and `vacuum()`
  reclaims space.
- **Export** (`export.py`) — JSON / CSV / NDJSON serialization of stored
  messages for feeding downstream tools.
- **Notifiers** — console, Slack-compatible webhook, and SMTP email
  (`EmailNotifier`, STARTTLS or implicit TLS; enabled via `DW_SMTP_HOST` +
  `DW_EMAIL_TO`).
- **Regex IOC engine** (`alerts/regex_engine.py`) — named-capture patterns for
  CVEs, .onion addresses, IPv4, emails and BTC wallets with per-rule severity
  (1–5); extracted indicators are stored in the alert's `metadata`. Custom
  pattern files use the shape of `regex_rules.example.json`.
- **Audit log** (`storage/event_log.py`) — every daemon cycle and notification
  dispatch is persisted to an `events` table (`darkwatch events` to inspect).
- **Schema migrations** — opening an older database upgrades it in place
  (e.g. adds `alerts.metadata`); a `meta` key/value table tracks versions.
- **Leak analysis (v0.4)** — `entities.py` extracts emails, credentials, API
  keys and crypto wallets via tuned regexes; `leak_parser.py` unpacks
  infostealer archives **in memory** (`io.BytesIO`) with magic-byte guards
  that drop executables before they touch disk; `cookies.py` de-serializes
  Netscape/JSON cookie logs and flags unexpired enterprise sessions;
  `watchlist.py` scores exposure against your corporate domains;
  `sanitize.py` masks PII at the storage boundary (GDPR/CCPA);
  `session_check.py` performs read-only liveness pings for leaked tokens;
  `channel_discovery.py` recursively harvests new `t.me` links from chatter;
  `health.py` exposes Prometheus-format metrics and deadman checks.
- **Anti-friction & hardening (v0.5)** — `session_pool.py` rotates Telegram
  accounts with per-minute rate caps and quarantine; `proxy_rotator.py`
  cycles residential/SOCKS endpoints; `fingerprint.py` mimics browser TLS/UA
  profiles; `dedup.py` catches re-packaged leaks with SHA-256 + fuzzy hashes;
  `queue.py` is a durable SQLite-backed producer/consumer work queue
  (Kafka-shaped interface without the ops burden); `ocr.py` and `yara_scan.py`
  are optional-dependency adapters that no-op cleanly when
  `pytesseract`/`yara-python` are absent.
- **Resolution & response (v0.6)** — `graph.py` builds an entity co-occurrence
  graph over stored messages: `cluster()` grafts personal <-> corporate
  identities across unrelated breaches and `risk_score()` computes a
  blast-radius score; `soar.py` runs incident playbooks with **dynamic
  severity scoring** (live enterprise session => P0, expired => downgraded),
  persists tickets, and posts SIEM/SOC webhooks (`DW_SOAR_WEBHOOK_URL`);
  `nlp_classify.py` labels chatter offline (credential dump / ransomware
  victim / malware source / scam-ad) and drops high-confidence noise before
  ingestion; `collectors/telegram_userbot.py` (Telethon, optional `[telegram]`
  extra) polls private channels through the session pool with randomized
  organic pacing; `collectors/darkweb_async.py` crawls onion sites
  concurrently over Tor via aiohttp with an optional Playwright fallback.

New CLI commands (v0.6): `graph`, `risk`, `soar-run`, `tickets`, `classify`,
`collect-userbot`, `crawl-async`. Install heavy integrations on demand:
`pip install -e ".[telegram]"`, `".[darkweb]"`, `".[playwright]"`, `".[ocr]"`,
`".[yara]"` — the core suite stays fully offline and CI-fast.

## Development

```bash
pip install -e ".[dev]"
pytest              # run the test suite
ruff check src tests
```

If your environment has an incompatible third-party pytest plugin installed
(e.g. old `libtmux`), disable it with `pytest -p no:libtmux`.

## Notes & safety

- Only **public** Telegram channels and lawful dark-web sources are supported.
- The dark-web collector degrades gracefully when Tor is unreachable.
- Duplicate suppression: identical channel+content pairs are stored once (SHA-256 dedup key).
