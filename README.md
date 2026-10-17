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
├── storage/
│   └── message_store.py       # Thread-safe SQLite store with dedup
├── search/
│   └── engine.py              # FTS5 full-text search (LIKE fallback)
└── alerts/
    ├── engine.py              # Keyword rules -> persisted alerts
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

# Send pending alerts to console (and DW_WEBHOOK_URL if set)
darkwatch notify

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
  (`EmailNotifier`, STARTTLS or implicit TLS).

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
