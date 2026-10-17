# tele-darkwatch

Telegram and dark-web monitoring and search project with collectors, storage, and alerts.

## Architecture

```
src/tele_darkwatch/
├── models.py                  # Message / MatchRule / Alert (pydantic)
├── config.py                  # Settings via DW_* env vars or .env
├── cli.py                     # `darkwatch` command-line entry point
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
    └── notifiers.py           # Console + Slack-compatible webhook dispatch
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

# Storage statistics
darkwatch stats
```

Configuration can live in a `.env` file (see `.env.example`), all variables prefixed `DW_`.

## Development

```bash
pytest            # run the test suite
```

## Notes & safety

- Only **public** Telegram channels and lawful dark-web sources are supported.
- The dark-web collector degrades gracefully when Tor is unreachable.
- Duplicate suppression: identical channel+content pairs are stored once (SHA-256 dedup key).
