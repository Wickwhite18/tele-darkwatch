<div align="center">

# 🛰️ tele-darkwatch

**Telegram & dark-web threat monitoring for breach, infostealer-log and credential-leak detection.**

Proactive defense pipeline: collect → dedup → parse → search → alert → respond.

[![CI](https://img.shields.io/github/actions/workflow/status/Wickwhite18/tele-darkwatch/ci.yml?branch=main&logo=githubactions&label=tests)](https://github.com/Wickwhite18/tele-darkwatch/actions)
![Version](https://img.shields.io/badge/version-0.7.0-8A2BE2?logo=python&logoColor=white)
![Python](https://img.shields.io/badge/python-3.10%20~%203.13-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-129%20passing-2ea44f)
![License](https://img.shields.io/badge/license-MIT-f5a623)
![DB](https://img.shields.io/badge/storage-SQLite%20FTS5-003b57?logo=sqlite&logoColor=white)
![Defensive](https://img.shields.io/badge/ops-defensive%20only-blueviolet)

```
╔══════════════════════════════════════════════════════════════════╗
║   [📡 Telegram RSS/userbot]   [🧅 Tor .onion crawler]            ║
│              ╲                       ╱                            │
║               ▼                     ▼                             ║
║        [🧱 Dedup · NLP triage · magic-byte guard]                 ║
║                          │                                        ║
║         [🗄 SQLite + FTS5 index]  [⚙ Durable queue · workers]     ║
║                          │                                        ║
║   [🔎 Search] [🚨 Alerts/IOCs] [🕸 Entity graph] [🎯 SOAR P0–P5]   ║
║                          │                                        ║
║        [📣 Console · Webhook · Slack · Email · SIEM]              ║
╚══════════════════════════════════════════════════════════════════╝
```

*Only public Telegram channels and lawful sources are supported. Built for blue-team / SOC use.*

</div>

---

## ✨ Highlights

| | Capability | Module |
|---|---|---|
| 📡 | **Telegram collection** — public channels via `t/s` RSS (no API key), or private via optional Telethon userbot with session pooling & organic pacing | `collectors/` |
| 🧅 | **Dark-web scraping** — `.onion` over Tor SOCKS5; async aiohttp crawler + optional Playwright fallback | `collectors/darkweb_async.py` |
| 🦠 | **Infostealer log parsing** — Lumma/Stealc/RedLine-style archives unpacked **in memory**, executables dropped by magic-byte guard | `leak_parser.py`, `magic_guard.py` |
| 🔑 | **Credential & IOC extraction** — emails, user:pass pairs, OpenAI/Anthropic/AWS/GitHub keys, BTC/ETH wallets, CVEs, IPs | `entities.py`, `alerts/regex_engine.py` |
| 🍪 | **Cookie/session triage** — Netscape/JSON cookie logs, expiry analysis, read-only liveness pings → live enterprise session = **P0** | `cookies.py`, `session_check.py` |
| 🕸 | **Entity resolution** — co-occurrence graph grafts personal ↔ corporate identities across breaches; blast-radius risk score | `graph.py` |
| 🚨 | **Alerting & SOAR** — keyword + regex rules, cooldown rate-limiting, dynamic severity, persistent tickets, SIEM/SOC webhooks | `alerts/`, `soar.py` |
| 🧹 | **Noise demodulation** — offline NLP classifier drops scam/ad chatter before ingestion | `nlp_classify.py` |
| 🔎 | **Full-text search** — SQLite FTS5 inverted index with LIKE fallback, channel filters | `search/engine.py` |
| 🛡 | **Privacy & OpSec** — GDPR/CCPA PII masking at the storage boundary, ephemeral archive handling, retention/prune/vacuum | `sanitize.py`, `retention.py` |
| 🖥 | **Rich CLI** — colors, progress bars, spinners, tables, interactive dashboard menu; plain/JSON modes for pipes & CI | `ui.py`, `dashboard.py` |
| 📊 | **Observability** — Prometheus-format metrics, deadman health checks, persistent audit event log | `health.py`, `storage/event_log.py` |
| 🐳 | **Deploy anywhere** — Dockerfile bundles Tor; compose runs the daemon; GitHub Actions CI on 3.10–3.13 | `Dockerfile`, `.github/` |

## 🚀 Quick start

```bash
git clone https://github.com/Wickwhite18/tele-darkwatch.git
cd tele-darkwatch
pip install -e ".[dev]"

darkwatch --version          # darkwatch 0.7.0
pytest                       # 129 passed ✅
darkwatch dashboard          # 🎛 interactive menu (colors, timing, tables)
```

**60-second demo** (fully offline):

```bash
darkwatch add "Leaked creds for corp.example: alice@corp.example:Passw0rd! openai key sk-proj-abc123def456ghi789jkl012mno345" --channel test
darkwatch pipeline           # extract entities + score against watchlist
darkwatch ioc-scan           # regex IOC alerts (emails, keys, wallets…)
darkwatch search "alice"     # FTS5 full-text search
darkwatch alerts --rules rules.example.json
darkwatch notify             # dispatch pending alerts (console/webhook/email)
darkwatch stats              # pretty breakdown, or: darkwatch stats --json
```

## 🧭 CLI tour

Every command supports three output modes:

| Mode | How | For |
|---|---|---|
| 🎨 Rich | default in a terminal | humans — colors ✔ ⚠ ✖, severity tags `P0..P5`, progress bars, spinners, tables |
| 📄 Plain | `DW_UI_PLAIN=1`, `NO_COLOR=1`, or piped stdout | logs, cron, scripts |
| 🔧 JSON | `--json` flag or `DW_JSON=1` | jq, SIEM ingestion, automation |

```bash
darkwatch collect --channels dcg345 bellingcat        # spinner + per-channel progress
darkwatch search "CVE-2026-" --channel analyst-note   # table with match highlighting
darkwatch events --limit 20                           # category-colored audit log
darkwatch health                                      # red/green status checks
darkwatch export --format csv --output leak.csv       # progress bar while streaming
DW_JSON=1 darkwatch stats | jq '.messages'            # machine-readable
```

### Command reference

<details>
<summary><b>Collection & ingestion</b></summary>

| Command | Description |
|---|---|
| `collect --channels A B` | Poll public Telegram channels (RSS export, no API key) |
| `collect-darkweb --urls http://x.onion/feed` | Scrape onion sites over Tor (`127.0.0.1:9050`) |
| `crawl-async --urls …` | Concurrent aiohttp Tor crawl (+Playwright fallback, `[playwright]` extra) |
| `collect-userbot --channels …` | Telethon MTProto userbot for private channels (`[telegram]` extra + `DW_TELEGRAM_API_ID/HASH`) |
| `add "text" --channel c` | Manual insert (dedup + rules applied) |
| `parse-archive FILE` | In-memory infostealer zip/tar parse (magic-byte guarded) |
| `parse-cookies FILE` | Netscape/JSON cookie log triage with expiry analysis |
| `pipeline` | Extract entities from new messages, dedup, watchlist scoring |
| `discover` | Recursively harvest new `t.me/…` links from stored chatter |
| `verify-channels` / `channels` | Triage & list discovered channels |
</details>

<details>
<summary><b>Search & analysis</b></summary>

| Command | Description |
|---|---|
| `search "query" [--channel c]` | FTS5 full-text search (LIKE fallback) |
| `entities "query" [--type email]` | Query the entity index (types: email/url/ipv4/btc/eth/api_key) |
| `profile IDENTITY` | Cross-source profile (entity resolution) |
| `graph ENTITY` / `risk ENTITY` | Co-occurrence cluster / blast-radius score |
| `classify TEXT` | Offline NLP label + INDEX/DROP verdict |
| `dedup-check FILE` | SHA-256 + fuzzy hash check against leak history |
| `check-token TOKEN` | Read-only liveness ping for a leaked token |
</details>

<details>
<summary><b>Alerting & response</b></summary>

| Command | Description |
|---|---|
| `alerts --rules rules.json` | Run keyword rules over recent messages |
| `ioc-scan` | Regex IOC scan (CVE/onion/IP/email/BTC/keys) |
| `notify` | Dispatch pending alerts (console/webhook/Slack/SMTP) |
| `soar-run` | Playbooks: graph enrichment, dynamic P-severity, tickets, SIEM webhook |
| `tickets` | List incident tickets (severity-colored) |
| `sanitize` | Mask PII (passwords/cards) in stored messages |
</details>

<details>
<summary><b>Operations</b></summary>

| Command | Description |
|---|---|
| `daemon --interval 120` | Continuous collect→alert→notify loop (Ctrl-C stops cleanly) |
| `queue --publish/--drain/--stats` | Durable producer/consumer work queue |
| `sessions` | Telegram session pool: rotation, rate caps, quarantine |
| `events --limit N` | Audit log of every cycle & dispatch |
| `health [--prometheus]` | Snapshot or Prometheus text exposition |
| `export --format json\|csv\|ndjson` | Archive export to file/stdout |
| `prune --older-than-days 30 [--vacuum]` | Retention enforcement |
| `stats` | Storage/entity/alert metrics |
| `dashboard` | 🎛 Interactive color menu for all of the above |
</details>

## ⚙️ Configuration

Zero-config defaults; everything overridable via env vars or `.env`
([`.env.example`](.env.example) documents all keys):

```ini
DW_DB_PATH=darkwatch.db          # SQLite location
DW_LOG_LEVEL=INFO                # DEBUG..CRITICAL
DW_ALERT_COOLDOWN=300            # seconds between repeat notifications
DW_RETENTION_DAYS=180            # pruning window (set >0 to enable daemon auto-prune)

# Notifications
DW_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...   # Slack-compatible
DW_SMTP_HOST=smtp.corp.example   # + DW_EMAIL_TO for email alerts
DW_SOAR_WEBHOOK_URL=https://siem/collection-endpoint  # SOAR/SIEM playbooks

# Optional integrations
DW_TOR_PROXY=socks5h://127.0.0.1:9050
DW_TELEGRAM_API_ID=...  DW_TELEGRAM_API_HASH=...      # userbot extra
DW_REGEX_RULES_PATH=regex_rules.example.json          # custom IOC patterns
DW_CORPORATE_DOMAINS=corp.example,brand.example       # protected assets
DW_DISCOVERY_ENABLED=true                                 # auto channel-sourcing

# UI / accessibility
DW_UI_PLAIN=1   NO_COLOR=1   DW_JSON=1                # plain, colorless, or JSON output
```

Full table of every setting (defaults + descriptions): [docs/CONFIG.md](docs/CONFIG.md).

## 🐳 Docker

The image bundles a Tor daemon so onion scraping works out of the box:

```bash
cp rules.example.json data/rules.json
docker compose up -d --build
docker compose logs -f darkwatch
```

Data persists in `./data` (SQLite DB, rules, logs). CI (`.github/workflows/ci.yml`)
runs lint + tests on Python 3.10–3.13 and builds the image on `main`.
Makefile shortcuts: `make install · test · lint · docker-up · clean`.

## 🏗 Architecture

```
src/tele_darkwatch/
├── models.py · config.py · cli.py · daemon.py     # core + entry points
├── ui.py · dashboard.py · validation.py           # rich terminal layer (v0.7)
├── collectors/                                    # telegram RSS · tor scraper ·
│                                                  # telethon userbot · async crawler
├── storage/                                       # sqlite store (dedup, migrations)
│                                                  # + audit event log
├── search/engine.py                               # FTS5 + LIKE fallback
├── alerts/                                        # keyword & regex engines,
│                                                  # notifiers, rate limiter
├── leak_parser.py · magic_guard.py · cookies.py   # infostealer log stack
├── entities.py · graph.py · profile logic         # extraction & entity resolution
├── nlp_classify.py · dedup.py · sanitize.py       # noise & privacy layers
├── queue.py · session_pool.py · proxy_rotator.py  # distributed-work & anti-friction
├── ocr.py · yara_scan.py · fingerprint.py         # optional-dependency adapters
├── soar.py · session_check.py · health.py         # response & observability
└── retention.py · export.py · logging_setup.py    # ops utilities
```

Design choices: **SQLite+FTS5** instead of OpenSearch/Kafka/Neo4j keeps the whole
stack single-binary and CI-offline while exposing Kafka-shaped interfaces
(`queue.py`) and graph APIs (`graph.py`) so heavier backends can be swapped in.
All risky parsing happens **in memory** with magic-byte guards; nothing executable
touches disk. Telemetry flows one-way: scrapers → store → responders.

## 🧩 Optional extras

```bash
pip install -e ".[telegram]"    # Telethon userbot collector
pip install -e ".[darkweb]"     # aiohttp + socks async crawler
pip install -e ".[playwright]"  # headless browser fallback
pip install -e ".[ocr]"         # pytesseract image OCR adapter
pip install -e ".[yara]"        # yara-python rule scanning
pip install -e ".[dev]"         # pytest, ruff
```

Adapters degrade gracefully — missing deps produce clear install hints, never crashes.

## 🤝 Contributing

Fork → branch → `make test && make lint` → PR. Add tests for new modules
(`tests/` is organized per feature area; 129 tests currently green).
Keep heavy dependencies behind extras and preserve offline CI.

## ⚖️ License & scope

MIT — see [LICENSE](LICENSE). This tool is intended for **defensive security**:
monitoring only public/lawful sources, read-only token validation, in-memory
handling of untrusted artifacts, and PII masking for GDPR/CCPA compliance.
Nothing here automates account-warming, CAPTCHA solving for access, or
interaction with threat actors.

<div align="right"><sub>Built for defenders · <b>v0.7.0</b></sub></div>
