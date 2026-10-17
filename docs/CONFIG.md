# ⚙️ Configuration reference

All settings load from environment variables (prefix `DW_`) or a `.env` file in
the working directory — see [`../.env.example`](../.env.example). Precedence:
CLI flags > environment > `.env` > defaults. Every value is validated on load;
bad input produces a friendly error, not a stack trace.

## Core

| Variable | Default | Description |
|---|---|---|
| `DW_DB_PATH` | `darkwatch.db` | SQLite database file (created + migrated on first open) |
| `DW_LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` \| `CRITICAL` |
| `DW_LOG_FILE` | *(unset)* | Optional log file path in addition to stderr |
| `DW_ALERT_COOLDOWN` | `300` | Seconds before the same `rule\|channel` alert may re-notify |
| `DW_RETENTION_DAYS` | `0` (disabled) | Daemon auto-prunes messages older than this each cycle when > 0 |

## Collection

| Variable | Default | Description |
|---|---|---|
| `DW_TELEGRAM_CHANNELS` | *(empty)* | Comma-separated default channel list for daemon mode |
| `DW_DARKWEB_URLS` | *(empty)* | Comma-separated onion URLs polled by the daemon |
| `DW_TOR_PROXY` | `socks5h://127.0.0.1:9050` | SOCKS5 endpoint for `.onion` traffic |
| `DW_POLL_INTERVAL` | `300` | Seconds between daemon cycles (`--interval` overrides) |
| `DW_TELEGRAM_API_ID` / `DW_TELEGRAM_API_HASH` | `0` / *(unset)* | Required only for the Telethon userbot extra |
| `DW_NLP_TRIAGE` | `true` | Drop high-confidence scam/ad chatter before indexing |
| `DW_NLP_DROP_THRESHOLD` | `0.5` | Confidence at/above which a `scam_or_ad` label is dropped |
| `DW_DISCOVERY_ENABLED` | `false` | Auto channel-sourcing inside the daemon loop |
| `DW_OCR_ENABLED` | `false` | Route message media through tesseract if installed |
| `DW_YARA_RULES_PATH` | *(unset)* | Directory of `.yar` rules for log scanning |

## Alerting & response

| Variable | Default | Description |
|---|---|---|
| `DW_RULES_PATH` | `rules.json` | Keyword rules file (shape: `rules.example.json`) |
| `DW_REGEX_RULES_PATH` | built-in set | Custom IOC patterns (shape: `regex_rules.example.json`) |
| `DW_ALERT_WEBHOOK_URL` | *(unset)* | Slack-compatible webhook for alert dispatch |
| `DW_SMTP_HOST` (+ `DW_SMTP_PORT`, `DW_SMTP_USER`, `DW_SMTP_PASSWORD`, `DW_EMAIL_SENDER`, `DW_EMAIL_TO`) | *(unset)* | Enables SMTP email notifier (STARTTLS via `DW_SMTP_STARTTLS`) |
| `DW_SOAR_WEBHOOK_URL` | *(unset)* | SIEM/SOC endpoint receiving playbook tickets |
| `DW_CORPORATE_DOMAINS` | *(empty)* | Protected corporate domains for exposure scoring & P0 escalation |

## Anti-friction & hardening (v0.5)

| Variable | Default | Description |
|---|---|---|
| `DW_PROXY_POOL` / `DW_PROXY_POOL_FILE` | *(unset)* | Residential/SOCKS proxies (comma list or one-per-line file) |
| `DW_SESSION_DIR` | `sessions` | Directory holding Telegram `.session` files for the pool |
| `DW_SESSION_RATE_PER_MIN` | `30` | Max requests per account per minute before throttling |
| `DW_JITTER_MIN` / `DW_JITTER_MAX` | `5.0` / `15.0` | Randomized organic delay range between fetches (seconds) |
| `DW_HEALTH_PROM_FILE` | *(unset)* | Optional path where the daemon writes a Prometheus text snapshot |

## UI / accessibility / environment adaptability

| Variable | Effect |
|---|---|
| `DW_UI_PLAIN=1` | Force plain text even on a TTY (no ANSI codes at all) |
| `NO_COLOR=1` or `DW_NO_COLOR=1` | Disable color, keep tables/layout (accessibility standard) |
| `DW_JSON=1` | Machine-readable JSON output for every command (pipes into jq/SIEM) |
| non-TTY stdout | Plain/machine mode engages **automatically** when piped or redirected |
| `TERM=dumb` | Same as `DW_UI_PLAIN=1` |

Screen-reader note: plain mode emits one stable line per record with `[OK]` /
`[WARN]` / `[ERROR]` prefixes instead of visual icons.

## Worked examples

```bash
# One-off override without touching .env
DW_DB_PATH=/srv/dw/monitor.db DW_ALERT_COOLDOWN=60 darkwatch daemon

# Persistent setup
cat > .env <<'EOF'
DW_DB_PATH=/srv/dw/monitor.db
DW_CORPORATE_DOMAINS=corp.example,brand.example
DW_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/XXX
DW_RETENTION_DAYS=90
EOF
darkwatch daemon --interval 60

# SIEM shipper sidecar: everything JSON, no color
DW_JSON=1 NO_COLOR=1 darkwatch events --limit 100 | vector add
```

🏠 Back to [README](../README.md) · 📖 See also [RECIPES](RECIPES.md)
