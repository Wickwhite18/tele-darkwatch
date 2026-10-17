# 📖 Recipe book — common workflows

Each recipe is copy-paste runnable. All commands work offline unless noted;
add `DW_JSON=1` for machine output, or run `darkwatch dashboard` for the
interactive color menu.

---

## 🥇 Recipe 1 — First-run: watch a corporate domain end-to-end

```bash
pip install -e ".[dev]"
export DW_CORPORATE_DOMAINS="corp.example,brand.example"
cp rules.example.json rules.json          # keyword rules (edit to taste)

# 1. Seed the archive from public Telegram OSINT channels
darkwatch collect --channels bellingcat

# 2. Extract entities + score exposure against the watchlist
darkwatch pipeline

# 3. Regex IOC sweep (emails, keys, wallets, CVEs, IPs, .onion)
darkwatch ioc-scan

# 4. Anything mentioning your domains?
darkwatch search "corp.example"

# 5. Raise alerts and dispatch them
darkwatch alerts --rules rules.json
darkwatch notify                            # console (+ webhook/email if configured)

# 6. Escalate through SOAR playbooks (graph enrichment + tickets)
darkwatch soar-run                          # live enterprise session => P0
darkwatch tickets                           # severity-colored ticket list
```

**Expected output:** color-coded alert table, then tickets tagged
`P1`–`P5`; `darkwatch events` shows the full audit trail of every step.

---

## 🥈 Recipe 2 — Triage an infostealer log drop (safe, in-memory)

A partner shared `redline_dump.zip` containing browser logs. Never unzip it yourself:

```bash
# Parse in memory; magic-byte guard drops any .exe/.scr/.vbs/.lnk automatically
darkwatch parse-archive redline_dump.zip

# Cookie files get expiry analysis; unexpired enterprise cookies escalate
darkwatch parse-cookies cookies_export.netscape

# Is this file one we've already processed (re-packaged leak)?
darkwatch dedup-check redline_dump.zip --register   # SHA-256 + fuzzy hash

# Stitch identities together: personal gmail <-> corporate creds from one victim
darkwatch profile alice@corp.example
darkwatch graph alice@corp.example --hops 2
darkwatch risk alice@corp.example        # blast-radius score with severity tag

# Validate a suspicious token READ-ONLY before paging anyone
darkwatch check-token "$TOKEN"           # 200 OK => P0 incident; 401 => downgrade
```

Raw archives are parsed from `io.BytesIO` buffers only — nothing touches disk.

---

## 🥉 Recipe 3 — Continuous monitoring daemon (deploy)

```bash
# Local long-running loop: collect → alert → notify → prune
darkwatch daemon --interval 120
# Ctrl-C stops cleanly; every cycle lands in the audit log (darkwatch events)

# Or containerized (Tor bundled, persistent ./data volume):
cp rules.example.json data/rules.json
docker compose up -d --build
docker compose logs -f darkwatch
```

Tuning knobs (`.env`):

```ini
DW_ALERT_COOLDOWN=300      # suppress repeat rule|channel notifications
DW_RETENTION_DAYS=180      # auto-pruned each daemon cycle
DW_LOG_FILE=/var/log/darkwatch.log
```

---

## 4️⃣ Recipe 4 — Feed a SIEM / SOC

```bash
# Slack-compatible webhook for alerts
DW_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/XXX darkwatch notify

# SOAR/SIEM playbook endpoint consumed by soar-run tickets
DW_SOAR_WEBHOOK_URL=https://siem.example/collection-endpoint darkwatch soar-run

# Structured exports for splunkforwarder / logstash
darkwatch export --format ndjson --output today.ndjson
DW_JSON=1 darkwatch stats | jq .                 # metrics snapshot
darkwatch health --prometheus --output metrics.prom   # scrape with Prometheus
```

Prometheus alerting example — page when the deadman switch trips:

```yaml
- alert: DarkwatchStale
  expr: time() - darkwatch_last_cycle_timestamp > 3600
  for: 10m
  labels: {severity: warning}
  annotations: {summary: "darkwatch daemon has not completed a cycle in 1h"}
```

---

## 5️⃣ Recipe 5 — Grow the collection surface automatically

```bash
# Harvest new t.me links out of stored chatter
darkwatch discover
darkwatch verify-channels        # samples pending candidates over the network
darkwatch channels               # status-colored list: pending/active/rejected

# Private/restricted channels: Telethon userbot behind a session pool
pip install -e ".[telegram]"
export DW_TELEGRAM_API_ID=... DW_TELEGRAM_API_HASH=...
darkwatch sessions --add acct1.session       # rotate accounts, rate caps, quarantine
darkwatch sessions
darkwatch collect-userbot --channels some_private_feed

# Onion sites at scale: concurrent crawl over Tor
pip install -e ".[darkweb]"                   # aiohttp + aiohttp-socks
darkwatch crawl-async --urls http://market1.onion/ads http://leaksites.onion/
```

Requires a running Tor daemon (`SOCKS5 127.0.0.1:9050`). Only lawful sources.

---

## 6️⃣ Recipe 6 — Noise demodulation & privacy hygiene

```bash
# Preview the offline NLP verdict before relying on the gate
darkwatch classify "BUY VERIFIED COMBOS CHEAP telegram scam link…"
# → label=scam_or_ad  verdict=DROP

# Collect paths drop high-confidence junk when triage is on (default true):
DW_NLP_TRIAGE=false darkwatch collect --channels noisy_channel   # opt out per-run

# GDPR/CCPA masking at the storage boundary (passwords -> hashes, PANs -> XXXX)
darkwatch sanitize

# Retention enforcement
darkwatch prune --older-than-days 30 --vacuum
```

---

## 7️⃣ Recipe 7 — Scripting & automation

```bash
# Everything JSON, everything pipeable
DW_JSON=1 darkwatch alerts | jq -r '.[].rule' | sort -u
DW_JSON=1 darkwatch queue --stats | jq .

# Durable work queue (Kafka-shaped, zero ops) — producer/consumer split
darkwatch queue --publish raw-ingest '{"path":"/tmp/drop.zip","kind":"archive"}'
darkwatch queue --drain raw-ingest          # workers pull & process pending jobs

# Cron: hourly single collection pass + nightly retention
15 * * * * cd /opt/darkwatch && darkwatch collect --channels my_feed >> /var/log/dw-cron.log 2>&1
30 3 * * * cd /opt/darkwatch && darkwatch prune --older-than-days 180 --vacuum

# CI-friendly plain mode (no ANSI even on a TTY)
DW_UI_PLAIN=1 darkwatch stats
NO_COLOR=1 darkwatch tickets
```

Exit codes: `0` success · `2` input/validation error · `130` interrupted.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Tor is unreachable` warnings | Start Tor (`tor`, or Tor Browser on 9150); collector degrades gracefully |
| `Telethon not installed` | `pip install -e ".[telegram]"` |
| `aiohttp-socks missing` | `pip install -e ".[darkweb]"` |
| OCR/YARA no-ops | Install the `[ocr]` / `[yara]` extras; adapters hint the pip command |
| FTS query odd chars | Engine falls back to LIKE automatically; try simpler terms |
| Duplicate messages skipped | By design — SHA-256 channel+content dedup key |
| Colors look broken over SSH/pipe | Expected: plain mode auto-engages when stdout isn't a TTY |
| Old DB after upgrade | Migrations run automatically on open (meta table tracks version) |

🏠 Back to [README](../README.md)
