"""Application settings loaded from environment variables / .env file."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for tele-darkwatch.

    All values can be set via environment variables (prefix ``DW_``) or a
    local ``.env`` file, e.g. ``DW_TELEGRAM_CHANNELS=dcg345,bellingcat``.
    """

    model_config = SettingsConfigDict(env_prefix="DW_", env_file=".env", extra="ignore")

    db_path: str = "darkwatch.db"
    telegram_channels: str = ""  # comma-separated channel names
    darkweb_urls: str = ""  # comma-separated onion URLs
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    rules_path: str = "rules.json"
    regex_rules_path: str = ""  # optional JSON file of RegexRule IOC patterns
    webhook_url: str = Field(  # optional Slack-compatible alert webhook
        default="", validation_alias="DW_ALERT_WEBHOOK_URL")
    poll_interval: int = 300  # seconds between collection cycles
    log_level: str = "INFO"
    log_file: str = ""  # optional log file path (in addition to stderr)
    alert_cooldown: int = 300  # seconds between repeat notifications per rule/channel
    retention_days: int = 0  # 0 disables automatic pruning in the daemon loop

    # Email notification settings (all optional; email disabled unless
    # DW_SMTP_HOST and DW_EMAIL_TO are set).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    email_sender: str = "darkwatch@localhost"
    email_to: str = ""  # comma-separated recipient addresses

    # Enterprise watchlist & compliance (v0.4)
    corporate_domains: str = ""   # comma-separated owned domains (e.g. acme.com)
    # v0.5 — anti-friction / evasion / hardening
    proxy_pool: str = ""            # comma-separated residential/SOCKS proxies
    proxy_pool_file: str = ""       # or one proxy URL per line
    session_dir: str = "sessions"   # directory with *.session Telegram files
    session_rate_per_min: int = 30  # max requests per account per minute
    jitter_min: float = 5.0         # organic delay range between fetches (s)
    jitter_max: float = 15.0
    ocr_enabled: bool = False       # route media through tesseract if installed
    yara_rules_path: str = ""       # directory of .yar rules for log scanning
    discovery_enabled: bool = False  # auto channel-sourcing in the daemon loop
    discovery_threshold: float = 0.08  # keyword score to accept a new channel
    health_prom_file: str = ""    # optional path for Prometheus text snapshot

    @property
    def channels(self) -> list[str]:
        return [c.strip() for c in self.telegram_channels.split(",") if c.strip()]

    @property
    def urls(self) -> list[str]:
        return [u.strip() for u in self.darkweb_urls.split(",") if u.strip()]

    @property
    def protect_domains(self) -> list[str]:
        return [d.strip().lower() for d in self.corporate_domains.split(",") if d.strip()]

