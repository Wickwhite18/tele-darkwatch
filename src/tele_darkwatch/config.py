"""Application settings loaded from environment variables / .env file."""
from __future__ import annotations

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
    webhook_url: str = ""  # optional Slack-compatible alert webhook
    poll_interval: int = 300  # seconds between collection cycles
    log_level: str = "INFO"
    log_file: str = ""  # optional log file path (in addition to stderr)
    alert_cooldown: int = 300  # seconds between repeat notifications per rule/channel
    retention_days: int = 0  # 0 disables automatic pruning in the daemon loop

    @property
    def channels(self) -> list[str]:
        return [c.strip() for c in self.telegram_channels.split(",") if c.strip()]

    @property
    def urls(self) -> list[str]:
        return [u.strip() for u in self.darkweb_urls.split(",") if u.strip()]
