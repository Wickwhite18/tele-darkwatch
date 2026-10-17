"""tele-darkwatch: Telegram and dark-web monitoring, storage, search and alerts."""
from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import (
    ConsoleNotifier,
    EmailNotifier,
    WebhookNotifier,
    dispatch_pending,
)
from tele_darkwatch.alerts.rate_limiter import RateLimiter
from tele_darkwatch.alerts.regex_engine import (
    RegexAlertEngine,
    RegexRule,
    default_regex_rules,
)
from tele_darkwatch.channel_discovery import (
    ChannelDiscovery,
    ChannelStatus,
    classify_text,
    extract_channel_names,
)
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.cookies import Cookie, parse_any as parse_cookies
from tele_darkwatch.entities import Entity, EntityType, extract_all
from tele_darkwatch.health import HealthMonitor
from tele_darkwatch.leak_parser import ParseReport, parse_archive_bytes
from tele_darkwatch.pipeline import process_new_messages
from tele_darkwatch.sanitize import mask_text, sanitize_store
from tele_darkwatch.session_check import ValidationResult, validate_token
from tele_darkwatch.watchlist import corporate_hits, profile_for
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.daemon import Daemon
from tele_darkwatch.export import export_messages
from tele_darkwatch.models import Alert, MatchRule, Message, SourceType
from tele_darkwatch.retention import prune, vacuum
from tele_darkwatch.search.engine import SearchEngine
from tele_darkwatch.storage.event_log import EventLog
from tele_darkwatch.storage.message_store import MessageStore

__version__ = "0.4.0"

__all__ = [
    "Alert",
    "ChannelDiscovery",
    "ChannelStatus",
    "Cookie",
    "Entity",
    "EntityType",
    "HealthMonitor",
    "ParseReport",
    "ValidationResult",
    "AlertEngine",
    "ConsoleNotifier",
    "Daemon",
    "DarkWebMonitor",
    "EmailNotifier",
    "EventLog",
    "MatchRule",
    "Message",
    "MessageStore",
    "RateLimiter",
    "RegexAlertEngine",
    "RegexRule",
    "SearchEngine",
    "Settings",
    "SourceType",
    "TelegramMonitor",
    "WebhookNotifier",
    "default_regex_rules",
    "dispatch_pending",
    "classify_text",
    "corporate_hits",
    "extract_all",
    "extract_channel_names",
    "export_messages",
    "mask_text",
    "parse_archive_bytes",
    "parse_cookies",
    "process_new_messages",
    "profile_for",
    "prune",
    "sanitize_store",
    "validate_token",
    "vacuum",
]
