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
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.daemon import Daemon
from tele_darkwatch.export import export_messages
from tele_darkwatch.models import Alert, MatchRule, Message, SourceType
from tele_darkwatch.retention import prune, vacuum
from tele_darkwatch.search.engine import SearchEngine
from tele_darkwatch.storage.event_log import EventLog
from tele_darkwatch.storage.message_store import MessageStore

__version__ = "0.3.0"

__all__ = [
    "Alert",
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
    "export_messages",
    "prune",
    "vacuum",
]
