"""tele-darkwatch: Telegram and dark-web monitoring, storage, search and alerts."""
from tele_darkwatch.alerts.engine import AlertEngine
from tele_darkwatch.alerts.notifiers import (
    ConsoleNotifier,
    WebhookNotifier,
    dispatch_pending,
)
from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor
from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor
from tele_darkwatch.config import Settings
from tele_darkwatch.models import Alert, MatchRule, Message, SourceType
from tele_darkwatch.search.engine import SearchEngine
from tele_darkwatch.storage.message_store import MessageStore

__version__ = "0.1.0"

__all__ = [
    "Alert",
    "AlertEngine",
    "ConsoleNotifier",
    "DarkWebMonitor",
    "MatchRule",
    "Message",
    "MessageStore",
    "SearchEngine",
    "Settings",
    "SourceType",
    "TelegramMonitor",
    "WebhookNotifier",
    "dispatch_pending",
]
