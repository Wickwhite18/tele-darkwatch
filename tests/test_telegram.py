import httpx

from tele_darkwatch.collectors.telegram_monitor import TelegramMonitor, strip_html
from tele_darkwatch.models import SourceType

SAMPLE_RSS = """<?xml version="1.0"?>
<rss><channel>
  <item>
    <title>Breaking</title>
    <description>Missile strike reported &lt;b&gt;here&lt;/b&gt;</description>
    <link>https://t.me/testchan/1</link>
    <pubDate>Mon, 05 Jan 2026 10:00:00 +0000</pubDate>
  </item>
  <item>
    <title></title>
    <description>second post</description>
    <link>https://t.me/testchan/2</link>
  </item>
</channel></rss>"""


def handler(request):
    assert request.url.path == "/s/testchan"
    return httpx.Response(200, text=SAMPLE_RSS)


def test_parse_rss(store):
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://t")
    monitor = TelegramMonitor(store, ["@testchan"], client=client)
    msgs = list(monitor.collect())
    assert len(msgs) == 2
    assert msgs[0].content.startswith("Breaking")
    assert "here" in msgs[0].content
    assert "<b>" not in msgs[0].content
    assert msgs[0].source_type == SourceType.TELEGRAM
    assert msgs[0].timestamp.year == 2026


def test_run_once_stores_and_dedups(store):
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://t")
    monitor = TelegramMonitor(store, ["testchan"], client=client)
    assert monitor.run_once() == 2
    assert monitor.run_once() == 0  # duplicates suppressed
    assert store.count() == 2


def test_strip_html():
    assert strip_html("a<br/>b<b>c</b>") == "a\nbc"


def test_network_error_swallowed(store):
    def failing(request):
        raise httpx.ConnectError("boom")

    client = httpx.Client(transport=httpx.MockTransport(failing), base_url="https://t")
    monitor = TelegramMonitor(store, ["x"], client=client)
    assert list(monitor.collect()) == []
