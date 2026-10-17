import httpx

from tele_darkwatch.collectors.darkweb_monitor import DarkWebMonitor, html_to_text
from tele_darkwatch.models import SourceType

PAGE = "<html><head><style>x{}</style></head><body><p>market <b>listings</b></p></body></html>"


def handler(request):
    return httpx.Response(200, text=PAGE)


def test_fetch_onion(store):
    client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="http://abc123.onion"
    )
    monitor = DarkWebMonitor(store, ["http://abc123.onion/index"], client=client)
    msgs = list(monitor.collect())
    assert len(msgs) == 1
    m = msgs[0]
    assert m.source_type == SourceType.DARKWEB
    assert m.channel == "abc123.onion"
    assert "market listings" in m.content
    assert "<" not in m.content


def test_tor_unreachable_degrades(store):
    def failing(request):
        raise httpx.ConnectError("no tor")

    client = httpx.Client(
        transport=httpx.MockTransport(failing), base_url="http://x.onion"
    )
    monitor = DarkWebMonitor(store, ["http://x.onion/a"], client=client)
    assert list(monitor.collect()) == []


def test_html_to_text():
    assert html_to_text("<script>var a=1;</script><p>hi   there</p>") == "hi there"
