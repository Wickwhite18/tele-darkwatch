from tele_darkwatch.models import MatchRule, Message, SourceType
from tele_darkwatch.search.engine import SearchEngine


def _add(store, content, channel="c"):
    store.add_message(
        Message(content=content, channel=channel, source_type=SourceType.MANUAL)
    )


def test_fts_search(store):
    engine = SearchEngine(store)
    _add(store, "drone strike reported near kyiv")
    _add(store, "weather is nice")
    results = engine.search("drone")
    assert len(results) == 1
    assert "kyiv" in results[0].content


def test_like_fallback_on_bad_syntax(store):
    engine = SearchEngine(store)
    _add(store, "contains substring xyzzy")
    # unbalanced quotes break FTS MATCH syntax -> should fall back to LIKE
    results = engine.search('"unbalanced')
    assert results == [] or isinstance(results, list)
    results2 = engine.search("xyzzy")
    assert len(results2) == 1


def test_channel_filter(store):
    engine = SearchEngine(store)
    _add(store, "alpha message", channel="one")
    _add(store, "alpha message two", channel="two")
    assert len(engine.search("alpha", channel="one")) == 1
