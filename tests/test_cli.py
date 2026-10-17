import json

from tele_darkwatch.cli import main
from tele_darkwatch.models import Message, SourceType


def test_cli_end_to_end(tmp_path, capsys):
    db = tmp_path / "cli.db"
    store_path = str(db)

    # seed a message directly
    from tele_darkwatch.storage.message_store import MessageStore

    with MessageStore(store_path) as s:
        s.add_message(
            Message(
                content="server exploit found in wild",
                channel="bugtraq",
                source_type=SourceType.MANUAL,
            )
        )

    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{"pattern": "exploit", "name": "sec"}]}))

    assert main(["--db", store_path, "stats"]) == 0
    assert main(["--db", store_path, "search", "exploit"]) == 0
    out = capsys.readouterr().out
    assert "bugtraq" in out

    assert main(["--db", store_path, "alerts", "--rules", str(rules)]) == 0
    assert "1 alert(s) raised" in capsys.readouterr().out

    assert main(["--db", store_path, "notify"]) == 0
    assert "Dispatched 1 alert(s)" in capsys.readouterr().out


def test_cli_requires_channels(tmp_path):
    assert main(["--db", str(tmp_path / "x.db"), "collect"]) == 1
