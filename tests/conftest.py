"""Shared pytest fixtures."""
import pytest

from tele_darkwatch.storage.message_store import MessageStore


@pytest.fixture()
def store(tmp_path):
    with MessageStore(tmp_path / "test.db") as s:
        yield s
