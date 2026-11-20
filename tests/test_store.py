import sqlite3

import pytest

from credstore.core import CredError
from credstore.store import Store
from tests.conftest import FakeDPAPI, FakeFido


def test_open_tier_roundtrip_before_init(store):
    assert store.default_tier() == "open"
    assert store.set("splunk", "s3cret", note="prod") == "stored"
    assert store.get("splunk") == "s3cret"
    assert store.row("splunk")["tier"] == "open"
    assert store.set("splunk", "n3w") == "updated"
    assert store.row("splunk")["note"] == "prod"


def test_list_never_returns_blobs(store):
    store.set("a", "1")
    assert [set(r) for r in store.rows()] == [{"name", "tier", "note", "created_at", "updated_at", "expires_at"}]


def test_missing_and_empty(store):
    with pytest.raises(CredError, match="no secret"):
        store.get("nope")
    with pytest.raises(CredError, match="empty"):
        store.set("x", "")
    assert store.delete("nope") is False


def test_new_files_are_private(store):
    store.set("a", "1")
    assert store.path.stat().st_mode & 0o077 == 0
    assert store.path.parent.stat().st_mode & 0o077 == 0


def test_migrates_a_store_from_the_single_file_version(env):
    path = env / "old.db"
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE secrets (name TEXT PRIMARY KEY, blob TEXT NOT NULL, note TEXT,
                   created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT)""")
    con.execute("INSERT INTO secrets VALUES ('legacy', ?, 'old', '2026-01-01', '2026-01-01', NULL)", (FakeDPAPI().protect("v1"),))
    con.commit()
    con.close()
    store = Store(path, dpapi=FakeDPAPI(), fido=FakeFido())
    assert store.rows()[0]["tier"] == "open"
    assert store.get("legacy") == "v1"


def test_expired_secret_warns_but_reads(store, capsys):
    store.set("old", "v", expires="2020-01-01T00:00:00+00:00")
    assert store.get("old") == "v"
    assert "expired" in capsys.readouterr().err
