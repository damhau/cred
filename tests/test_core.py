from datetime import datetime, timezone

import pytest

from credstore.core import CredError, b64d, b64e, check_name, expiry, parse_duration, parse_expires

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("text, seconds", [("90s", 90), ("15m", 900), ("2h", 7200), ("1h30m", 5400), (" 10M ", 600)])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "0m", "10", "abc", "5d", "-1m"])
def test_parse_duration_rejects(text):
    with pytest.raises(CredError):
        parse_duration(text)


def test_parse_expires():
    assert parse_expires("none") is None
    assert parse_expires("30d", NOW) == "2026-12-20T12:00:00+00:00"
    assert parse_expires("2027-01-31") == "2027-01-31T00:00:00+00:00"
    with pytest.raises(CredError):
        parse_expires("soon")


def test_expiry():
    assert expiry(None, NOW) == ("none", None)
    assert expiry("2026-11-19", NOW)[0] == "expired"
    assert expiry("2026-12-01", NOW)[0] == "expiring"
    assert expiry("2027-06-01", NOW)[0] == "ok"


def test_names():
    assert check_name("splunk/prod-1.token") == "splunk/prod-1.token"
    for bad in ("", "-x", "a b", "x" * 200):
        with pytest.raises(CredError):
            check_name(bad)


def test_b64_roundtrip():
    for data in (b"", b"\x00", bytes(range(256))):
        assert b64d(b64e(data)) == data
        assert "=" not in b64e(data)
