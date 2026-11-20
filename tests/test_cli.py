import io
import json

import pytest

from credstore import audit, cli
from credstore.core import b64d
from tests.conftest import PASSPHRASE, needs_agent


class Stdin(io.TextIOWrapper):
    def __init__(self, text, tty=False):
        super().__init__(io.BytesIO(text.encode()))
        self._tty = tty

    def isatty(self):
        return self._tty


def run(store, *argv, stdin="", monkeypatch=None):
    if monkeypatch:
        monkeypatch.setattr("sys.stdin", Stdin(stdin))
    return cli.main(list(argv), store=store)


@pytest.fixture
def tty_passphrase(monkeypatch):
    answers = iter([PASSPHRASE, PASSPHRASE])
    monkeypatch.setattr("sys.stdin", Stdin("\n", tty=True))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))


@needs_agent
def test_init_then_unlock_set_get_lock(store, tty_passphrase, monkeypatch, capsys):
    assert run(store, "init") == 0
    assert run(store, "unlock", "--for", "5m", "--idle", "1m") == 0
    assert "unlocked until" in capsys.readouterr().err
    assert run(store, "set", "prod", stdin="p4ss\n", monkeypatch=monkeypatch) == 0
    assert run(store, "get", "prod") == 0
    assert capsys.readouterr().out == "p4ss"
    assert run(store, "status") == 0
    assert "unlocked until" in capsys.readouterr().out
    assert run(store, "lock") == 0
    assert run(store, "get", "prod") == 1
    assert "run `cred unlock`" in capsys.readouterr().err


def test_confirm_tier_needs_the_key_every_read(keyed, monkeypatch, capsys):
    run(keyed, "set", "root", "--tier", "confirm", stdin="r00t", monkeypatch=monkeypatch)
    touches = keyed.fido.touches
    for _ in range(2):
        assert run(keyed, "get", "root") == 0
        assert capsys.readouterr().out == "r00t"
    assert keyed.fido.touches == touches + 2
    keyed.fido.plugged = False
    assert run(keyed, "get", "root") == 1
    reads = [e for e in audit.entries() if e["event"] == "read" and e["tier"] == "confirm"]
    assert [e["ok"] for e in reads] == [True, True, False]


@needs_agent
def test_confirm_read_ignores_an_unlocked_agent(keyed, monkeypatch, capsys):
    run(keyed, "set", "root", "--tier", "confirm", stdin="r00t", monkeypatch=monkeypatch)
    run(keyed, "unlock")
    keyed.fido.plugged = False
    assert run(keyed, "get", "root") == 1


@needs_agent
def test_tier_moves(keyed, monkeypatch, capsys):
    run(keyed, "set", "svc", "--tier", "open", stdin="v", monkeypatch=monkeypatch)
    run(keyed, "unlock")
    assert run(keyed, "tier", "svc", "locked") == 0
    assert keyed.row("svc")["tier"] == "locked"
    assert run(keyed, "tier", "svc", "confirm") == 0
    assert run(keyed, "lock") == 0
    assert run(keyed, "get", "svc") == 0
    assert capsys.readouterr().out == "v"


def test_list_shows_tiers(keyed, monkeypatch, capsys):
    run(keyed, "set", "a", "--tier", "open", stdin="1", monkeypatch=monkeypatch)
    run(keyed, "set", "b", "--tier", "confirm", stdin="2", monkeypatch=monkeypatch)
    capsys.readouterr()
    run(keyed, "list", "--json")
    rows = json.loads(capsys.readouterr().out)
    assert {r["name"]: r["tier"] for r in rows} == {"a": "open", "b": "confirm"}


@needs_agent
def test_exec_resolves_every_tier(keyed, monkeypatch):
    run(keyed, "set", "a", "--tier", "open", stdin="1", monkeypatch=monkeypatch)
    run(keyed, "set", "c", "--tier", "confirm", stdin="3", monkeypatch=monkeypatch)
    run(keyed, "unlock")
    run(keyed, "set", "b", stdin="2", monkeypatch=monkeypatch)
    seen = {}
    monkeypatch.setattr(cli.os, "execvpe", lambda prog, argv, env: seen.update(env))
    assert run(keyed, "exec", "-e", "A=a", "-e", "B=b", "-e", "C=c", "--", "true") == 0
    assert (seen["A"], seen["B"], seen["C"]) == ("1", "2", "3")


def test_curl_config_quotes(store, monkeypatch, capsys):
    run(store, "set", "api", stdin='p"a\\ss', monkeypatch=monkeypatch)
    run(store, "curl-config", "api", "bob")
    assert capsys.readouterr().out == 'user = "bob:p\\"a\\\\ss"\n'


@needs_agent
def test_log_and_key_list(keyed, monkeypatch, capsys):
    run(keyed, "unlock")
    run(keyed, "set", "prod", stdin="p", monkeypatch=monkeypatch)
    run(keyed, "get", "prod")
    capsys.readouterr()
    assert run(keyed, "log") == 0
    out = capsys.readouterr().out
    assert "read" in out and "prod" in out
    assert run(keyed, "key", "list") == 0
    out = capsys.readouterr().out
    assert "yubikey" in out and "(default)" in out and "passphrase" in out


def test_doctor_with_fakes(keyed, capsys):
    assert run(keyed, "doctor", "--yubikey") == 0
    out = capsys.readouterr().out
    assert "a wrong key is refused" in out and "YubiKey opens the unlock key" in out


@pytest.mark.parametrize("answer, methods", [("\n", ["fido2"]), ("2\n", ["hello"]), ("hello\n", ["hello"]), ("3\n", [])])
def test_init_asks_for_the_unlock_device(store, tty_passphrase, monkeypatch, capsys, answer, methods):
    monkeypatch.setattr("sys.stdin", Stdin(answer, tty=True))
    assert run(store, "init") == 0
    assert [s["method"] for s in store.keyslots()] == methods + ["passphrase"]
    assert "Windows Hello: face, fingerprint or PIN" in capsys.readouterr().err


def test_init_device_flag_skips_the_question(store, tty_passphrase, capsys):
    assert run(store, "init", "--device", "hello") == 0
    err = capsys.readouterr().err
    assert "Unlock device:" not in err and "Confirm with Windows Hello" in err
    assert run(store, "init", "--device", "yubikey") == 1
    assert "already exist" in capsys.readouterr().err


def test_init_refuses_an_unknown_answer(store, tty_passphrase, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", Stdin("4\n", tty=True))
    assert run(store, "init") == 1
    assert "choose 1, 2 or 3" in capsys.readouterr().err
    assert store.keyslots() == []


def test_key_add_hello_then_read_with_it(keyed, monkeypatch, capsys):
    assert run(keyed, "key", "add", "hello") == 0
    hello = next(b64d(s["params"]["cred_id"]) for s in keyed.keyslots() if s["method"] == "hello")
    run(keyed, "set", "root", "--tier", "confirm", "--with", "hello", stdin="r00t", monkeypatch=monkeypatch)
    assert keyed.fido.asked[-1] == {hello}
    capsys.readouterr()
    assert run(keyed, "get", "root", "--with", "hello") == 0
    assert capsys.readouterr().out == "r00t"
    assert keyed.fido.asked[-1] == {hello}
    assert [e["method"] for e in audit.entries() if e["event"] == "read"][-1] == "hello"
    assert run(keyed, "doctor", "--device", "--with", "hello") == 0
    assert "Windows Hello opens the unlock key" in capsys.readouterr().out


def test_key_add_yubikey_still_works(keyed):
    assert run(keyed, "key", "add-yubikey", "--label", "backup") == 0
    assert [s["label"] for s in keyed.keyslots()][-1] == "backup"
