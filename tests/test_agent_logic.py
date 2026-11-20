"""Agent behaviour that does not need a unix socket, so it also runs where sockets are blocked."""

import os

import pytest

from credstore import agent, audit
from credstore.core import CredError


def test_harden_makes_the_process_undumpable():
    ready_r, ready_w = os.pipe()
    hold_r, hold_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        os.close(hold_w)
        try:
            agent.harden()
            os.write(ready_w, b"ok")
        except BaseException as e:
            os.write(ready_w, str(e).encode())
        os.read(hold_r, 1)
        os._exit(0)
    os.close(ready_w)
    os.close(hold_r)
    try:
        assert os.read(ready_r, 200) == b"ok"
        with pytest.raises(PermissionError):
            open(f"/proc/{pid}/mem", "rb").read(1)
    finally:
        os.close(hold_w)
        os.waitpid(pid, 0)


def test_agent_reads_and_writes_with_the_unlock_key(keyed, tmp_path):
    key = bytearray(keyed.keys.data_key("unlock"))
    a = agent.Agent(keyed, key, ttl=60, idle=60, path=tmp_path / "unused.sock")
    blob = a.dispatch("protect", {"name": "prod", "secret": "p4ss"}, os.getpid())["blob"]
    keyed.put("prod", blob, "locked")
    assert a.dispatch("get", {"name": "prod"}, os.getpid())["secret"] == "p4ss"
    assert a.status()["reads"] == 1
    read = [e for e in audit.entries() if e["event"] == "read"][-1]
    assert read["name"] == "prod" and read["chain"][0].startswith(f"{os.getpid()} ")


def test_a_blob_only_opens_under_its_own_name(keyed, tmp_path):
    a = agent.Agent(keyed, bytearray(keyed.keys.data_key("unlock")), 60, 60, tmp_path / "unused.sock")
    keyed.put("one", a.dispatch("protect", {"name": "one", "secret": "1"}, os.getpid())["blob"], "locked")
    keyed.put("two", keyed.row("one")["blob"], "locked")
    with pytest.raises(CredError, match="wrong key"):
        a.dispatch("get", {"name": "two"}, os.getpid())
    assert [e["ok"] for e in audit.entries() if e["event"] == "read"] == [False]


def test_the_confirm_key_is_not_the_unlock_key(keyed, tmp_path, monkeypatch):
    monkeypatch.setattr(keyed.agent, "protect", lambda name, secret: pytest.fail("confirm writes must not use the agent"))
    keyed.set("root", "r00t", tier="confirm")
    a = agent.Agent(keyed, bytearray(keyed.keys.data_key("unlock")), 60, 60, tmp_path / "unused.sock")
    with pytest.raises(CredError, match="not in the locked tier"):
        a.dispatch("get", {"name": "root"}, os.getpid())
    keyed.put("root", keyed.row("root")["blob"], "locked")
    with pytest.raises(CredError, match="wrong key"):
        a.dispatch("get", {"name": "root"}, os.getpid())


def test_close_zeroes_the_key(keyed, tmp_path):
    key = bytearray(keyed.keys.data_key("unlock"))
    a = agent.Agent(keyed, key, 60, 60, tmp_path / "unused.sock")
    a.sock = type("S", (), {"close": lambda self: None})()
    a.close("test")
    assert key == bytearray(32)
    assert audit.entries()[-1]["event"] == "locked"
