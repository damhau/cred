import os
import stat
import time

import pytest

from credstore import agent, audit
from credstore.core import CredError
from tests.conftest import needs_agent

pytestmark = needs_agent


def unlock(store, ttl=60, idle=60, method=None):
    agent.start(store, bytearray(store.keys.data_key("unlock", method)), ttl, idle, store.agent.path)


def test_locked_secret_needs_unlock(keyed):
    with pytest.raises(CredError, match="unlock"):
        keyed.set("prod", "p4ss")
    unlock(keyed)
    keyed.set("prod", "p4ss")
    assert keyed.row("prod")["tier"] == "locked"
    assert keyed.get("prod") == "p4ss"
    assert keyed.agent.lock() is True
    with pytest.raises(CredError, match="is locked: run `cred unlock`"):
        keyed.get("prod")


def test_reads_are_logged_with_the_caller(keyed):
    unlock(keyed)
    keyed.set("prod", "p4ss")
    keyed.get("prod")
    reads = [e for e in audit.entries() if e["event"] == "read"]
    assert reads[-1]["name"] == "prod" and reads[-1]["ok"] is True
    assert reads[-1]["chain"][0].startswith(f"{os.getpid()} ")
    assert keyed.agent.status()["reads"] == 1


def test_unlogged_read_is_refused(keyed, monkeypatch, env):
    unlock(keyed)
    keyed.set("prod", "p4ss")
    log = env / "audit.log"
    log.unlink()
    log.mkdir()                                     # the agent cannot append any more
    with pytest.raises(CredError, match="audit log"):
        keyed.get("prod")


def test_socket_is_private_and_agent_not_dumpable(keyed):
    unlock(keyed)
    path = keyed.agent.path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    pid = keyed.agent.status()["pid"]
    assert pid != os.getpid()
    with pytest.raises(PermissionError):
        open(f"/proc/{pid}/mem", "rb").read(1)
    assert os.stat(f"/proc/{pid}/environ").st_uid != os.getuid()


def test_second_unlock_is_refused(keyed):
    unlock(keyed)
    with pytest.raises(CredError, match="already unlocked"):
        unlock(keyed)


def test_idle_lock(keyed):
    unlock(keyed, ttl=60, idle=1)
    assert keyed.agent.status() is not None
    time.sleep(1.5)
    assert keyed.agent.status() is None
    assert not keyed.agent.path.exists()
    assert any(e["event"] == "locked" and e["reason"] == "idle" for e in audit.entries())


def test_hard_expiry(keyed):
    unlock(keyed, ttl=1, idle=60)
    time.sleep(1.5)
    assert keyed.agent.status() is None


def test_stale_socket_is_replaced(keyed):
    keyed.agent.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    keyed.agent.path.write_text("")
    unlock(keyed)
    assert keyed.agent.status() is not None


def test_agent_refuses_other_tiers(keyed):
    keyed.set("plain", "x", tier="open")
    unlock(keyed)
    with pytest.raises(CredError, match="not in the locked tier"):
        keyed.agent.get("plain")


def test_unlock_with_passphrase(keyed):
    keyed.fido.plugged = False
    unlock(keyed, method="passphrase")
    keyed.set("prod", "p4ss")
    assert keyed.get("prod") == "p4ss"
