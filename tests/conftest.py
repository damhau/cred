import base64
import hashlib
import hmac
import json
import os
import socket
import tempfile

import pytest

from credstore.core import CredError
from credstore.store import Store

PASSPHRASE = "correct horse battery staple"


def _unix_sockets_allowed():
    try:
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
        return True
    except OSError:
        return False


UNIX_SOCKETS = _unix_sockets_allowed()
needs_agent = pytest.mark.skipif(not UNIX_SOCKETS, reason="unix sockets are blocked here (sandbox): the agent cannot run")


class FakeDPAPI:
    """Same contract as dpapi.PowerShell: a blob made with entropy only opens with the same entropy."""

    def protect(self, secret):
        return (b"open:" + secret.encode()).hex()

    def unprotect(self, blob):
        raw = bytes.fromhex(blob)
        if not raw.startswith(b"open:"):
            raise CredError("DPAPI call failed: bad blob")
        return raw[5:].decode()

    def protect_bytes(self, data, entropy):
        return base64.b64encode(json.dumps({"e": hashlib.sha256(entropy).hexdigest(), "d": data.hex()}).encode()).decode()

    def unprotect_bytes(self, blob, entropy):
        obj = json.loads(base64.b64decode(blob))
        if obj["e"] != hashlib.sha256(entropy).hexdigest():
            raise CredError("DPAPI call failed: The data is invalid. (wrong key for this blob)")
        return bytes.fromhex(obj["d"])


class FakeFido:
    """YubiKeys and Windows Hello: each credential has a device secret; PRF is HMAC(device secret, salt).
    `plugged` picks who answers. Windows Hello: `hello_prf = False` has no PRF at all, `hello_prf_at_create = False`
    gives it only on an assertion (as the real helper reports when authData leaves hmac-secret out)."""

    def __init__(self):
        self.devices = {}
        self.platform = set()
        self.plugged = None
        self.hello_prf = True
        self.hello_prf_at_create = True
        self.touches = 0
        self.asked = []

    def enroll(self, rp_id, salts, exclude=(), platform=False):
        if self.plugged is False:
            raise CredError("WebAuthn: NotAllowedError: timed out")
        self.touches += 1
        cred_id = os.urandom(16)
        self.devices[cred_id] = os.urandom(32)
        if platform:
            self.platform.add(cred_id)
            if not (self.hello_prf and self.hello_prf_at_create):
                return cred_id, []
        return cred_id, [self._prf(cred_id, s) for s in salts]

    def prf(self, rp_id, creds):
        if self.plugged is False:
            raise CredError("WebAuthn: NotAllowedError: timed out")
        self.touches += 1
        self.asked.append(set(creds))
        for cred_id, salts in creds.items():
            if cred_id in self.devices and (self.plugged in (None, True) or self.plugged == cred_id):
                if cred_id in self.platform and not self.hello_prf:
                    raise CredError("WebAuthn: the authenticator returned no PRF output")
                return cred_id, [self._prf(cred_id, s) for s in salts]
        raise CredError("WebAuthn: no enrolled key answered")

    def _prf(self, cred_id, salt):
        return hmac.new(self.devices[cred_id], salt, hashlib.sha256).digest()


@pytest.fixture
def env(tmp_path, monkeypatch):
    sock_dir = tempfile.mkdtemp(prefix="cs-")
    monkeypatch.setenv("CREDSTORE_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("CREDSTORE_AGENT_SOCKET", os.path.join(sock_dir, "agent.sock"))
    return tmp_path


@pytest.fixture
def store(env):
    s = Store(env / "store.db", dpapi=FakeDPAPI(), fido=FakeFido(), ask_passphrase=lambda prompt: PASSPHRASE)
    yield s
    if UNIX_SOCKETS:
        s.agent.lock()


@pytest.fixture
def keyed(store):
    """A store after `cred init`: one YubiKey and the recovery passphrase."""
    store.keys.init(PASSPHRASE)
    return store
