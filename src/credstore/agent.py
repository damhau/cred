"""The unlock agent: a background process that holds the unlock key and answers on a private unix socket until it locks.

It never hands the key out, only decrypted locked-tier secrets, one request at a time and each one logged. It marks
itself non-dumpable, so other processes running as you cannot read its memory, and it locks on its own after a
fixed time or after an idle period, whichever comes first.
"""

import ctypes
import hashlib
import json
import os
import resource
import select
import signal
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from . import audit
from .core import CredError

PR_SET_DUMPABLE = 4
MAX_MESSAGE = 1 << 20
CLIENT_TIMEOUT = 60
PEER_TIMEOUT = 5


class AgentDown(CredError):
    """No agent is listening: the store is locked."""


def socket_path(db_path):
    if path := os.environ.get("CREDSTORE_AGENT_SOCKET"):
        return Path(path)
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/credstore-{os.getuid()}"
    tag = hashlib.sha256(str(Path(db_path).expanduser().resolve()).encode()).hexdigest()[:12]
    return Path(base) / "credstore" / f"agent-{tag}.sock"


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.lstat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise CredError(f"{path} must be a directory owned by you with mode 700")


def recv_message(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_MESSAGE:
            raise CredError("message too large")
    return json.loads(data)


def send_message(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b"\n")


class AgentClient:
    def __init__(self, path):
        self.path = Path(path)

    def call(self, op, **args):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError as e:
            raise CredError(f"cannot open a unix socket to reach the agent ({e.strerror}): is this process sandboxed?") from None
        s.settimeout(CLIENT_TIMEOUT)
        with s:
            try:
                s.connect(str(self.path))
            except (FileNotFoundError, ConnectionRefusedError):
                raise AgentDown("the store is locked") from None
            except OSError as e:
                raise CredError(f"cannot reach the agent at {self.path}: {e.strerror}") from None
            send_message(s, {"op": op, **args})
            try:
                reply = recv_message(s)
            except ValueError:
                raise CredError("the agent sent an unreadable answer") from None
        if not reply.get("ok"):
            raise CredError(reply.get("error") or "the agent refused")
        return reply

    def status(self):
        try:
            return self.call("status")
        except AgentDown:
            return None

    def get(self, name):
        try:
            return self.call("get", name=name)["secret"]
        except AgentDown:
            raise CredError(f"{name!r} is locked: run `cred unlock`") from None

    def protect(self, name, secret):
        try:
            return self.call("protect", name=name, secret=secret)["blob"]
        except AgentDown:
            raise CredError("storing a locked secret needs an unlocked store: run `cred unlock`") from None

    def lock(self):
        try:
            self.call("lock")
            return True
        except AgentDown:
            return False


def harden():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE, 0) failed")


def detach_stdio():
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    os.close(null)


def _terminate(signum, frame):
    raise SystemExit("signal")


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).replace(microsecond=0).isoformat()


class Agent:
    def __init__(self, store, key, ttl, idle, path):
        self.store, self.key, self.ttl, self.idle, self.path = store, key, ttl, idle, Path(path)
        self.started_wall = time.time()
        self.deadline = time.monotonic() + ttl
        self.last = time.monotonic()
        self.reads = 0
        self.sock = None

    def bind(self):
        private_dir(self.path.parent)
        if self.path.exists() or self.path.is_symlink():
            if AgentClient(self.path).status() is not None:
                raise CredError("already unlocked: `cred lock` first")
            self.path.unlink()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            self.sock.bind(str(self.path))
        finally:
            os.umask(old)
        self.sock.listen(16)

    def serve(self):
        reason = "error"
        signal.signal(signal.SIGTERM, _terminate)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        try:
            while True:
                now = time.monotonic()
                left = min(self.deadline, self.last + self.idle) - now
                if left <= 0:
                    reason = "expired" if self.deadline <= now else "idle"
                    break
                ready, _, _ = select.select([self.sock], [], [], left)
                if ready:
                    conn, _ = self.sock.accept()
                    with conn:
                        if self.handle(conn) == "lock":
                            reason = "cred lock"
                            break
        except SystemExit:
            reason = "signal"
        finally:
            self.close(reason)

    def close(self, reason):
        self.key[:] = bytes(len(self.key))
        try:
            self.sock.close()
            self.path.unlink()
        except OSError:
            pass
        audit.record("locked", strict=False, reason=reason, reads=self.reads)

    def handle(self, conn):
        conn.settimeout(PEER_TIMEOUT)
        pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid != os.getuid():
            audit.record("refused", strict=False, pid=pid, uid=uid)
            return None
        op = None
        try:
            req = recv_message(conn)
            op = req.get("op")
            reply = self.dispatch(op, req, pid)
        except CredError as e:
            reply = {"ok": False, "error": str(e)}
        except (ValueError, KeyError, TypeError, OSError) as e:
            reply = {"ok": False, "error": f"bad request: {e}"}
        try:
            send_message(conn, reply)
        except OSError:
            pass
        return op

    def dispatch(self, op, req, pid):
        if op == "status":
            return {"ok": True, **self.status()}
        if op == "lock":
            audit.record("lock", strict=False, chain=audit.process_chain(pid))
            return {"ok": True}
        if op == "get":
            return {"ok": True, "secret": self.read(req["name"], pid)}
        if op == "protect":
            blob = self.store.encrypt_locked(req["name"], req["secret"], bytes(self.key))
            self.last = time.monotonic()
            return {"ok": True, "blob": blob}
        raise CredError(f"unknown request {op!r}")

    def read(self, name, pid):
        chain = audit.process_chain(pid)
        try:
            secret = self.store.decrypt_locked(name, bytes(self.key))
        except CredError as e:
            audit.record("read", strict=False, name=name, tier="locked", ok=False, error=str(e), chain=chain)
            raise
        audit.record("read", name=name, tier="locked", ok=True, chain=chain)
        self.reads += 1
        self.last = time.monotonic()
        return secret

    def status(self):
        now = time.monotonic()
        return {"pid": os.getpid(), "db": str(self.store.path), "reads": self.reads,
                "until": iso(self.started_wall + self.ttl),
                "idle_until": iso(time.time() + max(0.0, self.last + self.idle - now))}


def start(store, key, ttl, idle, path):
    """Fork the agent (double fork, new session) and wait until it listens. key: a bytearray the agent zeroes on lock."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            os.setsid()
            if os.fork():
                os._exit(0)
            os.closerange(3, w)
            os.closerange(w + 1, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
            harden()
            agent = Agent(store, key, ttl, idle, path)
            agent.bind()
            detach_stdio()
            os.write(w, b"ok")
            os.close(w)
            w = None
            agent.serve()
        except BaseException as e:
            if w is not None:
                try:
                    os.write(w, f"error {e}".encode())
                except OSError:
                    pass
        os._exit(0)
    os.close(w)
    os.waitpid(pid, 0)
    with os.fdopen(r, "rb") as f:
        answer = f.read().decode("utf-8", "replace")
    if answer != "ok":
        raise CredError(answer.removeprefix("error ").strip() or "the agent did not start")
