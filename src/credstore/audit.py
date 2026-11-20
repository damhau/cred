"""Audit log: one JSON line per unlock, read, write and key change, with the calling process chain.

Any process running as you can edit this file, so it shows activity; it does not prove it.
"""

import json
import os
from pathlib import Path

from .core import CredError, utcnow

CHAIN_DEPTH = 4
CMDLINE_MAX = 160


def log_path():
    if path := os.environ.get("CREDSTORE_AUDIT_LOG"):
        return Path(path).expanduser()
    return Path(os.environ.get("XDG_STATE_HOME") or "~/.local/state").expanduser() / "credstore" / "audit.log"


def record(event, strict=True, **fields):
    """Append an entry. strict: a failure raises, so a read that cannot be logged is refused."""
    path = log_path()
    line = json.dumps({"ts": utcnow().isoformat(), "event": event, **fields}) + "\n"
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line)
    except OSError as e:
        if strict:
            raise CredError(f"cannot write the audit log {path}: {e.strerror}") from None


def process_chain(pid, depth=CHAIN_DEPTH):
    """['pid cmdline', parent, grandparent, ...] from /proc, closest first."""
    chain = []
    while pid > 1 and len(chain) < depth:
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            stat = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            break
        chain.append(f"{pid} {cmd[:CMDLINE_MAX]}")
        pid = int(stat.rsplit(")", 1)[1].split()[1])
    return chain


def entries(limit=None):
    path = log_path()
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    out = []
    for line in lines[-limit:] if limit else lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
