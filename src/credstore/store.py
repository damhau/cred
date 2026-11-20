"""The SQLite store and the per-tier read and write paths.

Only the value is encrypted; names, notes, dates and tiers are plain columns, so list / rm never start PowerShell.
"""

import getpass
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from . import audit
from .agent import AgentClient, socket_path
from .core import KEEP, CredError, check_name, check_tier, expiry, utcnow
from .dpapi import PowerShell
from .fido import WindowsFido
from .keys import Keyring, secret_entropy

DEFAULT_DB = "~/.config/credstore/store.db"
SCHEMA = (
    """CREATE TABLE IF NOT EXISTS secrets (
        name TEXT PRIMARY KEY, blob TEXT NOT NULL, note TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT, tier TEXT NOT NULL DEFAULT 'open')""",
    """CREATE TABLE IF NOT EXISTS keyslots (
        id INTEGER PRIMARY KEY, method TEXT NOT NULL, label TEXT, params TEXT NOT NULL,
        wrapped_unlock TEXT NOT NULL, wrapped_confirm TEXT NOT NULL, created_at TEXT NOT NULL)""",
)


def prompt_passphrase(prompt="Passphrase: "):
    if not sys.stdin.isatty():
        raise CredError("a passphrase is needed: run this on a terminal")
    return getpass.getpass(prompt)


class Store:
    def __init__(self, path=None, dpapi=None, fido=None, agent=None, ask_passphrase=None):
        self.path = Path(path or os.environ.get("CREDSTORE_DB", DEFAULT_DB)).expanduser()
        self.dpapi = dpapi or PowerShell()
        self.fido = fido or WindowsFido()
        self.agent = agent or AgentClient(socket_path(self.path))
        self.ask_passphrase = ask_passphrase or prompt_passphrase
        self.keys = Keyring(self)

    def _open(self, create=True):
        """A connection, or None when there is no database yet and create is false. A new directory is 700 and a new file 600."""
        if not self.path.exists():
            if not create:
                return None
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        for statement in SCHEMA:
            con.execute(statement)
        if "tier" not in {r["name"] for r in con.execute("PRAGMA table_info(secrets)")}:
            con.execute("ALTER TABLE secrets ADD COLUMN tier TEXT NOT NULL DEFAULT 'open'")
        return con

    # ---- rows

    def row(self, name, missing_ok=False):
        check_name(name)
        con, row = self._open(create=False), None
        if con is not None:
            with closing(con):
                row = con.execute("SELECT * FROM secrets WHERE name = ?", (name,)).fetchone()
        if not row and not missing_ok:
            raise CredError(f"no secret named {name!r}")
        return dict(row) if row else None

    def put(self, name, blob, tier, note=KEEP, expires=KEEP):
        """Insert or update; note / expires left as KEEP stay as they were (None clears). -> 'stored' | 'updated'."""
        check_name(name)
        check_tier(tier)
        with closing(self._open()) as con, con:
            old = con.execute("SELECT note, expires_at, created_at FROM secrets WHERE name = ?", (name,)).fetchone()
            now = utcnow().isoformat()
            keep = (old["note"], old["expires_at"]) if old else (None, None)
            note, expires = (keep[0] if note is KEEP else note), (keep[1] if expires is KEEP else expires)
            con.execute("INSERT OR REPLACE INTO secrets (name, blob, note, created_at, updated_at, expires_at, tier) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (name, blob, note, old["created_at"] if old else now, now, expires, tier))
        return "updated" if old else "stored"

    def delete(self, name):
        check_name(name)
        con = self._open(create=False)
        if con is None:
            return False
        with closing(con) as c, c:
            return c.execute("DELETE FROM secrets WHERE name = ?", (name,)).rowcount > 0

    def rows(self):
        """Everything except the blob, by name."""
        con = self._open(create=False)
        if con is None:
            return []
        with closing(con) as c:
            return [dict(r) for r in c.execute("SELECT name, tier, note, created_at, updated_at, expires_at FROM secrets ORDER BY name")]

    # ---- key slots

    def keyslots(self):
        con = self._open(create=False)
        if con is None:
            return []
        with closing(con) as c:
            return [{**dict(r), "params": json.loads(r["params"])} for r in c.execute("SELECT * FROM keyslots ORDER BY id")]

    def add_keyslots(self, slots, replace_method=None):
        with closing(self._open()) as con, con:
            if replace_method:
                con.execute("DELETE FROM keyslots WHERE method = ?", (replace_method,))
            for s in slots:
                con.execute("INSERT INTO keyslots (method, label, params, wrapped_unlock, wrapped_confirm, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                            (s["method"], s["label"], json.dumps(s["params"]), s["wrapped_unlock"], s["wrapped_confirm"], utcnow().isoformat()))

    def replace_passphrase_slots(self, slot):
        self.add_keyslots([slot], replace_method="passphrase")

    def delete_keyslot(self, slot_id):
        with closing(self._open()) as con, con:
            con.execute("DELETE FROM keyslots WHERE id = ?", (slot_id,))

    def default_tier(self):
        return "locked" if self.keyslots() else "open"

    # ---- secrets

    def get(self, name, method=None):
        row = self.row(name)
        if expiry(row["expires_at"])[0] == "expired":
            print(f"cred: warning: {name!r} expired on {row['expires_at'][:10]}", file=sys.stderr)
        if row["tier"] == "open":
            return self.dpapi.unprotect(row["blob"])
        if row["tier"] == "locked":
            return self.agent.get(name)
        return self._confirm_read(name, row["blob"], method)

    def set(self, name, secret, tier=None, note=KEEP, expires=KEEP, method=None):
        check_name(name)
        if not secret:
            raise CredError("empty secret, nothing stored")
        old = self.row(name, missing_ok=True)
        tier = check_tier(tier or (old["tier"] if old else self.default_tier()))
        result = self.put(name, self.encrypt(name, secret, tier, method), tier, note, expires)
        audit.record("write", strict=False, name=name, tier=tier, chain=audit.process_chain(os.getpid()))
        return result

    def retier(self, name, tier, method=None):
        """Re-encrypt a secret under another tier: reads it the old way, writes it the new way."""
        check_tier(tier)
        old = self.row(name)
        if old["tier"] == tier:
            return False
        secret = self.get(name, method)
        self.put(name, self.encrypt(name, secret, tier, method), tier)
        audit.record("retier", strict=False, name=name, tier=tier, previous=old["tier"], chain=audit.process_chain(os.getpid()))
        return True

    def encrypt(self, name, secret, tier, method=None):
        if tier == "open":
            return self.dpapi.protect(secret)
        if tier == "locked":
            return self.agent.protect(name, secret)
        key = self.keys.data_key("confirm", method)
        return self.dpapi.protect_bytes(secret.encode(), secret_entropy(key, name))

    def decrypt_locked(self, name, key):
        """Agent side: the key is the unlock data key."""
        row = self.row(name)
        if row["tier"] != "locked":
            raise CredError(f"{name!r} is not in the locked tier")
        return self.dpapi.unprotect_bytes(row["blob"], secret_entropy(key, name)).decode()

    def encrypt_locked(self, name, secret, key):
        check_name(name)
        if not secret:
            raise CredError("empty secret, nothing stored")
        return self.dpapi.protect_bytes(secret.encode(), secret_entropy(key, name))

    def _confirm_read(self, name, blob, method):
        chain = audit.process_chain(os.getpid())
        try:
            key = self.keys.data_key("confirm", method)
            secret = self.dpapi.unprotect_bytes(blob, secret_entropy(key, name)).decode()
        except CredError as e:
            audit.record("read", strict=False, name=name, tier="confirm", ok=False, error=str(e), chain=chain)
            raise
        audit.record("read", name=name, tier="confirm", ok=True, method=method or "auto", chain=chain)
        return secret
