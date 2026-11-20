"""cred: the command line."""

import argparse
import getpass
import json
import os
import shutil
import stat
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from . import agent, audit
from .core import KEEP, TIERS, VAR_RE, CredError, check_name, expiry, parse_duration, parse_expires, utcnow
from .dpapi import HEX_BLOB_RE, PowerShell
from .fido import WindowsFido, find_uv
from .store import Store

CANARY = "Pässwörd-日本語-🔐 \" \\ ' $x `t"           # doctor's round-trip value: non-ASCII, quote, backslash, shell and PowerShell specials
MAX_UNLOCK = 24 * 3600


def stdout_is_tty():
    return sys.stdout.isatty()


def local_hhmm(iso):
    return datetime.fromisoformat(iso).astimezone().strftime("%H:%M")


def method_of(args):
    return "passphrase" if getattr(args, "passphrase", False) else None


def read_secret():
    if sys.stdin.isatty():
        first = getpass.getpass("Secret: ")
        if getpass.getpass("Again: ") != first:
            raise CredError("the two entries differ, nothing stored")
        return first
    return sys.stdin.buffer.read().decode().removesuffix("\n").removesuffix("\r")


def new_passphrase():
    if not sys.stdin.isatty():
        raise CredError("choosing a passphrase needs a terminal")
    first = getpass.getpass("New recovery passphrase: ")
    if getpass.getpass("Again: ") != first:
        raise CredError("the two entries differ")
    return first


def note_and_expires(args):
    note = KEEP if args.note is None else (args.note or None)
    expires = KEEP if args.expires is None else parse_expires(args.expires)
    return note, expires


# ---- secrets

def cmd_set(args, store):
    note, expires = note_and_expires(args)
    result = store.set(check_name(args.name), read_secret(), args.tier, note, expires, method_of(args))
    print(f"{result} {args.name} ({store.row(args.name)['tier']})", file=sys.stderr)


def cmd_get(args, store):
    secret = store.get(args.name, method_of(args))
    sys.stdout.buffer.write(secret.encode() + (b"\n" if stdout_is_tty() else b""))
    sys.stdout.buffer.flush()


def cmd_list(args, store):
    now, rows = utcnow(), store.rows()
    for r in rows:
        r["state"], r["days_left"] = expiry(r["expires_at"], now)
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("no secrets stored", file=sys.stderr)
        return
    label = {"none": "-", "ok": "ok", "expired": "EXPIRED"}
    table = [("NAME", "TIER", "EXPIRES", "STATUS", "NOTE")] + [
        (r["name"], r["tier"], (r["expires_at"] or "-")[:10],
         f"EXPIRING in {r['days_left']}d" if r["state"] == "expiring" else label[r["state"]], r["note"] or "")
        for r in rows]
    widths = [max(len(row[i]) for row in table) for i in range(4)]
    for row in table:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)) + "  " + row[4])


def cmd_rm(args, store):
    if not store.delete(args.name):
        raise CredError(f"no secret named {args.name!r}")
    audit.record("remove", strict=False, name=args.name, chain=audit.process_chain(os.getpid()))
    print(f"removed {args.name}", file=sys.stderr)


def cmd_tier(args, store):
    changed = store.retier(args.name, args.tier, method_of(args))
    print(f"{args.name}: {'now' if changed else 'already'} {args.tier}", file=sys.stderr)


def cmd_exec(args, store):
    if not args.command:
        raise CredError("usage: cred exec -e VAR=NAME [-e VAR=NAME ...] -- command [args ...]")
    env = dict(os.environ)
    for spec in args.env:
        var, _, name = spec.partition("=")
        if not VAR_RE.match(var) or not name:
            raise CredError(f"bad -e {spec!r}: expected VAR=NAME")
        env[var] = store.get(name, method_of(args))     # every secret is resolved before anything runs
    try:
        os.execvpe(args.command[0], args.command, env)
    except OSError as e:
        print(f"cred: {args.command[0]}: {e.strerror}", file=sys.stderr)
        return 126 if isinstance(e, PermissionError) else 127


def cmd_curl_config(args, store):
    if ":" in args.user or not args.user:
        raise CredError("USER must be non-empty and cannot contain ':' (curl splits user:password at the first colon)")
    escape = {"\\": "\\\\", '"': '\\"', "\t": "\\t", "\n": "\\n", "\r": "\\r", "\v": "\\v"}
    quoted = "".join(escape.get(c, c) for c in f"{args.user}:{store.get(args.name, method_of(args))}")
    print(f'user = "{quoted}"')


def cmd_import(args, store):
    try:
        blob = Path(args.file).expanduser().read_text().strip()
    except OSError as e:
        raise CredError(f"cannot read {args.file}: {e.strerror}") from None
    if not HEX_BLOB_RE.match(blob):
        raise CredError(f"{args.file} is not a ConvertFrom-SecureString (hex) blob")
    store.dpapi.unprotect(blob)             # refuse a blob this Windows user cannot decrypt
    note, expires = note_and_expires(args)
    print(f"{store.put(check_name(args.name), blob, 'open', note, expires)} {args.name} (open tier, decrypts here; "
          f"`cred tier {args.name} locked` to protect it further)", file=sys.stderr)


# ---- keys and unlocking

def cmd_init(args, store):
    passphrase = new_passphrase()
    if not args.no_yubikey:
        print("Touch your YubiKey when Windows asks (one fingerprint, sometimes two).", file=sys.stderr)
    rows = store.keys.init(passphrase, yubikey=not args.no_yubikey, label=args.label)
    audit.record("init", strict=False, slots=[r["method"] for r in rows], chain=audit.process_chain(os.getpid()))
    print(f"keys created: {', '.join(r['label'] for r in rows)}. New secrets now default to the locked tier.", file=sys.stderr)


def cmd_unlock(args, store):
    ttl, idle = parse_duration(args.for_), parse_duration(args.idle)
    if ttl > MAX_UNLOCK:
        raise CredError("--for is capped at 24h")
    if status := store.agent.status():
        raise CredError(f"already unlocked until {local_hhmm(status['until'])}: `cred lock` first")
    key = bytearray(store.keys.data_key("unlock", method_of(args)))
    try:
        agent.start(store, key, ttl, min(idle, ttl), store.agent.path)
    finally:
        key[:] = bytes(len(key))
    audit.record("unlock", strict=False, method=method_of(args) or "auto", ttl=ttl, idle=idle, chain=audit.process_chain(os.getpid()))
    status = store.agent.status() or {}
    print(f"unlocked until {local_hhmm(status['until'])} (locks after {args.idle} without reads)" if status else "unlocked", file=sys.stderr)


def cmd_lock(args, store):
    print("locked" if store.agent.lock() else "already locked", file=sys.stderr)


def cmd_status(args, store):
    status = store.agent.status()
    tiers = Counter(r["tier"] for r in store.rows())
    slots = store.keyslots()
    if args.json:
        print(json.dumps({"unlocked": bool(status), "agent": status, "tiers": tiers, "slots": [s["label"] for s in slots]}, indent=2))
        return
    if status:
        print(f"unlocked until {local_hhmm(status['until'])}, idle lock at {local_hhmm(status['idle_until'])}, "
              f"{status['reads']} reads (agent pid {status['pid']})")
    else:
        print("locked")
    print("secrets: " + (", ".join(f"{tiers[t]} {t}" for t in TIERS if tiers[t]) or "none"))
    print("keys:    " + (", ".join(s["label"] for s in slots) or "none (run `cred init`)"))


def cmd_key_list(args, store):
    slots = store.keyslots()
    if not slots:
        print("no keys yet: run `cred init`", file=sys.stderr)
        return
    for s in slots:
        detail = f"credential {s['params']['cred_id'][:12]}…" if s["method"] == "fido2" else f"scrypt n=2^{s['params']['n'].bit_length() - 1}"
        print(f"{s['id']:>3}  {s['method']:<10}  {s['label']:<22}  {detail}  added {s['created_at'][:10]}")


def cmd_key_add_yubikey(args, store):
    print("First unlock with an enrolled key (or --passphrase), then touch the NEW YubiKey when Windows asks.", file=sys.stderr)
    row = store.keys.add_yubikey(args.label, method_of(args))
    audit.record("key-add", strict=False, method="fido2", label=row["label"], chain=audit.process_chain(os.getpid()))
    print(f"added {row['label']}", file=sys.stderr)


def cmd_key_passwd(args, store):
    store.keys.set_passphrase(new_passphrase, method_of(args))
    audit.record("key-passwd", strict=False, chain=audit.process_chain(os.getpid()))
    print("recovery passphrase changed", file=sys.stderr)


def cmd_key_rm(args, store):
    store.keys.remove(args.id, force=args.force)
    audit.record("key-remove", strict=False, slot=args.id, chain=audit.process_chain(os.getpid()))
    print(f"removed key slot {args.id}", file=sys.stderr)


def cmd_log(args, store):
    entries = audit.entries(args.n)
    if args.json:
        for e in entries:
            print(json.dumps(e))
        return
    if not entries:
        print(f"no audit entries yet ({audit.log_path()})", file=sys.stderr)
        return
    for e in entries:
        when = datetime.fromisoformat(e["ts"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        result = "" if e.get("ok", True) else "FAILED"
        chain = " < ".join(c.split(" ", 1)[-1][:50] for c in (e.get("chain") or [])[1:3])
        print(f"{when}  {e['event']:<9} {e.get('name', ''):<24} {e.get('tier', ''):<8} {result:<6}  {chain}".rstrip())


def cmd_doctor(args, store):
    bad = []

    def report(level, text):
        print(f"[{level:^4}] {text}")
        if level == "FAIL":
            bad.append(text)

    if isinstance(store.dpapi, PowerShell):
        exe = shutil.which(store.dpapi.exe)
        report("ok" if exe else "FAIL", f"{store.dpapi.exe}: {exe or 'not found (WSL2 interop disabled? set CREDSTORE_POWERSHELL)'}")
    try:
        start = time.monotonic()
        back = store.dpapi.unprotect(store.dpapi.protect(CANARY))
        report("ok" if back == CANARY else "FAIL", f"DPAPI round trip ({time.monotonic() - start:.1f}s)" if back == CANARY
               else "DPAPI round trip returned a different value")
        right, wrong = os.urandom(32), os.urandom(32)
        blob = store.dpapi.protect_bytes(CANARY.encode(), right)
        report("ok" if store.dpapi.unprotect_bytes(blob, right) == CANARY.encode() else "FAIL", "DPAPI with entropy: round trip")
        try:
            store.dpapi.unprotect_bytes(blob, wrong)
            report("FAIL", "DPAPI with entropy: a wrong key OPENED the blob")
        except CredError:
            report("ok", "DPAPI with entropy: a wrong key is refused")
    except CredError as e:
        report("FAIL", f"DPAPI: {e}")

    slots = store.keyslots()
    methods = Counter(s["method"] for s in slots)
    if isinstance(store.fido, WindowsFido) and (methods["fido2"] or args.yubikey):
        try:
            report("ok", f"uv.exe: {find_uv()}")
        except CredError as e:
            report("FAIL", str(e))
    if not slots:
        report("warn", "no keys yet: `cred init` adds the YubiKey and the recovery passphrase")
    else:
        report("ok" if methods["fido2"] else "warn", f"YubiKey slots: {methods['fido2']}")
        report("ok" if methods["passphrase"] else "warn", f"recovery passphrase: {'set' if methods['passphrase'] else 'MISSING'}")
    if args.yubikey:
        try:
            store.keys.data_key("unlock", "fido2")
            report("ok", "YubiKey opens the unlock key")
        except CredError as e:
            report("FAIL", f"YubiKey: {e}")

    if store.path.exists():
        loose = [str(p) for p in (store.path, store.path.parent) if stat.S_IMODE(p.stat().st_mode) & 0o077]
        tiers = Counter(r["tier"] for r in store.rows())
        counts = ", ".join(f"{tiers[t]} {t}" for t in TIERS if tiers[t]) or "no secrets"
        report("warn" if loose else "ok", f"{store.path}: {counts}" + (f"; group/other can access {', '.join(loose)}" if loose else ", private"))
    else:
        report("ok", f"{store.path}: not created yet (the first `cred set` creates it)")
    try:
        status = store.agent.status()
        report("ok", f"agent: unlocked until {local_hhmm(status['until'])}" if status else "agent: locked")
    except CredError as e:
        report("warn", f"agent: {e}")
    return 1 if bad else 0


# ---- parser

def build_parser():
    p = argparse.ArgumentParser(prog="cred", description="Machine-bound secret store for WSL2 (Windows DPAPI), unlocked with a YubiKey. "
                                                         "Run `cred doctor` first.")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(parent, name, func, help, *positionals, passphrase=False):
        sp = parent.add_parser(name, help=help, description=help)
        for a in positionals:
            sp.add_argument(a)
        if passphrase:
            sp.add_argument("--passphrase", action="store_true", help="use the recovery passphrase instead of the YubiKey")
        sp.set_defaults(func=func)
        return sp

    def meta(sp):
        sp.add_argument("--note", help="free text, shown by list ('' clears it; omitted keeps the stored one)")
        sp.add_argument("--expires", help="YYYY-MM-DD, YYYY-MM-DDTHH:MM (UTC), 90d, or none (omitted keeps the stored one)")
        return sp

    s = meta(add(sub, "set", cmd_set, "store or replace a secret (silent prompt on a tty, else stdin)", "name", passphrase=True))
    s.add_argument("--tier", choices=TIERS, help="open: no unlock needed; locked: needs `cred unlock`; confirm: YubiKey on every read "
                                                 "(default: the current tier, or locked once `cred init` ran)")
    add(sub, "get", cmd_get, "print a secret (no trailing newline when piped)", "name", passphrase=True)
    add(sub, "list", cmd_list, "list names, tiers, expiry and notes (never decrypts)").add_argument("--json", action="store_true")
    add(sub, "rm", cmd_rm, "delete a secret", "name")
    add(sub, "tier", cmd_tier, "move a secret to another tier (re-encrypts it)", "name", passphrase=True).add_argument("tier", choices=TIERS)
    add(sub, "exec", cmd_exec, "run a command with secrets as environment variables: cred exec -e VAR=NAME -- cmd ...",
        passphrase=True).add_argument("-e", "--env", action="append", required=True, metavar="VAR=NAME")
    add(sub, "curl-config", cmd_curl_config, 'print user = "USER:secret" for  curl -K - ...', "name", "user", passphrase=True)
    meta(add(sub, "import", cmd_import, "adopt an existing ConvertFrom-SecureString .dpapi file (open tier)", "name", "file"))

    i = add(sub, "init", cmd_init, "create the data keys: a recovery passphrase plus your YubiKey")
    i.add_argument("--no-yubikey", action="store_true", help="passphrase only for now (add the key later with `cred key add-yubikey`)")
    i.add_argument("--label", help="name for the YubiKey slot")
    u = add(sub, "unlock", cmd_unlock, "open the locked tier for a while (YubiKey fingerprint)", passphrase=True)
    u.add_argument("--for", dest="for_", default="30m", help="lock after this long in any case (default 30m, at most 24h)")
    u.add_argument("--idle", default="10m", help="lock after this long without a read (default 10m)")
    add(sub, "lock", cmd_lock, "lock now")
    add(sub, "status", cmd_status, "locked or unlocked, secrets per tier, key slots").add_argument("--json", action="store_true")

    k = sub.add_parser("key", help="manage the key slots (YubiKeys, recovery passphrase)", description="manage the key slots")
    ksub = k.add_subparsers(dest="key_cmd", required=True, metavar="action")
    add(ksub, "list", cmd_key_list, "list key slots")
    add(ksub, "add-yubikey", cmd_key_add_yubikey, "enroll another YubiKey (a backup key)", passphrase=True).add_argument("--label")
    add(ksub, "passwd", cmd_key_passwd, "set a new recovery passphrase", passphrase=True)
    r = add(ksub, "rm", cmd_key_rm, "remove a key slot")
    r.add_argument("id", type=int)
    r.add_argument("--force", action="store_true", help="allow removing the only recovery passphrase")

    lg = add(sub, "log", cmd_log, "show the audit log (who read what)")
    lg.add_argument("-n", type=int, default=20, help="entries to show (default 20)")
    lg.add_argument("--json", action="store_true")
    add(sub, "doctor", cmd_doctor, "check PowerShell, DPAPI, keys and the agent").add_argument(
        "--yubikey", action="store_true", help="also check that the YubiKey opens the store (one fingerprint)")
    return p


def main(argv=None, store=None):
    argv, command = list(sys.argv[1:] if argv is None else argv), []
    if "--" in argv and "exec" in argv[:argv.index("--")]:      # everything after -- is the command, never parsed
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    args.command = command
    try:
        return args.func(args, store or Store()) or 0
    except CredError as e:
        print(f"cred: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
