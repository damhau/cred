"""Data keys and the key slots that wrap them.

Two random 32-byte data keys:
* unlock:  opens the locked tier; the agent holds it while the store is unlocked.
* confirm: opens the confirm tier; never cached, so every read needs the YubiKey (or the passphrase).

A secret's DPAPI entropy is HMAC(data key, name): a blob only opens under its own name. Each key slot wraps both data keys
with DPAPI, using as entropy a value only that slot can produce: the YubiKey's PRF output for one salt per data key, or a
scrypt of the recovery passphrase. Because the two salts differ, unlocking (unlock salt only) never yields the confirm key.
"""

import hashlib
import hmac
import os

from .core import CredError, b64d, b64e

RP_ID = "cred.local"
WHICH = ("unlock", "confirm")
SCRYPT_PARAMS = {"n": 2**17, "r": 8, "p": 1}     # 128 MiB, about half a second
SCRYPT_MAXMEM = 256 * 1024 * 1024
MIN_PASSPHRASE = 12


def secret_entropy(key, name):
    return hmac.new(key, b"credstore/secret/v1\0" + name.encode(), hashlib.sha256).digest()


def passphrase_slot_keys(passphrase, params):
    master = hashlib.scrypt(passphrase.encode(), salt=b64d(params["salt"]), n=params["n"], r=params["r"], p=params["p"],
                            maxmem=SCRYPT_MAXMEM, dklen=32)
    return {w: hmac.new(master, b"credstore/slot/" + w.encode(), hashlib.sha256).digest() for w in WHICH}


def check_passphrase(passphrase):
    if len(passphrase) < MIN_PASSPHRASE:
        raise CredError(f"the recovery passphrase needs at least {MIN_PASSPHRASE} characters")
    return passphrase


class Keyring:
    def __init__(self, store):
        self.store = store

    def slots(self):
        return self.store.keyslots()

    def initialized(self):
        return bool(self.slots())

    def init(self, passphrase, yubikey=True, label=None):
        if self.slots():
            raise CredError("keys already exist: see `cred key list`")
        check_passphrase(passphrase)
        keys = {w: os.urandom(32) for w in WHICH}
        rows = [self._fido_slot(keys, label, exclude=[])] if yubikey else []
        rows.append(self._passphrase_slot(keys, passphrase))
        self.store.add_keyslots(rows)
        return rows

    def data_key(self, which, method=None):
        return self._open([which], method)[which]

    def data_keys(self, method=None):
        return self._open(list(WHICH), method)

    def add_yubikey(self, label=None, method=None):
        keys = self.data_keys(method)
        exclude = [b64d(s["params"]["cred_id"]) for s in self.slots() if s["method"] == "fido2"]
        row = self._fido_slot(keys, label, exclude)
        self.store.add_keyslots([row])
        return row

    def set_passphrase(self, choose, method=None):
        """Authenticate first (YubiKey or current passphrase), then ask choose() for the new passphrase."""
        keys = self.data_keys(method)
        row = self._passphrase_slot(keys, check_passphrase(choose()))
        self.store.replace_passphrase_slots(row)
        return row

    def remove(self, slot_id, force=False):
        slots = self.slots()
        target = next((s for s in slots if s["id"] == slot_id), None)
        if target is None:
            raise CredError(f"no key slot {slot_id}")
        rest = [s for s in slots if s["id"] != slot_id]
        if not rest:
            raise CredError("cannot remove the last key slot: every locked and confirm secret would be lost")
        if target["method"] == "passphrase" and not any(s["method"] == "passphrase" for s in rest) and not force:
            raise CredError("this is the only recovery passphrase: losing the YubiKey would then lose the secrets (--force to remove anyway)")
        self.store.delete_keyslot(slot_id)

    def _open(self, which, method):
        slots = self.slots()
        if not slots:
            raise CredError("no keys yet: run `cred init`")
        fido = [s for s in slots if s["method"] == "fido2"]
        method = method or ("fido2" if fido else "passphrase")
        if method == "fido2":
            return self._open_fido(fido, which)
        if method == "passphrase":
            return self._open_passphrase([s for s in slots if s["method"] == "passphrase"], which)
        raise CredError(f"unknown unlock method {method!r}")

    def _open_fido(self, fido, which):
        if not fido:
            raise CredError("no YubiKey enrolled: use --passphrase, or `cred key add-yubikey`")
        creds = {b64d(s["params"]["cred_id"]): [b64d(s["params"][f"salt_{w}"]) for w in which] for s in fido}
        cred_id, outputs = self.store.fido.prf(fido[0]["params"]["rp_id"], creds)
        slot = next((s for s in fido if b64d(s["params"]["cred_id"]) == cred_id), None)
        if slot is None:
            raise CredError("the YubiKey answered with a credential this store does not know")
        if len(outputs) < len(which):
            raise CredError("the YubiKey returned fewer PRF outputs than asked for")
        try:
            return self._unwrap(slot, dict(zip(which, outputs)), which)
        except CredError:
            raise CredError(f"the YubiKey output does not open key slot {slot['id']}") from None

    def _open_passphrase(self, slots, which):
        if not slots:
            raise CredError("no recovery passphrase is set: `cred key passwd`")
        passphrase = self.store.ask_passphrase("Recovery passphrase: ")
        for slot in slots:
            try:
                return self._unwrap(slot, passphrase_slot_keys(passphrase, slot["params"]), which)
            except CredError:
                continue
        raise CredError("wrong passphrase")

    def _unwrap(self, slot, slot_keys, which):
        return {w: self.store.dpapi.unprotect_bytes(slot[f"wrapped_{w}"], slot_keys[w]) for w in which}

    def _fido_slot(self, keys, label, exclude):
        salts = {w: os.urandom(32) for w in WHICH}
        cred_id, outputs = self.store.fido.enroll(RP_ID, [salts[w] for w in WHICH], exclude)
        if len(outputs) < len(WHICH):
            _, outputs = self.store.fido.prf(RP_ID, {cred_id: [salts[w] for w in WHICH]})
        params = {"rp_id": RP_ID, "cred_id": b64e(cred_id), **{f"salt_{w}": b64e(salts[w]) for w in WHICH}}
        return self._wrap("fido2", label or "YubiKey", params, dict(zip(WHICH, outputs)), keys)

    def _passphrase_slot(self, keys, passphrase):
        params = {"salt": b64e(os.urandom(16)), **SCRYPT_PARAMS}
        return self._wrap("passphrase", "recovery passphrase", params, passphrase_slot_keys(passphrase, params), keys)

    def _wrap(self, method, label, params, slot_keys, keys):
        return {"method": method, "label": label, "params": params,
                **{f"wrapped_{w}": self.store.dpapi.protect_bytes(keys[w], slot_keys[w]) for w in WHICH}}
