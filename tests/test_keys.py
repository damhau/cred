import pytest

from credstore.core import CredError, b64d
from credstore.keys import passphrase_slot_keys, secret_entropy
from tests.conftest import PASSPHRASE


def test_init_creates_a_yubikey_and_a_passphrase_slot(keyed):
    assert [s["method"] for s in keyed.keyslots()] == ["fido2", "passphrase"]
    assert keyed.default_tier() == "locked"


def test_init_twice_is_refused(keyed):
    with pytest.raises(CredError, match="already exist"):
        keyed.keys.init(PASSPHRASE)


def test_short_passphrase_is_refused(store):
    with pytest.raises(CredError, match="at least"):
        store.keys.init("short")
    assert store.keyslots() == []


def test_yubikey_and_passphrase_open_the_same_keys(keyed):
    by_key = keyed.keys.data_keys("fido2")
    by_passphrase = keyed.keys.data_keys("passphrase")
    assert by_key == by_passphrase
    assert len(by_key["unlock"]) == 32 and by_key["unlock"] != by_key["confirm"]


def test_wrong_passphrase(keyed):
    keyed.ask_passphrase = lambda prompt: "not the passphrase"
    with pytest.raises(CredError, match="wrong passphrase"):
        keyed.keys.data_key("unlock", "passphrase")


def test_unplugged_yubikey(keyed):
    keyed.fido.plugged = False
    with pytest.raises(CredError, match="timed out"):
        keyed.keys.data_key("unlock")
    assert len(keyed.keys.data_key("unlock", "passphrase")) == 32


def test_unlock_output_cannot_open_the_confirm_key(keyed):
    """The agent only ever sees the PRF output for the unlock salt; it must not open the confirm key."""
    slot = keyed.keyslots()[0]
    cred_id = b64d(slot["params"]["cred_id"])
    _, (unlock_output,) = keyed.fido.prf("cred.local", {cred_id: [b64d(slot["params"]["salt_unlock"])]})
    assert keyed.dpapi.unprotect_bytes(slot["wrapped_unlock"], unlock_output)
    with pytest.raises(CredError):
        keyed.dpapi.unprotect_bytes(slot["wrapped_confirm"], unlock_output)


def test_backup_yubikey(keyed):
    first = b64d(keyed.keyslots()[0]["params"]["cred_id"])
    keyed.keys.add_yubikey("backup")
    second = b64d(keyed.keyslots()[-1]["params"]["cred_id"])
    keyed.fido.plugged = second
    assert keyed.keys.data_keys() == keyed.keys.data_keys("passphrase")
    keyed.fido.plugged = first
    assert keyed.keys.data_key("confirm") == keyed.keys.data_key("confirm", "passphrase")


def test_change_passphrase(keyed):
    before = keyed.keys.data_keys()
    keyed.keys.set_passphrase(lambda: "a brand new recovery phrase", "fido2")
    assert [s["method"] for s in keyed.keyslots()].count("passphrase") == 1
    keyed.ask_passphrase = lambda prompt: "a brand new recovery phrase"
    assert keyed.keys.data_keys("passphrase") == before
    keyed.ask_passphrase = lambda prompt: PASSPHRASE
    with pytest.raises(CredError, match="wrong passphrase"):
        keyed.keys.data_keys("passphrase")


def test_slot_removal_guards(keyed):
    fido, passphrase = keyed.keyslots()
    with pytest.raises(CredError, match="only recovery passphrase"):
        keyed.keys.remove(passphrase["id"])
    keyed.keys.remove(fido["id"])
    with pytest.raises(CredError, match="last key slot"):
        keyed.keys.remove(passphrase["id"], force=True)
    assert keyed.keys.data_key("unlock")


def test_secret_entropy_binds_the_name():
    key = b"k" * 32
    assert secret_entropy(key, "a") != secret_entropy(key, "b")
    assert secret_entropy(key, "a") != secret_entropy(b"j" * 32, "a")


def test_passphrase_slot_keys_depend_on_salt():
    params = {"salt": "AAAAAAAAAAAAAAAAAAAAAA", "n": 2**10, "r": 8, "p": 1}
    other = {**params, "salt": "AQEBAQEBAQEBAQEBAQEBAQ"}
    assert passphrase_slot_keys("pw", params) == passphrase_slot_keys("pw", params)
    assert passphrase_slot_keys("pw", params)["unlock"] != passphrase_slot_keys("pw", other)["unlock"]
