"""The Windows-side helper, run here against a fake webauthn client but with fido2's real option parsing."""

import contextlib
import hashlib
import io
import json
import sys
import types
from types import SimpleNamespace

import pytest
from fido2.ctap2.extensions import AuthenticatorExtensionsPRFInputs
from fido2.webauthn import AuthenticatorAttachment, ResidentKeyRequirement, UserVerificationRequirement

from credstore.core import b64d, b64e
from credstore.fido import HELPER


def device_prf(cred_id, salt):
    return hashlib.sha256(cred_id + salt).digest()


class FakeWindowsClient:
    calls = []
    verified = True
    answer = 0
    fail = None

    def __init__(self, client_data_collector, handle=None, allow_hmac_secret=False):
        pass

    @staticmethod
    def is_available():
        return True

    def make_credential(self, options):
        self.calls.append(options)
        if self.fail:
            raise self.fail
        prf = AuthenticatorExtensionsPRFInputs.from_dict(options.extensions["prf"])
        cred_id = b"cred-new"
        results = {"first": device_prf(cred_id, prf.eval.first), "second": device_prf(cred_id, prf.eval.second)}
        return SimpleNamespace(
            raw_id=cred_id,
            response=SimpleNamespace(attestation_object=SimpleNamespace(auth_data=SimpleNamespace(is_user_verified=lambda: self.verified))),
            client_extension_results={"prf": {"enabled": True, "results": results}},
        )

    def get_assertion(self, options):
        self.calls.append(options)
        prf = AuthenticatorExtensionsPRFInputs.from_dict(options.extensions["prf"])
        cred_id = options.allow_credentials[self.answer].id
        values = prf.eval if prf.eval else prf.eval_by_credential[b64e(cred_id)]
        results = {"first": device_prf(cred_id, values.first)}
        if values.second:
            results["second"] = device_prf(cred_id, values.second)
        response = SimpleNamespace(
            raw_id=cred_id,
            response=SimpleNamespace(authenticator_data=SimpleNamespace(is_user_verified=lambda: self.verified)),
            client_extension_results={"prf": {"results": results}},
        )
        return SimpleNamespace(get_response=lambda i: response)


@pytest.fixture
def client(monkeypatch):
    fake = types.ModuleType("fido2.client.windows")
    fake.WindowsClient = FakeWindowsClient
    monkeypatch.setitem(sys.modules, "fido2.client.windows", fake)
    FakeWindowsClient.calls, FakeWindowsClient.verified, FakeWindowsClient.answer, FakeWindowsClient.fail = [], True, 0, None
    return FakeWindowsClient


def run_helper(monkeypatch, request):
    monkeypatch.setattr(sys, "argv", ["-", b64e(json.dumps(request).encode())])
    monkeypatch.setattr(sys, "path", ["", *sys.path])
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_:
        exec(compile(HELPER, "helper", "exec"), {"__name__": "__main__"})
    return exit_.value.code, json.loads(out.getvalue().strip().splitlines()[-1])


def test_enroll_asks_for_a_verified_roaming_non_resident_credential(client, monkeypatch):
    s1, s2 = b"1" * 32, b"2" * 32
    code, reply = run_helper(monkeypatch, {"op": "enroll", "rp_id": "cred.local", "salts": [b64e(s1), b64e(s2)], "exclude": [b64e(b"old")]})
    assert code == 0
    assert b64d(reply["cred_id"]) == b"cred-new"
    assert [b64d(o) for o in reply["outputs"]] == [device_prf(b"cred-new", s1), device_prf(b"cred-new", s2)]
    options = client.calls[0]
    assert options.rp.id == "cred.local"
    assert options.authenticator_selection.user_verification == UserVerificationRequirement.REQUIRED
    assert options.authenticator_selection.authenticator_attachment == AuthenticatorAttachment.CROSS_PLATFORM
    assert options.authenticator_selection.resident_key == ResidentKeyRequirement.DISCOURAGED
    assert [d.id for d in options.exclude_credentials] == [b"old"]


def test_prf_with_one_key_uses_eval(client, monkeypatch):
    salt = b"u" * 32
    code, reply = run_helper(monkeypatch, {"op": "prf", "rp_id": "cred.local", "creds": {b64e(b"k1"): [b64e(salt)]}})
    assert code == 0
    assert [b64d(o) for o in reply["outputs"]] == [device_prf(b"k1", salt)]
    assert "eval" in client.calls[0].extensions["prf"]
    assert client.calls[0].user_verification == UserVerificationRequirement.REQUIRED


def test_prf_with_two_keys_uses_per_credential_salts(client, monkeypatch):
    client.answer = 1
    creds = {b64e(b"k1"): [b64e(b"a" * 32), b64e(b"b" * 32)], b64e(b"k2"): [b64e(b"c" * 32), b64e(b"d" * 32)]}
    code, reply = run_helper(monkeypatch, {"op": "prf", "rp_id": "cred.local", "creds": creds})
    assert code == 0
    assert b64d(reply["cred_id"]) == b"k2"
    assert [b64d(o) for o in reply["outputs"]] == [device_prf(b"k2", b"c" * 32), device_prf(b"k2", b"d" * 32)]


def test_unverified_user_is_an_error(client, monkeypatch):
    client.verified = False
    code, reply = run_helper(monkeypatch, {"op": "prf", "rp_id": "cred.local", "creds": {b64e(b"k1"): [b64e(b"u" * 32)]}})
    assert code == 1 and "did not verify" in reply["error"]


def test_client_errors_are_reported(client, monkeypatch):
    client.fail = RuntimeError("timed out")
    code, reply = run_helper(monkeypatch, {"op": "enroll", "rp_id": "cred.local", "salts": [b64e(b"1" * 32), b64e(b"2" * 32)], "exclude": []})
    assert code == 1 and reply["error"] == "RuntimeError: timed out"
