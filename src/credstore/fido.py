"""YubiKey and Windows Hello through WebAuthn PRF (hmac-secret) and the Windows WebAuthn API.

Since Windows 10 1903 a non-admin process can only reach a FIDO key through webauthn.dll, so the helper below runs in
Windows Python (uv.exe) with Yubico's fido2 library. The same call reaches Windows Hello when the credential is a
platform one. Only non-secret values (credential ids, salts) go in argv; the PRF outputs come back on stdout. The
authenticator verifies the user itself and the output for a salt never changes, which makes it usable as key material.
"""

import glob
import json
import os
import shutil
import subprocess
from pathlib import Path

from .core import CredError, b64d, b64e

FIDO2_VERSION = "2.2.1"
WINDOWS_PYTHON = "3.12"
TIMEOUT = 180               # seconds: the first run downloads Python and fido2 on the Windows side

HELPER = r'''
import sys
if sys.path and sys.path[0] in ("", "."):
    sys.path.pop(0)

import json
import os

from fido2.client import DefaultClientDataCollector
from fido2.client.windows import WindowsClient
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AuthenticatorAttachment, AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, ResidentKeyRequirement, UserVerificationRequirement,
)

TIMEOUT_MS = 60000
KEY = PublicKeyCredentialType.PUBLIC_KEY


def reply(obj, code=0):
    print(json.dumps(obj))
    sys.exit(code)


def outputs(extensions):
    results = (extensions.get("prf") or {}).get("results") or {}
    return [v if isinstance(v, str) else websafe_encode(v) for v in (results.get("first"), results.get("second")) if v is not None]


def prf_values(salts):
    return {"first": salts[0], **({"second": salts[1]} if len(salts) > 1 else {})}


def descriptors(cred_ids):
    return [PublicKeyCredentialDescriptor(type=KEY, id=websafe_decode(c)) for c in cred_ids]


def enroll(client, req):
    platform = req.get("platform", False)
    result = client.make_credential(PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id=req["rp_id"], name="credstore"),
        user=PublicKeyCredentialUserEntity(id=os.urandom(16), name="credstore", display_name="credstore secret store"),
        challenge=os.urandom(32),
        pub_key_cred_params=[PublicKeyCredentialParameters(type=KEY, alg=-7), PublicKeyCredentialParameters(type=KEY, alg=-8)],
        timeout=TIMEOUT_MS,
        exclude_credentials=descriptors(req["exclude"]),
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM if platform else AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED if platform else ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        extensions={"prf": {"eval": prf_values(req["salts"])}},
    ))
    if not result.response.attestation_object.auth_data.is_user_verified():
        reply({"error": "you were not verified (no fingerprint, face or PIN check)"}, 1)
    extensions = result.client_extension_results
    out = outputs(extensions)
    if not out and not (extensions.get("prf") or {}).get("enabled"):
        reply({"error": "this authenticator does not support PRF (hmac-secret)"}, 1)
    reply({"cred_id": websafe_encode(result.raw_id), "outputs": out})


def prf(client, req):
    creds = req["creds"]
    if len(creds) == 1:
        extension = {"eval": prf_values(next(iter(creds.values())))}
    else:
        extension = {"evalByCredential": {c: prf_values(s) for c, s in creds.items()}}
    response = client.get_assertion(PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id=req["rp_id"],
        timeout=TIMEOUT_MS,
        allow_credentials=descriptors(creds),
        user_verification=UserVerificationRequirement.REQUIRED,
        extensions={"prf": extension},
    )).get_response(0)
    if not response.response.authenticator_data.is_user_verified():
        reply({"error": "you were not verified (no fingerprint, face or PIN check)"}, 1)
    out = outputs(response.client_extension_results)
    if not out:
        reply({"error": "the authenticator returned no PRF output"}, 1)
    reply({"cred_id": websafe_encode(response.raw_id), "outputs": out})


def main():
    req = json.loads(websafe_decode(sys.argv[1]))
    if not WindowsClient.is_available():
        reply({"error": "webauthn.dll is not available (needs Windows 10 1903 or later)"}, 1)
    client = WindowsClient(DefaultClientDataCollector("https://" + req["rp_id"]))
    try:
        {"enroll": enroll, "prf": prf}[req["op"]](client, req)
    except Exception as e:
        reply({"error": f"{type(e).__name__}: {e}"}, 1)


main()
'''


def find_uv():
    if exe := os.environ.get("CREDSTORE_UV_EXE"):
        return exe
    if exe := shutil.which("uv.exe"):
        return exe
    candidates = glob.glob("/mnt/c/Users/*/.local/bin/uv.exe")
    if len(candidates) == 1:
        return candidates[0]
    raise CredError("uv.exe not found on the Windows side: install it with  winget install --id astral-sh.uv -e  (or set CREDSTORE_UV_EXE)")


class WindowsFido:
    """enroll(rp_id, salts, exclude, platform) and prf(rp_id, {cred_id: salts}); tests use a fake with the same two methods."""

    def __init__(self, uv_exe=None):
        self._uv_exe = uv_exe

    @property
    def uv_exe(self):
        if self._uv_exe is None:
            self._uv_exe = find_uv()
        return self._uv_exe

    def enroll(self, rp_id, salts, exclude=(), platform=False):
        """New credential on a security key, or on Windows Hello when platform;
        -> (cred_id, PRF outputs for salts, or [] when Windows gives none at creation)."""
        r = self._run({"op": "enroll", "rp_id": rp_id, "salts": [b64e(s) for s in salts], "exclude": [b64e(c) for c in exclude],
                       "platform": platform})
        return b64d(r["cred_id"]), [b64d(o) for o in r.get("outputs") or []]

    def prf(self, rp_id, creds):
        """creds: {cred_id: [salt, salt?]}; any one of them answers -> (its cred_id, its PRF outputs)."""
        r = self._run({"op": "prf", "rp_id": rp_id, "creds": {b64e(c): [b64e(s) for s in salts] for c, salts in creds.items()}})
        return b64d(r["cred_id"]), [b64d(o) for o in r["outputs"]]

    def _run(self, request):
        uv = self.uv_exe
        cmd = [uv, "run", "--quiet", "--no-project", "--python", WINDOWS_PYTHON, "--with", f"fido2=={FIDO2_VERSION}",
               "python", "-", b64e(json.dumps(request).encode())]
        # A Windows-side working directory avoids handing uv.exe a \\wsl.localhost UNC path.
        cwd = str(Path(uv).parent) if uv.startswith("/mnt/") else None
        try:
            r = subprocess.run(cmd, input=HELPER.encode(), capture_output=True, timeout=TIMEOUT, cwd=cwd)
        except FileNotFoundError:
            raise CredError(f"{uv} not found (set CREDSTORE_UV_EXE)") from None
        except subprocess.TimeoutExpired:
            raise CredError(f"no answer from the authenticator within {TIMEOUT}s") from None
        lines = r.stdout.decode("utf-8", "replace").strip().splitlines()
        try:
            reply = json.loads(lines[-1])
        except (IndexError, ValueError):
            detail = r.stderr.decode("utf-8", "replace").strip()[-300:] or "no output"
            raise CredError(f"the WebAuthn helper failed: {detail}") from None
        if "error" in reply:
            raise CredError(f"WebAuthn: {reply['error']}")
        return reply
