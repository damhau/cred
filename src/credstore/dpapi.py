"""Windows DPAPI through powershell.exe.

Without entropy (open tier): the ConvertFrom-SecureString hex format, so existing .dpapi files import as they are.
With entropy (locked and confirm tiers, key slots): ProtectedData base64, which DPAPI only opens when given the same entropy back.
Values travel as base64 on stdin/stdout: never in argv (ps), and no codepage trouble.
"""

import base64
import binascii
import html
import os
import re
import subprocess

from .core import CredError

TIMEOUT = 30                # seconds for one powershell.exe call
HEX_BLOB_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
B64_BLOB_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

_PRELUDE = "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'\n"
PROTECT_PS = _PRELUDE + r"""
$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()))
ConvertFrom-SecureString (ConvertTo-SecureString $text -AsPlainText -Force)
"""
UNPROTECT_PS = _PRELUDE + r"""
$secure = ConvertTo-SecureString ([Console]::In.ReadToEnd().Trim())
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain))
"""
PROTECT_BYTES_PS = _PRELUDE + r"""
Add-Type -AssemblyName System.Security
$entropy, $data = [Console]::In.ReadToEnd().Trim() -split '\s+'
$out = [Security.Cryptography.ProtectedData]::Protect([Convert]::FromBase64String($data), [Convert]::FromBase64String($entropy), 'CurrentUser')
[Convert]::ToBase64String($out)
"""
UNPROTECT_BYTES_PS = _PRELUDE + r"""
Add-Type -AssemblyName System.Security
$entropy, $blob = [Console]::In.ReadToEnd().Trim() -split '\s+'
$out = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($blob), [Convert]::FromBase64String($entropy), 'CurrentUser')
[Convert]::ToBase64String($out)
"""


class PowerShell:
    """The DPAPI backend. Tests use a fake with the same four methods."""

    def __init__(self, exe=None):
        self.exe = exe or os.environ.get("CREDSTORE_POWERSHELL", "powershell.exe")

    def protect(self, secret):
        blob = self._run(PROTECT_PS, base64.b64encode(secret.encode()).decode())
        if not HEX_BLOB_RE.match(blob):
            raise CredError("powershell.exe returned something that is not a DPAPI blob")
        return blob

    def unprotect(self, blob):
        return self._decode(self._run(UNPROTECT_PS, blob)).decode()

    def protect_bytes(self, data, entropy):
        blob = self._run(PROTECT_BYTES_PS, f"{base64.b64encode(entropy).decode()} {base64.b64encode(data).decode()}")
        if not B64_BLOB_RE.match(blob):
            raise CredError("powershell.exe returned something that is not a DPAPI blob")
        return blob

    def unprotect_bytes(self, blob, entropy):
        if not B64_BLOB_RE.match(blob):
            raise CredError("stored blob is not base64: the database is damaged")
        return self._decode(self._run(UNPROTECT_BYTES_PS, f"{base64.b64encode(entropy).decode()} {blob}"))

    @staticmethod
    def _decode(answer):
        try:
            return base64.b64decode(answer, validate=True)
        except binascii.Error:
            raise CredError("powershell.exe returned an unreadable answer") from None

    def _run(self, script, data):
        cmd = [self.exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode()]
        try:
            r = subprocess.run(cmd, input=data.encode(), capture_output=True, timeout=TIMEOUT)
        except FileNotFoundError:
            raise CredError(f"{self.exe} not found: cred needs WSL2 with Windows interop (or set CREDSTORE_POWERSHELL)") from None
        except subprocess.TimeoutExpired:
            raise CredError(f"{self.exe} did not answer within {TIMEOUT}s") from None
        if r.returncode:
            raise CredError(f"DPAPI call failed: {ps_error(r.stderr)}")
        return r.stdout.decode("ascii", "replace").strip()


def ps_error(raw):
    """powershell.exe -EncodedCommand reports errors as CLIXML on stderr: keep the first message line."""
    text = raw.decode("utf-8", "replace")
    m = re.search(r'<S S="Error">(.*?)</S>', text, re.S)
    msg = " ".join(html.unescape((m.group(1) if m else text).replace("_x000D__x000A_", " ")).split())[:300] or "no error text"
    if "Key not valid" in msg:
        msg += " (the blob was protected by another Windows user or machine)"
    elif "data is invalid" in msg:
        msg += " (wrong key for this blob)"
    return msg
