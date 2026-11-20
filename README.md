# cred

A machine-bound secret store for WSL2. Secrets are encrypted with Windows DPAPI, so a copied `store.db` cannot be
decrypted on another PC or by another Windows user. On top of that, secrets can sit in tiers that only your unlock
device opens (a YubiKey fingerprint, or Windows Hello), so the store stays closed even to programs running as you.

## Tiers

| tier      | opens with                                    | use it for                                      |
|-----------|-----------------------------------------------|-------------------------------------------------|
| `open`    | nothing: any process running as you           | automation that runs unattended (cron, scripts) |
| `locked`  | `cred unlock` (one device check), for a while | everyday credentials                            |
| `confirm` | your device on **every** read                 | the few secrets that matter most                |

After `cred init`, new secrets default to `locked`. Existing secrets stay where they are; move them with `cred tier`.

## Setup

Windows side, once: `uv.exe` (the YubiKey and Windows Hello are reached through the Windows WebAuthn API, from Windows
Python):

    winget install --id astral-sh.uv -e

WSL side:

    cp ~/.config/credstore/store.db ~/.config/credstore/store.db.bak     # if you used the single-file version
    uv tool install git+https://github.com/damhau/cred    # add --force to replace an older ~/.local/bin/cred script
    cred doctor
    cred init                                   # pick the unlock device, set the recovery passphrase, one device check
    cred doctor --device

Upgrade with `uv tool upgrade credstore`; pin a release with `git+https://github.com/damhau/cred@v0.3.0`. Keep the
recovery passphrase somewhere safe, offline: it is the way back in if the device is lost or reset.

### Choosing the unlock device

`cred init` asks (or `cred init --device yubikey|hello|none`):

| device          | you verify with                              | needs                                                     |
|-----------------|----------------------------------------------|-----------------------------------------------------------|
| `yubikey`       | the fingerprint, matched on the key          | a FIDO2 key with a fingerprint reader (YubiKey Bio)       |
| `hello`         | face, fingerprint or PIN, whatever Hello uses | Windows 11 24H2/25H2 with the February 2026 update or later (PRF support) |
| `none`          | the recovery passphrase only, for now        | nothing                                                   |

The device chosen at `cred init` is the default for every unlock and confirm read. `cred key add yubikey|hello` enrolls
another one (a backup YubiKey, or the other kind); use it with `--with yubikey|hello`. Every enrolled device is a way
in, so the store is only as strong as the weakest one: a PIN-only Windows Hello next to a YubiKey Bio lowers it to the PIN.

## Use

    cred unlock [--for 30m] [--idle 10m]      fingerprint, then the locked tier opens until --for, or --idle without reads
    cred lock | cred status
    cred set NAME [--tier open|locked|confirm] [--note TEXT] [--expires 2027-01-31|90d|none]
    cred get NAME                             prints the secret (no trailing newline when piped)
    cred tier NAME TIER                       re-encrypts under another tier
    cred list [--json] | cred rm NAME
    cred exec -e VAR=NAME [-e ...] -- command ...
    cred curl-config NAME USER                user = "USER:secret" for  curl -K - ...
    cred import NAME FILE                     adopts a ConvertFrom-SecureString .dpapi file (open tier)
    cred log [-n 20] [--json]                 who read what
    cred key list | add yubikey|hello | passwd | rm ID
    cred doctor [--device [--with yubikey|hello]]

`--with yubikey|hello|passphrase` on get / set / tier / exec / curl-config / unlock / key picks how to verify, instead of the
device chosen at `cred init`; `--passphrase` is short for `--with passphrase`.

From Python (`uv run --with git+https://github.com/damhau/cred script.py`): `credstore.get("splunk")`, `credstore.resolve("cred:splunk")`.

## How it works

* **Open tier**: `ConvertFrom-SecureString` DPAPI, as in the first version (same hex format, so old blobs and `.dpapi` files work).
* **Data keys**: two random 32-byte keys, *unlock* and *confirm*. A locked or confirm secret is DPAPI-protected with
  `HMAC(data key, name)` as DPAPI's optional entropy: DPAPI refuses to open it without that value, even for you, and a
  blob copied to another name does not open.
* **Key slots** wrap both data keys with DPAPI, the entropy being a value only that slot can produce:
  * *YubiKey*: the WebAuthn PRF (`hmac-secret`) output of a non-discoverable credential for `cred.local`, with user
    verification required (the fingerprint, checked on the key). One salt per data key, so an unlock never yields the
    confirm key.
  * *Windows Hello*: the same PRF, from a platform credential (a passkey for `cred.local`, kept in this PC's TPM; it
    shows in Settings > Accounts > Passkeys, and deleting it there removes this way in).
  * *Recovery passphrase*: scrypt (n=2^17, r=8, 128 MiB).
* **The agent** (`cred unlock`) is a background process that holds only the unlock key. It marks itself non-dumpable
  (`PR_SET_DUMPABLE=0`, no core files), so other processes running as you cannot read its memory; it listens on a 0600
  socket in `$XDG_RUNTIME_DIR/credstore/`, checks the caller's uid, never hands the key out, logs every read with the
  caller's process chain, and refuses a read it cannot log. It locks at `--for`, after `--idle` without reads, on
  `cred lock`, or when WSL stops.
* **Confirm reads** go straight to the device from the reading process; the agent cannot open them.
* **Audit log**: `~/.local/state/credstore/audit.log` (JSON lines). Anything running as you can edit it: it shows
  activity, it does not prove it.

## What this does and does not protect

* A copied `store.db`, backups, repo leaks: nothing opens off this PC and Windows user.
* Programs running as you while the store is **locked**: open-tier secrets only. Anything more needs your device check
  (with the YubiKey unplugged, nothing else opens at all).
* While **unlocked**: any program running as you can ask the agent for locked secrets until it locks. Every such read
  is in `cred log`. Keep `--for` short and `cred lock` when done.
* `confirm` secrets need a device check each time. Do not confirm a prompt you did not just ask for: a program running
  as you can raise the same Windows prompt.
* Windows Hello compared with the YubiKey: nothing to carry or lose, but nothing to unplug either, and with a PIN-only
  Hello anyone who sees you type the PIN can unlock at this PC. The TPM limits guessing (it locks out after a few wrong
  PINs). A Hello with face or fingerprint is close to the YubiKey Bio.
* Not covered: someone with admin or root on the machine, or Windows malware running as your user.

## Settings

| variable                 | default                                      |
|--------------------------|----------------------------------------------|
| `CREDSTORE_DB`           | `~/.config/credstore/store.db`               |
| `CREDSTORE_POWERSHELL`   | `powershell.exe`                             |
| `CREDSTORE_UV_EXE`       | `uv.exe` on the PATH                         |
| `CREDSTORE_AGENT_SOCKET` | `$XDG_RUNTIME_DIR/credstore/agent-<db hash>.sock` |
| `CREDSTORE_AUDIT_LOG`    | `$XDG_STATE_HOME/credstore/audit.log`        |

## Development

    uv run pytest

DPAPI and the WebAuthn devices are replaced by fakes in the tests. The agent tests need unix sockets and are skipped where
those are blocked (for example inside a sandbox); CI runs all of them. `cred doctor --device` is the
end-to-end check on real hardware.
