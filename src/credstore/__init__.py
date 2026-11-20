"""credstore: a machine-bound secret store for WSL2 (Windows DPAPI) with YubiKey-gated tiers.

    credstore.get("splunk")              the secret
    credstore.resolve("cred:splunk")     "cred:NAME" -> the secret, "env:VAR" -> $VAR, anything else is returned as is
"""

import os

from .core import CredError
from .store import Store

__all__ = ["CredError", "Store", "get", "resolve"]


def get(name, store=None):
    return (store or Store()).get(name)


def resolve(value, store=None):
    """'cred:NAME' -> the secret, 'env:VAR' -> the variable, anything else is a literal and comes back unchanged."""
    if value.startswith("cred:"):
        return get(value[5:], store)
    if value.startswith("env:"):
        try:
            return os.environ[value[4:]]
        except KeyError:
            raise CredError(f"environment variable {value[4:]} is not set") from None
    return value
