"""Errors, names, dates, durations and encodings: everything that touches neither DPAPI, the YubiKey nor the agent."""

import base64
import re
from datetime import datetime, timedelta, timezone

TIERS = ("open", "locked", "confirm")
EXPIRING_DAYS = 30          # list flags secrets that expire within this many days
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DURATION_RE = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?")
KEEP = object()             # "leave the stored note / expiry / tier alone"


class CredError(Exception):
    """A failure the caller should see as a clean message."""


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc(text):
    """ISO date or datetime -> aware UTC datetime (naive input counts as UTC)."""
    d = datetime.fromisoformat(text)
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def parse_expires(text, now=None):
    """'2027-01-31' (00:00 UTC that day) | '2027-01-31T08:00' (UTC unless it has an offset) | '90d' -> ISO UTC string; 'none' -> None."""
    t = text.strip().lower()
    if t in ("none", "never", "-"):
        return None
    if m := re.fullmatch(r"(\d{1,5})d", t):
        return ((now or utcnow()) + timedelta(days=int(m.group(1)))).isoformat()
    try:
        return utc(text.strip()).isoformat()
    except ValueError:
        raise CredError(f"cannot read --expires {text!r}: use YYYY-MM-DD, 90d or none") from None


def expiry(expires_at, now=None):
    """-> (state, days_left): state is none | ok | expiring | expired; days_left is the floor of the days to go (negative once expired)."""
    if not expires_at:
        return "none", None
    delta = utc(expires_at) - (now or utcnow())
    return ("expired" if delta <= timedelta(0) else "expiring" if delta <= timedelta(days=EXPIRING_DAYS) else "ok"), delta.days


def parse_duration(text):
    """'90s' | '15m' | '2h' | '1h30m' -> seconds."""
    m = DURATION_RE.fullmatch(text.strip().lower())
    if not text.strip() or not m or not any(m.groups()):
        raise CredError(f"cannot read duration {text!r}: use e.g. 90s, 15m, 2h or 1h30m")
    h, mi, s = (int(g or 0) for g in m.groups())
    seconds = h * 3600 + mi * 60 + s
    if seconds <= 0:
        raise CredError(f"duration {text!r} must be positive")
    return seconds


def check_name(name):
    if not NAME_RE.match(name):
        raise CredError(f"bad secret name {name!r}: letters, digits and . _ / - only, starting with a letter or digit")
    return name


def check_tier(tier):
    if tier not in TIERS:
        raise CredError(f"unknown tier {tier!r}: one of {', '.join(TIERS)}")
    return tier


def b64e(data):
    """bytes -> base64url without padding (the WebAuthn encoding)."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
