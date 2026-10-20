"""
twofa.py
========
Two-step verification: the 6-digit codes from an authenticator app such as
Google Authenticator, Microsoft Authenticator, Authy, or 1Password.

This follows the open TOTP standard (RFC 6238), so any authenticator app
works. This file holds only the logic. The pages and session handling are
in app.py and auth.py.

HOW IT PROTECTS THE ACCOUNT
  - Each admin has their own secret. It is stored encrypted in the database,
    using a key derived from SECRETS_KEY (the same key that protects
    secrets.json.enc). The database alone is not enough to read it.
  - A code can only be used once (replay protection).
  - After 5 wrong codes the account is locked for 15 minutes.
  - Each admin gets 10 one-time recovery codes in case they lose their phone.
    Only a keyed hash of each code is stored.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STEP_SECONDS = 30          # a new code every 30 seconds
CODE_DIGITS = 6
WINDOW = 1                 # also accept the code just before and after (clock drift)
MAX_FAILED = 5             # wrong codes allowed before a lock
LOCK_MINUTES = 15
PAIRING_MAX_MINUTES = 15   # how long a new QR code stays valid while being set up
RECOVERY_CODE_COUNT = 10

# No 0/O or 1/I/L, so a code is hard to misread when typed from a printout
_RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'


def _utcnow():
    """Current UTC time without a timezone label, matching the database columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------
def _master_key_bytes():
    key = os.getenv('SECRETS_KEY')
    if not key:
        raise RuntimeError('SECRETS_KEY is not set')
    return base64.urlsafe_b64decode(key.encode())


def _subkey(purpose):
    """A separate key for each job, all derived from SECRETS_KEY."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=purpose).derive(_master_key_bytes())


def _fernet():
    return Fernet(base64.urlsafe_b64encode(_subkey(b'gws2ad/2fa/secret/v1')))


def encrypt_secret(plain):
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token):
    """Returns the secret, or None if it can't be read (for example, SECRETS_KEY changed)."""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------
# Codes from the authenticator app
# ---------------------------------------------------------------------
def new_secret():
    """A fresh random secret (160 bits, shown as 32 letters/digits)."""
    return pyotp.random_base32()


def format_key(secret):
    """Groups of four, easier to type by hand: ABCD EFGH ..."""
    return ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))


def provisioning_uri(secret, account_name, issuer):
    """The text inside the QR code that authenticator apps understand."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def qr_svg(uri):
    """
    The QR code as an inline SVG image, made on the server (no outside service).
    The library's SVG has no viewBox, so when the page resizes it the picture
    is cropped instead of scaled and can no longer be scanned. Adding the
    viewBox lets it scale to any size.
    """
    svg = segno.make(uri, error='m').svg_inline(scale=5, border=4, dark='#0B1324')
    match = re.match(r'<svg width="(\d+)" height="(\d+)"', svg)
    if not match:
        raise RuntimeError('Unexpected QR code format from the segno library')
    w, h = match.groups()
    return svg.replace(
        match.group(0),
        f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" shape-rendering="crispEdges" '
        f'role="img" aria-label="QR code to scan with your authenticator app"',
        1,
    )


def verify_code(secret, code, last_used_step=None, now=None):
    """
    Checks a 6-digit code. Returns the 30-second step it matched, or None.
    Spaces and dashes in what the person typed are ignored. A step that was
    already used (or an older one) is refused, so a code works only once.
    """
    digits = ''.join(ch for ch in str(code or '') if ch.isdigit())
    if len(digits) != CODE_DIGITS:
        return None

    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // STEP_SECONDS)

    matched = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        # Check every step so the time taken doesn't reveal which one matched
        if hmac.compare_digest(totp.at(step * STEP_SECONDS), digits):
            matched = step

    if matched is None:
        return None
    if last_used_step is not None and matched <= last_used_step:
        return None
    return matched


# ---------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------
def generate_recovery_codes(count=RECOVERY_CODE_COUNT):
    """Plain codes like 'K7QMR-4XD2P'. Show them once, store only hashes."""
    codes = []
    while len(codes) < count:
        raw = ''.join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        code = f'{raw[:5]}-{raw[5:]}'
        if code not in codes:
            codes.append(code)
    return codes


def _normalize_recovery(code):
    return ''.join(ch for ch in str(code or '').upper() if ch.isalnum())


def _recovery_digest(code):
    return hmac.new(_subkey(b'gws2ad/2fa/recovery/v1'),
                    _normalize_recovery(code).encode(), hashlib.sha256).hexdigest()


def hash_recovery_codes(codes):
    return json.dumps([_recovery_digest(c) for c in codes])


def recovery_codes_left(stored):
    try:
        return len(json.loads(stored)) if stored else 0
    except ValueError:
        return 0


def consume_recovery_code(stored, code):
    """Returns the updated stored list with that code removed, or None if it isn't valid."""
    try:
        digests = json.loads(stored) if stored else []
    except ValueError:
        return None
    candidate = _recovery_digest(code)
    found = None
    for d in digests:                      # check all, no early exit
        if hmac.compare_digest(d, candidate):
            found = d
    if found is None:
        return None
    digests.remove(found)
    return json.dumps(digests)


# ---------------------------------------------------------------------
# Lockout after repeated wrong codes
# ---------------------------------------------------------------------
def lock_seconds_left(admin, now=None):
    now = now or _utcnow()
    until = admin.twofa_locked_until
    if until and until > now:
        return int((until - now).total_seconds()) + 1
    return 0


def register_failure(admin, now=None):
    now = now or _utcnow()
    admin.twofa_failed_attempts = (admin.twofa_failed_attempts or 0) + 1
    if admin.twofa_failed_attempts >= MAX_FAILED:
        admin.twofa_locked_until = now + timedelta(minutes=LOCK_MINUTES)
        admin.twofa_failed_attempts = 0


def register_success(admin):
    admin.twofa_failed_attempts = 0
    admin.twofa_locked_until = None


# ---------------------------------------------------------------------
# Checking a code for an admin who already has two-step set up
# (these change the admin object; the caller saves it to the database)
# ---------------------------------------------------------------------
def check_code(admin, code):
    secret = decrypt_secret(admin.totp_secret) if admin.totp_secret else None
    if not secret:
        return False
    step = verify_code(secret, code, admin.totp_last_step)
    if step is None:
        register_failure(admin)
        return False
    admin.totp_last_step = step
    register_success(admin)
    return True


def check_recovery_code(admin, code):
    updated = consume_recovery_code(admin.recovery_codes, code)
    if updated is None:
        register_failure(admin)
        return False
    admin.recovery_codes = updated
    register_success(admin)
    return True


# ---------------------------------------------------------------------
# Setting up (or replacing) the authenticator app
# A new secret waits in a separate "pending" spot until the person proves it
# works, so a half-finished setup never breaks the working one.
# ---------------------------------------------------------------------
def begin_pairing(admin, now=None):
    secret = new_secret()
    admin.totp_pending_secret = encrypt_secret(secret)
    admin.totp_pending_at = now or _utcnow()
    return secret


def current_pairing_secret(admin, now=None):
    if not admin.totp_pending_secret or not admin.totp_pending_at:
        return None
    now = now or _utcnow()
    if now - admin.totp_pending_at > timedelta(minutes=PAIRING_MAX_MINUTES):
        return None
    return decrypt_secret(admin.totp_pending_secret)


def finish_pairing(admin, code, now=None):
    """
    Confirms the person's code against the pending secret and makes it the
    active one. Returns the new recovery codes (plain, show once) if this was
    first-time setup, an empty list if it was just a new device, or None if
    the code was wrong or the setup expired.
    """
    secret = current_pairing_secret(admin, now)
    if not secret:
        return None
    step = verify_code(secret, code)
    if step is None:
        return None

    first_time = not admin.two_factor_enabled
    admin.totp_secret = admin.totp_pending_secret
    admin.totp_pending_secret = None
    admin.totp_pending_at = None
    admin.totp_enabled = True
    admin.totp_last_step = step
    admin.twofa_enrolled_at = now or _utcnow()
    register_success(admin)

    if first_time or not admin.recovery_codes:
        codes = generate_recovery_codes()
        admin.recovery_codes = hash_recovery_codes(codes)
        return codes
    return []


def regenerate_recovery_codes(admin):
    codes = generate_recovery_codes()
    admin.recovery_codes = hash_recovery_codes(codes)
    return codes


def reset(admin):
    """Removes two-step verification completely (the person sets it up again at next sign-in)."""
    admin.totp_secret = None
    admin.totp_pending_secret = None
    admin.totp_pending_at = None
    admin.totp_enabled = False
    admin.totp_last_step = None
    admin.recovery_codes = None
    admin.twofa_enrolled_at = None
    admin.twofa_failed_attempts = 0
    admin.twofa_locked_until = None
