"""
test_twofa.py
=============
Checks the two-step verification logic in twofa.py. No web app, no database,
no phone needed.

Run it from the project folder:
    python test_twofa.py
"""
import base64
import contextlib
import io
import os
import sys
from datetime import datetime, timedelta

# A throwaway key for the tests (the real one is SECRETS_KEY in your .env)
from cryptography.fernet import Fernet
os.environ['SECRETS_KEY'] = Fernet.generate_key().decode()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pyotp
import twofa


class FakeAdmin:
    """Just the fields twofa.py touches."""
    def __init__(self):
        self.totp_secret = None
        self.totp_pending_secret = None
        self.totp_pending_at = None
        self.totp_enabled = False
        self.totp_last_step = None
        self.recovery_codes = None
        self.twofa_enrolled_at = None
        self.twofa_failed_attempts = 0
        self.twofa_locked_until = None

    @property
    def two_factor_enabled(self):
        return bool(self.totp_enabled and self.totp_secret)


NOW = 1_800_000_000          # a fixed moment, so the tests never depend on the real clock
STEP = NOW // 30

def code_for(secret, step): return pyotp.TOTP(secret).at(step * 30)

def enrolled_admin():
    a = FakeAdmin(); secret = twofa.begin_pairing(a)
    codes = twofa.finish_pairing(a, code_for(secret, int(__import__('time').time() // 30)))
    return a, secret, codes


# ---------------------------------------------------------------- checks
def t_matches_the_official_rfc6238_test_value():
    # RFC 6238 test vector: secret "12345678901234567890", time 59s -> ...287082 (6 digits)
    b32 = base64.b32encode(b'12345678901234567890').decode()
    assert pyotp.TOTP(b32).at(59) == '287082'
    assert twofa.verify_code(b32, '287082', now=59) == 1

def t_secret_is_encrypted_and_tamper_proof():
    token = twofa.encrypt_secret('ABCDEFGH')
    assert 'ABCDEFGH' not in token and twofa.decrypt_secret(token) == 'ABCDEFGH'
    assert twofa.decrypt_secret(token[:-4] + 'AAAA') is None
    assert twofa.decrypt_secret('not a token') is None

def t_wrong_key_cannot_read_the_secret():
    token = twofa.encrypt_secret('ABCDEFGH')
    old = os.environ['SECRETS_KEY']; os.environ['SECRETS_KEY'] = Fernet.generate_key().decode()
    try: assert twofa.decrypt_secret(token) is None
    finally: os.environ['SECRETS_KEY'] = old

def t_correct_code_accepted_wrong_code_refused():
    s = twofa.new_secret()
    assert twofa.verify_code(s, code_for(s, STEP), now=NOW) == STEP
    wrong = '000000' if code_for(s, STEP) != '000000' else '111111'
    assert twofa.verify_code(s, wrong, now=NOW) is None

def t_small_clock_drift_is_allowed_but_not_more():
    s = twofa.new_secret()
    assert twofa.verify_code(s, code_for(s, STEP - 1), now=NOW) == STEP - 1
    assert twofa.verify_code(s, code_for(s, STEP + 1), now=NOW) == STEP + 1
    assert twofa.verify_code(s, code_for(s, STEP - 2), now=NOW) is None
    assert twofa.verify_code(s, code_for(s, STEP + 2), now=NOW) is None

def t_spaces_and_dashes_in_the_typed_code_are_ignored():
    s = twofa.new_secret(); c = code_for(s, STEP)
    assert twofa.verify_code(s, f'{c[:3]} {c[3:]}', now=NOW) == STEP
    assert twofa.verify_code(s, f'{c[:3]}-{c[3:]}', now=NOW) == STEP
    assert twofa.verify_code(s, c[:5], now=NOW) is None and twofa.verify_code(s, '', now=NOW) is None
    assert twofa.verify_code(s, None, now=NOW) is None

def t_a_code_cannot_be_used_twice():
    s = twofa.new_secret(); c = code_for(s, STEP)
    step = twofa.verify_code(s, c, None, now=NOW)
    assert twofa.verify_code(s, c, step, now=NOW) is None                      # same code again
    assert twofa.verify_code(s, code_for(s, STEP - 1), step, now=NOW) is None  # an older code
    assert twofa.verify_code(s, code_for(s, STEP + 1), step, now=NOW) == STEP + 1

def t_qr_code_and_setup_key():
    s = twofa.new_secret()
    uri = twofa.provisioning_uri(s, 'admin', 'GWS2AD')
    assert uri.startswith('otpauth://totp/') and 'issuer=GWS2AD' in uri and s in uri
    svg = twofa.qr_svg(uri)
    assert svg.lstrip().startswith('<svg') and s not in svg                    # the picture doesn't print the secret as text
    import re
    vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)                          # without a viewBox the QR gets cropped, not scaled
    assert vb and vb.group(1) == re.search(r'width="(\d+)"', svg).group(1) and vb.group(1) == vb.group(2)
    assert twofa.format_key('ABCDEFGHIJKL') == 'ABCD EFGH IJKL'

def t_recovery_codes_work_once_and_are_not_stored_in_plain():
    codes = twofa.generate_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10 and all(len(c) == 11 and c[5] == '-' for c in codes)
    stored = twofa.hash_recovery_codes(codes)
    assert not any(c in stored or c.replace('-', '') in stored for c in codes)
    after = twofa.consume_recovery_code(stored, codes[3])
    assert after is not None and twofa.recovery_codes_left(after) == 9
    assert twofa.consume_recovery_code(after, codes[3]) is None                # already used
    assert twofa.consume_recovery_code(after, 'AAAAA-AAAAA') is None           # not a code

def t_recovery_code_typing_is_forgiving():
    codes = twofa.generate_recovery_codes(); stored = twofa.hash_recovery_codes(codes)
    typed = codes[0].lower().replace('-', ' ')
    assert twofa.consume_recovery_code(stored, typed) is not None

def t_five_wrong_codes_lock_the_account_for_fifteen_minutes():
    a = FakeAdmin(); t0 = datetime(2026, 10, 7, 9, 0, 0)
    for _ in range(4): twofa.register_failure(a, t0)
    assert twofa.lock_seconds_left(a, t0) == 0
    twofa.register_failure(a, t0)
    left = twofa.lock_seconds_left(a, t0)
    assert 14 * 60 < left <= 15 * 60 + 1
    assert twofa.lock_seconds_left(a, t0 + timedelta(minutes=16)) == 0
    twofa.register_success(a)
    assert a.twofa_failed_attempts == 0 and a.twofa_locked_until is None

def t_setup_only_takes_effect_after_a_correct_code():
    a = FakeAdmin(); secret = twofa.begin_pairing(a)
    assert not a.two_factor_enabled and a.totp_secret is None                  # nothing active yet
    assert twofa.finish_pairing(a, '000000') is None and not a.two_factor_enabled
    codes = twofa.finish_pairing(a, code_for(secret, int(__import__('time').time() // 30)))
    assert a.two_factor_enabled and len(codes) == 10 and a.totp_pending_secret is None
    assert twofa.recovery_codes_left(a.recovery_codes) == 10

def t_an_expired_setup_is_refused():
    a = FakeAdmin(); secret = twofa.begin_pairing(a, twofa._utcnow() - timedelta(minutes=16))
    assert twofa.finish_pairing(a, code_for(secret, int(__import__('time').time() // 30))) is None

def t_pairing_a_new_phone_keeps_the_old_one_until_confirmed():
    a, old_secret, _ = enrolled_admin(); old_token = a.totp_secret; codes_before = a.recovery_codes
    new_secret = twofa.begin_pairing(a)
    assert a.totp_secret == old_token                                          # still the old phone
    assert twofa.finish_pairing(a, '000000') is None and a.totp_secret == old_token
    import time as _t
    result = twofa.finish_pairing(a, code_for(new_secret, int(_t.time() // 30)))
    assert result == [] and a.totp_secret != old_token                         # swapped, no new recovery codes
    assert a.recovery_codes == codes_before
    assert twofa.decrypt_secret(a.totp_secret) == new_secret

def t_check_code_updates_counters_and_blocks_replay():
    import time as _t
    a, secret, _ = enrolled_admin()
    nxt = int(_t.time() // 30) + 1                                             # a step later than the setup code
    c = code_for(secret, nxt)
    assert twofa.check_code(a, c) is True and a.twofa_failed_attempts == 0
    assert twofa.check_code(a, c) is False and a.twofa_failed_attempts == 1    # replay refused and counted

def t_check_recovery_code_counts_failures():
    a, _, codes = enrolled_admin()
    assert twofa.check_recovery_code(a, codes[0]) is True
    assert twofa.check_recovery_code(a, codes[0]) is False and a.twofa_failed_attempts == 1
    assert twofa.recovery_codes_left(a.recovery_codes) == 9

def t_reset_clears_everything():
    a, _, _ = enrolled_admin(); twofa.register_failure(a); twofa.reset(a)
    assert not a.two_factor_enabled and a.totp_secret is None and a.recovery_codes is None
    assert a.totp_last_step is None and a.twofa_failed_attempts == 0

def t_unreadable_secret_fails_safely():
    a, _, _ = enrolled_admin(); a.totp_secret = 'garbage'
    assert twofa.check_code(a, '123456') is False                              # no crash


# keep the order the checks are written in
CHECKS = [(n[2:].replace('_', ' ').capitalize(), f) for n, f in
          [(k, v) for k, v in globals().items() if k.startswith('t_') and callable(v)]]

if __name__ == '__main__':
    failed = 0
    for i, (name, fn) in enumerate(CHECKS, 1):
        try:
            fn(); print(f"PASS  {i:2d}. {name}")
        except Exception as e:
            failed += 1; print(f"FAIL  {i:2d}. {name}  ->  {type(e).__name__}: {e}")
    print(f"\n{len(CHECKS) - failed} of {len(CHECKS)} checks passed")
    sys.exit(1 if failed else 0)
