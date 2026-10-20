"""
test_loginlock.py
=================
Checks the password lockout rules in loginlock.py. No web app, no database.

Run it from the project folder:
    python test_loginlock.py
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import loginlock as L


class Acct:
    def __init__(self):
        self.login_failed_attempts = 0
        self.login_locked_until = None
        self.twofa_failed_attempts = 0
        self.twofa_locked_until = None

T0 = datetime(2026, 10, 8, 9, 0, 0)


def t_four_wrong_passwords_do_not_lock():
    a = Acct()
    for _ in range(4): L.register_failure(a, T0)
    assert L.lock_seconds_left(a, T0) == 0 and a.login_failed_attempts == 4

def t_the_fifth_wrong_password_locks_for_fifteen_minutes():
    a = Acct()
    for _ in range(5): L.register_failure(a, T0)
    left = L.lock_seconds_left(a, T0)
    assert 14 * 60 < left <= 15 * 60 + 1 and a.login_failed_attempts == 0

def t_the_lock_ends_on_time():
    a = Acct()
    for _ in range(5): L.register_failure(a, T0)
    assert L.lock_seconds_left(a, T0 + timedelta(minutes=14)) > 0
    assert L.lock_seconds_left(a, T0 + timedelta(minutes=16)) == 0

def t_after_a_lock_ends_the_person_gets_five_fresh_tries():
    a = Acct()
    for _ in range(5): L.register_failure(a, T0)
    later = T0 + timedelta(minutes=16)
    for _ in range(4): L.register_failure(a, later)
    assert L.lock_seconds_left(a, later) == 0
    L.register_failure(a, later)
    assert L.lock_seconds_left(a, later) > 0

def t_a_correct_password_resets_the_count():
    a = Acct()
    for _ in range(4): L.register_failure(a, T0)
    L.register_success(a)
    for _ in range(4): L.register_failure(a, T0)
    assert L.lock_seconds_left(a, T0) == 0

def t_unlock_clears_password_and_code_locks():
    a = Acct()
    for _ in range(5): L.register_failure(a, T0)
    a.twofa_failed_attempts = 3; a.twofa_locked_until = T0 + timedelta(minutes=9)
    L.unlock(a)
    assert L.lock_seconds_left(a, T0) == 0 and a.login_failed_attempts == 0
    assert a.twofa_locked_until is None and a.twofa_failed_attempts == 0

def t_made_up_names_lock_exactly_like_real_ones():
    u = L.UnknownNames()
    for _ in range(4): u.register_failure('nobody', T0)
    assert u.lock_seconds_left('nobody', T0) == 0
    u.register_failure('nobody', T0)
    assert 14 * 60 < u.lock_seconds_left('nobody', T0) <= 15 * 60 + 1
    assert u.lock_seconds_left('nobody', T0 + timedelta(minutes=16)) == 0
    assert u.lock_seconds_left('someone else', T0) == 0

def t_made_up_names_do_not_use_unlimited_memory():
    u = L.UnknownNames(max_entries=100)
    for i in range(1000): u.register_failure(f'name{i}', T0 + timedelta(seconds=i))
    assert u.size() <= 100

def t_very_long_names_are_cut_for_tracking():
    u = L.UnknownNames()
    long_a, long_b = 'x' * 500 + 'a', 'x' * 500 + 'b'
    for _ in range(5): u.register_failure(long_a, T0)
    assert u.lock_seconds_left(long_b, T0) > 0                         # same first 80 characters, same entry

def t_pruning_keeps_active_locks():
    u = L.UnknownNames(max_entries=10)
    for _ in range(5): u.register_failure('locked-name', T0)
    for i in range(50): u.register_failure(f'n{i}', T0 + timedelta(seconds=i))
    assert u.lock_seconds_left('locked-name', T0 + timedelta(minutes=1)) > 0


CHECKS = [(k[2:].replace('_', ' ').capitalize(), v) for k, v in list(globals().items()) if k.startswith('t_') and callable(v)]

if __name__ == '__main__':
    failed = 0
    for i, (name, fn) in enumerate(CHECKS, 1):
        try:
            fn(); print(f"PASS  {i:2d}. {name}")
        except Exception as e:
            failed += 1; print(f"FAIL  {i:2d}. {name}  ->  {type(e).__name__}: {e}")
    print(f"\n{len(CHECKS) - failed} of {len(CHECKS)} checks passed")
    sys.exit(1 if failed else 0)
