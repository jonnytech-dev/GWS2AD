"""
test_twofa_flow.py
==================
Tests the REAL sign-in pages end to end, focusing on two-step verification.
(Roles, accounts, and permissions are tested in test_accounts_flow.py.)

It does not touch your real database, your real secrets, Google, or AD. It
works on a throwaway copy of the project with a database in the OLD layout.

Run it from the project folder with the project's Python:
    python test_twofa_flow.py
"""
import os
import re
import subprocess
import sys

import test_support as T
from test_support import advance

env = T.build()
H = T.Helpers(env)
PASSWORD = T.PASSWORD
S = {}
PROTECTED = ('/dashboard', '/settings/profile', '/how-it-works', '/api/users')


# ---------------------------------------------------------------------
def old_database_was_upgraded():
    import sqlite3
    cols = {r[1] for r in sqlite3.connect(os.path.join(env.tmp, 'gw2ad.db')).execute('PRAGMA table_info(admins)')}
    assert {'totp_secret', 'totp_enabled', 'recovery_codes', 'twofa_locked_until', 'role_id', 'custom_permissions'} <= cols
    a = H.row('admin'); assert a.role == 'owner' and a.check_password(PASSWORD)

def pages_need_a_sign_in():
    for p in PROTECTED:
        r = H.GET(p); assert r.status_code == 302 and '/login' in H.location(r), p

def wrong_password_is_refused():
    r = H.login_password('admin', 'wrong'); assert r.status_code == 200 and 'Invalid username or password' in H.html(r)

def right_password_leads_to_setup_and_the_old_off_switch_is_gone():
    # test_support set TWO_FACTOR_REQUIRED=false. It used to switch two-step off. It must do nothing now.
    assert os.environ.get('TWO_FACTOR_REQUIRED') == 'false'
    r = H.login_password('admin'); assert r.status_code == 302 and '/login/setup' in H.location(r), H.location(r)

def half_signed_in_gets_no_access():
    for p in PROTECTED:
        r = H.GET(p); assert r.status_code == 302 and 'login/setup' not in H.location(r) and '/login' in H.location(r), p

def setup_page_shows_qr_and_key():
    r = H.GET('/login/setup'); page = H.html(r)
    assert r.status_code == 200 and '<svg' in page and 'no-store' in r.headers.get('Cache-Control', '')
    S['secret'] = H.manual_key(page)
    assert len(S['secret']) == 32 and S['secret'] not in re.sub(r'class="manual-key">[^<]*<', '', page)

def setup_without_a_token_is_refused():
    r = H.POST('/login/setup', {'code': '000000'}); assert r.status_code == 302 and 'expired' in H.location(r)
    H.login_password('admin'); H.GET('/login/setup')

def setup_with_a_wrong_code_fails():
    page = H.html(H.GET('/login/setup')); S['secret'] = H.manual_key(page)
    r = H.POST('/login/setup', {'csrf_token': H.csrf(page), 'code': H.wrong_code(S['secret'])})
    assert r.status_code == 200 and 'not correct' in H.html(r)
    assert H.GET('/dashboard').status_code == 302 and not H.row('admin').two_factor_enabled

def setup_with_the_right_code_signs_in():
    page = H.html(H.GET('/login/setup')); S['secret'] = H.manual_key(page)
    S['setup_code'] = H.code_for(S['secret'])
    r = H.POST('/login/setup', {'csrf_token': H.csrf(page), 'code': S['setup_code']})
    S['codes'] = H.recovery_codes(H.html(r))
    assert r.status_code == 200 and len(S['codes']) == 10 and 'no-store' in r.headers.get('Cache-Control', '')
    assert H.GET('/dashboard').status_code == 200 and H.GET('/how-it-works').status_code == 200
    H.secrets['admin'] = S['secret']

def secrets_are_not_stored_in_plain():
    a = H.row('admin')
    assert a.two_factor_enabled and S['secret'] not in a.totp_secret
    assert env.twofa.decrypt_secret(a.totp_secret) == S['secret']
    assert not any(c in a.recovery_codes or c.replace('-', '') in a.recovery_codes for c in S['codes'])

def next_sign_in_asks_for_a_code():
    H.logout(); r = H.login_password('admin')
    assert r.status_code == 302 and '/login/verify' in H.location(r)
    for p in PROTECTED: assert H.GET(p).status_code == 302

def a_used_code_cannot_be_replayed():
    page = H.html(H.GET('/login/verify'))
    r = H.POST('/login/verify', {'csrf_token': H.csrf(page), 'code': S['setup_code']})
    assert r.status_code == 200 and 'not correct' in H.html(r) and H.GET('/dashboard').status_code == 302

def verify_without_a_token_is_refused():
    r = H.POST('/login/verify', {'code': H.code_for(S['secret'], 1)}); assert r.status_code == 302 and 'expired' in H.location(r)
    H.login_password('admin')

def a_fresh_code_signs_in():
    advance(31); page = H.html(H.GET('/login/verify'))
    r = H.POST('/login/verify', {'csrf_token': H.csrf(page), 'code': H.code_for(S['secret'])})
    assert r.status_code == 302 and '/dashboard' in H.location(r) and H.GET('/dashboard').status_code == 200
    assert H.row('admin').last_login is not None

def five_wrong_codes_lock_the_account():
    H.logout(); H.login_password('admin'); t = H.csrf(H.html(H.GET('/login/verify')))
    bad = H.wrong_code(S['secret'])
    for i in range(4):
        r = H.POST('/login/verify', {'csrf_token': t, 'code': bad}); assert 'not correct' in H.html(r), i
    r = H.POST('/login/verify', {'csrf_token': t, 'code': bad}); assert 'locked' in H.html(r)
    advance(31)
    r = H.POST('/login/verify', {'csrf_token': t, 'code': H.code_for(S['secret'])})           # the RIGHT code, but locked
    assert r.status_code == 200 and 'Try again in' in H.html(r) and H.GET('/dashboard').status_code == 302

def lock_ends_and_signing_in_works_again():
    with env.flask_app.app_context():
        a = env.Admin.query.filter_by(username='admin').first(); a.twofa_locked_until = None; env.db.session.commit()
    advance(31); page = H.html(H.GET('/login/verify'))
    r = H.POST('/login/verify', {'csrf_token': H.csrf(page), 'code': H.code_for(S['secret'])})
    assert r.status_code == 302 and H.GET('/dashboard').status_code == 200

def a_slow_second_step_expires():
    H.logout(); H.login_password('admin'); advance(301)
    r = H.GET('/login/verify'); assert r.status_code == 302 and 'expired' in H.location(r)

def recovery_code_signs_in_once():
    H.logout(); H.login_password('admin'); page = H.html(H.GET('/login/verify'))
    r = H.POST('/login/verify', {'csrf_token': H.csrf(page), 'recovery_code': S['codes'][0].lower().replace('-', ' ')})
    assert r.status_code == 302 and 'recovery_used' in H.location(r), H.location(r)
    profile = H.html(H.GET(H.location(r)))
    assert 'recovery code' in profile and '9 of 10' in profile
    H.logout(); H.login_password('admin'); page = H.html(H.GET('/login/verify'))
    r = H.POST('/login/verify', {'csrf_token': H.csrf(page), 'recovery_code': S['codes'][0]})
    assert r.status_code == 200 and 'not correct' in H.html(r) and H.GET('/dashboard').status_code == 302

def profile_changes_need_a_current_code_and_a_token():
    H.sign_in('admin')
    page = H.html(H.GET('/settings/profile'))
    assert 'Two-Step Verification' in page and '9 of 10' in page
    assert H.POST('/settings/profile/2fa/pair', {'code': H.code_for(S['secret'], 1)}).status_code == 400      # no token
    r = H.POST('/settings/profile/2fa/pair', {'csrf_token': H.csrf(page), 'code': H.wrong_code(S['secret'])})
    assert r.status_code == 200 and 'not correct' in H.html(r) and 'manual-key' not in H.html(r)

def pairing_a_new_phone():
    page = H.html(H.GET('/settings/profile'))
    r = H.POST('/settings/profile/2fa/pair', {'csrf_token': H.csrf(page), 'code': H.fresh_code('admin')})
    assert r.status_code == 200 and 'manual-key' in H.html(r)
    S['new_secret'] = H.manual_key(H.html(r)); assert S['new_secret'] != S['secret']
    t = H.csrf(H.html(r))
    r = H.POST('/settings/profile/2fa/pair/confirm', {'csrf_token': t, 'code': H.wrong_code(S['new_secret'])})
    assert r.status_code == 200 and 'not correct' in H.html(r)
    assert env.twofa.decrypt_secret(H.row('admin').totp_secret) == S['secret']                      # old phone still active
    r = H.POST('/settings/profile/2fa/pair/confirm', {'csrf_token': t, 'code': H.code_for(S['new_secret'])})
    assert r.status_code == 302 and 'paired' in H.location(r)
    assert env.twofa.decrypt_secret(H.row('admin').totp_secret) == S['new_secret']

def old_phone_stops_working_new_one_works():
    H.logout(); H.login_password('admin'); advance(31); t = H.csrf(H.html(H.GET('/login/verify')))
    r = H.POST('/login/verify', {'csrf_token': t, 'code': H.code_for(S['secret'])})
    assert r.status_code == 200 and 'not correct' in H.html(r)
    r = H.POST('/login/verify', {'csrf_token': t, 'code': H.code_for(S['new_secret'])})
    assert r.status_code == 302 and H.GET('/dashboard').status_code == 200
    H.secrets['admin'] = S['new_secret']

def new_recovery_codes_replace_the_old_ones():
    page = H.html(H.GET('/settings/profile'))
    r = H.POST('/settings/profile/2fa/recovery-codes', {'csrf_token': H.csrf(page), 'code': H.fresh_code('admin')})
    fresh = H.recovery_codes(H.html(r)); assert len(fresh) == 10 and not set(fresh) & set(S['codes'])
    H.logout(); H.login_password('admin'); t = H.csrf(H.html(H.GET('/login/verify')))
    r = H.POST('/login/verify', {'recovery_code': S['codes'][3], 'csrf_token': t})
    assert r.status_code == 200 and 'not correct' in H.html(r)                                      # an old code
    r = H.POST('/login/verify', {'recovery_code': fresh[0], 'csrf_token': t})
    assert r.status_code == 302

def old_account_address_goes_to_settings():
    H.sign_in('admin')
    r = H.GET('/account'); assert r.status_code == 302 and '/settings/profile' in H.location(r)

def reset_tool_clears_two_step_and_ends_live_sessions():
    env_vars = dict(os.environ)
    run = lambda *args, inp=None: subprocess.run([sys.executable, 'reset_2fa.py', *args], cwd=env.tmp, env=env_vars,
                                                  input=inp, capture_output=True, text=True)
    listing = run('--list'); assert listing.returncode == 0 and 'admin' in listing.stdout and ' on ' in listing.stdout
    declined = run('admin', inp='n\n'); assert H.row('admin').two_factor_enabled and declined.returncode == 1
    H.sign_in('admin'); assert H.GET('/dashboard').status_code == 200
    done = run('admin', inp='y\n'); assert done.returncode == 0, done.stderr
    a = H.row('admin'); assert not a.two_factor_enabled and a.totp_secret is None and a.recovery_codes is None
    assert H.GET('/dashboard').status_code == 302                                                    # the live session ended too
    H.logout(); r = H.login_password('admin'); assert 'login/setup' in H.location(r)                 # must enroll again
    assert run('nobody').returncode == 1

def sign_in_events_were_audited():
    got = H.audit_actions()
    want = {'login', 'login_password', 'login_2fa', '2fa_enrolled', '2fa_recovery_used',
            '2fa_device_changed', '2fa_recovery_regenerated', '2fa_stepup', '2fa_reset'} - {'2fa_reset'}
    assert want <= got, want - got


STEPS = [
    ("Old-style database is upgraded and the first account became the Owner", old_database_was_upgraded),
    ("Pages need a sign-in", pages_need_a_sign_in),
    ("Wrong password is refused", wrong_password_is_refused),
    ("Right password leads to setup, and the old off switch does nothing", right_password_leads_to_setup_and_the_old_off_switch_is_gone),
    ("A half signed-in person can open nothing", half_signed_in_gets_no_access),
    ("Setup page shows a QR code and key, and is never cached", setup_page_shows_qr_and_key),
    ("Setup form without its security token is refused", setup_without_a_token_is_refused),
    ("Setup with a wrong code fails and stays signed out", setup_with_a_wrong_code_fails),
    ("Setup with the right code signs in and shows 10 recovery codes", setup_with_the_right_code_signs_in),
    ("Secret and recovery codes are not stored in plain", secrets_are_not_stored_in_plain),
    ("Next sign-in asks for a code", next_sign_in_asks_for_a_code),
    ("A code that was already used is refused", a_used_code_cannot_be_replayed),
    ("Code form without its security token is refused", verify_without_a_token_is_refused),
    ("A fresh code signs in", a_fresh_code_signs_in),
    ("Five wrong codes lock the account, even for the right code", five_wrong_codes_lock_the_account),
    ("After the lock ends, signing in works again", lock_ends_and_signing_in_works_again),
    ("Taking over five minutes on the second step expires it", a_slow_second_step_expires),
    ("A recovery code signs in once, then never again", recovery_code_signs_in_once),
    ("Profile changes need a current code and a security token", profile_changes_need_a_current_code_and_a_token),
    ("Pairing a new phone keeps the old one until confirmed", pairing_a_new_phone),
    ("The old phone stops working, the new one works", old_phone_stops_working_new_one_works),
    ("New recovery codes replace the old ones", new_recovery_codes_replace_the_old_ones),
    ("The old Account address goes to Settings", old_account_address_goes_to_settings),
    ("Reset tool clears two-step, ends live sessions, and forces setup again", reset_tool_clears_two_step_and_ends_live_sessions),
    ("Sign-in events were written to the audit log", sign_in_events_were_audited),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
