"""
test_lockout_and_profile_flow.py
================================
Tests, on the REAL app, the password lockout and changing your own username
and email. It works on a throwaway copy of the project; your real data is
never touched.

Run it from the project folder with the project's Python:
    python test_lockout_and_profile_flow.py
"""
import json
import os
import re
import subprocess
import sys

import test_support as T

env = T.build()
H = T.Helpers(env)
B = T.Helpers(env, client=env.flask_app.test_client(), shared_with=H)      # a second browser
PASSWORD = T.PASSWORD
S = {}


def token(client=H): return client.csrf(client.html(client.GET('/settings/profile')))
def uid(name): return H.row(name).id
def wrong_password_error(client, name, times):
    """Tries a wrong password several times, returns the last message shown"""
    page = ''
    for _ in range(times):
        page = client.html(client.login_password(name, 'definitely not it'))
    return page

def profile_details(client, username=None, email=None, password=PASSWORD, **kw):
    user = H.row(S['me'])
    data = {'csrf_token': token(client), 'username': user.username if username is None else username,
            'email': (user.email or '') if email is None else email, 'current_password': password}
    data.update(kw)
    return client.POST('/settings/profile/details', data)

def unlock_in_db(name):
    import loginlock
    with env.flask_app.app_context():
        a = env.Admin.query.filter_by(username=name).first(); loginlock.unlock(a); env.db.session.commit()

def sign_in_as(name, client=H):
    client.sign_in(name); S['me'] = name


# ---------------------------------------------------------------- the steps
def everyone_is_set_up():
    for name in ('admin', 'boss2', 'helper', 'viewer'):
        H.enroll(name)

def four_wrong_passwords_do_not_lock_the_fifth_does():
    H.logout()
    for i in range(4):
        assert 'Invalid username or password' in H.html(H.login_password('viewer', 'nope nope nope')), i
    page = H.html(H.login_password('viewer', 'nope nope nope'))
    assert 'Too many failed attempts' in page and '15 minute' in page
    assert H.row('viewer').login_locked_until is not None

def a_correct_password_is_refused_while_locked_and_the_lock_does_not_extend():
    before = H.row('viewer').login_locked_until
    r = H.login_password('viewer', PASSWORD)
    assert r.status_code == 200 and 'Too many failed attempts' in H.html(r)
    for _ in range(3): H.login_password('viewer', 'nope nope nope')
    assert H.row('viewer').login_locked_until == before                                    # hammering does not push it out

def names_that_are_not_accounts_behave_exactly_the_same():
    for i in range(4):
        assert 'Invalid username or password' in H.html(H.login_password('nosuchperson', 'x')), i
    unknown = H.html(H.login_password('nosuchperson', 'x'))
    real = H.html(H.login_password('viewer', 'x'))
    strip = lambda p: re.sub(r'\d+', 'N', re.search(r'Too many failed attempts[^<]*', p).group(0))
    assert strip(unknown) == strip(real)                                                    # the page cannot tell them apart

def the_lock_ends_and_a_correct_password_clears_the_count():
    with env.flask_app.app_context():
        from datetime import datetime, timedelta
        a = env.Admin.query.filter_by(username='viewer').first()
        a.login_locked_until = datetime.utcnow() - timedelta(minutes=1); env.db.session.commit()
    r = H.login_password('viewer', PASSWORD)
    assert r.status_code == 302 and '/login/verify' in H.location(r)
    v = H.row('viewer'); assert v.login_failed_attempts == 0 and v.login_locked_until is None

def a_good_sign_in_in_the_middle_resets_the_count():
    H.logout()
    for _ in range(4): H.login_password('boss2', 'nope nope nope')
    assert '/login/verify' in H.location(H.login_password('boss2', PASSWORD))
    H.logout()
    for i in range(4): assert 'Invalid username or password' in H.html(H.login_password('boss2', 'nope nope nope')), i

def managers_see_a_lock_and_can_end_it_with_their_code():
    H.logout(); H.login_password('boss2', 'x')                                              # fifth failure in a row (4 + this = 5)
    assert H.row('boss2').is_locked
    for _ in range(5): H.login_password('viewer', 'nope nope nope')
    assert H.row('viewer').is_locked
    sign_in_as('admin')
    page = H.html(H.GET('/settings/accounts'))
    assert 'Locked' in page
    detail = H.html(H.GET(f"/settings/accounts/{uid('viewer')}"))
    assert 'Unlock account' in detail
    bad = H.POST(f"/settings/accounts/{uid('viewer')}/unlock", {'csrf_token': token(), 'code': H.wrong_code(H.secrets['admin'])})
    assert 'not correct' in H.html(bad) and H.row('viewer').is_locked
    ok = H.POST(f"/settings/accounts/{uid('viewer')}/unlock", {'csrf_token': token(), 'code': H.fresh_code('admin')})
    assert ok.status_code == 302 and 'unlocked' in H.location(ok)
    assert not H.row('viewer').is_locked and '/login/verify' in B.location(B.login_password('viewer', PASSWORD))

def a_lock_does_not_end_a_session_that_is_already_open():
    for _ in range(5): B.login_password('admin', 'nope nope nope')                         # someone locks the Owner out
    assert H.row('admin').is_locked
    assert H.GET('/dashboard').status_code == 200                                           # the Owner's open session still works
    assert 'Too many failed attempts' in B.html(B.login_password('admin', PASSWORD))

def only_the_server_can_unlock_the_owner():
    unlock_in_db('boss2')                                                                   # left locked by an earlier step
    other = T.Helpers(env, client=env.flask_app.test_client(), shared_with=H)
    other.passwords['boss2'] = PASSWORD
    # boss2 has no account-management switches, so there is no way for them to reach the Owner
    other.sign_in('boss2')
    r = other.POST(f"/settings/accounts/{uid('admin')}/unlock", {'csrf_token': token(other), 'code': other.fresh_code('boss2')})
    assert r.status_code in (403, 404) and H.row('admin').is_locked
    run = lambda *a: subprocess.run([sys.executable, 'unlock_account.py', *a], cwd=env.tmp, env=dict(os.environ), capture_output=True, text=True)
    listing = run('--list'); assert 'admin' in listing.stdout and listing.returncode == 0
    done = run('admin'); assert done.returncode == 0, done.stderr
    assert not H.row('admin').is_locked
    assert '/login/verify' in B.location(B.login_password('admin', PASSWORD))
    assert run('nobody').returncode == 1

def wrong_current_passwords_on_profile_count_toward_the_same_lock():
    sign_in_as('helper')
    page = token()
    for i in range(5):
        r = H.POST('/settings/profile/password', {'csrf_token': page, 'current_password': 'nope nope nope',
                                                  'new_password': 'brand new passphrase', 'confirm_password': 'brand new passphrase'})
        assert 'current password is not correct' in H.html(r), i
    assert H.row('helper').is_locked
    r = H.POST('/settings/profile/password', {'csrf_token': page, 'current_password': PASSWORD,
                                              'new_password': 'brand new passphrase', 'confirm_password': 'brand new passphrase'})
    assert 'Too many wrong attempts' in H.html(r)
    assert 'Too many failed attempts' in B.html(B.login_password('helper', PASSWORD))
    unlock_in_db('helper')

def username_and_email_changes_are_checked():
    S['me'] = 'helper'
    page = H.html(profile_details(H, username='helper'))
    assert 'Nothing to change' in page
    before = H.row('helper').login_failed_attempts
    assert 'Username must be' in H.html(profile_details(H, username='bad name!'))
    assert 'already taken' in H.html(profile_details(H, username='BOSS2'))
    assert 'email address' in H.html(profile_details(H, email='not-an-email'))
    assert H.row('helper').login_failed_attempts == before                                  # form mistakes are not password failures
    assert 'current password is not correct' in H.html(profile_details(H, username='helper_new', password='wrong wrong wrong'))
    assert H.row('helper').username == 'helper' and H.row('helper').login_failed_attempts == before + 1
    with env.flask_app.app_context():
        env.AuditLog.log_action(admin_username='ghost_user', action='login', target='system', status='success', details=None, source='test')
        env.AuditLog.log_action(admin_username='typo_only', action='login', target='system', status='failed', details=None, source='test')
    assert 'activity history' in H.html(profile_details(H, username='ghost_user'))          # belongs to someone in the history
    assert 'activity history' in H.html(profile_details(H, username='GHOST_user'))

def changing_username_and_email():
    r = profile_details(H, username='typo_only', email='helper.new@x.org')                 # a name only seen in failed sign-ins is free
    assert r.status_code == 302 and 'details_saved' in H.location(r), H.html(r)[:300]
    a = H.row('typo_only')
    assert a.username == 'typo_only' and a.email == 'helper.new@x.org' and json.loads(a.former_usernames) == ['helper']
    assert H.GET('/dashboard').status_code == 200                                           # the open session is not disturbed
    H.secrets['typo_only'] = H.secrets['helper']; H.passwords['typo_only'] = PASSWORD; S['me'] = 'typo_only'
    page = H.html(H.GET('/settings/profile')); assert 'typo_only' in page and 'helper.new@x.org' in page
    H.logout()
    assert 'Invalid username or password' in H.html(H.login_password('helper', PASSWORD))   # the old name no longer works
    H.sign_in('typo_only')

def the_change_was_written_to_the_audit_log_under_both_names():
    with env.flask_app.app_context():
        rows = env.AuditLog.query.filter(env.AuditLog.action.in_(['username_changed', 'email_changed'])).all()
        by = {(r.action, r.admin_username): json.loads(r.details) if isinstance(r.details, str) else r.details for r in rows}
    assert ('username_changed', 'helper') in by                                              # logged under the OLD name
    d = by[('username_changed', 'helper')]; assert d['from'] == 'helper' and d['to'] == 'typo_only'
    assert ('email_changed', 'typo_only') in by

def a_person_can_take_their_own_old_name_back_but_nobody_else_can():
    S['me'] = 'typo_only'
    assert 'activity history' not in H.html(profile_details(H, username='helper'))
    assert H.row('helper') is not None and H.row('typo_only') is None                        # allowed, even though 'helper' is in the history
    H.secrets['helper'] = H.secrets['typo_only']; H.passwords['helper'] = PASSWORD; S['me'] = 'helper'
    sign_in_as('boss2')
    assert 'activity history' in H.html(profile_details(H, username='typo_only'))           # someone else cannot take the name 'typo_only' held
    # (typo_only is now in the history of an account that used it successfully)

def email_can_be_cleared_on_its_own():
    sign_in_as('helper')
    r = profile_details(H, email=''); assert r.status_code == 302
    assert H.row('helper').email is None and H.row('helper').username == 'helper'
    assert json.loads(H.row('helper').former_usernames) == ['helper', 'typo_only']          # both past names are remembered

def the_owner_can_rename_and_stays_the_owner():
    sign_in_as('admin')
    r = profile_details(H, username='jon'); assert r.status_code == 302
    o = H.row('jon'); assert o.role == 'owner' and o.id == 1
    H.secrets['jon'] = H.secrets['admin']; H.passwords['jon'] = PASSWORD; S['me'] = 'jon'
    assert H.GET('/settings/accounts').status_code == 200                                    # still has the Owner's powers
    r = profile_details(H, username='admin'); assert r.status_code == 302 and H.row('admin').role == 'owner'

def everything_was_audited():
    got = H.audit_actions()
    want = {'account_unlocked', 'username_changed', 'email_changed', 'profile_change', 'password_change'}
    assert want <= got, want - got
    with env.flask_app.app_context():
        reasons = [r.details for r in env.AuditLog.query.filter_by(action='login', status='failed').all()]
    assert any('locked' in str(x) for x in reasons)


STEPS = [
    ("Every account is set up with two-step", everyone_is_set_up),
    ("Four wrong passwords do not lock, the fifth does", four_wrong_passwords_do_not_lock_the_fifth_does),
    ("A correct password is refused while locked, and hammering does not extend the lock", a_correct_password_is_refused_while_locked_and_the_lock_does_not_extend),
    ("Names that are not accounts behave exactly the same", names_that_are_not_accounts_behave_exactly_the_same),
    ("The lock ends, and a correct password clears the count", the_lock_ends_and_a_correct_password_clears_the_count),
    ("A good sign-in in the middle resets the count", a_good_sign_in_in_the_middle_resets_the_count),
    ("Managers see a lock and can end it with their code", managers_see_a_lock_and_can_end_it_with_their_code),
    ("A lock does not end a session that is already open", a_lock_does_not_end_a_session_that_is_already_open),
    ("Only the server can unlock the Owner", only_the_server_can_unlock_the_owner),
    ("Wrong current passwords on Profile count toward the same lock", wrong_current_passwords_on_profile_count_toward_the_same_lock),
    ("Username and email changes are checked", username_and_email_changes_are_checked),
    ("Changing username and email works and the old name stops working", changing_username_and_email),
    ("The change is in the audit log under both names", the_change_was_written_to_the_audit_log_under_both_names),
    ("Someone can take their own old name back, nobody else can", a_person_can_take_their_own_old_name_back_but_nobody_else_can),
    ("Email can be cleared on its own", email_can_be_cleared_on_its_own),
    ("The Owner can rename and stays the Owner", the_owner_can_rename_and_stays_the_owner),
    ("Lockouts and profile changes were written to the audit log", everything_was_audited),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
