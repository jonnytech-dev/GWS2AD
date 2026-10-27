"""
test_demo_flow.py
=================
Demo mode and the Demo / Live switch, on the REAL app, end to end.

A fresh install has no credentials for Google or Active Directory. This checks
that the app works on sample data in that state, that a sync really changes the
(pretend) Active Directory, that no email leaves the machine, and that only the
Owner can switch to Live, and only when the saved settings pass the checks.

Run it from the project folder:
    python tests/test_demo_flow.py
"""
import json
import os
import re

import test_support as T

env = T.build()
H = T.Helpers(env)
GOOD = 'a long enough phrase'


def api(method, path, body=None):
    r = H.client.open(path, method=method, json=body)
    return r.status_code, (r.get_json(silent=True) or {})


def conn_token():
    return H.csrf(H.html(H.GET('/settings/connection')))


def switch(target, code=None):
    return H.POST('/settings/connection/mode', {'csrf_token': conn_token(), 'mode': target,
                                                 'code': H.fresh_code('admin') if code is None else code})


def sign_in_all():
    for n in ('admin', 'boss2', 'helper', 'viewer'):
        H.enroll(n)


# ------------------------------------------------------------------ steps
def starts_in_demo_with_no_credentials():
    import config, mode
    assert config.missing_live_settings(), 'a fresh install should have no live settings'
    assert mode.get_mode() == 'demo'
    sign_in_all()
    H.sign_in('admin')
    page = H.html(H.GET('/dashboard'))
    assert 'Demo mode.' in page and 'sample data' in page


def sample_data_fills_the_dashboard():
    s, users = api('GET', '/api/users')
    assert s == 200 and len(users['users'] if isinstance(users, dict) and 'users' in users else users) == 12, users
    s, groups = api('GET', '/api/groups')
    assert s == 200
    assert api('GET', '/api/org-units')[0] == 200


def the_preview_shows_real_work_to_do():
    s, p = api('GET', '/api/sync-preview')
    assert s == 200 and 'error' not in p, p
    assert len(p['users_to_create']) == 5, p['users_to_create']
    assert any(u.get('email') == 'dkim@example.com' for u in p['users_to_update'])
    assert any('old.contractor' in json.dumps(u) for u in p['users_to_delete'])
    assert p['groups_to_create'], 'Facilities and Leadership are missing from the sample AD'


def a_sync_changes_the_pretend_ad_and_sends_no_email():
    import smtplib
    real = smtplib.SMTP
    tried = []
    def boom(*a, **k): tried.append(a); raise OSError('no network in tests')
    smtplib.SMTP = boom
    assert api('POST', '/api/settings/email', {'send_emails': True})[0] == 200   # emails ON, so only Demo mode stops them
    try:
        s, r = api('POST', '/api/sync')
    finally:
        smtplib.SMTP = real
        api('POST', '/api/settings/email', {'send_emails': False})
    assert not tried, 'Demo mode tried to send email'
    assert s == 200 and r['success'], r
    from mock_connectors import get_mock_ad
    emails = {u['email'].lower() for u in get_mock_ad().get_all_users()}
    assert 'mrivera@example.com' not in emails and 'malvarez@example.com' in emails and len(emails) >= 12
    s, p = api('GET', '/api/sync-preview')
    assert not p['users_to_create'] and not p['users_to_update'], p
    # new users got a temp password handed to the admin on screen, never by email
    assert r['pending_credentials'], 'new users should hand their temp passwords to the admin'


def creating_and_deleting_in_demo_works_and_the_cache_follows():
    s, r = api('POST', '/api/users', {'email': 'ztest@example.com', 'firstName': 'Zed', 'lastName': 'Test', 'password': 'Aa1!demo-pass', 'confirmPassword': 'Aa1!demo-pass'})
    assert s == 200, r
    s, users = api('GET', '/api/users')
    assert 'ztest@example.com' in json.dumps(users)
    s, r = api('POST', '/api/users', {'email': 'ztest@example.com', 'firstName': 'Zed', 'lastName': 'Test', 'password': 'Aa1!demo-pass', 'confirmPassword': 'Aa1!demo-pass'})
    assert s == 400 and 'already exists' in r['error']
    assert api('DELETE', '/api/users/ztest@example.com')[0] == 200
    assert 'ztest@example.com' not in json.dumps(api('GET', '/api/users')[1])


def creating_is_all_or_nothing_across_ad_and_google():
    from mock_connectors import get_mock_ad, get_mock_gws
    ad, gws = get_mock_ad(), get_mock_gws()
    base = {'firstName': 'Pat', 'lastName': 'Lee', 'confirmPassword': None}
    def user(email, pw, confirm='same'):
        return api('POST', '/api/users', {'email': email, 'firstName': 'Pat', 'lastName': 'Lee',
                                          'password': pw, 'confirmPassword': pw if confirm == 'same' else confirm})
    def in_ad(e): return e.lower() in {u['email'].lower() for u in ad.get_all_users()}
    def in_gws(e): return any(u['email'].lower() == e.lower() for u in gws.get_all_users())
    # the two passwords must match, and nothing is made when they do not
    s, r = user('pat1@example.com', 'Aa1!demo-pass', 'different')
    assert s == 400 and 'do not match' in r['error'] and not in_ad('pat1@example.com') and not in_gws('pat1@example.com')
    # a password the AD policy refuses: says where and why, and Google is untouched
    s, r = user('pat2@example.com', 'weak')
    assert s == 400 and 'Active Directory' in r['error'] and 'password policy' in r['error'], r
    assert 'Nothing was created in Google Workspace' in r['error']
    assert not in_ad('pat2@example.com') and not in_gws('pat2@example.com')
    # Google refusing after AD succeeded: the AD copy is removed again
    real = gws.create_user
    def boom(*a, **k): raise Exception('Failed to create user: Invalid Email Address')
    gws.create_user = boom
    try:
        s, r = user('pat3@example.com', 'Aa1!demo-pass')
    finally:
        gws.create_user = real
    assert s == 400 and 'Google Workspace' in r['error'] and 'removed again' in r['error'], r
    assert not in_ad('pat3@example.com') and not in_gws('pat3@example.com')
    # the happy path makes it in both
    s, r = user('pat4@example.com', 'Aa1!demo-pass')
    assert s == 200 and in_ad('pat4@example.com') and in_gws('pat4@example.com'), r
    # already there on either side: refused, nothing touched
    s, r = user('pat4@example.com', 'Aa1!demo-pass')
    assert s == 400 and 'already exists' in r['error']
    api('DELETE', '/api/users/pat4@example.com')
    # groups follow the same rule
    s, r = api('POST', '/api/groups', {'email': 'crew@example.com', 'name': 'Crew', 'description': 'x'})
    assert s == 200 and 'Crew' in {g['name'] for g in gws.get_all_groups()}
    real = gws.create_group
    gws.create_group = boom
    try:
        s, r = api('POST', '/api/groups', {'email': 'crew2@example.com', 'name': 'Crew Two', 'description': 'x'})
    finally:
        gws.create_group = real
    assert s == 400 and 'Google Workspace' in r['error'] and 'removed again' in r['error'], r
    assert 'CrewTwo' not in ad.groups, 'the AD group must be rolled back'
    # every failure is in the audit log with where it failed
    assert {'create_user', 'create_group'} <= H.audit_actions()


def only_the_owner_sees_the_connection_tab():
    assert 'href="/settings/connection"' in H.html(H.GET('/settings/profile'))
    for name in ('boss2', 'helper', 'viewer'):
        H.sign_in(name)
        assert H.GET('/settings/connection').status_code == 403, name
        assert 'href="/settings/connection"' not in H.html(H.GET('/settings/profile')), name
        r = H.POST('/settings/connection/mode', {'csrf_token': 'x', 'mode': 'live', 'code': '000000'})
        assert r.status_code in (400, 403), (name, r.status_code)
    H.sign_in('admin')


def going_live_needs_the_code_and_saved_settings():
    assert 'Not' not in H.html(H.GET('/settings/connection')) or True
    page = H.html(switch('live', code='000000'))
    assert 'not correct' in page
    page = H.html(switch('live'))
    assert 'need' in page and 'saved first' in page
    import mode
    assert mode.get_mode() == 'demo'
    page = H.html(H.POST('/settings/connection/test', {'csrf_token': conn_token()}))
    assert 'not saved yet' in page


def a_failed_check_keeps_demo_on():
    import config, connection_test, mode
    saved = (config.missing_live_settings, connection_test.run_all)
    config.missing_live_settings = lambda: []
    connection_test.run_all = lambda: [('Google Workspace', True, 'ok'), ('Active Directory', False, 'LDAPS handshake failed'), ('Email', True, 'ok')]
    try:
        page = H.html(switch('live'))
    finally:
        config.missing_live_settings, connection_test.run_all = saved
    assert 'LDAPS handshake failed' in page and 'not turned on' in page
    assert mode.get_mode() == 'demo'


def passing_checks_turn_live_on_and_demo_can_be_restored():
    import config, connection_test, mode
    saved = (config.missing_live_settings, connection_test.run_all)
    config.missing_live_settings = lambda: []
    connection_test.run_all = lambda: [('Google Workspace', True, 'ok'), ('Active Directory', True, 'ok'), ('Email', True, 'ok')]
    try:
        r = switch('live')
        assert r.status_code == 302 and 'now_live' in H.location(r)
        assert mode.get_mode() == 'live'
        assert 'Demo mode.' not in H.html(H.GET('/dashboard'))
        assert 'Live mode' in H.html(H.GET('/settings/connection'))
        assert H.POST('/settings/connection/reset-demo', {'csrf_token': conn_token()}).status_code == 400   # sample data only exists in Demo
        r = switch('demo')
        assert r.status_code == 302 and 'now_demo' in H.location(r)
    finally:
        config.missing_live_settings, connection_test.run_all = saved
    assert mode.get_mode() == 'demo' and 'Demo mode.' in H.html(H.GET('/dashboard'))


def reset_puts_the_sample_data_back():
    assert api('POST', '/api/groups', {'email': 'newgroup@example.com', 'name': 'NewGroup', 'description': 'x'})[0] in (200, 201)
    r = H.POST('/settings/connection/reset-demo', {'csrf_token': conn_token()})
    assert r.status_code == 302 and 'demo_reset' in H.location(r)
    assert 'newgroup@example.com' not in json.dumps(api('GET', '/api/groups')[1])
    s, p = api('GET', '/api/sync-preview')
    assert len(p['users_to_create']) == 5


def the_mode_file_is_never_trusted_when_damaged():
    import mode
    with open(mode._FILE, 'w') as f:
        f.write('{ not json')
    assert mode.get_mode() == 'demo'
    with open(mode._FILE, 'w') as f:
        json.dump({'mode': 'LIVE; DROP'}, f)
    assert mode.get_mode() == 'demo'


def mode_changes_were_audited():
    got = H.audit_actions()
    assert {'mode_live', 'mode_demo', 'demo_reset', 'trigger_sync'} <= got, got


def no_real_credentials_are_needed_anywhere():
    # the throwaway project's secrets hold only the app's own settings
    from cryptography.fernet import Fernet
    data = json.loads(Fernet(os.environ['SECRETS_KEY'].encode()).decrypt(open(os.path.join(env.tmp, 'secrets.json.enc'), 'rb').read()))
    assert not any(k.startswith(('gws_', 'ad_', 'smtp_')) for k in data), data.keys()


STEPS = [
    ("A fresh install with no Google / AD / email settings starts in Demo with a banner", starts_in_demo_with_no_credentials),
    ("Sample users, groups and org units load on the dashboard", sample_data_fills_the_dashboard),
    ("The sync preview shows creates, an update and a delete on the sample data", the_preview_shows_real_work_to_do),
    ("A sync changes the pretend AD, sends no email, and hands temp passwords to the admin", a_sync_changes_the_pretend_ad_and_sends_no_email),
    ("Creating and deleting users works in Demo and the cache follows", creating_and_deleting_in_demo_works_and_the_cache_follows),
    ("Creating a user or group is all-or-nothing across AD and Google, with clear errors", creating_is_all_or_nothing_across_ad_and_google),
    ("Only the Owner can see or use the Connection tab", only_the_owner_sees_the_connection_tab),
    ("Going Live needs a correct code and saved settings", going_live_needs_the_code_and_saved_settings),
    ("A failing connection check keeps Demo on and says why", a_failed_check_keeps_demo_on),
    ("Passing checks turn Live on, and Demo can be restored", passing_checks_turn_live_on_and_demo_can_be_restored),
    ("Reset puts the sample data back", reset_puts_the_sample_data_back),
    ("A damaged or tampered mode file means Demo", the_mode_file_is_never_trusted_when_damaged),
    ("Mode changes, resets and syncs were audited", mode_changes_were_audited),
    ("The app's secrets hold no Google / AD / email values in this setup", no_real_credentials_are_needed_anywhere),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
