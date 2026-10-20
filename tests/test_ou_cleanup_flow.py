"""
test_ou_cleanup_flow.py
=======================
Organizational units that are in AD but no longer in Google, on the REAL app
with the Demo connectors.

The rules being tested:
  - An OU that Google's structure does not account for is deleted by the sync.
  - It is only deleted if it is EMPTY by then. Anything still holding objects stays.
  - Deepest first, so an emptied child frees its parent.
  - The Ignore list keeps an OU. The preview shows all of this before anything runs.
  - OUs Google does account for (mirrors, Users, Groups) are never touched.
  - The base DN, anything outside it, and the Domain Controllers OU are never touched.
  - A rename in Google (users moved, old OU gone) moves the people, then removes the old OU.

    python tests/test_ou_cleanup_flow.py
"""
import test_support as T

env = T.build()
H = T.Helpers(env)


def api(method, path, body=None):
    r = H.client.open(path, method=method, json=body)
    return r.status_code, (r.get_json(silent=True) or {})


def ous():
    s, p = api('GET', '/api/sync-preview')
    assert s == 200 and 'error' not in p, p
    return {o['name']: o for o in p['ous_to_delete']}


def ad():
    from mock_connectors import get_mock_ad
    return get_mock_ad()


def gws():
    from mock_connectors import get_mock_gws
    return get_mock_gws()


def ad_ou_names():
    return {dn.split(',')[0].split('=')[1] + '@' + dn.split(',', 1)[1] for dn in ad().list_ous()}


def has_ou(fragment):
    return any(dn.lower().startswith(fragment.lower()) for dn in ad().list_ous())


def fresh():
    from mock_connectors import reset_demo_data
    reset_demo_data()
    with env.flask_app.app_context():
        env.db.session.execute(env.db.text('DELETE FROM ignored_sync_items'))
        env.db.session.commit()


def sync():
    s, r = api('POST', '/api/sync')
    assert s == 200 and r['success'], r
    return r


# ------------------------------------------------------------------ steps
def sign_in():
    H.enroll('admin')


def the_preview_lists_ous_google_does_not_have():
    fresh()
    found = ous()
    assert set(found) == {'Old Interns', 'Legacy', 'Users'}, set(found)          # Users here is the one inside Legacy
    assert all(o['action'] == 'delete' for o in found.values()), found
    # Nothing Google accounts for is ever offered
    names = {o['name'] for o in api('GET', '/api/sync-preview')[1]['ous_to_delete']}
    assert not names & {'Staff', 'Facilities', 'Volunteers', 'Groups'}


def a_sync_deletes_them_deepest_first_and_keeps_the_rest():
    fresh()
    r = sync()
    assert not has_ou('OU=Old Interns') and not has_ou('OU=Legacy')
    assert not any('OU=Legacy' in dn for dn in ad().list_ous())
    log = '\n'.join(r['logs'])
    assert log.index('[DELETE] OU: OU=Users,OU=Legacy') < log.index('[DELETE] OU: OU=Legacy'), log
    # what Google accounts for is still there, and so is the Users / Groups structure
    for keep in ('OU=Staff', 'OU=Volunteers', 'OU=Users,OU=Staff', 'OU=Groups', 'OU=Users,OU=GWS-Sync'):
        assert has_ou(keep), keep
    assert not ous()


def ignoring_an_ou_keeps_it():
    fresh()
    interns = ous()['Old Interns']
    assert api('POST', '/api/ignored-items', {'type': 'ou', 'identifier': interns['identifier']})[0] == 200
    now = ous()['Old Interns']
    assert now['ignored'] and now['action'] == 'ignored'
    s, status = api('GET', '/api/sync-status')
    sync()
    assert has_ou('OU=Old Interns'), 'an ignored OU must survive the sync'
    assert not has_ou('OU=Legacy')
    # unignoring puts it back on the list
    assert api('DELETE', f"/api/ignored-items/ou/{interns['identifier']}")[0] == 200
    assert ous()['Old Interns']['action'] == 'delete'
    sync()
    assert not has_ou('OU=Old Interns')


def an_ou_that_still_holds_something_is_kept():
    fresh()
    # Someone ignores the account that lives in the old OU. It stays, so its OUs must too.
    assert api('POST', '/api/ignored-items', {'type': 'user', 'identifier': 'old.contractor@example.com'})[0] == 200
    found = ous()
    assert found['Users']['action'] == 'not_empty' and found['Users']['remaining'] == 1, found['Users']
    assert found['Legacy']['action'] == 'not_empty', found['Legacy']
    assert found['Old Interns']['action'] == 'delete'
    r = sync()
    assert has_ou('OU=Legacy') and has_ou('OU=Users,OU=Legacy') and not has_ou('OU=Old Interns')
    assert 'old.contractor@example.com' in {u['email'] for u in ad().get_all_users()}
    assert any('still contains' in line for line in r['logs']), r['logs']
    assert not any(d.get('type') == 'ou' for d in r['differences']), 'keeping a non-empty OU is not a failure'


def a_rename_in_google_moves_people_then_removes_the_old_ou():
    fresh()
    sync()                                                      # AD now matches Google, including /Volunteers
    assert has_ou('OU=Volunteers')
    g = gws()                                                   # rename /Volunteers to /Helpers in Google
    g.ous = [dict(o, path='/Helpers', name='Helpers') if o['path'] == '/Volunteers' else o for o in g.ous]
    for u in g.users:
        if u['orgUnitPath'] == '/Volunteers':
            u['orgUnitPath'] = '/Helpers'
    from sync_engine import SyncEngine
    env.directory = None
    s, p = api('GET', '/api/sync-preview')
    assert len(p['users_to_update']) == 5 and all('organizationalUnit' in u['changes'] for u in p['users_to_update']), p['users_to_update']
    assert {o['name'] for o in p['ous_to_create']} == {'Helpers', 'Users'}, p['ous_to_create']
    found = {o['name']: o for o in p['ous_to_delete']}
    assert found['Volunteers']['action'] == 'delete', 'everyone moves out, so the old OU will be empty'
    sync()
    assert has_ou('OU=Helpers') and has_ou('OU=Users,OU=Helpers')
    assert not has_ou('OU=Volunteers') and not has_ou('OU=Users,OU=Volunteers')
    moved = [u for u in ad().get_all_users() if u['email'].startswith(('nfischer', 'epetrova'))]
    assert moved and all('OU=Helpers' in u['dn'] for u in moved), moved
    assert not ous()


def a_failed_delete_is_reported_and_its_parent_is_left_alone():
    fresh()
    a = ad()
    real = a.delete_ou
    a.delete_ou = lambda dn: (False, 'insufficientAccessRights')
    try:
        r = sync()
    finally:
        a.delete_ou = real
    failed = [d for d in r['differences'] if d.get('type') == 'ou' and d['action'] == 'delete_failed']
    assert failed and all('insufficientAccessRights' in d['error'] for d in failed), r['differences']
    assert has_ou('OU=Legacy'), 'a parent whose child could not be deleted must stay'


def an_ou_check_that_cannot_run_deletes_nothing():
    fresh()
    a = ad()
    real = a.get_ou_children
    def broken(dn): raise Exception('LDAP timeout')
    a.get_ou_children = broken
    try:
        r = sync()
    finally:
        a.get_ou_children = real
    assert has_ou('OU=Old Interns') and has_ou('OU=Legacy'), 'if emptiness cannot be checked, nothing is deleted'
    assert any(d.get('type') == 'ou' and d['action'] == 'delete_failed' for d in r['differences'])


def the_connectors_refuse_to_delete_unsafe_things():
    fresh()
    a = ad()
    base = 'OU=GWS-Sync,DC=demo,DC=example,DC=com'
    assert a.delete_ou(base)[0] is False                                              # the base itself
    assert a.delete_ou('OU=Elsewhere,DC=demo,DC=example,DC=com')[0] is False          # outside the base
    ok, err = a.delete_ou(f'OU=Staff,{base}')
    assert not ok                                                                    # not empty: AD would refuse too
    # the real connector must refuse the same cases BEFORE sending anything to AD
    from ad_connector import ADConnector

    class Spy:
        calls = []
        result = {}
        def delete(self, dn):
            self.calls.append(dn); return True
    real = ADConnector.__new__(ADConnector)
    real.conn = Spy()
    import config
    config.AD_CONFIG['base_dn'] = base
    assert real.delete_ou(base)[0] is False
    assert real.delete_ou('OU=Elsewhere,DC=demo,DC=example,DC=com')[0] is False
    assert real.conn.calls == [], 'nothing outside the base DN may reach AD'
    assert real.delete_ou(f'OU=Old,{base}') == (True, None) and real.conn.calls == [f'OU=Old,{base}']


def protected_and_ordering_rules():
    from sync_engine import SyncEngine
    with env.flask_app.app_context():
        e = SyncEngine()
        assert e._is_protected_ou('OU=Domain Controllers,DC=corp,DC=example,DC=com')
        assert not e._is_protected_ou('OU=Domain Controllers,OU=GWS-Sync,DC=corp,DC=example,DC=com')
        import config
        config.AD_CONFIG['base_dn'] = 'DC=corp,DC=example,DC=com'                        # whole-domain base DN
        listed = ['DC=corp,DC=example,DC=com', 'OU=Domain Controllers,DC=corp,DC=example,DC=com',
                  'OU=A,DC=corp,DC=example,DC=com', 'OU=B,OU=A,DC=corp,DC=example,DC=com',
                  'OU=Keep,DC=corp,DC=example,DC=com', 'OU=Other,DC=elsewhere,DC=com']
        out = e._extra_ous(listed, {'ou=keep,dc=corp,dc=example,dc=com'})
        assert out == ['OU=B,OU=A,DC=corp,DC=example,DC=com', 'OU=A,DC=corp,DC=example,DC=com'], out   # children first; no base, DCs, kept, or outsiders
        config.AD_CONFIG['base_dn'] = 'OU=GWS-Sync,DC=demo,DC=example,DC=com'


def a_short_google_ou_list_cannot_make_a_real_ou_look_extra():
    fresh()
    sync()
    g = gws()
    g.ous = []                                                                           # Google "forgets" every sub-OU
    found = ous()                                                                        # users still live in /Staff, /Volunteers...
    assert not {'Staff', 'Facilities', 'Volunteers'} & set(found), set(found)
    sync()
    for keep in ('OU=Staff', 'OU=Volunteers', 'OU=Facilities'):
        assert has_ou(keep), keep


def the_ignore_api_rejects_unknown_types():
    assert api('POST', '/api/ignored-items', {'type': 'computer', 'identifier': 'x'})[0] == 400


def it_was_all_audited_and_nothing_secret_leaked():
    got = H.audit_actions()
    assert {'trigger_sync', 'add_ignored_item', 'remove_ignored_item'} <= got, got


STEPS = [
    ("Sign in as the Owner", sign_in),
    ("The preview lists OUs that Google does not have, and never the ones it does", the_preview_lists_ous_google_does_not_have),
    ("A sync deletes them deepest first and keeps everything else", a_sync_deletes_them_deepest_first_and_keeps_the_rest),
    ("Ignore keeps an OU, and Unignore puts it back", ignoring_an_ou_keeps_it),
    ("An OU that still holds something is kept, and that is not a failure", an_ou_that_still_holds_something_is_kept),
    ("A rename in Google moves the people, then removes the old OU", a_rename_in_google_moves_people_then_removes_the_old_ou),
    ("A failed delete is reported and its parent is left alone", a_failed_delete_is_reported_and_its_parent_is_left_alone),
    ("If emptiness cannot be checked, nothing is deleted", an_ou_check_that_cannot_run_deletes_nothing),
    ("The connectors refuse the base DN, outsiders and non-empty OUs", the_connectors_refuse_to_delete_unsafe_things),
    ("Domain Controllers, the base DN and kept OUs are never offered, children come first", protected_and_ordering_rules),
    ("A short or empty OU list from Google cannot make a real OU look extra", a_short_google_ou_list_cannot_make_a_real_ou_look_extra),
    ("The ignore list only accepts user, group and ou", the_ignore_api_rejects_unknown_types),
    ("It was all audited", it_was_all_audited_and_nothing_secret_leaked),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
