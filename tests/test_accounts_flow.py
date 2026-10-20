"""
test_accounts_flow.py
=====================
Tests roles, accounts, and permissions on the REAL app, end to end.

It works on a throwaway copy of the project with a database in the OLD layout
and four accounts that have the OLD roles. It signs in as each kind of account
and tries every protected action. Your real data is never touched.

Run it from the project folder with the project's Python:
    python test_accounts_flow.py
"""
import re

import test_support as T
from test_support import advance

env = T.build()
H = T.Helpers(env)
B = T.Helpers(env, client=env.flask_app.test_client(), shared_with=H)     # a second browser
P = env.permissions
PASSWORD = T.PASSWORD
GOOD = 'a long enough phrase'
S = {'me': None}

ALL = {'read', 'create_user', 'edit_user', 'delete_user', 'create_group', 'edit_group', 'delete_group', 'preview_sync', 'trigger_sync'}
ROUTES = [
    ('GET', '/api/users', 'read'), ('GET', '/api/groups', 'read'), ('GET', '/api/org-units', 'read'),
    ('POST', '/api/users', 'create_user'), ('PUT', '/api/users/a@b.co', 'edit_user'), ('DELETE', '/api/users/a@b.co', 'delete_user'),
    ('POST', '/api/groups', 'create_group'), ('PUT', '/api/groups/g@b.co', 'edit_group'), ('DELETE', '/api/groups/g@b.co', 'delete_group'),
    ('GET', '/api/sync-preview', 'preview_sync'), ('GET', '/api/ignored-items', 'preview_sync'),
    ('POST', '/api/sync', 'trigger_sync'), ('POST', '/api/ignored-items', 'trigger_sync'),
    ('DELETE', '/api/ignored-items/user/x', 'trigger_sync'), ('POST', '/api/settings/email', 'trigger_sync'),
]


# ---------------------------------------------------------------- helpers
def sign_in_as(name, client=H):
    client.sign_in(name); S['me'] = name

def token(client=H): return client.csrf(client.html(client.GET('/settings/profile')))
def uid(name): return H.row(name).id
def code(client=H, name=None): return client.fresh_code(name or S['me'])

def create(username, role_choice='custom', perms=(), password=GOOD, confirm=None, c=None, extra=None, display_name='', email=''):
    data = {'csrf_token': token(), 'username': username, 'display_name': display_name, 'email': email,
            'role_choice': role_choice, 'perm': list(perms), 'password': password,
            'confirm_password': password if confirm is None else confirm, 'code': code() if c is None else c}
    data.update(extra or {})
    H.passwords[username] = password                       # so enroll() and sign_in() can use it
    return H.POST('/settings/accounts/new', data)

def edit(target, role_choice=None, perms=None, extra=None, display_name='', c='auto'):
    row = H.row(target)
    choice = role_choice or (f'role:{row.role_id}' if row.role == 'named' else row.role)
    data = {'csrf_token': token(), 'display_name': display_name, 'email': row.email or '', 'role_choice': choice,
            'perm': list(perms) if perms is not None else [], 'code': code() if c == 'auto' else c}
    data.update(extra or {})
    return H.POST(f'/settings/accounts/{row.id}/edit', data)

def act(target, what, data=None, c='auto', client=H, me=None):
    data = dict(data or {})
    data['csrf_token'] = token(client)
    data['code'] = code(client, me or S['me']) if c == 'auto' else c
    return client.POST(f'/settings/accounts/{uid(target)}/{what}', data)

def role_form(path, name, perms, c='auto'):
    return H.POST(path, {'csrf_token': token(), 'name': name, 'perm': list(perms), 'code': code() if c == 'auto' else c})

def role_info(name_or_id):
    """A role as plain data, looked up inside an app context"""
    with env.flask_app.app_context():
        r = (env.Role.query.filter_by(name=name_or_id).first() if isinstance(name_or_id, str)
             else env.db.session.get(env.Role, name_or_id))
        return None if r is None else {'id': r.id, 'name': r.name, 'perms': r.permission_list()}

def perms_of(name): return env.permissions.clean(H.row(name).assigned_permissions())
def cards(page): return re.findall(r'class="account-card[^"]*"\s+href="/settings/accounts/(\d+)"', page)


# ---------------------------------------------------------------- the steps
def old_roles_were_converted():
    a, b, c, d = (H.row(n) for n in ('admin', 'boss2', 'helper', 'viewer'))
    assert a.role == 'owner' and b.role == 'admin' and (b.can_manage_admins, b.can_manage_staff) == (False, False)
    assert c.role == 'custom' and perms_of('helper') == ['create_user', 'edit_user', 'create_group', 'edit_group']
    assert d.role == 'custom' and perms_of('viewer') == []
    assert (a.id, b.id, c.id, d.id) == (1, 2, 3, 4)
    from sqlalchemy.exc import IntegrityError
    with env.flask_app.app_context():
        env.db.session.get(env.Admin, 2).role = 'owner'                 # the database itself must refuse a second owner
        try:
            env.db.session.commit(); raised = False
        except IntegrityError:
            env.db.session.rollback(); raised = True
        assert raised

def a_session_without_two_step_does_not_count():
    with env.client.session_transaction() as s:
        s['user_id'] = uid('helper')
    r = H.GET('/dashboard'); assert r.status_code == 302 and '/login' in H.location(r)
    H.logout()

def everyone_has_to_set_up_two_step_first():
    for name in ('admin', 'boss2', 'helper', 'viewer'):
        H.enroll(name)
        assert H.GET('/dashboard').status_code == 200, name

def owner_sees_settings_and_all_tabs():
    sign_in_as('admin')
    page = H.html(H.GET('/settings/profile'))
    assert 'Settings' in page and 'href="/settings/accounts"' in page and 'href="/settings/roles"' in page
    assert 'Change Password' in page and 'Owner' in page
    r = H.GET('/account'); assert '/settings/profile' in H.location(r)

def changing_your_own_password():
    def change(cur, new, conf):
        return H.html(H.POST('/settings/profile/password', {'csrf_token': token(), 'current_password': cur,
                                                           'new_password': new, 'confirm_password': conf}))
    assert 'current password is not correct' in change('nope nope nope', GOOD, GOOD)
    assert 'do not match' in change(PASSWORD, GOOD, GOOD + 'x')
    assert 'at least 12' in change(PASSWORD, 'short', 'short')
    assert 'cannot contain the username' in change(PASSWORD, 'my admin password', 'my admin password')
    assert 'must be different' in change(PASSWORD, PASSWORD, PASSWORD)
    r = H.POST('/settings/profile/password', {'csrf_token': token(), 'current_password': PASSWORD,
                                              'new_password': 'brand new passphrase', 'confirm_password': 'brand new passphrase'})
    assert r.status_code == 302 and 'password_changed' in H.location(r)
    H.passwords['admin'] = 'brand new passphrase'
    H.logout()
    assert 'Invalid' in H.html(H.login_password('admin', PASSWORD))
    sign_in_as('admin')

def accounts_tab_shows_a_card_for_everyone():
    page = H.html(H.GET('/settings/accounts'))
    assert len(cards(page)) == 4 and '@helper' in page and '@boss2' in page and 'Owner' in page
    detail = H.html(H.GET(f"/settings/accounts/{uid('helper')}"))
    shown = re.search(r'Permissions</h2>.*?</ul>', detail, re.S).group(0)            # the Permissions card only
    assert 'Add users' in shown and 'Edit users' in shown and 'Delete users' not in shown and 'Run sync' not in shown

def creating_an_account_checks_everything():
    n = lambda: len(env.Admin.query.all()) if False else None
    secret = H.secrets['admin']
    r = create('nina', c=H.wrong_code(secret)); assert 'code is not correct' in H.html(r) and H.row('nina') is None
    assert 'do not match' in H.html(create('nina', confirm=GOOD + 'x'))
    assert 'at least 12' in H.html(create('nina', password='short', confirm='short'))
    assert 'cannot contain the username' in H.html(create('nina', password='nina is here today'))
    assert 'already taken' in H.html(create('Helper'))
    assert 'letters, numbers' in H.html(create('bad name!'))
    assert 'email address' in H.html(create('nina', email='not-an-email'))
    assert H.row('nina') is None
    r = create('nina', perms=['create_user', 'edit_user'], display_name='Nina Staff', email='nina@x.org')
    assert r.status_code == 302 and 'created' in H.location(r), H.html(r)[:300]
    a = H.row('nina')
    assert a.role == 'custom' and perms_of('nina') == ['create_user', 'edit_user'] and a.created_by == 'admin'
    assert a.display_name == 'Nina Staff' and a.is_active and not a.two_factor_enabled and a.check_password(GOOD)
    assert a.custom_permissions is not None and 'account_created' in H.audit_actions()

def a_new_account_cannot_use_anything_until_two_step_is_set_up():
    assert 'Two-step not set up yet' in H.html(H.GET('/settings/accounts'))           # the owner sees it on the card
    H.logout(); H.passwords['nina'] = GOOD
    r = H.login_password('nina'); assert '/login/setup' in H.location(r)
    for p in ('/dashboard', '/settings/profile', '/api/users'): assert H.GET(p).status_code == 302, p
    H.enroll('nina'); assert H.GET('/dashboard').status_code == 200

def an_admin_without_the_switches_has_no_accounts_or_roles():
    sign_in_as('boss2')
    page = H.html(H.GET('/settings/profile'))
    assert 'href="/settings/accounts"' not in page and 'href="/settings/roles"' not in page
    for p in ('/settings/accounts', '/settings/roles', '/settings/accounts/new', '/settings/roles/new'):
        r = H.GET(p); assert r.status_code == 403, (p, r.status_code)
    assert 'do not have access' in H.html(H.GET('/settings/accounts'))
    assert H.GET('/dashboard').status_code == 200 and H.GET('/api/users').status_code != 403   # still a super user on the dashboard

def only_the_owner_turns_the_switches_on():
    sign_in_as('admin')
    r = edit('boss2', extra={'can_manage_staff': '1'})
    assert r.status_code == 302 and 'updated' in H.location(r)
    b = H.row('boss2'); assert (b.can_manage_admins, b.can_manage_staff) == (False, True)
    sign_in_as('boss2')
    assert H.GET('/settings/accounts').status_code == 200 and H.GET('/settings/roles').status_code == 200

def an_admin_who_manages_staff_sees_and_changes_only_staff():
    page = H.html(H.GET('/settings/accounts'))
    ids = set(cards(page))
    assert ids == {str(uid(n)) for n in ('helper', 'viewer', 'nina')}, ids
    assert H.GET(f"/settings/accounts/{uid('admin')}").status_code == 404                 # the owner is not visible to them
    assert H.GET(f"/settings/accounts/{uid('boss2')}").status_code == 404                 # nor are admins
    r = create('carl', perms=['edit_user']); assert r.status_code == 302, H.html(r)[:300]
    assert create('boss5', role_choice='admin').status_code == 403                         # cannot create admins
    r = edit('carl', role_choice='admin'); assert r.status_code == 403                     # or promote to admin
    r = create('carol', perms=['edit_user'], extra={'can_manage_admins': '1', 'can_manage_staff': '1'})
    assert r.status_code == 302 and (H.row('carol').can_manage_admins, H.row('carol').can_manage_staff) == (False, False)
    H.enroll('carl'); H.enroll('carol')
    H.passwords['carl'] = H.passwords['carol'] = GOOD

def the_owner_makes_an_admin_who_manages_admins():
    sign_in_as('admin')
    r = create('boss3', role_choice='admin', extra={'can_manage_admins': '1'})
    assert r.status_code == 302, H.html(r)[:300]
    b = H.row('boss3'); assert b.role == 'admin' and (b.can_manage_admins, b.can_manage_staff) == (True, False)
    H.enroll('boss3')
    sign_in_as('boss3')
    ids = set(cards(H.html(H.GET('/settings/accounts'))))
    assert str(uid('admin')) in ids and str(uid('boss2')) in ids and str(uid('helper')) not in ids   # the owner counts as admin-level
    assert H.GET('/settings/roles').status_code == 403                                      # roles need the staff switch
    assert create('carl2', perms=[]).status_code == 403                                     # cannot create staff
    r = create('boss4', role_choice='admin', extra={'can_manage_staff': '1', 'can_manage_admins': '1'})
    assert r.status_code == 302 and (H.row('boss4').can_manage_admins, H.row('boss4').can_manage_staff) == (False, False)
    r = edit('boss2', display_name='Boss Two', c=None, extra={'role_choice': 'admin'})        # name only: no code needed
    assert r.status_code == 302 and H.row('boss2').display_name == 'Boss Two'

def nobody_can_touch_the_owner():
    owner_id = uid('admin')
    me = 'boss3'
    for what, data in (('edit', {'display_name': 'x', 'role_choice': 'custom'}), ('password', {'password': GOOD, 'confirm_password': GOOD}),
                       ('reset-2fa', {}), ('active', {'active': '0'}), ('delete', {})):
        data = dict(data, csrf_token=token(), code=code())
        r = H.POST(f'/settings/accounts/{owner_id}/{what}', data)
        assert r.status_code == 403, (what, r.status_code)
    sign_in_as('admin')                                                                         # and not even the owner, on their own account
    for what in ('delete', 'active', 'reset-2fa'):
        r = H.POST(f'/settings/accounts/{owner_id}/{what}', {'csrf_token': token(), 'code': code(), 'active': '0'})
        assert r.status_code == 403, what
    o = H.row('admin'); assert o.role == 'owner' and o.is_active and o.two_factor_enabled and o.check_password('brand new passphrase')
    assert 'Choose a role' in H.html(edit('carl', role_choice='owner'))                         # there is no way to make a second owner
    assert H.row('carl').role == 'custom'

def roles_can_be_made_and_rules_are_enforced():
    sign_in_as('admin')
    secret = H.secrets['admin']
    assert 'code is not correct' in H.html(role_form('/settings/roles/new', 'Help Desk', ['edit_user'], c=H.wrong_code(secret)))
    assert 'reserved' in H.html(role_form('/settings/roles/new', 'Admin', ['edit_user']))
    assert 'name of 2 to 60' in H.html(role_form('/settings/roles/new', '!', ['edit_user']))
    r = role_form('/settings/roles/new', 'Help Desk', ['edit_user', 'trigger_sync'])
    assert r.status_code == 302 and 'role_created' in H.location(r)
    S['role_id'] = role_info('Help Desk')['id']
    assert role_info('Help Desk')['perms'] == ['edit_user', 'preview_sync', 'trigger_sync']          # running a sync includes previewing it
    assert 'already exists' in H.html(role_form('/settings/roles/new', 'help desk', ['edit_user']))
    page = H.html(H.GET('/settings/roles'))
    assert 'Help Desk' in page and 'Owner' in page and 'Everything' in page

def putting_an_account_in_a_role_gives_it_the_roles_permissions():
    r = edit('nina', role_choice=f"role:{S['role_id']}"); assert r.status_code == 302, H.html(r)[:300]
    n = H.row('nina'); assert n.role == 'named' and n.role_id == S['role_id'] and n.role_label == 'Help Desk'
    assert n.has_permission('edit_user') and n.has_permission('trigger_sync') and n.has_permission('preview_sync')
    assert not n.has_permission('create_user') and not n.has_permission('delete_user')
    assert 'Help Desk' in H.html(H.GET('/settings/accounts'))

def editing_a_role_updates_everyone_in_it():
    r = role_form(f"/settings/roles/{S['role_id']}", 'Help Desk', ['create_user'])
    assert r.status_code == 302 and 'role_updated' in H.location(r)
    n = H.row('nina'); assert n.has_permission('create_user') and not n.has_permission('edit_user') and not n.has_permission('trigger_sync')

def a_role_in_use_cannot_be_deleted():
    page_token = token()
    r = H.POST(f"/settings/roles/{S['role_id']}/delete", {'csrf_token': page_token, 'code': code()})
    assert r.status_code == 200 and 'Move them' in H.html(r) and role_info(S['role_id']) is not None
    assert edit('nina', role_choice='custom', perms=['edit_user']).status_code == 302
    r = H.POST(f"/settings/roles/{S['role_id']}/delete", {'csrf_token': token(), 'code': code()})
    assert r.status_code == 302 and 'role_deleted' in H.location(r) and role_info(S['role_id']) is None

def an_admin_who_manages_staff_can_make_accounts_in_a_role():
    assert role_form('/settings/roles/new', 'Reader', []).status_code == 302
    S['reader_id'] = role_info('Reader')['id']
    sign_in_as('boss2')
    r = create('dave', role_choice=f"role:{S['reader_id']}"); assert r.status_code == 302, H.html(r)[:300]
    d = H.row('dave'); assert d.role == 'named' and d.role_label == 'Reader' and not d.has_permission('create_user')
    assert H.GET('/settings/roles').status_code == 200
    H.enroll('dave'); H.passwords['dave'] = GOOD

def every_protected_action_is_enforced_for_every_kind_of_account():
    sign_in_as('admin')
    assert create('peek', perms=['preview_sync']).status_code == 302
    H.enroll('peek'); H.passwords['peek'] = GOOD
    expected = {
        'admin': ALL, 'boss2': ALL, 'boss3': ALL,
        'helper': {'read', 'create_user', 'edit_user', 'create_group', 'edit_group'},
        'viewer': {'read'}, 'dave': {'read'}, 'peek': {'read', 'preview_sync'},
    }
    for name, allowed in expected.items():
        sign_in_as(name)
        for method, path, needs in ROUTES:
            r = H.client.open(path, method=method, json={})
            denied = r.status_code == 403
            assert denied == (needs not in allowed), f'{name} {method} {path} needs {needs}: got {r.status_code}'

def buttons_are_hidden_for_people_who_cannot_use_them():
    can = lambda page, key: re.search(rf'"{key}":\s*(true|false)', page).group(1) == 'true'
    sign_in_as('viewer'); page = H.html(H.GET('/dashboard'))
    assert not can(page, 'create_user') and not can(page, 'delete_group') and not can(page, 'trigger_sync')
    assert "showModal('addUserModal')" not in page and "showModal('addGroupModal')" not in page and 'id="syncButton"' not in page
    assert 'onclick="confirmSync()"' not in page and re.search(r'id="emailToggleBtn"[^>]*disabled', page)
    sign_in_as('helper'); page = H.html(H.GET('/dashboard'))
    assert can(page, 'create_user') and not can(page, 'delete_user') and "showModal('addUserModal')" in page and 'id="syncButton"' not in page
    sign_in_as('peek'); page = H.html(H.GET('/dashboard'))
    assert 'id="syncButton"' in page and 'onclick="confirmSync()"' not in page
    sign_in_as('admin'); page = H.html(H.GET('/dashboard'))
    assert can(page, 'trigger_sync') and 'onclick="confirmSync()"' in page and "showModal('addUserModal')" in page

def staff_see_no_settings_tabs():
    sign_in_as('viewer')
    page = H.html(H.GET('/settings/profile'))
    assert 'href="/settings/accounts"' not in page and 'href="/settings/roles"' not in page
    assert H.GET('/settings/accounts').status_code == 403 and H.GET('/settings/roles').status_code == 403

def deactivating_ends_a_live_session_and_reactivating_restores_it():
    sign_in_as('carl', B)                                            # a second browser, signed in as carl
    assert B.GET('/dashboard').status_code == 200
    sign_in_as('admin')
    r = act('carl', 'active', {'active': '0'}, c=H.wrong_code(H.secrets['admin'])); assert 'not correct' in H.html(r)
    assert H.row('carl').is_active
    r = act('carl', 'active', {'active': '0'}); assert r.status_code == 302 and 'deactivated' in H.location(r)
    assert B.GET('/dashboard').status_code == 302                    # carl's open session ended
    B.logout(); assert 'Invalid username or password' in B.html(B.login_password('carl'))
    r = act('carl', 'active', {'active': '1'}); assert 'reactivated' in H.location(r)
    B.sign_in('carl'); assert B.GET('/dashboard').status_code == 200

def an_admin_resets_someones_password():
    sign_in_as('admin')
    good = {'password': 'a fresh passphrase 1', 'confirm_password': 'a fresh passphrase 1'}
    assert 'do not match' in H.html(act('viewer', 'password', {'password': GOOD, 'confirm_password': 'x'}))
    assert 'at least 12' in H.html(act('viewer', 'password', {'password': 'short', 'confirm_password': 'short'}))
    assert 'not correct' in H.html(act('viewer', 'password', good, c=H.wrong_code(H.secrets['admin'])))
    r = act('viewer', 'password', good); assert r.status_code == 302 and 'password_reset' in H.location(r)
    H.logout(); assert 'Invalid' in H.html(H.login_password('viewer', PASSWORD))
    H.passwords['viewer'] = 'a fresh passphrase 1'; sign_in_as('viewer'); assert H.GET('/dashboard').status_code == 200

def resetting_two_step_ends_their_session_and_forces_setup():
    sign_in_as('peek', B); assert B.GET('/dashboard').status_code == 200
    sign_in_as('admin')
    r = act('peek', 'reset-2fa'); assert r.status_code == 302 and 'twofa_reset' in H.location(r)
    assert not H.row('peek').two_factor_enabled
    assert B.GET('/dashboard').status_code == 302                    # kicked out
    B.logout(); r = B.login_password('peek'); assert '/login/setup' in B.location(r)
    B.enroll('peek'); assert B.GET('/dashboard').status_code == 200

def deleting_an_account():
    sign_in_as('admin')
    r = act('carol', 'delete', c=H.wrong_code(H.secrets['admin'])); assert 'not correct' in H.html(r) and H.row('carol')
    r = act('carol', 'delete'); assert r.status_code == 302 and 'deleted' in H.location(r)
    assert H.row('carol') is None
    H.logout(); assert 'Invalid' in H.html(H.login_password('carol'))
    sign_in_as('boss2')                                              # boss2 manages staff only
    r = H.POST(f"/settings/accounts/{uid('boss3')}/delete", {'csrf_token': token(), 'code': code()})
    assert r.status_code == 404 and H.row('boss3')                    # cannot even see an admin to delete

def everything_was_audited():
    got = H.audit_actions()
    want = {'account_created', 'account_edited', 'account_password_reset', 'account_2fa_reset', 'account_deactivated',
            'account_reactivated', 'account_deleted', 'role_created', 'role_edited', 'role_deleted', 'password_change'}
    assert want <= got, want - got


STEPS = [
    ("Old roles became Owner / Admin / Custom, and the database refuses a second Owner", old_roles_were_converted),
    ("A session without two-step set up does not count as signed in", a_session_without_two_step_does_not_count),
    ("Every existing account has to set up two-step before using anything", everyone_has_to_set_up_two_step_first),
    ("The Owner sees Settings with all three tabs, and the old Account address redirects", owner_sees_settings_and_all_tabs),
    ("Changing your own password follows the rules", changing_your_own_password),
    ("The Accounts tab shows a card for everyone", accounts_tab_shows_a_card_for_everyone),
    ("Creating an account checks the code, passwords, name, and email", creating_an_account_checks_everything),
    ("A new account can use nothing until two-step is set up", a_new_account_cannot_use_anything_until_two_step_is_set_up),
    ("An admin without the switches has no Accounts or Roles, but is still a dashboard super user", an_admin_without_the_switches_has_no_accounts_or_roles),
    ("Only the Owner can turn an admin's switches on", only_the_owner_turns_the_switches_on),
    ("An admin who manages staff sees and changes only staff", an_admin_who_manages_staff_sees_and_changes_only_staff),
    ("The Owner can make an admin who manages admins, and that admin is limited correctly", the_owner_makes_an_admin_who_manages_admins),
    ("Nobody can touch the Owner, not even the Owner", nobody_can_touch_the_owner),
    ("Roles can be made, and the naming and code rules are enforced", roles_can_be_made_and_rules_are_enforced),
    ("Putting an account in a role gives it the role's permissions", putting_an_account_in_a_role_gives_it_the_roles_permissions),
    ("Editing a role updates everyone in it", editing_a_role_updates_everyone_in_it),
    ("A role in use cannot be deleted until people are moved", a_role_in_use_cannot_be_deleted),
    ("An admin who manages staff can make accounts in a role", an_admin_who_manages_staff_can_make_accounts_in_a_role),
    ("Every protected action is enforced for every kind of account", every_protected_action_is_enforced_for_every_kind_of_account),
    ("Dashboard buttons are hidden for people who cannot use them", buttons_are_hidden_for_people_who_cannot_use_them),
    ("Staff see no Accounts or Roles tabs", staff_see_no_settings_tabs),
    ("Deactivating ends a live session, and reactivating restores access", deactivating_ends_a_live_session_and_reactivating_restores_it),
    ("An admin can reset someone's password", an_admin_resets_someones_password),
    ("Resetting two-step ends their session and forces setup again", resetting_two_step_ends_their_session_and_forces_setup),
    ("Deleting an account, and not being able to delete what you cannot see", deleting_an_account),
    ("Every account and role change was written to the audit log", everything_was_audited),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
