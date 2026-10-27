"""
test_permissions.py
===================
Checks the account and permission rules in permissions.py and passwords.py.
No web app and no database needed.

Run it from the project folder:
    python test_permissions.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import permissions as P
import passwords


class Acct:
    _next = 1
    def __init__(self, role, perms=(), manage_admins=False, manage_staff=False, active=True):
        self.id = Acct._next; Acct._next += 1
        self.role = role
        self.perms = list(perms)
        self.can_manage_admins = manage_admins
        self.can_manage_staff = manage_staff
        self.is_active = active
    def assigned_permissions(self): return self.perms

owner = Acct('owner')
admin_plain = Acct('admin')
admin_staff = Acct('admin', manage_staff=True)
admin_admins = Acct('admin', manage_admins=True)
admin_both = Acct('admin', manage_admins=True, manage_staff=True)
custom_view = Acct('custom')
custom_editor = Acct('custom', ['create_user', 'edit_user'])
named_helpdesk = Acct('named', ['edit_user', 'trigger_sync'])
ALL_ACTORS = [owner, admin_plain, admin_staff, admin_admins, admin_both, custom_view, custom_editor, named_helpdesk]


def t_owner_and_admins_hold_every_dashboard_permission():
    for a in (owner, admin_plain, admin_both):
        assert all(P.has_permission(a, k) for k in P.ALL_PERMISSIONS + ['read'])

def t_everyone_active_can_view_but_inactive_can_do_nothing():
    assert all(P.has_permission(a, 'read') for a in ALL_ACTORS)
    ghost = Acct('owner', active=False)
    assert not P.has_permission(ghost, 'read') and not P.has_permission(ghost, 'delete_user')

def t_custom_and_named_hold_only_what_they_were_given():
    assert P.has_permission(custom_editor, 'create_user') and P.has_permission(custom_editor, 'edit_user')
    assert not P.has_permission(custom_editor, 'delete_user') and not P.has_permission(custom_editor, 'trigger_sync')
    assert not any(P.has_permission(custom_view, k) for k in P.ALL_PERMISSIONS)

def t_running_a_sync_includes_previewing_it():
    assert P.has_permission(named_helpdesk, 'trigger_sync') and P.has_permission(named_helpdesk, 'preview_sync')
    only_preview = Acct('custom', ['preview_sync'])
    assert P.has_permission(only_preview, 'preview_sync') and not P.has_permission(only_preview, 'trigger_sync')

def t_unknown_permissions_are_dropped():
    assert P.clean(['edit_user', 'launch_missiles', 'edit_user']) == ['edit_user']
    assert not P.has_permission(Acct('custom', ['manage_accounts']), 'manage_accounts')

def t_flags_for_the_dashboard():
    f = P.flags(custom_editor)
    assert f['create_user'] and f['edit_user'] and not f['delete_user'] and f['read']

def t_card_summaries():
    assert P.summary(owner) == 'Everything' and P.summary(admin_plain) == 'Everything on the dashboard'
    assert P.summary(custom_view) == 'View only'
    assert P.summary(custom_editor) == 'Add users, Edit users'
    big = Acct('custom', ['create_user', 'edit_user', 'delete_user', 'create_group', 'edit_group'])
    assert P.summary(big) == 'Add users, Edit users, Delete users +2 more'

def t_the_accounts_tab_is_only_for_people_with_a_manage_switch():
    seen = {id(a): P.can_see_accounts_tab(a) for a in ALL_ACTORS}
    assert seen[id(owner)] and seen[id(admin_staff)] and seen[id(admin_admins)] and seen[id(admin_both)]
    assert not seen[id(admin_plain)] and not seen[id(custom_view)] and not seen[id(custom_editor)] and not seen[id(named_helpdesk)]

def t_admin_switches_decide_which_accounts_you_can_see():
    staff_acct, admin_acct = Acct('custom'), Acct('admin')
    assert P.can_view_account(admin_staff, staff_acct) and not P.can_view_account(admin_staff, admin_acct)
    assert P.can_view_account(admin_admins, admin_acct) and not P.can_view_account(admin_admins, staff_acct)
    assert P.can_view_account(owner, staff_acct) and P.can_view_account(owner, admin_acct)
    assert not P.can_view_account(admin_plain, staff_acct) and not P.can_view_account(admin_plain, admin_acct)
    assert P.can_view_account(admin_admins, owner) and not P.can_view_account(admin_staff, owner)   # the owner counts as admin-level

def t_nobody_can_edit_or_delete_the_owner():
    for a in ALL_ACTORS:
        assert not P.can_edit_account(a, owner) and not P.can_delete_account(a, owner)

def t_nobody_can_edit_or_delete_themselves_here():
    for a in ALL_ACTORS:
        assert not P.can_edit_account(a, a) and not P.can_delete_account(a, a)

def t_owner_can_manage_every_other_account():
    for target in (admin_plain, admin_both, custom_view, named_helpdesk):
        assert P.can_edit_account(owner, target) and P.can_delete_account(owner, target)

def t_admins_manage_only_the_side_their_switch_covers():
    other_admin, other_staff = Acct('admin'), Acct('custom')
    assert P.can_edit_account(admin_staff, other_staff) and not P.can_edit_account(admin_staff, other_admin)
    assert P.can_edit_account(admin_admins, other_admin) and not P.can_edit_account(admin_admins, other_staff)
    assert P.can_edit_account(admin_both, other_admin) and P.can_edit_account(admin_both, other_staff)
    assert not P.can_edit_account(admin_plain, other_admin) and not P.can_edit_account(admin_plain, other_staff)

def t_staff_can_manage_no_accounts():
    for actor in (custom_view, custom_editor, named_helpdesk):
        for target in (admin_plain, custom_view, named_helpdesk):
            assert not P.can_edit_account(actor, target) and not P.can_view_account(actor, target)
        assert not P.can_create_account(actor, 'custom') and not P.can_create_account(actor, 'admin')

def t_who_can_create_which_kind():
    assert P.can_create_account(owner, 'admin') and P.can_create_account(owner, 'custom') and P.can_create_account(owner, 'named')
    assert not any(P.can_create_account(a, 'owner') for a in ALL_ACTORS)                      # there is only one owner
    assert P.can_create_account(admin_staff, 'custom') and not P.can_create_account(admin_staff, 'admin')
    assert P.can_create_account(admin_admins, 'admin') and not P.can_create_account(admin_admins, 'custom')
    assert not P.can_create_account(admin_plain, 'custom') and not P.can_create_account(admin_plain, 'admin')

def t_changing_between_admin_and_staff_needs_rights_over_both_sides():
    staff_acct, admin_acct = Acct('custom'), Acct('admin')
    assert P.can_change_kind(owner, staff_acct, 'admin') and P.can_change_kind(owner, admin_acct, 'custom')
    assert not P.can_change_kind(admin_staff, staff_acct, 'admin')          # cannot create admins
    assert not P.can_change_kind(admin_admins, staff_acct, 'admin')         # cannot manage staff
    assert P.can_change_kind(admin_both, staff_acct, 'admin') and P.can_change_kind(admin_both, admin_acct, 'named')
    assert not P.can_change_kind(owner, owner, 'custom')

def t_only_the_owner_sets_the_admin_switches():
    assert P.can_set_admin_flags(owner)
    assert not any(P.can_set_admin_flags(a) for a in ALL_ACTORS if a is not owner)

def t_roles_are_managed_by_the_owner_or_admins_who_manage_staff():
    assert P.can_manage_roles(owner) and P.can_manage_roles(admin_staff) and P.can_manage_roles(admin_both)
    assert not P.can_manage_roles(admin_plain) and not P.can_manage_roles(admin_admins)
    assert not P.can_manage_roles(custom_editor)

def t_nobody_can_grant_a_permission_they_do_not_hold():
    assert P.can_grant(owner, P.ALL_PERMISSIONS) and P.can_grant(admin_staff, P.ALL_PERMISSIONS)
    assert not P.can_grant(custom_editor, ['delete_user']) and P.can_grant(custom_editor, ['edit_user'])

def t_visible_accounts_are_filtered_by_what_you_manage():
    pool = [owner, admin_plain, custom_view, named_helpdesk]
    assert P.visible_accounts(admin_staff, pool) == [custom_view, named_helpdesk]
    assert P.visible_accounts(admin_admins, pool) == [owner, admin_plain]
    assert P.visible_accounts(owner, pool) == pool
    assert P.visible_accounts(custom_editor, pool) == []

def t_capabilities_for_the_page_templates():
    assert P.capabilities(owner) == {'see_accounts': True, 'create_admin': True, 'create_staff': True, 'manage_roles': True, 'set_flags': True, 'manage_connection': True, 'manage_branding': True, 'see_ignored': True, 'edit_ignored': True}
    c = P.capabilities(admin_staff)
    assert c['see_accounts'] and c['create_staff'] and c['manage_roles'] and not c['create_admin'] and not c['set_flags']
    assert not c['manage_connection'] and not P.can_manage_connection(admin_staff)  # only the Owner switches Demo/Live
    assert not c['manage_branding'] and not P.can_manage_branding(admin_staff)      # only the Owner sets the logo
    assert not any(P.capabilities(custom_editor).values()) and P.capabilities(None) == {}

def t_ignore_list_permissions():
    # Reading the list needs preview_sync; changing it needs trigger_sync (which implies preview_sync)
    assert P.can_see_ignored(owner) and P.can_edit_ignored(owner) and P.can_edit_ignored(admin_plain)
    assert not P.can_see_ignored(custom_view) and not P.can_see_ignored(custom_editor)
    assert P.can_see_ignored(named_helpdesk) and P.can_edit_ignored(named_helpdesk)
    viewer = Acct('custom', ['preview_sync'])
    assert P.can_see_ignored(viewer) and not P.can_edit_ignored(viewer)
    assert not P.can_see_ignored(None) and not P.can_edit_ignored(None)

def t_password_rules():
    ok = 'a long enough phrase'
    assert passwords.check_new_password(ok, ok, 'jon') is None
    assert 'do not match' in passwords.check_new_password(ok, ok + 'x', 'jon')
    assert 'at least 12' in passwords.check_new_password('short1', 'short1', 'jon')
    assert 'username' in passwords.check_new_password('My-JON-password-1', 'My-JON-password-1', 'jon')
    assert '128' in passwords.check_new_password('x' * 129, 'x' * 129, 'jon')
    assert passwords.check_new_password('a' * 12, 'a' * 12, '') is None                     # no username given, nothing to compare


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
