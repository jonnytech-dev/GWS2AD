"""
permissions.py
==============
Who can do what. This file holds only the rules (no web app, no database),
so they can be tested on their own.

ROLES
  owner   Exactly one. Can do everything and can never be deleted,
          deactivated, or demoted.
  admin   Super user for users, groups, and sync. Two extra switches,
          both OFF when the account is made and settable only by the Owner:
            can_manage_admins  view, add, edit, delete other admin accounts
            can_manage_staff   view, add, edit, delete everyone else
  custom  Permissions picked one account at a time.
  named   A role (security group) someone created, such as "Help Desk".
          The account gets whatever permissions the role has.

"Staff" means any account that is not an admin or the owner.
Managing accounts is never a permission a role can hold, and nobody can
hand out a permission they do not have themselves.
"""

# (key, short name, longer description for the checklist)
PERMISSIONS = [
    ('create_user',  'Add users',     'Create new Google Workspace users'),
    ('edit_user',    'Edit users',    'Change a user\'s name, password, groups, and organizational unit'),
    ('delete_user',  'Delete users',  'Delete users from Google Workspace'),
    ('create_group', 'Add groups',    'Create new groups'),
    ('edit_group',   'Edit groups',   'Change a group, including who is in it'),
    ('delete_group', 'Delete groups', 'Delete groups from Google Workspace'),
    ('preview_sync', 'Preview sync',  'See what a sync would change (look only)'),
    ('trigger_sync', 'Run sync',      'Apply a sync to Active Directory. Includes the ignore list and the email setting'),
]
ALL_PERMISSIONS = [key for key, _, _ in PERMISSIONS]
SHORT_NAMES = {key: short for key, short, _ in PERMISSIONS}
DESCRIPTIONS = {key: long for key, _, long in PERMISSIONS}

# Having the first also gives you the second
IMPLIED = {'trigger_sync': ['preview_sync']}

OWNER, ADMIN, CUSTOM, NAMED = 'owner', 'admin', 'custom', 'named'
ROLE_LABELS = {OWNER: 'Owner', ADMIN: 'Admin', CUSTOM: 'Custom'}


def clean(permissions):
    """Known permissions only, implied ones added, no repeats, in a steady order"""
    wanted = set(permissions or [])
    for key in list(wanted):
        wanted.update(IMPLIED.get(key, []))
    return [key for key in ALL_PERMISSIONS if key in wanted]


def permission_set(acct):
    """Every dashboard permission this account holds (viewing is separate and always on)"""
    if acct.role in (OWNER, ADMIN):
        return set(ALL_PERMISSIONS)
    return set(clean(acct.assigned_permissions()))


def has_permission(acct, action):
    if acct is None or not acct.is_active:
        return False
    if action == 'read':
        return True
    return action in permission_set(acct)


def flags(acct):
    """{'create_user': True, ...} for the dashboard page"""
    held = permission_set(acct)
    result = {key: key in held for key in ALL_PERMISSIONS}
    result['read'] = True
    return result


def summary_of(keys):
    """A short line listing permissions, for the cards"""
    held = [SHORT_NAMES[k] for k in clean(keys)]
    if not held:
        return 'View only'
    if len(held) <= 3:
        return ', '.join(held)
    return ', '.join(held[:3]) + f' +{len(held) - 3} more'


def summary(acct):
    """A short line for the account cards"""
    if acct.role == OWNER:
        return 'Everything'
    if acct.role == ADMIN:
        return 'Everything on the dashboard'
    return summary_of(acct.assigned_permissions())


# ---------------------------------------------------------------------
# Managing accounts
# ---------------------------------------------------------------------
def is_admin_class(acct):
    return acct.role in (OWNER, ADMIN)


def manages_admins(actor):
    return actor.role == OWNER or (actor.role == ADMIN and bool(actor.can_manage_admins))


def manages_staff(actor):
    return actor.role == OWNER or (actor.role == ADMIN and bool(actor.can_manage_staff))


def _manages_class_of(actor, target):
    return manages_admins(actor) if is_admin_class(target) else manages_staff(actor)


def can_see_accounts_tab(actor):
    return manages_admins(actor) or manages_staff(actor)


def can_view_account(actor, target):
    return _manages_class_of(actor, target)


def can_edit_account(actor, target):
    """Edit, reset password or two-step, deactivate, delete. Never the owner, never yourself here."""
    return target.role != OWNER and target.id != actor.id and _manages_class_of(actor, target)


can_delete_account = can_edit_account


def can_create_account(actor, kind):
    if kind == OWNER:
        return False
    if kind == ADMIN:
        return manages_admins(actor)
    return manages_staff(actor)       # custom, or a named role


def can_change_kind(actor, target, new_kind):
    """Moving someone between admin and staff needs rights over both sides"""
    return can_edit_account(actor, target) and can_create_account(actor, new_kind)


def can_set_admin_flags(actor):
    return actor.role == OWNER


def can_manage_connection(actor):
    """Switching between Demo and Live decides which real systems get changed, so only the Owner may."""
    return actor.role == OWNER


def can_see_ignored(actor):
    """The ignore list shows what the sync is told to leave alone, so anyone who may preview a sync may read it"""
    return has_permission(actor, 'preview_sync')


def can_edit_ignored(actor):
    """Adding to or removing from the ignore list changes what a sync deletes, so it takes the sync permission"""
    return has_permission(actor, 'trigger_sync')


def can_manage_roles(actor):
    return manages_staff(actor)


def can_grant(actor, permissions):
    """Nobody can hand out a permission they do not hold"""
    return set(clean(permissions)) <= permission_set(actor)


def visible_accounts(actor, accounts):
    return [a for a in accounts if can_view_account(actor, a)]


def capabilities(actor):
    """Everything the page templates need to know about what this person may do"""
    if actor is None:
        return {}
    return {
        'see_accounts': can_see_accounts_tab(actor),
        'create_admin': can_create_account(actor, ADMIN),
        'create_staff': can_create_account(actor, CUSTOM),
        'manage_roles': can_manage_roles(actor),
        'manage_connection': can_manage_connection(actor),
        'see_ignored': can_see_ignored(actor),
        'edit_ignored': can_edit_ignored(actor),
        'set_flags': can_set_admin_flags(actor),
    }
