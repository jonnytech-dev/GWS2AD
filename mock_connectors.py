"""
mock_connectors.py
==================
Stand-ins for the Google Workspace and Active Directory connectors, used in
Demo mode. They have the same methods and return the same shapes as the real
ones (gws_connector.py, ad_connector.py), so the dashboard, the sync preview
and the sync itself run unchanged - but everything lives in memory and nothing
leaves this computer.

The sample company is fictional ("Northwind Community Center", example.com).
It is built so the sync has something to do: some people exist in Google but
not yet in AD, one name differs, and one AD account has no Google twin.

Data resets when the app restarts. Settings > Connection has a reset button.
"""
import threading

from ad_connector import ADConnector, friendly_ad_error
from config import AD_CONFIG

DEMO_DOMAIN = 'example.com'

_lock = threading.RLock()


def _sample_google():
    people = [
        # first, last, org unit
        ('Maria', 'Alvarez', '/'),
        ('James', 'Okafor', '/'),
        ('Priya', 'Raman', '/Staff'),
        ('Daniel', 'Kim', '/Staff'),
        ('Sofia', 'Marin', '/Staff'),
        ('Liam', 'Walsh', '/Staff/Facilities'),
        ('Aisha', 'Bello', '/Staff/Facilities'),
        ('Noah', 'Fischer', '/Volunteers'),
        ('Elena', 'Petrova', '/Volunteers'),
        ('Carlos', 'Reyes', '/Volunteers'),
        ('Grace', 'Hopper-Lee', '/Volunteers'),
        ('Tom', 'Becker', '/Volunteers'),
    ]
    users = []
    for first, last, ou in people:
        users.append({
            'email': f"{first[0].lower()}{last.lower().replace('-', '')}@{DEMO_DOMAIN}",
            'firstName': first, 'lastName': last, 'fullName': f"{first} {last}",
            'orgUnitPath': ou, 'suspended': False,
        })
    groups = [
        {'email': f'staff@{DEMO_DOMAIN}', 'name': 'Staff', 'description': 'All paid staff'},
        {'email': f'volunteers@{DEMO_DOMAIN}', 'name': 'Volunteers', 'description': 'Volunteer team'},
        {'email': f'facilities@{DEMO_DOMAIN}', 'name': 'Facilities', 'description': 'Building and grounds'},
        {'email': f'leadership@{DEMO_DOMAIN}', 'name': 'Leadership', 'description': 'Directors and leads'},
    ]
    e = {u['fullName']: u['email'] for u in users}
    members = {
        f'staff@{DEMO_DOMAIN}': [e['Priya Raman'], e['Daniel Kim'], e['Sofia Marin'], e['Liam Walsh'], e['Aisha Bello']],
        f'volunteers@{DEMO_DOMAIN}': [e['Noah Fischer'], e['Elena Petrova'], e['Carlos Reyes'], e['Grace Hopper-Lee'], e['Tom Becker']],
        f'facilities@{DEMO_DOMAIN}': [e['Liam Walsh'], e['Aisha Bello']],
        f'leadership@{DEMO_DOMAIN}': [e['Maria Alvarez'], e['James Okafor']],
    }
    ous = [
        {'path': '/Staff', 'name': 'Staff', 'parentPath': '/'},
        {'path': '/Staff/Facilities', 'name': 'Facilities', 'parentPath': '/Staff'},
        {'path': '/Volunteers', 'name': 'Volunteers', 'parentPath': '/'},
    ]
    return users, groups, members, ous


class MockGWSConnector:
    """Same interface as GWSConnector, backed by memory."""

    def __init__(self):
        self.reset()

    def reset(self):
        with _lock:
            self.users, self.groups, self.members, self.ous = _sample_google()

    # ---- reads ----
    def get_all_users(self):
        with _lock:
            return [dict(u) for u in self.users]

    def get_user_security_info(self, email):
        """Same answer the real connector gives. In the sample company Maria Alvarez is a
        super admin and Tom Becker has no recovery email, so the reset page's refusals can be tried."""
        with _lock:
            u = self._user(email or '')
            if not u:
                return None
            local = u['email'].split('@')[0]
            return {
                'email': u['email'],
                'suspended': bool(u.get('suspended')),
                'isAdmin': u['email'].lower() == f'malvarez@{DEMO_DOMAIN}',
                'isDelegatedAdmin': False,
                'recoveryEmail': '' if u['email'].lower() == f'tbecker@{DEMO_DOMAIN}' else f'{local}.home@example.net',
            }

    def get_all_groups(self):
        with _lock:
            return [dict(g) for g in self.groups]

    def get_all_org_units(self):
        with _lock:
            return [dict(o) for o in self.ous]

    def get_group_members(self, group_email):
        with _lock:
            if group_email not in self.members:
                raise Exception(f"Failed to fetch members for group {group_email}: Resource Not Found")
            return list(self.members[group_email])

    def get_user_group_membership_map(self):
        with _lock:
            out = {}
            for g in self.groups:
                for m in self.members.get(g['email'], []):
                    out.setdefault(m, []).append({'email': g['email'], 'name': g['name']})
            return out

    def get_group_members_for_user(self, user_email):
        with _lock:
            return [g for g, m in self.members.items() if user_email in m]

    # ---- writes ----
    def _user(self, email):
        return next((u for u in self.users if u['email'].lower() == email.lower()), None)

    def create_user(self, email, first_name, last_name, password=None, org_unit_path='/'):
        if not password:
            raise ValueError(f"Cannot create user {email}: no password was provided")
        with _lock:
            if self._user(email):
                raise Exception(f"Failed to create user {email}: Entity already exists.")
            user = {'email': email, 'firstName': first_name, 'lastName': last_name,
                    'fullName': f"{first_name} {last_name}".strip(),
                    'orgUnitPath': org_unit_path or '/', 'suspended': False}
            self.users.append(user)
            return {'primaryEmail': email}

    def update_user(self, email, updates):
        with _lock:
            u = self._user(email)
            if not u:
                raise Exception(f"Failed to update user {email}: Resource Not Found: userKey")
            if 'firstName' in updates:
                u['firstName'] = updates['firstName']
            if 'lastName' in updates:
                u['lastName'] = updates['lastName']
            if 'orgUnitPath' in updates:
                u['orgUnitPath'] = updates['orgUnitPath']
            if updates.get('password'):
                # Demo keeps no password. It only notes that one was set, so the reset page can be tested.
                u['passwordChanges'] = u.get('passwordChanges', 0) + 1
            u['fullName'] = f"{u['firstName']} {u['lastName']}".strip()

    def delete_user(self, email):
        with _lock:
            if not self._user(email):
                raise Exception(f"Failed to delete user {email}: Resource Not Found: userKey")
            self.users = [u for u in self.users if u['email'].lower() != email.lower()]
            for m in self.members.values():
                if email in m:
                    m.remove(email)

    def create_group(self, email, name, description=''):
        with _lock:
            if any(g['email'].lower() == email.lower() for g in self.groups):
                raise Exception(f"Failed to create group {email}: Entity already exists.")
            self.groups.append({'email': email, 'name': name, 'description': description})
            self.members[email] = []
            return {'email': email}

    def update_group(self, email, updates):
        with _lock:
            g = next((g for g in self.groups if g['email'] == email), None)
            if not g:
                raise Exception(f"Failed to update group {email}: Resource Not Found: groupKey")
            for key in ('name', 'description'):
                if key in updates:
                    g[key] = updates[key]

    def delete_group(self, email):
        with _lock:
            if not any(g['email'] == email for g in self.groups):
                raise Exception(f"Failed to delete group {email}: Resource Not Found: groupKey")
            self.groups = [g for g in self.groups if g['email'] != email]
            self.members.pop(email, None)

    def add_group_member(self, group_email, member_email):
        with _lock:
            if group_email not in self.members:
                raise Exception(f"Failed to add {member_email} to group {group_email}: Resource Not Found: groupKey")
            if member_email in self.members[group_email]:
                raise Exception(f"Failed to add {member_email} to group {group_email}: Member already exists.")
            self.members[group_email].append(member_email)

    def remove_group_member(self, group_email, member_email):
        with _lock:
            if member_email not in self.members.get(group_email, []):
                raise Exception(f"Failed to remove {member_email} from group {group_email}: Resource Not Found: memberKey")
            self.members[group_email].remove(member_email)

    def add_user_to_group(self, user_email, group_email):
        return self.add_group_member(group_email, user_email)


class MockADConnector(ADConnector):
    """
    Same interface as ADConnector. It reuses the real class's pure helpers
    (name cleaning, password generation, OU path maths) so Demo mode computes
    exactly what Live mode would, and swaps only the LDAP calls for memory.
    """

    def __init__(self):  # no LDAP connection
        self.conn = None
        self.reset()

    def reset(self):
        with _lock:
            base = AD_CONFIG['base_dn']
            self.ous = {}      # lowercased DN -> DN as written
            self.users = {}    # lowercased email -> record
            self.groups = {}   # sAMAccountName -> record
            # Part of the company is already in AD, as it would be after an earlier sync.
            for dn in (base, f"OU={AD_CONFIG['users_ou_name']},{base}", f"OU={AD_CONFIG['groups_ou_name']},{base}"):
                self._note_ou(dn)
            sample, _, _, _ = _sample_google()
            for u in sample[:7]:
                self._add_user(u['email'], u['firstName'], u['lastName'], self._compute_users_container_dn(u['orgUnitPath']))
            for ou in self._ou_chain_dns('/Staff/Facilities'):
                self._note_ou(ou)
            # A name that differs from Google (the sync will correct it)...
            self.users[f'dkim@{DEMO_DOMAIN}']['firstName'] = 'Dan'
            # ...an AD-only account that has no Google twin, kept in an old OU tree
            # that Google no longer has (so the sync deletes the account, then the
            # now-empty OUs, deepest first)...
            legacy = f"OU=Legacy,{base}"
            self._note_ou(legacy)
            self._add_user(f'old.contractor@{DEMO_DOMAIN}', 'Old', 'Contractor', f"OU={AD_CONFIG['users_ou_name']},{legacy}")
            # ...and an old OU with nothing in it.
            self._note_ou(f"OU=Old Interns,{base}")
            self._add_group('Staff', 'All paid staff')
            self._add_group('Volunteers', 'Volunteer team')
            for u in sample[2:5]:
                self.groups['Staff']['members'].append(self.users[u['email'].lower()]['dn'])

    # ---- helpers ----
    def _ou_chain_dns(self, org_unit_path):
        return [c['dn'] for c in self._compute_ou_chain(org_unit_path)]

    def _add_user(self, email, first, last, container_dn):
        sam = self.sanitize_samaccountname(email.split('@')[0])
        full = f"{first} {last}".strip()
        self.users[email.lower()] = {
            'email': email, 'firstName': first, 'lastName': last, 'displayName': full,
            'samAccountName': sam, 'dn': f"CN={full},{container_dn}",
        }
        self._note_ou(container_dn)

    def _add_group(self, name, description):
        sam = self.sanitize_samaccountname(name.replace(' ', ''))
        groups_ou = f"OU={AD_CONFIG['groups_ou_name']},{AD_CONFIG['base_dn']}"
        self._note_ou(groups_ou)
        self.groups[sam] = {'samAccountName': sam, 'description': description, 'email': '',
                            'members': [], 'dn': f"CN={sam},{groups_ou}"}
        return sam

    def _note_ou(self, dn):
        self.ous[dn.lower()] = dn

    @staticmethod
    def _parent(dn):
        return dn.split(',', 1)[1].strip().lower() if ',' in dn else ''

    def _find_user_dn(self, email, retries=4, retry_delay=0.5):
        u = self.users.get((email or '').lower())
        return u['dn'] if u else None

    def has_user(self, email):
        return self._find_user_dn(email, retries=1) is not None

    def _ensure_ou_exists(self, ou_name, base_dn):
        dn = f"OU={self._escape_dn_value(ou_name)},{base_dn}"
        self._note_ou(dn)
        return dn, None

    # ---- reads ----
    def get_all_users(self):
        with _lock:
            return [dict(u) for u in self.users.values()]

    def get_all_groups(self):
        with _lock:
            return [dict(g, members=list(g['members'])) for g in self.groups.values()]

    def get_all_ous(self):
        with _lock:
            return set(self.ous)

    def list_ous(self):
        with _lock:
            return [dn for low, dn in self.ous.items() if low != AD_CONFIG['base_dn'].strip().lower()]

    def get_ou_children(self, ou_dn):
        with _lock:
            low = ou_dn.strip().lower()
            kids = [u['dn'].lower() for u in self.users.values() if self._parent(u['dn']) == low]
            kids += [g['dn'].lower() for g in self.groups.values() if self._parent(g['dn']) == low]
            kids += [d for d in self.ous if d != low and self._parent(d) == low]
            return kids

    def delete_ou(self, ou_dn):
        with _lock:
            base = AD_CONFIG['base_dn'].strip().lower()
            low = ou_dn.strip().lower()
            if low == base or not low.endswith(',' + base):
                return False, "Refusing to delete an OU that is not inside the base DN"
            if low not in self.ous:
                return False, "Failed to delete OU: noSuchObject"
            if self.get_ou_children(ou_dn):
                return False, "Failed to delete OU: notAllowedOnNonLeaf"
            del self.ous[low]
            return True, None

    # ---- writes (same (success, ..., error) conventions as the real class) ----
    def create_user(self, email, first_name, last_name, full_name=None, org_unit_path='/', root_ou_name='', password=None):
        with _lock:
            if email.lower() in self.users:
                return False, None, friendly_ad_error(f"Failed to create base user object: {email} already exists")
            if password and not (len(password) >= 8 and any(c.isdigit() for c in password)
                                 and any(c.isupper() for c in password) and any(c.islower() for c in password)):
                # Demo stand-in for AD's password policy, so the error path can be seen and tested
                return False, None, friendly_ad_error("Failed to set password: constraint violation 0000052D unicodePwd")
            container, error = self._resolve_users_container_dn(org_unit_path, root_ou_name)
            if error:
                return False, None, error
            self._add_user(email, first_name, last_name, container)
            return True, self.generate_temp_password(), None

    def update_user(self, email, updates):
        with _lock:
            u = self.users.get(email.lower())
            if not u:
                return False, f"User {email} not found"
            if 'firstName' in updates:
                u['firstName'] = updates['firstName']
            if 'lastName' in updates:
                u['lastName'] = updates['lastName']
            if 'displayName' in updates:
                u['displayName'] = updates['displayName']
            if updates.get('password'):
                # Demo keeps no password. It only notes that one was set, so the reset page can be tested.
                u['passwordChanges'] = u.get('passwordChanges', 0) + 1
            return True, None

    def move_user(self, current_dn, new_parent_dn):
        with _lock:
            for u in self.users.values():
                if u['dn'] == current_dn:
                    cn = current_dn.split(',', 1)[0]
                    old = u['dn']
                    u['dn'] = f"{cn},{new_parent_dn}"
                    self._note_ou(new_parent_dn)
                    for g in self.groups.values():
                        g['members'] = [u['dn'] if m == old else m for m in g['members']]
                    return True, None
            return False, "Failed to move user: noSuchObject"

    def delete_user(self, email):
        with _lock:
            u = self.users.pop(email.lower(), None)
            if not u:
                return False, f"User {email} not found"
            for g in self.groups.values():
                g['members'] = [m for m in g['members'] if m != u['dn']]
            return True, None

    def create_group(self, name, description=''):
        with _lock:
            if self.sanitize_samaccountname(name.replace(' ', '')) in self.groups:
                return False, friendly_ad_error("Failed to create group: entryAlreadyExists")
            self._add_group(name, description or ' ')
            return True, None

    def update_group(self, sam_name, updates):
        with _lock:
            g = self.groups.get(sam_name)
            if not g:
                return False, f"Group {sam_name} not found"
            if 'description' in updates:
                g['description'] = updates['description']
            return True, None

    def delete_group(self, sam_name):
        with _lock:
            if self.groups.pop(sam_name, None) is None:
                return False, f"Group {sam_name} not found"
            return True, None

    def add_group_member(self, sam_name, user_email):
        with _lock:
            g = self.groups.get(sam_name)
            if not g:
                return False, f"Group {sam_name} not found"
            u = self.users.get(user_email.lower())
            if not u:
                return False, f"User {user_email} not found"
            if u['dn'] in g['members']:
                return False, "Failed to add member: entryAlreadyExists"
            g['members'].append(u['dn'])
            return True, None

    def remove_group_member(self, sam_name, user_email):
        with _lock:
            g = self.groups.get(sam_name)
            if not g:
                return False, f"Group {sam_name} not found"
            u = self.users.get(user_email.lower())
            if not u:
                return False, f"User {user_email} not found"
            if u['dn'] not in g['members']:
                return False, "Failed to remove member: noSuchAttribute"
            g['members'].remove(u['dn'])
            return True, None


# One shared copy for the whole app (the real connectors are per-thread; the
# demo data must be the same for every request).
_gws = None
_ad = None


def get_mock_gws():
    global _gws
    with _lock:
        if _gws is None:
            _gws = MockGWSConnector()
        return _gws


def get_mock_ad():
    global _ad
    with _lock:
        if _ad is None:
            _ad = MockADConnector()
        return _ad


def reset_demo_data():
    get_mock_gws().reset()
    get_mock_ad().reset()
