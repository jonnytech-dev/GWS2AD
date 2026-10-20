"""
ad_connector.py
===============
Active Directory LDAP connector.
Handles all AD operations: read users/groups, create, update, delete.
"""

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, SUBTREE, LEVEL
from config import AD_CONFIG
import secrets
import string
import re
import time


class ADConnector:
    """Active Directory LDAP connector"""
    
    def __init__(self):
        self.conn = None
        self._connect()
    
    def _connect(self):
        """Connect to Active Directory over LDAPS"""
        try:
            server = Server(
                AD_CONFIG['server'],
                port=636,
                use_ssl=True,
                get_info=ALL,
                connect_timeout=10  # fail fast if the DC is unreachable, rather than hanging forever
            )
            
            self.conn = Connection(
                server,
                user=AD_CONFIG['bind_dn'],
                password=AD_CONFIG['bind_password'],
                auto_bind=True,
                # Without this, a search/add/modify call has NO timeout
                # at all - if the connection ever stalls (network blip,
                # idle disconnect, anything), it can hang indefinitely
                # with zero indication of what's wrong. This makes any
                # stuck operation fail with a clear error after 15s
                # instead of leaving the sync spinner stuck forever.
                receive_timeout=15
            )
            
            print(f"[OK] Connected to Active Directory: {AD_CONFIG['server']}")
        except Exception as e:
            raise Exception(f"Failed to connect to Active Directory: {e}")
    
    @staticmethod
    def sanitize_samaccountname(raw, max_len=20):
        """Make a string safe for AD sAMAccountName (<=20 chars, no special chars)"""
        cleaned = re.sub(r'[^A-Za-z0-9._-]', '', raw)
        return cleaned[:max_len]
    
    @staticmethod
    def generate_temp_password(length=16):
        """Generate a cryptographically-secure temporary password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+"),
        ]
        pwd += [secrets.choice(alphabet) for _ in range(length - len(pwd))]
        secrets.SystemRandom().shuffle(pwd)
        return ''.join(pwd)
    
    def _find_user_dn(self, email, retries=4, retry_delay=0.5):
        """
        Search for a user by email (falling back to userPrincipalName),
        retrying briefly if not found. A user created moments ago in
        this same sync run isn't always instantly visible to a fresh
        LDAP search on every AD setup - a short consistency/indexing lag
        between "object created" and "object searchable" is a known,
        normal AD behavior, not a bug on our end. Without retrying,
        that lag looks identical to "this user doesn't exist," which is
        exactly what was causing group-membership adds to fail right
        after creating the user in the same sync pass.
        Returns the user's DN, or None if still not found after retrying.
        """
        for attempt in range(retries):
            self.conn.search(
                AD_CONFIG['base_dn'],
                f'(|(mail={email})(userPrincipalName={email}))',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            if self.conn.entries:
                return self.conn.entries[0].entry_dn
            if attempt < retries - 1:
                time.sleep(retry_delay)
        return None
    
    def _escape_dn_value(self, value):
        """
        Escape a value for safe use inside a raw DN string (e.g. as an
        'OU=' component). GWS OU names are dynamic data pulled from the
        directory, not something typed in by hand, so a name containing
        a comma or other DN-special character must not be allowed to
        break the DN structure. Per RFC 4514.
        """
        value = value.replace('\\', '\\\\')
        for char in [',', '+', '"', '<', '>', ';', '=']:
            value = value.replace(char, '\\' + char)
        value = value.strip()
        if value.startswith('#'):
            value = '\\' + value
        return value
    
    def _ensure_ou_exists(self, ou_name, base_dn):
        """
        Ensure an OU exists, creating it if needed.
        Returns (ou_dn, error) - error is None on success (OU already
        existed, or was just created). If creation was attempted and
        failed (e.g. insufficient AD permissions), error is a string
        with the LDAP failure detail - the returned ou_dn must NOT be
        used to create child objects under it in that case, since it
        doesn't actually exist.
        """
        ou_dn = f"OU={self._escape_dn_value(ou_name)},{base_dn}"
        
        if not self.conn.search(ou_dn, '(objectClass=organizationalUnit)'):
            # OU doesn't exist, create it. ldap3's add() returns False
            # on a normal LDAP failure (e.g. permission denied) rather
            # than raising - that return value MUST be checked, or a
            # failed creation looks identical to a successful one and
            # every child object placed "inside" it fails with a
            # confusing "no such object" error instead.
            try:
                created = self.conn.add(ou_dn, 'organizationalUnit', {'ou': ou_name})
            except Exception as e:
                created = False
                self._last_ldap_exception = str(e)
            
            if created:
                print(f"[CREATE] OU: {ou_dn}")
            else:
                # "Already exists" here almost always means a benign
                # race, not a real failure: this same OU was needed by
                # an earlier user/group processed moments ago in this
                # same sync run, that call created it successfully, but
                # AD hadn't made it visible to a fresh search yet when
                # THIS call checked - so we tried to create it again and
                # collided with our own earlier success. Treat that as
                # success rather than bailing out.
                result = self.conn.result if isinstance(self.conn.result, dict) else {}
                description = str(result.get('description', '')).lower()
                if 'alreadyexists' in description or 'already exists' in description:
                    print(f"[INFO] OU already exists (created moments ago in this same sync): {ou_dn}")
                else:
                    detail = getattr(self, '_last_ldap_exception', None) or self.conn.result
                    error = f"Could not create OU '{ou_name}' under {base_dn}: {detail}"
                    print(f"[FAILED] {error}")
                    return ou_dn, error
        
        return ou_dn, None
    
    def _ensure_nested_ou_path(self, ou_segments, base_dn):
        """
        Ensure a chain of nested OUs exists under base_dn, creating any
        missing ones along the way.
        Returns (final_dn, error) - error is None on success. Stops at
        the first failure in the chain (a later segment can't be
        created under a parent that doesn't actually exist).
        ou_segments is root-to-leaf order, e.g. ['Operations', 'Staff'] for
        a GWS orgUnitPath of '/Operations/Staff'. An empty list just
        returns base_dn unchanged.
        """
        current_dn = base_dn
        for segment in ou_segments:
            current_dn, error = self._ensure_ou_exists(segment, current_dn)
            if error:
                return current_dn, error
        return current_dn, None
    
    def _users_ou_segments(self, org_unit_path, root_ou_name=''):
        """
        Build the full root-to-leaf OU segment chain mirroring GWS's
        actual hierarchy, including the real root OU name pulled from
        GWS (e.g. "Example Organization") rather than dumping
        everyone under a generic top-level Users OU.
        '/' with root_ou_name set            -> [root_ou_name]
        '/TestOU' with root_ou_name set       -> [root_ou_name, 'TestOU']
        '/' with root_ou_name unavailable     -> [] (falls back to
                                                  placing directly under
                                                  base_dn - old behavior)
        """
        org_unit_path = org_unit_path or '/'
        sub_segments = [s for s in org_unit_path.split('/') if s]
        segments = [root_ou_name] if root_ou_name else []
        segments.extend(sub_segments)
        return segments
    
    def _compute_users_container_dn(self, org_unit_path, root_ou_name=''):
        """
        Pure string computation of the AD DN where a user from this GWS
        orgUnitPath belongs - does NOT touch AD (no search/create calls),
        so it's safe to use for read-only comparisons like the sync
        preview. Must produce the exact same DN as
        _resolve_users_container_dn for the same input.
        """
        dn = AD_CONFIG['base_dn']
        for segment in self._users_ou_segments(org_unit_path, root_ou_name):
            dn = f"OU={self._escape_dn_value(segment)},{dn}"
        return f"OU={AD_CONFIG['users_ou_name']},{dn}"
    
    def _compute_ou_chain(self, org_unit_path, root_ou_name=''):
        """
        Pure computation (no AD calls) of every OU along the path to a
        user's container, in top-down creation order - e.g. for GWS
        orgUnitPath '/Operations/Staff' this returns:
        [
            {'name': 'Operations', 'dn': 'OU=Operations,<base_dn>'},
            {'name': 'Staff', 'dn': 'OU=Staff,OU=Operations,<base_dn>'},
            {'name': 'Users', 'dn': 'OU=Users,OU=Staff,OU=Operations,<base_dn>'},
        ]
        Used by the sync preview to show which OUs don't exist in AD
        yet, without creating anything.
        """
        dn = AD_CONFIG['base_dn']
        chain = []
        for segment in self._users_ou_segments(org_unit_path, root_ou_name):
            dn = f"OU={self._escape_dn_value(segment)},{dn}"
            chain.append({'name': segment, 'dn': dn})
        dn = f"OU={AD_CONFIG['users_ou_name']},{dn}"
        chain.append({'name': AD_CONFIG['users_ou_name'], 'dn': dn})
        return chain
    
    def _resolve_users_container_dn(self, org_unit_path, root_ou_name=''):
        """
        Given a GWS orgUnitPath (e.g. '/', '/Operations', '/Operations/Staff')
        and the GWS root OU's display name, return the AD DN where a
        user from that OU should be created: a 'Users' OU nested one
        level inside a mirrored copy of the GWS OU chain, rooted at an
        OU matching GWS's actual top-level OU name. Creates any missing
        OUs along the way.
        Returns (dn, error) - error is None on success. If any OU along
        the path failed to create, dn should not be used to create a
        user under it.
        """
        segments = self._users_ou_segments(org_unit_path, root_ou_name)
        parent_dn, error = self._ensure_nested_ou_path(segments, AD_CONFIG['base_dn'])
        if error:
            return parent_dn, error
        return self._ensure_ou_exists(AD_CONFIG['users_ou_name'], parent_dn)
    
    def get_all_users(self):
        """
        Fetch all users from Active Directory.
        Returns list of user dicts.
        """
        try:
            users = []
            self.conn.search(
                AD_CONFIG['base_dn'],
                '(&(objectCategory=person)(objectClass=user))',
                search_scope=SUBTREE,
                attributes=['mail', 'userPrincipalName', 'givenName', 'sn', 'displayName', 'sAMAccountName']
            )
            
            for entry in self.conn.entries:
                # Some AD users (especially ones created manually in ADUC)
                # have userPrincipalName set but never had the separate
                # 'mail' attribute filled in. Fall back to UPN so those
                # users are still matched against GWS instead of being
                # treated as "doesn't exist in AD" forever.
                email = str(entry.mail.value) if entry.mail.value else None
                if not email and entry.userPrincipalName.value:
                    email = str(entry.userPrincipalName.value)
                
                if email:
                    users.append({
                        'email': email,
                        'firstName': str(entry.givenName.value or ''),
                        'lastName': str(entry.sn.value or ''),
                        'displayName': str(entry.displayName.value or ''),
                        'samAccountName': str(entry.sAMAccountName.value or ''),
                        'dn': entry.entry_dn,
                    })
            
            return users
        except Exception as e:
            raise Exception(f"Failed to fetch users from Active Directory: {e}")
    
    def get_all_groups(self):
        """
        Fetch all groups from Active Directory.
        Returns list of group dicts.
        """
        try:
            groups = []
            self.conn.search(
                AD_CONFIG['base_dn'],
                '(objectClass=group)',
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'description', 'mail', 'member']
            )
            
            for entry in self.conn.entries:
                groups.append({
                    'samAccountName': str(entry.sAMAccountName.value or ''),
                    'description': str(entry.description.value or '') if entry.description else '',
                    'email': str(entry.mail.value or '') if entry.mail else '',
                    'members': [str(m) for m in entry.member.values] if entry.member else [],
                    'dn': entry.entry_dn,
                })
            
            return groups
        except Exception as e:
            raise Exception(f"Failed to fetch groups from Active Directory: {e}")
    
    def get_all_ous(self):
        """
        Fetch the DNs of every organizational unit that currently exists
        under base_dn. Used by the sync preview to determine which OUs
        (if any) would need to be created - read-only, no AD writes.
        Returns a set of DNs, lowercased for case-insensitive comparison.
        """
        try:
            self.conn.search(
                AD_CONFIG['base_dn'],
                '(objectClass=organizationalUnit)',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            return {entry.entry_dn.strip().lower() for entry in self.conn.entries}
        except Exception as e:
            raise Exception(f"Failed to fetch organizational units from Active Directory: {e}")
    
    def list_ous(self):
        """
        Every organizational unit under base_dn, with the DN's original
        capitalization (get_all_ous returns the same set lowercased).
        Read-only.
        """
        try:
            self.conn.search(
                AD_CONFIG['base_dn'],
                '(objectClass=organizationalUnit)',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            return [entry.entry_dn.strip() for entry in self.conn.entries]
        except Exception as e:
            raise Exception(f"Failed to list organizational units from Active Directory: {e}")

    def get_ou_children(self, ou_dn):
        """
        DNs (lowercased) of everything directly inside one OU: users,
        groups, computers, child OUs, anything. Used to tell whether an OU
        is empty. Read-only. Raises if AD cannot answer, so a caller never
        mistakes "could not check" for "empty".
        """
        self.conn.search(ou_dn, '(objectClass=*)', search_scope=LEVEL, attributes=['distinguishedName'])
        result = self.conn.result if isinstance(self.conn.result, dict) else {}
        if result.get('description') not in ('success', 'noSuchObject'):
            raise Exception(f"Could not list the contents of {ou_dn}: {result}")
        return [entry.entry_dn.strip().lower() for entry in self.conn.entries]

    def delete_ou(self, ou_dn):
        """
        Delete ONE organizational unit. Never recursive: this sends a plain
        LDAP delete (no tree-delete control), so AD itself refuses with
        notAllowedOnNonLeaf if anything is still inside. Also refuses
        anything that is not strictly inside base_dn.
        Returns (success, error_message)
        """
        try:
            base = AD_CONFIG['base_dn'].strip().lower()
            low = ou_dn.strip().lower()
            if low == base or not low.endswith(',' + base):
                return False, "Refusing to delete an OU that is not inside the base DN"
            if not self.conn.delete(ou_dn):
                return False, f"Failed to delete OU: {self.conn.result}"
            print(f"[DELETE] OU: {ou_dn}")
            return True, None
        except Exception as e:
            return False, str(e)

    def create_user(self, email, first_name, last_name, full_name=None, org_unit_path='/', root_ou_name=''):
        """
        Create a new user in Active Directory.
        org_unit_path: the user's GWS orgUnitPath (e.g. '/', '/Operations',
        '/Operations/Staff'). root_ou_name: GWS's actual top-level OU
        display name (e.g. "Example Organization"), fetched via
        gws.get_root_org_unit_name(). The user is placed in a 'Users' OU
        nested one level inside a mirrored copy of GWS's real OU
        hierarchy, rooted at an OU matching that top-level name. Any
        missing OUs along the way are created automatically.
        Returns (success, temp_password, error_message)
        """
        try:
            sam_name = self.sanitize_samaccountname(email.split('@')[0])
            users_ou, ou_error = self._resolve_users_container_dn(org_unit_path, root_ou_name)
            if ou_error:
                # Don't attempt to create the user under an OU that
                # doesn't actually exist - that would just fail with a
                # confusing "no such object" error instead of the real
                # reason (usually an AD permissions issue)
                return False, None, f"Could not prepare target OU for user: {ou_error}"
            user_dn = f"CN={full_name or sam_name},{users_ou}"
            
            # Create with only the bare minimum - matching your working
            # `New-ADUser -Name X -Path Y` test as closely as possible.
            # Every other field gets set afterward via its own separate
            # modify() call, so if something is still blocked, the error
            # will name exactly which attribute - instead of one opaque
            # failure covering everything bundled into a single create.
            user_attrs = {
                'sAMAccountName': sam_name,
            }
            
            if not self.conn.add(user_dn, ['top', 'person', 'organizationalPerson', 'user'], user_attrs):
                return False, None, f"Failed to create base user object: {self.conn.result}"
            
            if not self.conn.modify(user_dn, {'userPrincipalName': [(MODIFY_REPLACE, [email])]}):
                return False, None, f"User created, but failed to set userPrincipalName: {self.conn.result}"
            
            if not self.conn.modify(user_dn, {
                'givenName': [(MODIFY_REPLACE, [first_name])],
                'sn': [(MODIFY_REPLACE, [last_name])],
                'displayName': [(MODIFY_REPLACE, [full_name or f"{first_name} {last_name}"])],
            }):
                return False, None, f"User created, but failed to set name fields: {self.conn.result}"
            
            if not self.conn.modify(user_dn, {'mail': [(MODIFY_REPLACE, [email])]}):
                return False, None, f"User created, but failed to set mail: {self.conn.result}"
            
            # Generate temp password
            temp_password = self.generate_temp_password()
            
            # Set password (requires LDAPS)
            pwd_value = f'"{temp_password}"'.encode('utf-16-le')
            if not self.conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [pwd_value])]}):
                return False, None, f"User created, but failed to set password: {self.conn.result}"
            
            # Force password change at next logon, enable account
            if not self.conn.modify(user_dn, {
                'pwdLastSet': [(MODIFY_REPLACE, ['0'])],
                'userAccountControl': [(MODIFY_REPLACE, ['512'])],
            }):
                return False, None, f"User created, but failed to enable account: {self.conn.result}"
            
            print(f"[CREATE] User: {email}")
            return True, temp_password, None
        except Exception as e:
            return False, None, str(e)
    
    def update_user(self, email, updates):
        """
        Update an existing user in Active Directory.
        updates: dict with fields to update (firstName, lastName, displayName, password, etc.)
        """
        try:
            # Find the user by email - falls back to userPrincipalName,
            # and retries briefly to ride out AD consistency lag if this
            # user was just created moments ago in the same sync run
            user_dn = self._find_user_dn(email)
            
            if not user_dn:
                return False, f"User {email} not found"
            changes = {}
            
            if 'firstName' in updates:
                changes['givenName'] = [(MODIFY_REPLACE, [updates['firstName']])]
            if 'lastName' in updates:
                changes['sn'] = [(MODIFY_REPLACE, [updates['lastName']])]
            if 'displayName' in updates:
                changes['displayName'] = [(MODIFY_REPLACE, [updates['displayName']])]
            
            # Handle password change (requires LDAPS/SSL)
            if 'password' in updates and updates['password']:
                pwd_value = f'\"{updates["password"]}\"'.encode('utf-16-le')
                changes['unicodePwd'] = [(MODIFY_REPLACE, [pwd_value])]
            
            if changes:
                if not self.conn.modify(user_dn, changes):
                    return False, f"Failed to update user: {self.conn.result}"
                if 'unicodePwd' in changes:
                    print(f"[UPDATE] User {email}: password changed")
                else:
                    print(f"[UPDATE] User: {email}")
            
            return True, None
        except Exception as e:
            return False, str(e)
    
    def move_user(self, current_dn, new_parent_dn):
        """
        Move a user to a different parent OU (their CN/RDN stays the
        same, only the container changes). Used to keep a user's AD
        location in sync when their GWS OU changes.
        Returns (success, error_message)
        """
        try:
            # The RDN is everything before the first comma, e.g. "CN=John Doe"
            rdn = current_dn.split(',', 1)[0]
            if not self.conn.modify_dn(current_dn, rdn, new_superior=new_parent_dn):
                return False, f"Failed to move user: {self.conn.result}"
            return True, None
        except Exception as e:
            return False, str(e)
    
    def delete_user(self, email):
        """
        Delete a user from Active Directory.
        """
        try:
            user_dn = self._find_user_dn(email)
            
            if not user_dn:
                return False, f"User {email} not found"
            
            if not self.conn.delete(user_dn):
                return False, f"Failed to delete user: {self.conn.result}"
            
            print(f"[DELETE] User: {email}")
            return True, None
        except Exception as e:
            return False, str(e)
    
    def create_group(self, name, description=''):
        """
        Create a new group in Active Directory.
        """
        try:
            sam_name = self.sanitize_samaccountname(name.replace(' ', ''))
            groups_ou, ou_error = self._ensure_ou_exists(
                AD_CONFIG['groups_ou_name'],
                AD_CONFIG['base_dn']
            )
            if ou_error:
                return False, f"Could not prepare Groups OU: {ou_error}"
            group_dn = f"CN={sam_name},{groups_ou}"
            
            group_attrs = {
                'sAMAccountName': sam_name,
                'groupType': -2147483646,  # global, security-enabled
                'description': description or ' ',
            }
            
            if not self.conn.add(group_dn, ['top', 'group'], group_attrs):
                return False, f"Failed to create group: {self.conn.result}"
            
            print(f"[CREATE] Group: {sam_name}")
            return True, None
        except Exception as e:
            return False, str(e)
    
    def update_group(self, sam_name, updates):
        """
        Update an existing group in Active Directory.
        """
        try:
            # Find group by sAMAccountName
            self.conn.search(
                AD_CONFIG['base_dn'],
                f'(sAMAccountName={sam_name})',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            if not self.conn.entries:
                return False, f"Group {sam_name} not found"
            
            group_dn = self.conn.entries[0].entry_dn
            changes = {}
            
            if 'description' in updates:
                changes['description'] = [(MODIFY_REPLACE, [updates['description']])]
            
            if changes:
                if not self.conn.modify(group_dn, changes):
                    return False, f"Failed to update group: {self.conn.result}"
                print(f"[UPDATE] Group: {sam_name}")
            
            return True, None
        except Exception as e:
            return False, str(e)
    
    def delete_group(self, sam_name):
        """
        Delete a group from Active Directory.
        """
        try:
            self.conn.search(
                AD_CONFIG['base_dn'],
                f'(sAMAccountName={sam_name})',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            if not self.conn.entries:
                return False, f"Group {sam_name} not found"
            
            group_dn = self.conn.entries[0].entry_dn
            if not self.conn.delete(group_dn):
                return False, f"Failed to delete group: {self.conn.result}"
            
            print(f"[DELETE] Group: {sam_name}")
            return True, None
        except Exception as e:
            return False, str(e)
    
    def add_group_member(self, sam_name, user_email):
        """
        Add a user to a group in Active Directory.
        """
        try:
            # Find group
            self.conn.search(
                AD_CONFIG['base_dn'],
                f'(sAMAccountName={sam_name})',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            if not self.conn.entries:
                return False, f"Group {sam_name} not found"
            
            group_dn = self.conn.entries[0].entry_dn
            
            # Find user - retries briefly to ride out AD consistency lag
            # if this user was just created moments ago in this same
            # sync run (this was the actual cause of "failed to add
            # member: user not found" right after creating the user)
            user_dn = self._find_user_dn(user_email)
            
            if not user_dn:
                return False, f"User {user_email} not found"
            
            # Add user to group
            if not self.conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]}):
                return False, f"Failed to add member: {self.conn.result}"
            
            print(f"[UPDATE] Added {user_email} to group {sam_name}")
            return True, None
        except Exception as e:
            return False, str(e)
    
    def remove_group_member(self, sam_name, user_email):
        """
        Remove a user from a group in Active Directory.
        """
        try:
            # Find group
            self.conn.search(
                AD_CONFIG['base_dn'],
                f'(sAMAccountName={sam_name})',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            if not self.conn.entries:
                return False, f"Group {sam_name} not found"
            
            group_dn = self.conn.entries[0].entry_dn
            
            # Find user
            self.conn.search(
                AD_CONFIG['base_dn'],
                f'(|(mail={user_email})(userPrincipalName={user_email}))',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            if not self.conn.entries:
                return False, f"User {user_email} not found"
            
            user_dn = self.conn.entries[0].entry_dn
            
            # Remove user from group
            if not self.conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]}):
                return False, f"Failed to remove member: {self.conn.result}"
            
            print(f"[UPDATE] Removed {user_email} from group {sam_name}")
            return True, None
        except Exception as e:
            return False, str(e)


# Thread-local storage - each Flask worker thread gets its own connector
# instance, since ldap3.Connection objects are not safe to share across
# threads under concurrent use.
import threading
_thread_local = threading.local()

def get_ad_connector():
    """Demo mode: the shared sample-data stand-in. Live mode: a real connector for the current thread."""
    import mode
    if mode.is_demo():
        from mock_connectors import get_mock_ad
        return get_mock_ad()
    if not hasattr(_thread_local, 'connector') or _thread_local.connector is None:
        _thread_local.connector = ADConnector()
    return _thread_local.connector
