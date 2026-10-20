"""
gws_connector.py
================
Google Workspace Admin API connector.
Handles all GWS operations: read users/groups/OUs, create, update, delete.
"""

from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from config import GWS_CONFIG
import json


class GWSConnector:
    """Google Workspace API connector"""
    
    def __init__(self):
        self.service = None
        self._connect()
    
    def _connect(self):
        """Authenticate to Google Workspace using service account"""
        try:
            scopes = [
                'https://www.googleapis.com/auth/admin.directory.user',
                'https://www.googleapis.com/auth/admin.directory.group',
                'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
            ]
            
            credentials = Credentials.from_service_account_file(
                GWS_CONFIG['key_path'],
                scopes=scopes,
                subject=GWS_CONFIG['subject']
            )
            
            self.service = build('admin', 'directory_v1', credentials=credentials)
            print("[OK] Connected to Google Workspace")
        except Exception as e:
            raise Exception(f"Failed to connect to Google Workspace: {e}")
    
    def get_all_users(self):
        """
        Fetch all users from Google Workspace.
        Returns list of user dicts with: email, firstName, lastName, fullName, orgUnitPath, suspended
        """
        try:
            users = []
            page_token = None
            
            while True:
                results = self.service.users().list(
                    customer=GWS_CONFIG['customer'],
                    maxResults=500,
                    pageToken=page_token,
                    projection='full'
                ).execute()
                
                for user in results.get('users', []):
                    name = user.get('name', {})
                    users.append({
                        'email': user.get('primaryEmail', ''),
                        'firstName': name.get('givenName', ''),
                        'lastName': name.get('familyName', ''),
                        'fullName': name.get('fullName', ''),
                        'orgUnitPath': user.get('orgUnitPath', ''),
                        'suspended': user.get('suspended', False),
                    })
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            return users
        except Exception as e:
            raise Exception(f"Failed to fetch users from Google Workspace: {e}")
    
    def get_all_groups(self):
        """
        Fetch all groups from Google Workspace.
        Returns list of group dicts with: email, name, description
        """
        try:
            groups = []
            page_token = None
            
            while True:
                results = self.service.groups().list(
                    customer=GWS_CONFIG['customer'],
                    maxResults=500,
                    pageToken=page_token
                ).execute()
                
                for group in results.get('groups', []):
                    groups.append({
                        'email': group.get('email', ''),
                        'name': group.get('name', ''),
                        'description': group.get('description') or '',
                    })
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            return groups
        except Exception as e:
            raise Exception(f"Failed to fetch groups from Google Workspace: {e}")
    
    def get_all_org_units(self):
        """
        Fetch all organizational units from Google Workspace.
        Returns list of OU dicts with: path, name, parentPath
        Note: this does NOT include the root/top-level OU - Google's API
        only returns sub-OUs here. Use get_root_org_unit_name() for the
        root OU's actual display name.
        """
        try:
            results = self.service.orgunits().list(
                customerId=GWS_CONFIG['customer'],
                type='all'
            ).execute()
            
            ous = []
            for ou in results.get('organizationUnits', []):
                ous.append({
                    'path': ou.get('orgUnitPath', ''),
                    'name': ou.get('name', ''),
                    'parentPath': ou.get('parentOrgUnitPath', ''),
                })
            
            return ous
        except Exception as e:
            raise Exception(f"Failed to fetch org units from Google Workspace: {e}")
    
    # DISABLED per admin preference: this adds an extra GWS API call just
    # to fetch the root OU's display name for mirroring into AD. Commented
    # out rather than removed - re-enable by uncommenting this method and
    # its call sites in sync_engine.py (2 places) and app.py (1 place) if
    # you want AD to auto-create a top-level OU matching GWS's root OU
    # name later. In the meantime, use a manually-designated root OU
    # instead (see AD_CONFIG['base_dn'] in config.py).
    #
    # def get_root_org_unit_name(self):
    #     """
    #     Fetch the display name of the top-level (root) organizational
    #     unit - e.g. "Example Organization". orgunits().list()
    #     never includes the root OU itself (it only returns sub-OUs), so
    #     this needs its own dedicated get() call for orgUnitPath='/'.
    #     Returns the name string, or '' if it can't be determined (in
    #     which case callers should fall back to not mirroring a root OU).
    #     """
    #     try:
    #         result = self.service.orgunits().get(
    #             customerId=GWS_CONFIG['customer'],
    #             orgUnitPath='/'
    #         ).execute()
    #         return result.get('name', '')
    #     except Exception as e:
    #         print(f"[WARN] Could not fetch root org unit name: {e}")
    #         return ''
    
    def get_group_members(self, group_email):
        """
        Fetch all members of a specific group.
        Returns list of member emails.
        """
        try:
            members = []
            page_token = None
            
            while True:
                results = self.service.members().list(
                    groupKey=group_email,
                    maxResults=500,
                    pageToken=page_token
                ).execute()
                
                for member in results.get('members', []):
                    if member.get('type') == 'USER' and member.get('email'):
                        members.append(member.get('email'))
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            return members
        except Exception as e:
            raise Exception(f"Failed to fetch members for group {group_email}: {e}")
    
    def get_user_group_membership_map(self):
        """
        Build a map of user email -> list of {email, name} for groups
        they belong to. Fetches each group's members once (cheaper than
        one API call per user) and inverts it into a per-user lookup.
        Returns dict: { 'user@domain.com': [{'email': ..., 'name': ...}, ...] }
        """
        membership_map = {}
        groups = self.get_all_groups()
        
        for group in groups:
            try:
                member_emails = self.get_group_members(group['email'])
            except Exception as e:
                print(f"[WARN] Could not get members for group {group['email']}: {e}")
                continue
            
            for member_email in member_emails:
                membership_map.setdefault(member_email, []).append({
                    'email': group['email'],
                    'name': group['name'],
                })
        
        return membership_map
    
    def create_user(self, email, first_name, last_name, password=None, org_unit_path='/'):
        """
        Create a new user in Google Workspace.
        If password provided, sets it immediately. Otherwise, user must set on first login.
        Returns the created user object or None if failed.
        """
        try:
            user_body = {
                'primaryEmail': email,
                'name': {
                    'givenName': first_name,
                    'familyName': last_name,
                },
                'orgUnitPath': org_unit_path,
            }
            
            if not password:
                # Never silently fall back to a fixed password - GWS
                # requires one to create a user, and any caller of this
                # method needs to supply one explicitly (a random temp
                # password, or one the admin chose)
                raise ValueError(f"Cannot create user {email}: no password was provided")
            
            user_body['password'] = password
            user_body['changePasswordAtNextLogin'] = False
            
            user = self.service.users().insert(body=user_body).execute()
            print(f"[OK] Created user: {email}")
            return user
        except Exception as e:
            raise Exception(f"Failed to create user {email}: {e}")
    
    def update_user(self, email, updates):
        """
        Update an existing user in Google Workspace.
        updates: dict with fields to update (firstName, lastName, password, orgUnitPath, etc.)
        """
        try:
            user_body = {
                'name': {},
            }
            
            if 'firstName' in updates:
                user_body['name']['givenName'] = updates['firstName']
            if 'lastName' in updates:
                user_body['name']['familyName'] = updates['lastName']
            if 'orgUnitPath' in updates:
                user_body['orgUnitPath'] = updates['orgUnitPath']
            if 'password' in updates and updates['password']:
                user_body['password'] = updates['password']
                user_body['changePasswordAtNextLogin'] = False
            
            self.service.users().update(userKey=email, body=user_body).execute()
            print(f"[OK] Updated user: {email}")
        except Exception as e:
            raise Exception(f"Failed to update user {email}: {e}")
    
    def delete_user(self, email):
        """
        Delete a user from Google Workspace.
        Note: This is a permanent action.
        """
        try:
            self.service.users().delete(userKey=email).execute()
            print(f"[OK] Deleted user: {email}")
        except Exception as e:
            raise Exception(f"Failed to delete user {email}: {e}")
    
    def create_group(self, email, name, description=''):
        """
        Create a new group in Google Workspace.
        Returns the created group object or None if failed.
        """
        try:
            group_body = {
                'email': email,
                'name': name,
                'description': description,
            }
            
            group = self.service.groups().insert(body=group_body).execute()
            print(f"[OK] Created group: {email}")
            return group
        except Exception as e:
            raise Exception(f"Failed to create group {email}: {e}")
    
    def update_group(self, email, updates):
        """
        Update an existing group in Google Workspace.
        updates: dict with fields to update (name, description, etc.)
        """
        try:
            group_body = {}
            if 'name' in updates:
                group_body['name'] = updates['name']
            if 'description' in updates:
                group_body['description'] = updates['description']
            
            self.service.groups().update(groupKey=email, body=group_body).execute()
            print(f"[OK] Updated group: {email}")
        except Exception as e:
            raise Exception(f"Failed to update group {email}: {e}")
    
    def delete_group(self, email):
        """
        Delete a group from Google Workspace.
        Note: This is a permanent action.
        """
        try:
            self.service.groups().delete(groupKey=email).execute()
            print(f"[OK] Deleted group: {email}")
        except Exception as e:
            raise Exception(f"Failed to delete group {email}: {e}")
    
    def add_group_member(self, group_email, member_email):
        """
        Add a member to a group in Google Workspace.
        """
        try:
            member_body = {
                'email': member_email,
            }
            self.service.members().insert(
                groupKey=group_email,
                body=member_body
            ).execute()
            print(f"[OK] Added {member_email} to group {group_email}")
        except Exception as e:
            raise Exception(f"Failed to add {member_email} to group {group_email}: {e}")
    
    def remove_group_member(self, group_email, member_email):
        """
        Remove a member from a group in Google Workspace.
        """
        try:
            self.service.members().delete(
                groupKey=group_email,
                memberKey=member_email
            ).execute()
            print(f"[OK] Removed {member_email} from group {group_email}")
        except Exception as e:
            raise Exception(f"Failed to remove {member_email} from group {group_email}: {e}")
    
    def add_user_to_group(self, user_email, group_email):
        """
        Add a user to a group in Google Workspace.
        This is an alias for add_group_member with swapped parameter order.
        """
        return self.add_group_member(group_email, user_email)
    
    def get_group_members_for_user(self, user_email):
        """
        Get all groups that a user is a member of.
        Returns list of group emails.
        """
        try:
            groups = self.service.groups().list(userKey=user_email).execute()
            return [g['email'] for g in groups.get('groups', [])]
        except Exception as e:
            print(f"[WARN] Could not get groups for {user_email}: {e}")
            return []


# Thread-local storage - each Flask worker thread gets its own connector
# instance. This avoids sharing a single httplib2.Http object across
# threads, which is not thread-safe and causes intermittent
# "SSL: RECORD_LAYER_FAILURE" errors under concurrent requests.
import threading
_thread_local = threading.local()

def get_gws_connector():
    """Demo mode: the shared sample-data stand-in. Live mode: a real connector for the current thread."""
    import mode
    if mode.is_demo():
        from mock_connectors import get_mock_gws
        return get_mock_gws()
    if not hasattr(_thread_local, 'connector') or _thread_local.connector is None:
        _thread_local.connector = GWSConnector()
    return _thread_local.connector
