"""
sync_engine.py
==============
Master sync orchestration between Google Workspace and Active Directory.
Pulls from GWS, compares to AD, creates/updates/deletes as needed.
"""

from gws_connector import get_gws_connector
from ad_connector import get_ad_connector
from database import SyncStatus, AuditLog, db
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from config import SMTP_CONFIG, AD_CONFIG
from backup import create_pre_sync_backup


class SyncEngine:
    """Orchestrates GWS <-> AD sync"""
    
    def __init__(self):
        self.gws = get_gws_connector()
        self.ad = get_ad_connector()
        self.sync_log = []
        # New users' temp passwords, when email is disabled - deliberately
        # kept OUT of sync_log/self.log(), since that gets printed to the
        # server console, returned in the /api/sync response, AND written
        # into the AuditLog database table (permanently, in plaintext).
        # This list only lives in memory for this one sync run and is
        # surfaced once, directly, by the /api/sync route - never logged
        # or persisted anywhere.
        self.pending_credentials = []
    
    def log(self, message):
        """Log a sync message with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_msg = f"[{timestamp}] {message}"
        self.sync_log.append(formatted_msg)
        print(formatted_msg)
    
    def _send_user_email(self, user_email, full_name, sam_name, temp_password):
        """
        Send welcome email with temp password to new user.
        Returns (sent, password_needs_manual_handoff) - the second value
        is True when email is disabled, signaling the caller that this
        password still needs to reach the admin some other way (never
        via self.log(), which persists to the audit log in plaintext).
        """
        from database import AppSettings
        
        # Check if email sending is enabled in settings
        settings = AppSettings.get_or_create()
        if not settings.send_emails:
            self.log(f"[EMAIL] Email disabled in settings - skipping email to {user_email}")
            return True, True
        
        import mode
        if mode.is_demo():
            self.log(f"[EMAIL] Demo mode - no email is sent. Would have emailed {user_email}")
            return True, True
        
        try:
            subject = "Your new network account is ready"
            body = f"""Hello {full_name},

Your new network (Active Directory) account has been created.

USERNAME: {sam_name}
TEMPORARY PASSWORD: {temp_password}

IMPORTANT - This password is for signing into your on-premise computer (Windows workstations) in the office.

If you want, you can use the same password as your Gmail/Google account for consistency. Just let IT know and we can update it.

For security, if this is a temporary password, you'll be required to change it the first time you sign in to a Windows computer.

Questions? Contact IT.

Thank you,
IT Department"""
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = SMTP_CONFIG['from_address']
            msg['To'] = user_email
            
            with smtplib.SMTP(SMTP_CONFIG['smtp_server'], SMTP_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(SMTP_CONFIG['from_address'], SMTP_CONFIG['smtp_password'])
                server.send_message(msg)
            
            self.log(f"[EMAIL] Sent account-ready email to {user_email}")
            return True, False
        except Exception as e:
            self.log(f"[WARNING] Could not send email to {user_email}: {e}")
            # Email failed to actually send - this password also needs
            # to reach the admin some other way, same as when email is
            # disabled entirely
            return False, True
    
    # ------------------------------------------------------------------
    # Extra organizational units (in AD, but not in Google)
    # ------------------------------------------------------------------

    def _expected_ou_dns(self, gws_ous, gws_users, root_ou_name=''):
        """
        Every OU that Google's structure accounts for, as lowercased DNs:
        the mirrored OUs for each Google OU, the `Users` container inside
        each (and at the root), and the `Groups` OU. Built from Google's OU
        list AND from where Google's users actually live, so a partial or
        empty OU list from Google can never make a real OU look "extra".
        Pure computation, no AD calls.
        """
        paths = {'/'}
        paths.update(o['path'] for o in gws_ous if o.get('path'))
        paths.update((u.get('orgUnitPath') or '/') for u in gws_users)
        expected = set()
        for path in paths:
            for ou in self.ad._compute_ou_chain(path, root_ou_name):
                expected.add(ou['dn'].strip().lower())
        expected.add(f"OU={AD_CONFIG['groups_ou_name']},{AD_CONFIG['base_dn']}".strip().lower())
        return expected

    @staticmethod
    def _is_protected_ou(dn):
        """OUs that must never be offered for deletion, whatever else is true"""
        rdn, _, parent = dn.strip().partition(',')
        # Windows' own OU for domain controllers, when the base DN is the domain root
        return rdn.strip().lower() == 'ou=domain controllers' and parent.strip().lower().startswith('dc=')

    def _extra_ous(self, ad_ou_dns, expected):
        """
        OUs under the base DN that Google's structure does not account for,
        deepest first (a child's DN is always longer than its parent's, so
        sorting by length puts children before parents, which is the order
        they have to be deleted in). The base DN itself is never included.
        """
        base = AD_CONFIG['base_dn'].strip().lower()
        extra = []
        for dn in ad_ou_dns:
            low = dn.strip().lower()
            if low == base or not low.endswith(',' + base):
                continue
            if low in expected or self._is_protected_ou(dn):
                continue
            extra.append(dn.strip())
        return sorted(extra, key=len, reverse=True)

    @staticmethod
    def _ou_name(dn):
        return dn.split(',', 1)[0].split('=', 1)[-1]

    def sync(self):
        """
        Execute full sync: GWS -> AD
        Compares desired state (GWS) to current state (AD) and syncs.
        Returns (success: bool, differences: list)
        """
        self.log("\n" + "="*70)
        self.log("Starting GWS -> AD Sync")
        self.log("="*70)
        
        # Snapshot GWS data before touching anything - a backup failure
        # is logged but never blocks the sync itself from proceeding
        try:
            backup_path = create_pre_sync_backup(self.gws)
            self.log(f"[BACKUP] Pre-sync backup saved: {backup_path}")
        except Exception as e:
            self.log(f"[WARNING] Pre-sync backup failed (continuing with sync anyway): {e}")
        
        differences = []
        
        try:
            # --- STEP 1: Pull from Google Workspace ---
            self.log("\n[STEP 1] Fetching data from Google Workspace...")
            gws_users = self.gws.get_all_users()
            gws_groups = self.gws.get_all_groups()
            gws_ous = self.gws.get_all_org_units()
            # DISABLED per admin preference (avoids an extra GWS API call):
            # root_ou_name = self.gws.get_root_org_unit_name()
            # Instead, place a manually-designated root OU (see
            # AD_CONFIG['base_dn'] in config.py) - everything (sub-OUs
            # mirroring GWS structure, Users, Groups) lives under that.
            root_ou_name = ''
            
            self.log(f"[OK] Fetched {len(gws_users)} users, {len(gws_groups)} groups, {len(gws_ous)} OUs")
            
            # --- STEP 2: Pull current state from AD ---
            self.log("\n[STEP 2] Fetching current state from Active Directory...")
            ad_users = self.ad.get_all_users()
            ad_groups = self.ad.get_all_groups()
            
            self.log(f"[OK] Found {len(ad_users)} users, {len(ad_groups)} groups in AD")
            
            # --- STEP 3: Create/update groups ---
            self.log("\n[STEP 3] Syncing groups...")
            ad_groups_by_sam = {g['samAccountName']: g for g in ad_groups}
            
            for g in gws_groups:
                sam_name = self.ad.sanitize_samaccountname(g['name'].replace(' ', ''))
                
                if sam_name not in ad_groups_by_sam:
                    # Create new group
                    success, error = self.ad.create_group(g['name'], g.get('description', ''))
                    if success:
                        self.log(f"[CREATE] Group: {sam_name}")
                    else:
                        self.log(f"[FAILED] Could not create group {sam_name}: {error}")
                        differences.append({'type': 'group', 'action': 'create_failed', 'name': sam_name})
                else:
                    # Check if description changed (normalize None/whitespace
                    # so a blank description on both sides never looks like
                    # a change)
                    existing = ad_groups_by_sam[sam_name]
                    existing_desc = (existing.get('description') or '').strip()
                    gws_desc = (g.get('description') or '').strip()
                    if existing_desc != gws_desc:
                        success, error = self.ad.update_group(sam_name, {'description': gws_desc})
                        if success:
                            self.log(f"[UPDATE] Group '{sam_name}' description changed")
                        else:
                            self.log(f"[FAILED] Could not update group {sam_name}: {error}")
                            differences.append({'type': 'group', 'action': 'update_failed', 'name': sam_name, 'error': error})
                    else:
                        self.log(f"[SKIP] Group '{sam_name}' unchanged")
            
            # --- STEP 4: Create/update users ---
            self.log("\n[STEP 4] Syncing users...")
            # Lowercase the keys - email addresses are case-insensitive,
            # and a casing mismatch between GWS and AD (e.g. from a
            # manually-created AD account) would otherwise make a user
            # who already exists look like they still need to be created.
            ad_users_by_email = {u['email'].lower(): u for u in ad_users if u.get('email')}
            
            for u in gws_users:
                email = u['email']
                if not email:
                    continue
                
                if email.lower() not in ad_users_by_email:
                    # Create new user - mirroring their GWS OU into AD
                    success, temp_password, error = self.ad.create_user(
                        email,
                        u.get('firstName', ''),
                        u.get('lastName', ''),
                        u.get('fullName', ''),
                        u.get('orgUnitPath', '/'),
                        root_ou_name
                    )
                    
                    if success:
                        self.log(f"[CREATE] User: {email}")
                        # Send welcome email
                        sam_name = self.ad.sanitize_samaccountname(email.split('@')[0])
                        _, needs_manual_handoff = self._send_user_email(email, u.get('fullName', email), sam_name, temp_password)
                        if needs_manual_handoff:
                            self.pending_credentials.append({
                                'email': email,
                                'name': u.get('fullName', email),
                                'temp_password': temp_password
                            })
                    else:
                        self.log(f"[FAILED] Could not create user {email}: {error}")
                        differences.append({'type': 'user', 'action': 'create_failed', 'email': email})
                else:
                    # Check if anything changed
                    existing = ad_users_by_email[email.lower()]
                    changes = {}
                    
                    existing_first = (existing.get('firstName') or '').strip()
                    gws_first = (u.get('firstName') or '').strip()
                    if existing_first != gws_first:
                        changes['firstName'] = gws_first
                    existing_last = (existing.get('lastName') or '').strip()
                    gws_last = (u.get('lastName') or '').strip()
                    if existing_last != gws_last:
                        changes['lastName'] = gws_last
                    
                    if changes:
                        success, error = self.ad.update_user(email, changes)
                        if success:
                            self.log(f"[UPDATE] User '{email}': {', '.join(changes.keys())}")
                        else:
                            self.log(f"[FAILED] Could not update user {email}: {error}")
                            differences.append({'type': 'user', 'action': 'update_failed', 'email': email, 'error': error})
                    else:
                        self.log(f"[SKIP] User '{email}' unchanged")
                    
                    # Check if the user's AD location still matches their
                    # GWS OU, and move them if it doesn't (this also
                    # creates any missing OUs along the target path)
                    current_dn = existing.get('dn', '')
                    desired_ou_dn, ou_error = self.ad._resolve_users_container_dn(u.get('orgUnitPath', '/'), root_ou_name)
                    if ou_error:
                        self.log(f"[FAILED] Could not prepare target OU for {email}: {ou_error}")
                        differences.append({'type': 'user', 'action': 'move_failed', 'email': email, 'error': ou_error})
                    else:
                        current_parent_dn = current_dn.split(',', 1)[1] if ',' in current_dn else ''
                        if current_parent_dn.strip().lower() != desired_ou_dn.strip().lower():
                            move_success, move_error = self.ad.move_user(current_dn, desired_ou_dn)
                            if move_success:
                                self.log(f"[MOVE] User '{email}' moved to match GWS OU: {u.get('orgUnitPath', '/')}")
                            else:
                                self.log(f"[FAILED] Could not move user {email}: {move_error}")
                                differences.append({'type': 'user', 'action': 'move_failed', 'email': email, 'error': move_error})
            
            # --- STEP 5: Sync group membership ---
            self.log("\n[STEP 5] Syncing group membership...")
            
            # Refresh AD's view of users/groups now - STEP 3/4 just
            # created and moved things, and using the stale STEP 2
            # snapshot here would mean a group created moments ago gets
            # no members until the *next* sync run.
            ad_users = self.ad.get_all_users()
            ad_groups = self.ad.get_all_groups()
            
            # DN -> email lookup. AD stores group membership as DNs
            # (e.g. "CN=John Doe,OU=..."), but GWS membership is
            # expressed as email addresses - without translating one to
            # match the other, a DN would never equal an email string,
            # so EVERY existing member would look like a mismatch on
            # EVERY run: spamming redundant re-adds, and - if removals
            # were enabled without this fix - wiping every group's
            # membership on the next sync.
            dn_to_email = {
                u['dn'].strip().lower(): u['email'].lower()
                for u in ad_users if u.get('dn') and u.get('email')
            }
            
            # Get all group members from GWS
            group_members = {}  # {group_email: [member_emails]}
            for g in gws_groups:
                members = self.gws.get_group_members(g['email'])
                group_members[g['email']] = members
            
            # For each group, sync its members
            ad_groups_by_sam = {g['samAccountName']: g for g in ad_groups}
            
            for g in gws_groups:
                sam_name = self.ad.sanitize_samaccountname(g['name'].replace(' ', ''))
                if sam_name not in ad_groups_by_sam:
                    # Group wasn't created (error above), skip membership
                    continue
                
                gws_members = set(email.lower() for email in group_members.get(g['email'], []) if email)
                
                ad_member_dns = ad_groups_by_sam[sam_name].get('members', [])
                ad_members = set()
                for dn in ad_member_dns:
                    resolved_email = dn_to_email.get(dn.strip().lower())
                    if resolved_email:
                        ad_members.add(resolved_email)
                    # else: this member isn't a known AD user (could be a
                    # nested group or something outside what we track) -
                    # leave it alone rather than guessing
                
                # Members to add (in GWS but not in AD)
                to_add = gws_members - ad_members
                for member_email in to_add:
                    success, error = self.ad.add_group_member(sam_name, member_email)
                    if success:
                        self.log(f"[UPDATE] Added '{member_email}' to group '{sam_name}'")
                    else:
                        self.log(f"[FAILED] Could not add '{member_email}' to group '{sam_name}': {error}")
                        differences.append({'type': 'group', 'action': 'add_member_failed', 'name': sam_name, 'email': member_email, 'error': error})
                
                # Members to remove (in AD but not in GWS) - full mirror,
                # matching whatever's actually in GWS
                to_remove = ad_members - gws_members
                for member_email in to_remove:
                    success, error = self.ad.remove_group_member(sam_name, member_email)
                    if success:
                        self.log(f"[UPDATE] Removed '{member_email}' from group '{sam_name}'")
                    else:
                        self.log(f"[FAILED] Could not remove '{member_email}' from group '{sam_name}': {error}")
                        differences.append({'type': 'group', 'action': 'remove_member_failed', 'name': sam_name, 'email': member_email, 'error': error})
            
            # --- STEP 6: Delete users/groups in AD that aren't in GWS (unless ignored) ---
            self.log("\n[STEP 6] Checking for deletions...")
            from database import IgnoredSyncItem
            
            # Delete users
            gws_emails_lower = {u['email'].lower() for u in gws_users if u.get('email')}
            for ad_user in ad_users:
                email = ad_user['email']
                if email.lower() not in gws_emails_lower:
                    if not IgnoredSyncItem.is_ignored('user', email):
                        success, error = self.ad.delete_user(email)
                        if success:
                            self.log(f"[DELETE] User: {email}")
                        else:
                            self.log(f"[FAILED] Could not delete user {email}: {error}")
                            differences.append({'type': 'user', 'action': 'delete_failed', 'email': email})
                    else:
                        self.log(f"[SKIP] User '{email}' in ignore list, not deleted")
            
            # Delete groups
            gws_group_sam_names = set()
            for g in gws_groups:
                sam_name = self.ad.sanitize_samaccountname(g['name'].replace(' ', ''))
                gws_group_sam_names.add(sam_name)
            
            for ad_group in ad_groups:
                sam_name = ad_group['samAccountName']
                if sam_name not in gws_group_sam_names:
                    if not IgnoredSyncItem.is_ignored('group', sam_name):
                        success, error = self.ad.delete_group(sam_name)
                        if success:
                            self.log(f"[DELETE] Group: {sam_name}")
                        else:
                            self.log(f"[FAILED] Could not delete group {sam_name}: {error}")
                            differences.append({'type': 'group', 'action': 'delete_failed', 'name': sam_name})
                    else:
                        self.log(f"[SKIP] Group '{sam_name}' in ignore list, not deleted")
            
            # --- STEP 7: Delete organizational units that Google no longer has ---
            # Last, so the users and groups that lived in them are already
            # moved or deleted. Deepest first. An OU is only removed if it is
            # EMPTY right now, checked live; AD is also asked for a plain
            # (non-recursive) delete, so it refuses a non-empty one itself.
            self.log("\n[STEP 7] Checking for organizational units Google no longer has...")
            try:
                extra_ous = self._extra_ous(self.ad.list_ous(), self._expected_ou_dns(gws_ous, gws_users, root_ou_name))
            except Exception as e:
                extra_ous = []
                self.log(f"[FAILED] Could not check organizational units: {e}")
                differences.append({'type': 'ou', 'action': 'delete_failed', 'name': 'organizational units', 'error': str(e)})
            for ou_dn in extra_ous:
                if IgnoredSyncItem.is_ignored('ou', ou_dn.strip().lower()):
                    self.log(f"[SKIP] OU '{ou_dn}' in ignore list, not deleted")
                    continue
                try:
                    contents = self.ad.get_ou_children(ou_dn)
                except Exception as e:
                    self.log(f"[FAILED] Could not check whether OU '{ou_dn}' is empty, left alone: {e}")
                    differences.append({'type': 'ou', 'action': 'delete_failed', 'name': self._ou_name(ou_dn), 'error': str(e)})
                    continue
                if contents:
                    self.log(f"[SKIP] OU '{ou_dn}' still contains {len(contents)} object(s), not deleted")
                    continue
                success, error = self.ad.delete_ou(ou_dn)
                if success:
                    self.log(f"[DELETE] OU: {ou_dn}")
                else:
                    self.log(f"[FAILED] Could not delete OU {ou_dn}: {error}")
                    differences.append({'type': 'ou', 'action': 'delete_failed', 'name': self._ou_name(ou_dn), 'error': error})
            
            # --- Sync complete ---
            self.log("\n" + "="*70)
            self.log("[SUCCESS] Sync complete!")
            
            # Add summary statistics
            self.log(f"Summary: {len(gws_users)} GWS users, {len(gws_groups)} GWS groups")
            self.log(f"         {len(ad_users)} AD users, {len(ad_groups)} AD groups")
            if differences:
                self.log(f"         {len(differences)} differences found")
            else:
                self.log("         All items synced successfully!")
            
            self.log("="*70 + "\n")
            
            # Update sync status in database
            SyncStatus.update_sync_status(
                'synced',
                len(gws_users),
                len(gws_groups),
                len(ad_users),
                len(ad_groups),
                error=None,
                differences=differences
            )
            
            # Full, unabridged log of every CRUD action and failure from
            # this run - separate from the AuditLog DB summary, which
            # only keeps a short excerpt to avoid database bloat
            from file_logger import write_sync_log
            write_sync_log(self.sync_log, status='success' if not any(
                d.get('action', '').endswith('_failed') for d in differences
            ) else 'partial')
            
            return True, differences
        
        except Exception as e:
            self.log(f"\n[ERROR] Sync failed: {e}")
            self.log("="*70 + "\n")
            
            # Update sync status with error
            SyncStatus.update_sync_status(
                'error',
                0, 0, 0, 0,
                error=str(e),
                differences=[]
            )
            
            from file_logger import write_sync_log
            write_sync_log(self.sync_log, status='error')
            
            return False, []
    
    def get_sync_preview(self):
        """
        Get a preview of what will be synced and deleted without making changes.
        Returns dict with create/update/delete lists.
        """
        from database import IgnoredSyncItem
        
        preview = {
            'users_to_create': [],
            'users_to_update': [],
            'users_to_delete': [],
            'groups_to_create': [],
            'groups_to_update': [],
            'groups_to_delete': [],
            'group_membership_changes': [],
            'ous_to_create': [],
            'ous_to_delete': [],
            'ignored_items': []
        }
        
        try:
            # Pull fresh data
            gws_users = self.gws.get_all_users()
            gws_groups = self.gws.get_all_groups()
            gws_ous = self.gws.get_all_org_units()
            ad_users = self.ad.get_all_users()
            ad_groups = self.ad.get_all_groups()
            existing_ou_dns = self.ad.get_all_ous()  # lowercased set, for the OU-existence check below
            # DISABLED per admin preference (avoids an extra GWS API call) -
            # see the matching note in sync() above
            # root_ou_name = self.gws.get_root_org_unit_name()
            root_ou_name = ''
            
            # Tracks OUs that don't exist yet but will be needed - keyed
            # by lowercased DN to dedupe when multiple users need the
            # same new OU (e.g. two new hires in the same new sub-OU)
            ous_to_create_by_dn = {}
            
            def _note_missing_ous(org_unit_path):
                for ou in self.ad._compute_ou_chain(org_unit_path, root_ou_name):
                    dn_lower = ou['dn'].strip().lower()
                    if dn_lower not in existing_ou_dns and dn_lower not in ous_to_create_by_dn:
                        ous_to_create_by_dn[dn_lower] = ou
            
            # Create lookup dicts - keyed by lowercased email since email
            # addresses are case-insensitive, and a casing mismatch (e.g.
            # from a manually-created AD account) would otherwise make an
            # existing user look like they still need to be created (or
            # worse, look like they need to be deleted)
            gws_user_emails = {u['email'].lower(): u for u in gws_users if u.get('email')}
            gws_group_names = {g['name']: g for g in gws_groups}
            ad_users_by_email = {u['email'].lower(): u for u in ad_users if u.get('email')}
            ad_groups_by_sam = {g['samAccountName']: g for g in ad_groups}
            
            # --- USERS ---
            # What will be created
            for email_lower, user in gws_user_emails.items():
                if email_lower not in ad_users_by_email:
                    preview['users_to_create'].append({
                        'email': user['email'],
                        'name': user.get('fullName', user['email'])
                    })
                    _note_missing_ous(user.get('orgUnitPath', '/'))
            
            # What will be updated
            for email_lower, user in gws_user_emails.items():
                if email_lower in ad_users_by_email:
                    ad_user = ad_users_by_email[email_lower]
                    changes = {}
                    ad_first = (ad_user.get('firstName') or '').strip()
                    gws_first = (user.get('firstName') or '').strip()
                    if ad_first != gws_first:
                        changes['firstName'] = gws_first
                    ad_last = (ad_user.get('lastName') or '').strip()
                    gws_last = (user.get('lastName') or '').strip()
                    if ad_last != gws_last:
                        changes['lastName'] = gws_last
                    
                    # Check if the user's AD location matches their GWS OU.
                    # Uses the pure DN computation (no AD writes) since a
                    # preview must never create OUs as a side effect.
                    desired_ou_dn = self.ad._compute_users_container_dn(user.get('orgUnitPath', '/'), root_ou_name)
                    current_dn = ad_user.get('dn', '')
                    current_parent_dn = current_dn.split(',', 1)[1] if ',' in current_dn else ''
                    if current_parent_dn.strip().lower() != desired_ou_dn.strip().lower():
                        changes['organizationalUnit'] = user.get('orgUnitPath', '/')
                        _note_missing_ous(user.get('orgUnitPath', '/'))
                    
                    if changes:
                        preview['users_to_update'].append({
                            'email': user['email'],
                            'changes': changes
                        })
            
            # What will be deleted (in AD but not in GWS)
            for email_lower, ad_user in ad_users_by_email.items():
                if email_lower not in gws_user_emails:
                    email = ad_user['email']
                    is_ignored = IgnoredSyncItem.is_ignored('user', email)
                    preview['users_to_delete'].append({
                        'email': email,
                        'name': ad_user.get('fullName', email),
                        'ignored': is_ignored,
                        'note': IgnoredSyncItem.get_note('user', email) if is_ignored else None
                    })
                    if is_ignored:
                        preview['ignored_items'].append({'type': 'user', 'identifier': email})
            
            # --- GROUPS ---
            # What will be created
            for g in gws_groups:
                sam_name = self.ad.sanitize_samaccountname(g['name'].replace(' ', ''))
                if sam_name not in ad_groups_by_sam:
                    preview['groups_to_create'].append({
                        'name': g['name'],
                        'email': g['email'],
                        'description': g.get('description', '')
                    })
            
            # What will be updated
            for g in gws_groups:
                sam_name = self.ad.sanitize_samaccountname(g['name'].replace(' ', ''))
                if sam_name in ad_groups_by_sam:
                    ad_group = ad_groups_by_sam[sam_name]
                    ad_desc = (ad_group.get('description') or '').strip()
                    gws_desc = (g.get('description') or '').strip()
                    if ad_desc != gws_desc:
                        preview['groups_to_update'].append({
                            'name': g['name'],
                            'email': g['email'],
                            'old_description': ad_desc,
                            'new_description': gws_desc
                        })
            
            # What will be deleted (in AD but not in GWS)
            for sam_name, ad_group in ad_groups_by_sam.items():
                # Find matching GWS group
                gws_group = None
                for g in gws_groups:
                    if self.ad.sanitize_samaccountname(g['name'].replace(' ', '')) == sam_name:
                        gws_group = g
                        break
                
                if gws_group is None:
                    is_ignored = IgnoredSyncItem.is_ignored('group', sam_name)
                    preview['groups_to_delete'].append({
                        'name': ad_group.get('name', sam_name),
                        'sam_name': sam_name,
                        'ignored': is_ignored,
                        'note': IgnoredSyncItem.get_note('group', sam_name) if is_ignored else None
                    })
                    if is_ignored:
                        preview['ignored_items'].append({'type': 'group', 'identifier': sam_name})
            
            # --- GROUP MEMBERSHIP ---
            # Same DN -> email translation as the actual sync run needs -
            # AD stores membership as DNs, GWS as email addresses, and
            # comparing them directly would make every existing member
            # look like a mismatch. Read-only here (no AD writes), safe
            # to call on every preview load.
            dn_to_email = {
                u['dn'].strip().lower(): u['email'].lower()
                for u in ad_users if u.get('dn') and u.get('email')
            }
            
            for g in gws_groups:
                sam_name = self.ad.sanitize_samaccountname(g['name'].replace(' ', ''))
                if sam_name not in ad_groups_by_sam:
                    continue  # group doesn't exist yet - covered by groups_to_create
                
                gws_members = set(email.lower() for email in self.gws.get_group_members(g['email']) if email)
                ad_member_dns = ad_groups_by_sam[sam_name].get('members', [])
                ad_members = set()
                for dn in ad_member_dns:
                    resolved_email = dn_to_email.get(dn.strip().lower())
                    if resolved_email:
                        ad_members.add(resolved_email)
                
                to_add = sorted(gws_members - ad_members)
                to_remove = sorted(ad_members - gws_members)
                if to_add or to_remove:
                    preview['group_membership_changes'].append({
                        'name': g['name'],
                        'sam_name': sam_name,
                        'add': to_add,
                        'remove': to_remove
                    })
            
            # --- ORGANIZATIONAL UNITS to delete ---
            # OUs under the base DN that Google's structure does not account for.
            # An OU is only deleted if it will be EMPTY by then, so work out what
            # this same sync is about to remove or move out of it. Deepest first,
            # same as the real sync, so an emptied child frees its parent.
            will_be_gone = set()
            for item in preview['users_to_delete']:
                if not item.get('ignored'):
                    will_be_gone.add((ad_users_by_email[item['email'].lower()].get('dn') or '').strip().lower())
            for item in preview['users_to_update']:
                if 'organizationalUnit' in item.get('changes', {}):
                    will_be_gone.add((ad_users_by_email[item['email'].lower()].get('dn') or '').strip().lower())
            for item in preview['groups_to_delete']:
                if not item.get('ignored'):
                    will_be_gone.add((ad_groups_by_sam[item['sam_name']].get('dn') or '').strip().lower())
            will_be_gone.discard('')
            
            expected_ous = self._expected_ou_dns(gws_ous, gws_users, root_ou_name)
            for ou_dn in self._extra_ous(self.ad.list_ous(), expected_ous):
                ident = ou_dn.strip().lower()
                entry = {'name': self._ou_name(ou_dn), 'dn': ou_dn, 'identifier': ident,
                         'ignored': False, 'action': 'delete', 'remaining': 0}
                if IgnoredSyncItem.is_ignored('ou', ident):
                    entry['ignored'] = True
                    entry['action'] = 'ignored'
                    entry['note'] = IgnoredSyncItem.get_note('ou', ident)
                    preview['ignored_items'].append({'type': 'ou', 'identifier': ident})
                else:
                    remaining = [c for c in self.ad.get_ou_children(ou_dn) if c not in will_be_gone]
                    if remaining:
                        entry['action'] = 'not_empty'
                        entry['remaining'] = len(remaining)
                    else:
                        will_be_gone.add(ident)
                preview['ous_to_delete'].append(entry)
            preview['ous_to_delete'].reverse()   # shown top-down; they run deepest-first
            
            # Sort top-down (shallower OUs first) for a sensible display
            # order - a DN's depth roughly tracks its length since each
            # nesting level adds another "OU=...," segment
            preview['ous_to_create'] = sorted(
                ous_to_create_by_dn.values(),
                key=lambda ou: len(ou['dn'])
            )
            
            return preview
        
        except Exception as e:
            return {
                'error': str(e),
                'users_to_create': [],
                'users_to_update': [],
                'users_to_delete': [],
                'groups_to_create': [],
                'groups_to_update': [],
                'groups_to_delete': [],
                'group_membership_changes': [],
                'ous_to_create': [],
                'ous_to_delete': [],
                'ignored_items': []
            }


# Thread-local storage - SyncEngine holds self.gws/self.ad references
# captured at construction time, so a shared singleton would pin those
# connectors to whichever thread created it and reintroduce the same
# cross-thread SSL/LDAP corruption fixed in gws_connector.py and
# ad_connector.py. Now that get_sync_preview() runs on every dashboard
# poll (not just an occasional manual sync click), this matters far more.
import threading
_thread_local = threading.local()

def get_sync_engine():
    """Get or create a SyncEngine for the current thread"""
    if not hasattr(_thread_local, 'engine') or _thread_local.engine is None:
        _thread_local.engine = SyncEngine()
    return _thread_local.engine
