"""
database.py
===========
SQLite models for accounts, roles, audit logs, and sync status.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

import permissions

db = SQLAlchemy()


class Admin(db.Model):
    """Admin user accounts with role-based permissions"""
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    
    # What kind of account this is (see permissions.py):
    #   'owner'  exactly one, can never be deleted, deactivated, or demoted
    #   'admin'  super user for users, groups, and sync
    #   'custom' permissions picked for this one account (custom_permissions)
    #   'named'  gets its permissions from a Role (role_id), such as "Help Desk"
    role = db.Column(db.String(20), default='custom', nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)
    custom_permissions = db.Column(db.Text, nullable=True)     # JSON list, used when role == 'custom'
    display_name = db.Column(db.String(120), nullable=True)
    created_by = db.Column(db.String(80), nullable=True)
    
    # Wrong-password lockout (see loginlock.py) and past usernames (so a renamed
    # account can take an old name back, but nobody else can)
    login_failed_attempts = db.Column(db.Integer, default=0, nullable=False, server_default=db.text('0'))
    login_locked_until = db.Column(db.DateTime, nullable=True)
    former_usernames = db.Column(db.Text, nullable=True)           # JSON list
    
    # Admin-only switches. OFF when the account is made; only the Owner can turn them on.
    can_manage_admins = db.Column(db.Boolean, default=False, nullable=False, server_default=db.text('0'))
    can_manage_staff = db.Column(db.Boolean, default=False, nullable=False, server_default=db.text('0'))
    
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # --- Two-step verification (logic lives in twofa.py) ---
    totp_secret = db.Column(db.Text, nullable=True)            # active secret, stored encrypted
    totp_pending_secret = db.Column(db.Text, nullable=True)    # new secret waiting for its first code
    totp_pending_at = db.Column(db.DateTime, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False, server_default=db.text('0'))
    totp_last_step = db.Column(db.Integer, nullable=True)      # last code used, so it can't be reused
    recovery_codes = db.Column(db.Text, nullable=True)         # JSON list of keyed hashes, never the codes
    twofa_enrolled_at = db.Column(db.DateTime, nullable=True)
    twofa_failed_attempts = db.Column(db.Integer, default=0, nullable=False, server_default=db.text('0'))
    twofa_locked_until = db.Column(db.DateTime, nullable=True)
    
    @property
    def two_factor_enabled(self):
        """True once the person has finished setting up their authenticator app"""
        return bool(self.totp_enabled and self.totp_secret)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    named_role = db.relationship('Role', foreign_keys=[role_id])
    
    def assigned_permissions(self):
        """The permissions given to a custom account or by a named role (owners and admins hold all)"""
        if self.role == permissions.CUSTOM:
            raw = self.custom_permissions
        elif self.role == permissions.NAMED and self.named_role:
            raw = self.named_role.permissions
        else:
            return []
        try:
            return json.loads(raw) if raw else []
        except ValueError:
            return []
    
    def has_permission(self, action):
        """Check if this account may do an action (the rules live in permissions.py)"""
        return permissions.has_permission(self, action)
    
    @property
    def role_label(self):
        if self.role == permissions.NAMED:
            return self.named_role.name if self.named_role else 'Role removed'
        return permissions.ROLE_LABELS.get(self.role, self.role)
    
    @property
    def is_locked(self):
        """True while the account is locked for wrong passwords or wrong codes"""
        now = datetime.utcnow()
        return bool((self.login_locked_until and self.login_locked_until > now)
                    or (self.twofa_locked_until and self.twofa_locked_until > now))
    
    @property
    def display(self):
        """The name shown on cards: the display name, or the username if none was set"""
        return self.display_name or self.username
    
    def __repr__(self):
        return f'<Admin {self.username} ({self.role})>'


class Role(db.Model):
    """A named set of permissions (a security group), such as "Help Desk" """
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True, nullable=False)
    permissions = db.Column(db.Text, nullable=False, default='[]')    # JSON list
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(80), nullable=True)
    
    def permission_list(self):
        try:
            return permissions.clean(json.loads(self.permissions or '[]'))
        except ValueError:
            return []
    
    def member_count(self):
        return Admin.query.filter_by(role_id=self.id, role=permissions.NAMED).count()

    def summary(self):
        return permissions.summary_of(self.permission_list())
    
    def __repr__(self):
        return f'<Role {self.name}>'


class AuditLog(db.Model):
    """Log of all admin actions for compliance and troubleshooting"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    admin_username = db.Column(db.String(80), nullable=False, index=True)
    
    # Action type: 'create_user', 'edit_user', 'delete_user', 'create_group', etc.
    action = db.Column(db.String(50), nullable=False, index=True)
    
    # What was modified: 'user:john@example.com', 'group:engineering'
    target = db.Column(db.String(255), nullable=False)
    
    # Status: 'success', 'failed'
    status = db.Column(db.String(20), nullable=False, index=True)
    
    # Details as JSON: what changed, error message, etc.
    details = db.Column(db.Text, nullable=True)
    
    # IP address or hostname of admin making the change
    source = db.Column(db.String(120), nullable=True)
    
    @staticmethod
    def log_action(admin_username, action, target, status, details=None, source=None):
        """Create an audit log entry (database row + a durable log file)"""
        log = AuditLog(
            admin_username=admin_username,
            action=action,
            target=target,
            status=status,
            details=json.dumps(details) if details else None,
            source=source,
        )
        db.session.add(log)
        db.session.commit()
        
        # Also write a standalone log file - this covers every CRUD
        # action, login, ignore-list change, etc. in one place, since
        # they all already flow through this method. Sync gets its own
        # separate, more detailed file (see file_logger.write_sync_log)
        # since a sync run's full CRUD log is much longer than what's
        # kept in the 'details' summary here.
        from file_logger import write_action_log
        write_action_log(action, admin_username, target, status, details, source)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'admin': self.admin_username,
            'action': self.action,
            'target': self.target,
            'status': self.status,
            'details': json.loads(self.details) if self.details else None,
            'source': self.source,
        }
    
    def __repr__(self):
        return f'<AuditLog {self.timestamp} {self.action} {self.status}>'



class IgnoredSyncItem(db.Model):
    """Items in AD that should be ignored during sync (not deleted)"""
    __tablename__ = 'ignored_sync_items'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Type: 'user', 'group' or 'ou' (for 'ou' the identifier is the OU's DN, lowercased)
    item_type = db.Column(db.String(20), nullable=False, index=True)
    
    # Email or name of the item
    item_identifier = db.Column(db.String(255), nullable=False)
    
    # When it was added to ignore list
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Reason why it's ignored
    reason = db.Column(db.Text, nullable=True)
    
    # Admin who added it
    added_by = db.Column(db.String(80), nullable=True)
    
    @staticmethod
    def add_ignored_item(item_type, item_identifier, reason=None, added_by=None):
        """Add an item to the ignore list"""
        # Check if already ignored
        existing = IgnoredSyncItem.query.filter_by(
            item_type=item_type,
            item_identifier=item_identifier
        ).first()
        if existing:
            return existing
        
        item = IgnoredSyncItem(
            item_type=item_type,
            item_identifier=item_identifier,
            reason=reason,
            added_by=added_by
        )
        db.session.add(item)
        db.session.commit()
        return item
    
    NOTE_MAX = 200
    DEFAULT_NOTE = 'Ignored via sync preview'     # older entries carry this text; it says nothing, so it counts as no note

    @staticmethod
    def clean_note(text):
        """A note is one short line. Returns the cleaned text (or None when empty); raises ValueError when too long."""
        text = ' '.join((text or '').split())
        if len(text) > IgnoredSyncItem.NOTE_MAX:
            raise ValueError(f'The note is too long. Use {IgnoredSyncItem.NOTE_MAX} characters or fewer.')
        return text or None

    @staticmethod
    def get_note(item_type, item_identifier):
        item = IgnoredSyncItem.query.filter_by(item_type=item_type, item_identifier=item_identifier).first()
        if not item or item.reason == IgnoredSyncItem.DEFAULT_NOTE:
            return None
        return item.reason or None

    @staticmethod
    def set_note(item_type, item_identifier, note):
        """Change the note on an item that is already ignored. Returns False if it is not on the list."""
        item = IgnoredSyncItem.query.filter_by(item_type=item_type, item_identifier=item_identifier).first()
        if not item:
            return False
        item.reason = IgnoredSyncItem.clean_note(note)
        db.session.commit()
        return True

    @staticmethod
    def remove_ignored_item(item_type, item_identifier):
        """Remove an item from the ignore list"""
        IgnoredSyncItem.query.filter_by(
            item_type=item_type,
            item_identifier=item_identifier
        ).delete()
        db.session.commit()
    
    @staticmethod
    def is_ignored(item_type, item_identifier):
        """Check if an item is in the ignore list"""
        return IgnoredSyncItem.query.filter_by(
            item_type=item_type,
            item_identifier=item_identifier
        ).first() is not None
    
    @staticmethod
    def get_all_ignored():
        """Get all ignored items"""
        items = IgnoredSyncItem.query.order_by(IgnoredSyncItem.created_at.desc(), IgnoredSyncItem.id.desc()).all()
        return [{'type': i.item_type, 'identifier': i.item_identifier,
                 'reason': None if i.reason == IgnoredSyncItem.DEFAULT_NOTE else i.reason,
                 'added_by': i.added_by,
                 'added_at': i.created_at.isoformat() if i.created_at else None} for i in items]
    
    def __repr__(self):
        return f'<IgnoredSyncItem {self.item_type}:{self.item_identifier}>'




class AppSettings(db.Model):
    """Global application settings"""
    __tablename__ = 'app_settings'
    
    id = db.Column(db.Integer, primary_key=True, default=1)  # Always single row
    
    # Email settings
    send_emails = db.Column(db.Boolean, default=False, nullable=False)
    
    # When settings were last updated
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    @staticmethod
    def get_or_create():
        """Get the singleton settings record"""
        settings = AppSettings.query.filter_by(id=1).first()
        if not settings:
            settings = AppSettings(id=1, send_emails=False)
            db.session.add(settings)
            db.session.commit()
        return settings
    
    @staticmethod
    def get_send_emails():
        """Get email sending status"""
        settings = AppSettings.get_or_create()
        return settings.send_emails
    
    @staticmethod
    def set_send_emails(value):
        """Set email sending status"""
        settings = AppSettings.get_or_create()
        settings.send_emails = value
        settings.updated_at = datetime.utcnow()
        db.session.commit()
        return settings
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'send_emails': self.send_emails,
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<AppSettings send_emails={self.send_emails}>'


class SyncStatus(db.Model):
    """Track last sync time and alignment status between GW and AD"""
    __tablename__ = 'sync_status'
    
    id = db.Column(db.Integer, primary_key=True, default=1)  # Always single row
    
    # Timestamp of last successful sync
    last_sync_time = db.Column(db.DateTime, nullable=True)
    
    # Overall status: 'synced', 'out_of_sync', 'syncing', 'error'
    status = db.Column(db.String(20), default='unknown', nullable=False)
    
    # Last error message if sync failed
    last_error = db.Column(db.Text, nullable=True)
    
    # Summary statistics
    gws_users_count = db.Column(db.Integer, default=0)
    gws_groups_count = db.Column(db.Integer, default=0)
    ad_users_count = db.Column(db.Integer, default=0)
    ad_groups_count = db.Column(db.Integer, default=0)
    
    # List of differences found (JSON array)
    differences = db.Column(db.Text, nullable=True)
    
    @staticmethod
    def get_or_create():
        """Get the singleton SyncStatus record"""
        status = SyncStatus.query.filter_by(id=1).first()
        if not status:
            status = SyncStatus(id=1, status='unknown')
            db.session.add(status)
            db.session.commit()
        return status
    
    @staticmethod
    def update_sync_status(status_str, gws_users, gws_groups, ad_users, ad_groups, error=None, differences=None):
        """Update sync status after a sync run"""
        status = SyncStatus.get_or_create()
        status.status = status_str
        status.last_sync_time = datetime.utcnow() if status_str == 'synced' else status.last_sync_time
        status.gws_users_count = gws_users
        status.gws_groups_count = gws_groups
        status.ad_users_count = ad_users
        status.ad_groups_count = ad_groups
        status.last_error = error
        status.differences = json.dumps(differences) if differences else None
        db.session.commit()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'status': self.status,
            'last_sync_time': self.last_sync_time.isoformat() if self.last_sync_time else None,
            'last_error': self.last_error,
            'gws_users': self.gws_users_count,
            'gws_groups': self.gws_groups_count,
            'ad_users': self.ad_users_count,
            'ad_groups': self.ad_groups_count,
            'differences': json.loads(self.differences) if self.differences else [],
        }
    
    def __repr__(self):
        return f'<SyncStatus {self.status} at {self.last_sync_time}>'


def _add_missing_admin_columns():
    """
    db.create_all() creates missing TABLES but never adds columns to a table
    that already exists. This adds the two-step verification columns to an
    existing admins table (existing rows and passwords are left untouched).
    """
    from sqlalchemy import inspect, text
    wanted = {
        'totp_secret': 'TEXT',
        'totp_pending_secret': 'TEXT',
        'totp_pending_at': 'DATETIME',
        'totp_enabled': 'BOOLEAN NOT NULL DEFAULT 0',
        'totp_last_step': 'INTEGER',
        'recovery_codes': 'TEXT',
        'twofa_enrolled_at': 'DATETIME',
        'twofa_failed_attempts': 'INTEGER NOT NULL DEFAULT 0',
        'twofa_locked_until': 'DATETIME',
        # Roles and permissions
        'role_id': 'INTEGER REFERENCES roles(id)',
        'custom_permissions': 'TEXT',
        'display_name': 'VARCHAR(120)',
        'created_by': 'VARCHAR(80)',
        'can_manage_admins': 'BOOLEAN NOT NULL DEFAULT 0',
        'can_manage_staff': 'BOOLEAN NOT NULL DEFAULT 0',
        # Password lockout and username history
        'login_failed_attempts': 'INTEGER NOT NULL DEFAULT 0',
        'login_locked_until': 'DATETIME',
        'former_usernames': 'TEXT',
    }
    existing = {c['name'] for c in inspect(db.engine).get_columns('admins')}
    missing = {name: ddl for name, ddl in wanted.items() if name not in existing}
    if not missing:
        return
    with db.engine.begin() as conn:
        for name, ddl in missing.items():
            conn.execute(text(f'ALTER TABLE admins ADD COLUMN {name} {ddl}'))
    print(f"[OK] Database upgraded for roles and two-step verification ({len(missing)} columns added)")


def _migrate_roles():
    """
    Moves accounts from the old three roles to the new ones, once.
      oldest 'full' account -> Owner (your first account)
      other 'full' accounts -> Admin
      'limited'             -> Custom: add and edit users and groups
      'read_only'           -> Custom: view only
    Nobody gains or loses anything they could do before. Also makes sure the
    database itself refuses a second Owner.
    """
    from sqlalchemy import text
    legacy = Admin.query.filter(Admin.role.in_(['full', 'limited', 'read_only'])).order_by(Admin.id).all()
    if legacy:
        have_owner = Admin.query.filter_by(role=permissions.OWNER).count() > 0
        candidates = [a for a in legacy if a.role == 'full'] or legacy[:1]
        if not have_owner and candidates:
            candidates[0].role = permissions.OWNER
            print(f"[OK] '{candidates[0].username}' is now the Owner account")
        for a in legacy:
            if a.role == permissions.OWNER:
                continue
            if a.role == 'full':
                a.role = permissions.ADMIN
            elif a.role == 'limited':
                a.role = permissions.CUSTOM
                a.custom_permissions = json.dumps(['create_user', 'edit_user', 'create_group', 'edit_group'])
            else:
                a.role = permissions.CUSTOM
                a.custom_permissions = json.dumps([])
        db.session.commit()
        print(f"[OK] Moved {len(legacy)} account(s) to the new roles")
    with db.engine.begin() as conn:
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_admins_single_owner "
                          "ON admins(role) WHERE role = 'owner'"))


class PasswordResetRequest(db.Model):
    """
    One "I forgot my password" request on the self-service reset page
    (reset_portal.py). It holds only fingerprints: the 6-digit code and the
    one-time token are stored as keyed hashes, never as the codes themselves,
    and a new password is never stored here at all.
    """
    __tablename__ = 'password_reset_requests'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False, index=True)       # as typed, lowercased
    ip = db.Column(db.String(64), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Set only when the person may reset (see reset_portal.is_eligible)
    eligible = db.Column(db.Boolean, default=False, nullable=False)
    code_hash = db.Column(db.String(64), nullable=True)
    code_expires_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, default=0, nullable=False)          # wrong codes so far

    # Set once the right code has been entered
    verified_at = db.Column(db.DateTime, nullable=True)
    token_hash = db.Column(db.String(64), nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    password_attempts = db.Column(db.Integer, default=0, nullable=False)  # refused new passwords so far

    used = db.Column(db.Boolean, default=False, nullable=False)          # finished or burned: cannot be used again


def init_db(app):
    """Initialize database and create default admin if needed"""
    from config import ADMIN_CONFIG
    
    with app.app_context():
        db.create_all()
        _add_missing_admin_columns()
        _migrate_roles()
        
        # Create default admin if none exist
        if Admin.query.count() == 0:
            configured_username = ADMIN_CONFIG.get('username')
            configured_password = ADMIN_CONFIG.get('password')
            
            if not configured_username or not configured_password:
                raise RuntimeError(
                    "No dashboard admin account is configured. Run "
                    "'python setup_secrets.py' first and set an admin "
                    "username/password there before starting the app."
                )
            
            admin = Admin(
                username=configured_username,
                email='admin@local',
                role=permissions.OWNER,
                is_active=True
            )
            admin.set_password(configured_password)
            db.session.add(admin)
            
            status = SyncStatus(id=1, status='unknown')
            db.session.add(status)
            
            db.session.commit()
            print(f"[OK] Database initialized with admin account '{configured_username}'")
        else:
            print("[OK] Database initialized")
