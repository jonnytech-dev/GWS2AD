"""
app.py
======
Main Flask application with all routes and API endpoints.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, make_response, abort
from config import Config, APP_ROOT
from database import db, init_db, Admin, Role, AuditLog, SyncStatus, IgnoredSyncItem, AppSettings
from auth import (login_required, permission_required, login_user, set_session, logout_user,
                  get_current_user, get_client_ip, complete_login, start_pending_login,
                  get_pending_admin, clear_pending_login, csrf_token, csrf_valid)
import twofa
import loginlock
import permissions
import passwords
import mode
import connection_test
from sqlalchemy.exc import IntegrityError
from functools import wraps
from gws_connector import get_gws_connector
from ad_connector import get_ad_connector
from sync_engine import get_sync_engine
from directory_cache import DirectoryCache
from datetime import datetime
import json
import os
import re

# Initialize Flask app with explicit paths (works from any directory)
app = Flask(
    __name__,
    template_folder=str(APP_ROOT / 'templates'),
    static_folder=str(APP_ROOT / 'static')
)
app.config.from_object(Config)

# Product name shown in the page titles, header, and footer. Change it
# here and every page updates.
APP_NAME = 'GWS2AD'

@app.context_processor
def inject_app_name():
    return {'app_name': APP_NAME}

@app.context_processor
def inject_mode():
    """Lets every page show the Demo banner"""
    return {'demo_mode': mode.is_demo()}

@app.context_processor
def inject_csrf_token():
    """Lets forms write {{ csrf_token() }} (see auth.py)"""
    return {'csrf_token': csrf_token}

@app.context_processor
def inject_capabilities():
    """What the signed-in person may do, for the nav tabs and page buttons"""
    user = get_current_user() if 'user_id' in session else None
    return {'caps': permissions.capabilities(user), 'perm': permissions}

@app.context_processor
def inject_asset_version():
    """
    Lets templates write style.css?v=<number>. The number is the file's
    last-changed time, so when style.css changes the browser sees a new
    address and downloads the new file instead of showing its old copy.
    """
    def asset_version(filename):
        try:
            return int(os.path.getmtime(os.path.join(app.static_folder, filename)))
        except OSError:
            return 0
    return {'asset_version': asset_version}

# Initialize database
db.init_app(app)
with app.app_context():
    init_db(app)

# ============================================================
#   DIRECTORY CACHE
# ============================================================
# See directory_cache.py for how this works. In short: users, groups,
# and group membership are fetched from Google once and reused by the
# Users table, the Groups table, and every Edit modal. After any change
# made through this app, the matching directory_cache.* call below
# updates the cache in place (rather than re-reading Google's lists,
# which can lag for a few seconds after a change).
directory_cache = DirectoryCache(get_gws_connector)

def get_directory_cache():
    """Current users / groups / group_members_map (rebuilt only if empty or expired)."""
    return directory_cache.snapshot()

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# =====================================================================
# AUTHENTICATION ROUTES
# =====================================================================

@app.route('/', methods=['GET'])
def index():
    """Redirect to dashboard if logged in, else to login"""
    if get_current_user():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# =====================================================================
# LOGIN: password first, then two-step verification
# =====================================================================

# Wrong passwords for names that are not accounts (see loginlock.py)
unknown_names = loginlock.UnknownNames()

def _log(username, action, status, details=None):
    """One line in the audit log for a sign-in event"""
    AuditLog.log_action(
        admin_username=username,
        action=action,
        target='system',
        status=status,
        details=details,
        source=get_client_ip()
    )

def _no_store(response):
    """Pages that show secrets or recovery codes must never be kept in the browser's cache"""
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

def _render_no_store(template, **context):
    return _no_store(make_response(render_template(template, **context)))

def _minutes(seconds):
    """Seconds rounded UP to whole minutes, for messages like 'try again in 5 minutes'"""
    return max(1, -(-int(seconds) // 60))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Step 1 of signing in: username and password"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Real account or not, a name is locked after 5 wrong passwords, so the
        # page behaves the same either way and never reveals which names exist.
        account = Admin.query.filter_by(username=username).first()
        tracker = (lambda: loginlock.lock_seconds_left(account)) if account else (lambda: unknown_names.lock_seconds_left(username))
        locked_msg = lambda secs: f'Too many failed attempts. Try again in {_minutes(secs)} minute(s).'

        if tracker():
            _log(username, 'login', 'failed', {'reason': 'locked'})
            return render_template('login.html', error=locked_msg(tracker()))

        admin = login_user(username, password)

        if not admin:
            if account:
                loginlock.register_failure(account)
                db.session.commit()
            else:
                unknown_names.register_failure(username)
            _log(username, 'login', 'failed', {'reason': 'Invalid credentials'})
            error = locked_msg(tracker()) if tracker() else 'Invalid username or password'
            return render_template('login.html', error=error)

        loginlock.register_success(admin)
        db.session.commit()

        # The password was right. Now the second step.
        if admin.two_factor_enabled:
            start_pending_login(admin, 'verify')
            _log(username, 'login_password', 'success', {'next': 'two-step code'})
            return redirect(url_for('login_verify'))

        # Not set up yet: they cannot get in until they finish it
        start_pending_login(admin, 'enroll')
        _log(username, 'login_password', 'success', {'next': 'two-step setup'})
        return redirect(url_for('login_setup'))

    error = 'Your sign-in took too long. Please sign in again.' if request.args.get('expired') else None
    return render_template('login.html', error=error)

@app.route('/login/verify', methods=['GET', 'POST'])
def login_verify():
    """Step 2 of signing in: the 6-digit code (or a recovery code)"""
    admin = get_pending_admin('verify')
    if not admin or not admin.two_factor_enabled:
        return redirect(url_for('login', expired=1))

    error = None
    show_recovery = False

    if request.method == 'POST':
        if not csrf_valid():
            return redirect(url_for('login', expired=1))

        recovery = request.form.get('recovery_code', '').strip()
        show_recovery = bool(recovery)
        locked_for = twofa.lock_seconds_left(admin)

        if locked_for:
            error = f'Too many incorrect codes. Try again in {_minutes(locked_for)} minute(s).'
            _log(admin.username, 'login_2fa', 'failed', {'reason': 'locked'})
        else:
            if recovery:
                ok = twofa.check_recovery_code(admin, recovery)
                method = 'recovery code'
            else:
                ok = twofa.check_code(admin, request.form.get('code', ''))
                method = 'authenticator code'
            db.session.commit()

            if ok:
                complete_login(admin)
                _log(admin.username, 'login', 'success', {'two_step': method})
                if recovery:
                    _log(admin.username, '2fa_recovery_used', 'success',
                         {'codes_left': twofa.recovery_codes_left(admin.recovery_codes)})
                    return redirect(url_for('settings_profile', notice='recovery_used'))
                return redirect(url_for('dashboard'))

            _log(admin.username, 'login_2fa', 'failed', {'method': method})
            if twofa.lock_seconds_left(admin):
                error = f'Too many incorrect codes. This account is locked for {twofa.LOCK_MINUTES} minutes.'
            else:
                error = 'That code is not correct. Please try again.'

    return _render_no_store('twofa_verify.html', error=error, show_recovery=show_recovery)

@app.route('/login/setup', methods=['GET', 'POST'])
def login_setup():
    """Required first-time setup of the authenticator app, as part of signing in"""
    admin = get_pending_admin('enroll')
    if not admin:
        return redirect(url_for('login', expired=1))

    error = None
    if request.method == 'POST':
        if not csrf_valid():
            return redirect(url_for('login', expired=1))

        codes = twofa.finish_pairing(admin, request.form.get('code', ''))
        if codes is not None:
            db.session.commit()
            complete_login(admin)
            _log(admin.username, '2fa_enrolled', 'success')
            _log(admin.username, 'login', 'success', {'two_step': 'set up just now'})
            return _render_recovery(codes, url_for('dashboard'), 'Continue to the dashboard')
        error = 'That code is not correct, or this setup expired. Check the current code in your app and try again.'

    secret = twofa.current_pairing_secret(admin)
    if not secret:
        secret = twofa.begin_pairing(admin)
        db.session.commit()
    return _render_setup(admin, secret, url_for('login_setup'),
                         url_for('login_cancel'), 'Back to sign in', error)

@app.route('/login/cancel', methods=['GET'])
def login_cancel():
    """Give up on the second step and go back to the password page"""
    clear_pending_login()
    return redirect(url_for('login'))

def _render_setup(admin, secret, form_action, cancel_url, cancel_label, error=None):
    uri = twofa.provisioning_uri(secret, admin.username, APP_NAME)
    return _render_no_store(
        'twofa_setup.html',
        qr_svg=twofa.qr_svg(uri),
        manual_key=twofa.format_key(secret),
        form_action=form_action,
        cancel_url=cancel_url,
        cancel_label=cancel_label,
        error=error
    )

def _render_recovery(codes, next_url, next_label):
    return _render_no_store('twofa_recovery.html', codes=codes, next_url=next_url, next_label=next_label)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    """Logout user"""
    user = get_current_user()
    AuditLog.log_action(
        admin_username=user.username,
        action='logout',
        target='system',
        status='success',
        source=get_client_ip()
    )
    logout_user()
    return redirect(url_for('login'))

# =====================================================================
# DASHBOARD ROUTES
# =====================================================================

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Main dashboard"""
    user = get_current_user()
    sync_status = SyncStatus.get_or_create()
    return render_template('dashboard.html', user=user, sync_status=sync_status, can=permissions.flags(user))

@app.route('/how-it-works', methods=['GET'])
@login_required
def how_it_works():
    """Plain-language guide to how the app works (logged-in users only)"""
    user = get_current_user()
    return render_template('how_it_works.html', user=user)

# =====================================================================
# SETTINGS: profile, accounts, and roles
# =====================================================================

NOTICES = {
    'paired': ('success', 'Your new authenticator app is set up.'),
    'recovery_used': ('warning', 'You signed in with a recovery code. Each code works only once. '
                                 'Consider getting a fresh set below.'),
    'password_changed': ('success', 'Your password was changed.'),
    'created': ('success', 'Account created. They will set up two-step verification the first time they sign in.'),
    'updated': ('success', 'Changes saved.'),
    'password_reset': ('success', 'Password changed.'),
    'twofa_reset': ('success', 'Two-step verification was reset. They will set it up again at their next sign-in.'),
    'deactivated': ('success', 'Account deactivated. They can no longer sign in.'),
    'reactivated': ('success', 'Account reactivated.'),
    'deleted': ('success', 'Account deleted.'),
    'role_created': ('success', 'Role created.'),
    'role_updated': ('success', 'Role saved. Everyone in it now has the new permissions.'),
    'role_deleted': ('success', 'Role deleted.'),
    'details_saved': ('success', 'Your details were saved.'),
    'unlocked': ('success', 'Account unlocked.'),
    'ignore_note_saved': ('success', 'Note saved.'),
    'ignore_removed': ('success', 'Removed from the ignore list. The next sync will treat it like anything else.'),
    'now_live': ('success', 'Live mode is on. The app now reads and changes your real Google Workspace and Active Directory.'),
    'now_demo': ('success', 'Demo mode is on. The app uses sample data again and cannot change anything real.'),
    'demo_reset': ('success', 'Sample data was reset.'),
}

USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9._-]{3,40}$')
ROLE_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{1,58}$')
RESERVED_ROLE_NAMES = {'owner', 'admin', 'custom'}


def settings_access(rule):
    """Page guard: must be signed in AND pass rule(user), otherwise a 403 page"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            if not rule(user):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def _stepup_error(user):
    """
    Sensitive actions ask for the person's own current 6-digit code, so a
    stolen sign-in cannot quietly make changes. Returns an error message, or None.
    """
    locked_for = twofa.lock_seconds_left(user)
    if locked_for:
        return f'Too many incorrect codes. Try again in {_minutes(locked_for)} minute(s).'
    ok = twofa.check_code(user, request.form.get('code', ''))
    db.session.commit()
    if not ok:
        _log(user.username, '2fa_stepup', 'failed')
        return 'Your 6-digit code is not correct.'
    return None


def _looks_like_email(value):
    return len(value) <= 120 and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value) is not None


def _username_problem(new_name, user):
    """Why this person cannot take this username, or None if they can"""
    if not USERNAME_PATTERN.match(new_name):
        return 'Username must be 3 to 40 characters: letters, numbers, dots, dashes, underscores.'
    if Admin.query.filter(db.func.lower(Admin.username) == new_name.lower(), Admin.id != user.id).first():
        return 'That username is already taken.'
    try:
        former = {n.lower() for n in json.loads(user.former_usernames or '[]')}
    except ValueError:
        former = set()
    if new_name.lower() not in former and new_name.lower() != user.username.lower():
        # A name that appears in the activity history belongs to whoever used it. Taking it
        # would make their old entries look like yours. (Failed sign-in attempts do not count.)
        if AuditLog.query.filter(db.func.lower(AuditLog.admin_username) == new_name.lower(),
                                 AuditLog.status != 'failed').first():
            return 'That username appears in the activity history, so it cannot be reused. Pick another.'
    return None


def _parse_role_choice(value):
    """'admin', 'custom', or 'role:7'  ->  (kind, role_id), or (None, None) if it is not valid"""
    if value == 'admin':
        return permissions.ADMIN, None
    if value == 'custom':
        return permissions.CUSTOM, None
    if value and value.startswith('role:') and value[5:].isdigit():
        role = db.session.get(Role, int(value[5:]))
        if role:
            return permissions.NAMED, role.id
    return None, None


def _choice_of(account):
    return f'role:{account.role_id}' if account.role == permissions.NAMED else account.role


def _role_choices(user):
    """The roles this person may give to an account: [(value, label), ...]"""
    choices = []
    if permissions.can_create_account(user, permissions.ADMIN):
        choices.append(('admin', 'Admin'))
    if permissions.can_create_account(user, permissions.CUSTOM):
        choices.append(('custom', 'Custom (pick permissions)'))
        choices += [(f'role:{r.id}', r.name) for r in Role.query.order_by(Role.name).all()]
    return choices


# ---------------------------------------------------------------- profile
@app.route('/settings', methods=['GET'])
@login_required
def settings():
    return redirect(url_for('settings_profile'))

@app.route('/account', methods=['GET'])
@login_required
def account():
    """The old address of the Account page. It is now Settings, Profile."""
    return redirect(url_for('settings_profile'))

def _profile_page(user, **extra):
    return render_template(
        'settings_profile.html',
        user=user,
        tab='profile',
        my_permissions=permissions.clean(permissions.permission_set(user)),
        recovery_left=twofa.recovery_codes_left(user.recovery_codes),
        notice=NOTICES.get(request.args.get('notice')),
        **extra
    )

@app.route('/settings/profile', methods=['GET'])
@login_required
def settings_profile():
    return _profile_page(get_current_user())

@app.route('/settings/profile/password', methods=['POST'])
@login_required
def settings_profile_password():
    """Change your own password (asks for the current one)"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    locked_for = loginlock.lock_seconds_left(user)
    if locked_for:
        return _profile_page(user, password_error=f'Too many wrong attempts. Try again in {_minutes(locked_for)} minute(s).')
    if not user.check_password(request.form.get('current_password', '')):
        loginlock.register_failure(user)
        db.session.commit()
        _log(user.username, 'password_change', 'failed', {'reason': 'wrong current password'})
        return _profile_page(user, password_error='Your current password is not correct.')
    loginlock.register_success(user)
    new, confirm = request.form.get('new_password', ''), request.form.get('confirm_password', '')
    error = passwords.check_new_password(new, confirm, user.username)
    if not error and user.check_password(new):
        error = 'The new password must be different from the current one.'
    if error:
        return _profile_page(user, password_error=error)
    user.set_password(new)
    db.session.commit()
    _log(user.username, 'password_change', 'success')
    return redirect(url_for('settings_profile', notice='password_changed'))

@app.route('/settings/profile/details', methods=['POST'])
@login_required
def settings_profile_details():
    """Change your own username and email (asks for your current password)"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    new_name = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()
    name_changed = new_name != user.username
    email_changed = (new_email or None) != (user.email or None)

    def fail(message):
        return _profile_page(user, details_error=message, details_form=request.form)

    if not name_changed and not email_changed:
        return fail('Nothing to change.')
    # Mistakes in the form are reported before the password is checked, so they never count as wrong passwords
    if name_changed:
        problem = _username_problem(new_name, user)
        if problem:
            return fail(problem)
    if email_changed and new_email and not _looks_like_email(new_email):
        return fail('That email address does not look right.')

    locked_for = loginlock.lock_seconds_left(user)
    if locked_for:
        return fail(f'Too many wrong attempts. Try again in {_minutes(locked_for)} minute(s).')
    if not user.check_password(request.form.get('current_password', '')):
        loginlock.register_failure(user)
        db.session.commit()
        _log(user.username, 'profile_change', 'failed', {'reason': 'wrong current password'})
        return fail('Your current password is not correct.')
    loginlock.register_success(user)

    old_name, old_email = user.username, user.email
    if name_changed:
        _log(old_name, 'username_changed', 'success', {'from': old_name, 'to': new_name})    # logged under the old name, then the name changes
        try:
            former = json.loads(user.former_usernames or '[]')
        except ValueError:
            former = []
        if old_name not in former:
            former.append(old_name)
        user.former_usernames = json.dumps(former)
        user.username = new_name
    if email_changed:
        user.email = new_email or None
        _log(user.username, 'email_changed', 'success', {'from': old_email, 'to': user.email})
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return fail('That username is already taken.')
    return redirect(url_for('settings_profile', notice='details_saved'))

@app.route('/settings/profile/2fa/pair', methods=['POST'])
@login_required
def settings_profile_2fa_pair():
    """Start setting up a new authenticator app"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    error = _stepup_error(user)
    if error:
        return _profile_page(user, twofa_error=error)
    secret = twofa.begin_pairing(user)
    db.session.commit()
    return _render_setup(user, secret, url_for('settings_profile_2fa_pair_confirm'),
                         url_for('settings_profile'), 'Cancel')

@app.route('/settings/profile/2fa/pair/confirm', methods=['POST'])
@login_required
def settings_profile_2fa_pair_confirm():
    """Finish setting up the authenticator app with its first code"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    codes = twofa.finish_pairing(user, request.form.get('code', ''))
    if codes is None:
        secret = twofa.current_pairing_secret(user)
        if not secret:
            return redirect(url_for('settings_profile'))
        return _render_setup(user, secret, url_for('settings_profile_2fa_pair_confirm'),
                             url_for('settings_profile'), 'Cancel',
                             'That code is not correct. Check the current code in your app and try again.')
    db.session.commit()
    _log(user.username, '2fa_device_changed', 'success')
    if codes:
        return _render_recovery(codes, url_for('settings_profile'), 'Back to settings')
    return redirect(url_for('settings_profile', notice='paired'))

@app.route('/settings/profile/2fa/recovery-codes', methods=['POST'])
@login_required
def settings_profile_2fa_recovery_codes():
    """Replace the recovery codes with a fresh set (the old ones stop working)"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    error = _stepup_error(user)
    if error:
        return _profile_page(user, twofa_error=error)
    codes = twofa.regenerate_recovery_codes(user)
    db.session.commit()
    _log(user.username, '2fa_recovery_regenerated', 'success')
    return _render_recovery(codes, url_for('settings_profile'), 'Back to settings')


# ---------------------------------------------------------------- accounts
def _target_or_404(user, account_id):
    target = db.session.get(Admin, account_id)
    if not target or not permissions.can_view_account(user, target):
        abort(404)
    return target

@app.route('/settings/accounts', methods=['GET'])
@settings_access(permissions.can_see_accounts_tab)
def settings_accounts():
    user = get_current_user()
    everyone = Admin.query.order_by(Admin.created_at, Admin.id).all()
    return render_template(
        'settings_accounts.html', user=user, tab='accounts',
        accounts=permissions.visible_accounts(user, everyone),
        notice=NOTICES.get(request.args.get('notice')),
    )

def _account_form_page(user, form=None, error=None):
    return render_template(
        'settings_account_form.html', user=user, tab='accounts', form=form or {}, error=error,
        role_choices=_role_choices(user),
        selected_perms=set((form or {}).getlist('perm')) if form else set(),
    )

@app.route('/settings/accounts/new', methods=['GET', 'POST'])
@settings_access(lambda u: permissions.can_create_account(u, permissions.ADMIN)
                 or permissions.can_create_account(u, permissions.CUSTOM))
def settings_account_new():
    user = get_current_user()
    if request.method == 'GET':
        return _account_form_page(user)
    if not csrf_valid():
        abort(400)

    form = request.form
    kind, role_id = _parse_role_choice(form.get('role_choice', ''))
    if kind is None:
        return _account_form_page(user, form, 'Choose a role.')
    if not permissions.can_create_account(user, kind):
        abort(403)

    username = form.get('username', '').strip()
    email = form.get('email', '').strip()
    display_name = form.get('display_name', '').strip()[:120] or None
    if not USERNAME_PATTERN.match(username):
        return _account_form_page(user, form, 'Username must be 3 to 40 characters: letters, numbers, dots, dashes, underscores.')
    if Admin.query.filter(db.func.lower(Admin.username) == username.lower()).first():
        return _account_form_page(user, form, 'That username is already taken.')
    if email and not _looks_like_email(email):
        return _account_form_page(user, form, 'That email address does not look right.')

    perms = []
    if kind == permissions.CUSTOM:
        perms = permissions.clean(form.getlist('perm'))
    elif kind == permissions.NAMED:
        perms = db.session.get(Role, role_id).permission_list()
    if not permissions.can_grant(user, perms):
        abort(403)

    can_admins = can_staff = False
    if kind == permissions.ADMIN and permissions.can_set_admin_flags(user):
        can_admins = form.get('can_manage_admins') == '1'
        can_staff = form.get('can_manage_staff') == '1'

    error = passwords.check_new_password(form.get('password', ''), form.get('confirm_password', ''), username)
    if error:
        return _account_form_page(user, form, error)

    error = _stepup_error(user)
    if error:
        return _account_form_page(user, form, error)

    account_new = Admin(
        username=username, email=email or None, display_name=display_name, role=kind, role_id=role_id,
        custom_permissions=json.dumps(perms) if kind == permissions.CUSTOM else None,
        can_manage_admins=can_admins, can_manage_staff=can_staff,
        is_active=True, created_by=user.username,
    )
    account_new.set_password(form.get('password', ''))
    db.session.add(account_new)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _account_form_page(user, form, 'That username is already taken.')
    _log(user.username, 'account_created', 'success', {
        'username': username, 'role': account_new.role_label, 'permissions': perms,
        'can_manage_admins': can_admins, 'can_manage_staff': can_staff})
    return redirect(url_for('settings_account_detail', account_id=account_new.id, notice='created'))

def _detail_page(user, target, **extra):
    return render_template(
        'settings_account_detail.html', user=user, target=target, tab='accounts',
        can_edit=permissions.can_edit_account(user, target),
        role_choices=_role_choices(user),
        current_choice=_choice_of(target),
        target_perms=set(permissions.clean(target.assigned_permissions())) if target.role == permissions.CUSTOM else set(),
        target_permission_list=permissions.clean(permissions.permission_set(target)),
        recovery_left=twofa.recovery_codes_left(target.recovery_codes),
        notice=NOTICES.get(request.args.get('notice')),
        **extra
    )

@app.route('/settings/accounts/<int:account_id>', methods=['GET'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_detail(account_id):
    user = get_current_user()
    return _detail_page(user, _target_or_404(user, account_id))

@app.route('/settings/accounts/<int:account_id>/edit', methods=['POST'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_edit(account_id):
    """Change name, email, role, permissions, and the admin switches"""
    user = get_current_user()
    target = _target_or_404(user, account_id)
    if not csrf_valid():
        abort(400)
    if not permissions.can_edit_account(user, target):
        abort(403)

    form = request.form
    email = form.get('email', '').strip()
    if email and not _looks_like_email(email):
        return _detail_page(user, target, edit_error='That email address does not look right.')
    kind, role_id = _parse_role_choice(form.get('role_choice', _choice_of(target)))
    if kind is None:
        return _detail_page(user, target, edit_error='Choose a role.')

    was_named = target.role == permissions.NAMED
    kind_changed = (kind, role_id) != (target.role, target.role_id if was_named else None)
    new_perms = permissions.clean(form.getlist('perm')) if kind == permissions.CUSTOM else []
    old_perms = permissions.clean(target.assigned_permissions()) if target.role == permissions.CUSTOM else []
    perms_changed = kind == permissions.CUSTOM and new_perms != old_perms

    if kind == permissions.ADMIN and permissions.can_set_admin_flags(user):
        can_admins = form.get('can_manage_admins') == '1'
        can_staff = form.get('can_manage_staff') == '1'
    elif kind == permissions.ADMIN and not kind_changed:
        can_admins, can_staff = bool(target.can_manage_admins), bool(target.can_manage_staff)
    else:
        can_admins = can_staff = False
    flags_changed = (can_admins, can_staff) != (bool(target.can_manage_admins), bool(target.can_manage_staff))

    if kind_changed and not permissions.can_change_kind(user, target, kind):
        abort(403)
    if perms_changed and not permissions.can_grant(user, new_perms):
        abort(403)
    if kind == permissions.NAMED and kind_changed and not permissions.can_grant(
            user, db.session.get(Role, role_id).permission_list()):
        abort(403)

    sensitive = kind_changed or perms_changed or flags_changed
    if sensitive:
        error = _stepup_error(user)
        if error:
            return _detail_page(user, target, edit_error=error)

    target.display_name = form.get('display_name', '').strip()[:120] or None
    target.email = email or None
    if sensitive:
        target.role = kind
        target.role_id = role_id if kind == permissions.NAMED else None
        target.custom_permissions = json.dumps(new_perms) if kind == permissions.CUSTOM else None
        target.can_manage_admins = can_admins
        target.can_manage_staff = can_staff
    db.session.commit()
    _log(user.username, 'account_edited', 'success', {
        'account': target.username, 'role': target.role_label,
        'permissions': new_perms if kind == permissions.CUSTOM else None,
        'can_manage_admins': can_admins, 'can_manage_staff': can_staff,
        'role_or_permissions_changed': sensitive})
    return redirect(url_for('settings_account_detail', account_id=target.id, notice='updated'))

def _account_action(account_id):
    """The checks every account action shares. Returns (user, target)."""
    user = get_current_user()
    target = _target_or_404(user, account_id)
    if not csrf_valid():
        abort(400)
    if not permissions.can_edit_account(user, target):
        abort(403)
    return user, target

@app.route('/settings/accounts/<int:account_id>/password', methods=['POST'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_password(account_id):
    """Set a new password for someone else (they can change it themselves afterwards)"""
    user, target = _account_action(account_id)
    error = passwords.check_new_password(request.form.get('password', ''), request.form.get('confirm_password', ''), target.username)
    error = error or _stepup_error(user)
    if error:
        return _detail_page(user, target, password_error=error)
    target.set_password(request.form.get('password', ''))
    db.session.commit()
    _log(user.username, 'account_password_reset', 'success', {'account': target.username})
    return redirect(url_for('settings_account_detail', account_id=target.id, notice='password_reset'))

@app.route('/settings/accounts/<int:account_id>/unlock', methods=['POST'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_unlock(account_id):
    """End a lock caused by wrong passwords or codes, without waiting 15 minutes"""
    user, target = _account_action(account_id)
    error = _stepup_error(user)
    if error:
        return _detail_page(user, target, danger_error=error)
    loginlock.unlock(target)
    db.session.commit()
    _log(user.username, 'account_unlocked', 'success', {'account': target.username})
    return redirect(url_for('settings_account_detail', account_id=target.id, notice='unlocked'))

@app.route('/settings/accounts/<int:account_id>/reset-2fa', methods=['POST'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_reset_2fa(account_id):
    """Clear their two-step verification. They must set it up again at their next sign-in."""
    user, target = _account_action(account_id)
    error = _stepup_error(user)
    if error:
        return _detail_page(user, target, danger_error=error)
    twofa.reset(target)
    db.session.commit()
    _log(user.username, 'account_2fa_reset', 'success', {'account': target.username})
    return redirect(url_for('settings_account_detail', account_id=target.id, notice='twofa_reset'))

@app.route('/settings/accounts/<int:account_id>/active', methods=['POST'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_active(account_id):
    """Deactivate (they cannot sign in) or reactivate"""
    user, target = _account_action(account_id)
    activate = request.form.get('active') == '1'
    error = _stepup_error(user)
    if error:
        return _detail_page(user, target, danger_error=error)
    target.is_active = activate
    db.session.commit()
    _log(user.username, 'account_reactivated' if activate else 'account_deactivated', 'success', {'account': target.username})
    return redirect(url_for('settings_account_detail', account_id=target.id,
                            notice='reactivated' if activate else 'deactivated'))

@app.route('/settings/accounts/<int:account_id>/delete', methods=['POST'])
@settings_access(permissions.can_see_accounts_tab)
def settings_account_delete(account_id):
    """Delete the account for good"""
    user, target = _account_action(account_id)
    error = _stepup_error(user)
    if error:
        return _detail_page(user, target, danger_error=error)
    name = target.username
    db.session.delete(target)
    db.session.commit()
    _log(user.username, 'account_deleted', 'success', {'account': name})
    return redirect(url_for('settings_accounts', notice='deleted'))


# ---------------------------------------------------------------- roles
def _role_form_page(user, role=None, form=None, error=None):
    selected = set(form.getlist('perm')) if form else set(role.permission_list() if role else [])
    return render_template(
        'settings_role_form.html', user=user, tab='roles', role=role, form=form or {}, error=error,
        selected_perms=selected,
        members=Admin.query.filter_by(role=permissions.NAMED, role_id=role.id).order_by(Admin.username).all() if role else [],
    )

def _check_role_form(user, role=None):
    """Validates the role form. Returns (name, perms, error)."""
    name = request.form.get('name', '').strip()
    perms = permissions.clean(request.form.getlist('perm'))
    if not ROLE_NAME_PATTERN.match(name):
        return name, perms, 'Give the role a name of 2 to 60 characters (letters, numbers, spaces, dots, dashes).'
    if name.lower() in RESERVED_ROLE_NAMES:
        return name, perms, 'That name is reserved. Pick another.'
    clash = Role.query.filter(db.func.lower(Role.name) == name.lower()).first()
    if clash and (not role or clash.id != role.id):
        return name, perms, 'A role with that name already exists.'
    if not permissions.can_grant(user, perms):
        abort(403)
    return name, perms, None

@app.route('/settings/roles', methods=['GET'])
@settings_access(permissions.can_manage_roles)
def settings_roles():
    user = get_current_user()
    return render_template(
        'settings_roles.html', user=user, tab='roles',
        roles=Role.query.order_by(Role.name).all(),
        notice=NOTICES.get(request.args.get('notice')),
    )

@app.route('/settings/roles/new', methods=['GET', 'POST'])
@settings_access(permissions.can_manage_roles)
def settings_role_new():
    user = get_current_user()
    if request.method == 'GET':
        return _role_form_page(user)
    if not csrf_valid():
        abort(400)
    name, perms, error = _check_role_form(user)
    error = error or _stepup_error(user)
    if error:
        return _role_form_page(user, form=request.form, error=error)
    role = Role(name=name, permissions=json.dumps(perms), created_by=user.username)
    db.session.add(role)
    db.session.commit()
    _log(user.username, 'role_created', 'success', {'role': name, 'permissions': perms})
    return redirect(url_for('settings_roles', notice='role_created'))

@app.route('/settings/roles/<int:role_id>', methods=['GET', 'POST'])
@settings_access(permissions.can_manage_roles)
def settings_role_edit(role_id):
    user = get_current_user()
    role = db.session.get(Role, role_id) or abort(404)
    if request.method == 'GET':
        return _role_form_page(user, role=role)
    if not csrf_valid():
        abort(400)
    name, perms, error = _check_role_form(user, role)
    error = error or _stepup_error(user)
    if error:
        return _role_form_page(user, role=role, form=request.form, error=error)
    role.name, role.permissions = name, json.dumps(perms)
    db.session.commit()
    _log(user.username, 'role_edited', 'success', {'role': name, 'permissions': perms, 'accounts_affected': role.member_count()})
    return redirect(url_for('settings_roles', notice='role_updated'))

@app.route('/settings/roles/<int:role_id>/delete', methods=['POST'])
@settings_access(permissions.can_manage_roles)
def settings_role_delete(role_id):
    user = get_current_user()
    role = db.session.get(Role, role_id) or abort(404)
    if not csrf_valid():
        abort(400)
    in_use = role.member_count()
    if in_use:
        return _role_form_page(user, role=role, error=f'{in_use} account(s) still use this role. Move them to another role first.')
    error = _stepup_error(user)
    if error:
        return _role_form_page(user, role=role, error=error)
    name = role.name
    db.session.delete(role)
    db.session.commit()
    _log(user.username, 'role_deleted', 'success', {'role': name})
    return redirect(url_for('settings_roles', notice='role_deleted'))

# =====================================================================
# SETTINGS: CONNECTION (Demo / Live)
# =====================================================================

def _connection_page(user, error=None, results=None):
    import config
    return render_template(
        'settings_connection.html', user=user, tab='connection',
        is_demo=mode.is_demo(), missing=config.missing_live_settings(),
        results=results, error=error,
        notice=NOTICES.get(request.args.get('notice')),
    )

# ---------------------------------------------------------------- ignore list
@app.route('/settings/ignored', methods=['GET'])
@settings_access(permissions.can_see_ignored)
def settings_ignored():
    user = get_current_user()
    return render_template(
        'settings_ignored.html', user=user, tab='ignored',
        items=IgnoredSyncItem.get_all_ignored(),
        notice=NOTICES.get(request.args.get('notice')),
    )

@app.route('/settings/ignored/remove', methods=['POST'])
@settings_access(permissions.can_edit_ignored)
def settings_ignored_remove():
    """Take one item off the ignore list (the sync will treat it like any other item again)"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    item_type = request.form.get('type', '')
    identifier = request.form.get('identifier', '')
    if item_type not in ('user', 'group', 'ou') or not identifier:
        abort(400)
    IgnoredSyncItem.remove_ignored_item(item_type, identifier)
    AuditLog.log_action(
        admin_username=user.username,
        action='remove_ignored_item',
        target=f'{item_type}:{identifier}',
        status='success',
        details={'from': 'ignore list page'},
        source=get_client_ip()
    )
    return redirect(url_for('settings_ignored', notice='ignore_removed'))

@app.route('/settings/ignored/note', methods=['POST'])
@settings_access(permissions.can_edit_ignored)
def settings_ignored_note():
    """Add, change or clear the note saying why something is ignored"""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    item_type = request.form.get('type', '')
    identifier = request.form.get('identifier', '')
    if item_type not in ('user', 'group', 'ou') or not identifier:
        abort(400)
    try:
        saved = IgnoredSyncItem.set_note(item_type, identifier, request.form.get('note', ''))
    except ValueError as e:
        return render_template('settings_ignored.html', user=user, tab='ignored',
                               items=IgnoredSyncItem.get_all_ignored(), notice=('error', str(e))), 400
    if not saved:
        abort(404)
    AuditLog.log_action(
        admin_username=user.username,
        action='edit_ignored_note',
        target=f'{item_type}:{identifier}',
        status='success',
        details={'note': IgnoredSyncItem.get_note(item_type, identifier)},
        source=get_client_ip()
    )
    return redirect(url_for('settings_ignored', notice='ignore_note_saved'))

@app.route('/settings/connection', methods=['GET'])
@settings_access(permissions.can_manage_connection)
def settings_connection():
    return _connection_page(get_current_user())

@app.route('/settings/connection/test', methods=['POST'])
@settings_access(permissions.can_manage_connection)
def settings_connection_test():
    """Read-only check of the saved Live settings. Works in either mode."""
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    import config
    if config.missing_live_settings():
        return _connection_page(user, error='Some Live settings are not saved yet, so there is nothing to test.')
    _log(user.username, 'connection_test', 'success')
    return _connection_page(user, results=connection_test.run_all())

@app.route('/settings/connection/mode', methods=['POST'])
@settings_access(permissions.can_manage_connection)
def settings_connection_mode():
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    target = request.form.get('mode')
    if target not in (mode.DEMO, mode.LIVE):
        abort(400)
    error = _stepup_error(user)
    if error:
        return _connection_page(user, error=error)
    if target == mode.LIVE:
        import config
        if config.missing_live_settings():
            return _connection_page(user, error='Live mode needs the Google, Active Directory and email settings saved first (see below).')
        results = connection_test.run_all()
        if not all(ok for _, ok, _ in results):
            _log(user.username, 'mode_live', 'failed')
            return _connection_page(user, error='Live mode was not turned on because a check failed. Fix it and try again.', results=results)
    mode.set_mode(target, changed_by=user.username)
    directory_cache.invalidate(provisional=False)
    _log(user.username, 'mode_' + target, 'success')
    return redirect(url_for('settings_connection', notice='now_live' if target == mode.LIVE else 'now_demo'))

@app.route('/settings/connection/reset-demo', methods=['POST'])
@settings_access(permissions.can_manage_connection)
def settings_connection_reset_demo():
    user = get_current_user()
    if not csrf_valid():
        abort(400)
    if not mode.is_demo():
        abort(400)
    from mock_connectors import reset_demo_data
    reset_demo_data()
    directory_cache.invalidate(provisional=False)
    _log(user.username, 'demo_reset', 'success')
    return redirect(url_for('settings_connection', notice='demo_reset'))

@app.errorhandler(403)
def forbidden(error):
    """A page you are signed in for but not allowed to use"""
    return render_template('forbidden.html', user=get_current_user()), 403

# =====================================================================
# API: SYNC STATUS
# =====================================================================

@app.route('/api/sync-status', methods=['GET'])
@login_required
def api_sync_status():
    """
    Get current sync status. Runs a live GWS-vs-AD comparison on every
    call (reusing the same diff logic as the sync preview) rather than
    trusting a cached DB flag - that flag only used to update when an
    actual sync ran, so it went stale the moment anything changed on
    either side outside of a sync (e.g. deleting a group directly in AD).
    """
    stored_status = SyncStatus.get_or_create()
    response = stored_status.to_dict()
    
    engine = get_sync_engine()
    preview = engine.get_sync_preview()
    
    if preview.get('error'):
        response['status'] = 'error'
        response['last_error'] = preview['error']
    else:
        # Deletions on the ignore list are intentionally not being acted
        # on, so they shouldn't count as "out of sync" - only actionable
        # differences do. Creates/updates aren't subject to the ignore
        # list (it only ever applies to deletions), so those count as-is.
        actionable_users_to_delete = [u for u in preview['users_to_delete'] if not u.get('ignored')]
        actionable_groups_to_delete = [g for g in preview['groups_to_delete'] if not g.get('ignored')]
        ous_to_delete = preview.get('ous_to_delete', [])
        actionable_ous_to_delete = [o for o in ous_to_delete if o.get('action') == 'delete']
        ignored_count = (len(preview['users_to_delete']) - len(actionable_users_to_delete)) + \
                        (len(preview['groups_to_delete']) - len(actionable_groups_to_delete)) + \
                        len([o for o in ous_to_delete if o.get('ignored')])
        
        # Group membership changes are real differences too: the preview lists
        # them and the sync applies them, so "Synced" must not hide them.
        membership_changes = preview.get('group_membership_changes', [])

        total_diffs = (
            len(preview['users_to_create']) + len(preview['users_to_update']) +
            len(preview.get('ous_to_create', [])) +
            len(actionable_users_to_delete) + len(preview['groups_to_create']) +
            len(preview['groups_to_update']) + len(actionable_groups_to_delete) +
            len(actionable_ous_to_delete) + len(membership_changes)
        )
        if total_diffs == 0:
            response['status'] = 'synced'
            response['last_error'] = (
                f"{ignored_count} item(s) on the ignore list are excluded from deletion"
                if ignored_count > 0 else None
            )
        else:
            response['status'] = 'out_of_sync'
            response['last_error'] = (
                f"{total_diffs} difference(s) found - "
                f"{len(preview['users_to_create']) + len(preview['groups_to_create']) + len(preview.get('ous_to_create', []))} to create, "
                f"{len(preview['users_to_update']) + len(preview['groups_to_update'])} to update, "
                f"{len(actionable_users_to_delete) + len(actionable_groups_to_delete) + len(actionable_ous_to_delete)} to delete"
                + (f", {len(membership_changes)} group membership change(s)" if membership_changes else "")
            )
    
    response['ignored_count'] = 0 if preview.get('error') else ignored_count
    response['last_checked_time'] = datetime.utcnow().isoformat()
    return jsonify(response)

@app.route('/api/settings/email', methods=['GET'])
@login_required
def api_get_email_settings():
    """Get email settings status"""
    settings = AppSettings.get_or_create()
    return jsonify(settings.to_dict())

@app.route('/api/settings/email', methods=['POST'])
@login_required
@permission_required('trigger_sync')
def api_toggle_email_settings():
    """Toggle email sending on/off"""
    user = get_current_user()
    data = request.get_json()
    send_emails = data.get('send_emails', False)
    
    try:
        AppSettings.set_send_emails(send_emails)
        AuditLog.log_action(
            admin_username=user.username,
            action='toggle_email_settings',
            target='system',
            status='success',
            details={'send_emails': send_emails},
            source=get_client_ip()
        )
        return jsonify({'success': True, 'message': f'Email sending {"enabled" if send_emails else "disabled"}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sync-preview', methods=['GET'])
@login_required
@permission_required('preview_sync')
def api_sync_preview():
    """Get preview of what will be synced and deleted"""
    try:
        engine = get_sync_engine()
        preview = engine.get_sync_preview()
        return jsonify(preview)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ignored-items', methods=['GET'])
@login_required
@permission_required('preview_sync')
def api_get_ignored_items():
    """Get list of ignored sync items"""
    ignored = IgnoredSyncItem.get_all_ignored()
    return jsonify({'ignored_items': ignored})

@app.route('/api/ignored-items', methods=['POST'])
@login_required
@permission_required('trigger_sync')
def api_add_ignored_item():
    """Add an item to ignore list"""
    user = get_current_user()
    data = request.get_json()
    
    item_type = data.get('type')  # 'user', 'group' or 'ou'
    item_identifier = data.get('identifier')  # email or name
    reason = data.get('reason')
    
    if not all([item_type, item_identifier]):
        return jsonify({'error': 'Missing type or identifier'}), 400
    if item_type not in ('user', 'group', 'ou'):
        return jsonify({'error': 'Type must be user, group or ou'}), 400
    
    try:
        reason = IgnoredSyncItem.clean_note(reason)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    try:
        IgnoredSyncItem.add_ignored_item(item_type, item_identifier, reason, user.username)
        AuditLog.log_action(
            admin_username=user.username,
            action='add_ignored_item',
            target=f'{item_type}:{item_identifier}',
            status='success',
            details={'reason': reason},
            source=get_client_ip()
        )
        return jsonify({'success': True, 'message': f'Added {item_identifier} to ignore list'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ignored-items/<item_type>/<item_identifier>', methods=['DELETE'])
@login_required
@permission_required('trigger_sync')
def api_remove_ignored_item(item_type, item_identifier):
    """Remove an item from ignore list"""
    user = get_current_user()
    
    try:
        IgnoredSyncItem.remove_ignored_item(item_type, item_identifier)
        AuditLog.log_action(
            admin_username=user.username,
            action='remove_ignored_item',
            target=f'{item_type}:{item_identifier}',
            status='success',
            details={},
            source=get_client_ip()
        )
        return jsonify({'success': True, 'message': f'Removed {item_identifier} from ignore list'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sync', methods=['POST'])
@login_required
@permission_required('trigger_sync')
def api_trigger_sync():
    """Trigger a manual sync"""
    user = get_current_user()
    
    try:
        engine = get_sync_engine()
        success, differences = engine.sync()
        
        # A sync only writes to AD, so the cached Google data hasn't
        # changed - but it's a natural moment to re-check it against
        # Google, which also corrects anything changed outside this app
        # (e.g. directly in the Google Admin console).
        directory_cache.invalidate(provisional=False)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='trigger_sync',
            target='system',
            status='success' if success else 'failed',
            details={'differences': differences, 'logs': engine.sync_log[:10]},
            source=get_client_ip()
        )
        
        status = SyncStatus.get_or_create()
        return jsonify({
            'success': success,
            'status': status.to_dict(),
            'logs': engine.sync_log[-20:],  # Last 20 log lines
            'differences': differences,  # per-item outcomes, including any *_failed entries
            # Temp passwords for users created while email is disabled.
            # Deliberately NOT included in AuditLog.log_action above (or
            # anywhere else) - this is a one-time, in-memory-only handoff
            # to the admin who triggered this specific sync, not
            # something that should ever be persisted or logged.
            'pending_credentials': engine.pending_credentials
        })
    except Exception as e:
        AuditLog.log_action(
            admin_username=user.username,
            action='trigger_sync',
            target='system',
            status='failed',
            details={'error': str(e)},
            source=get_client_ip()
        )
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================================================================
# API: USERS
# =====================================================================

@app.route('/api/users', methods=['GET'])
@login_required
@permission_required('read')
def api_get_users():
    """Get all users from GWS"""
    try:
        users = get_directory_cache()['users']
        
        # Pagination
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        per_page = min(limit, 20) if limit <= 20 else limit  # Allow large limits for "all"
        total = len(users)
        pages = (total + per_page - 1) // per_page if per_page <= 20 else 1
        
        start = (page - 1) * per_page
        end = start + per_page
        paginated_users = users[start:end]
        
        return jsonify({
            'users': paginated_users,
            'total': total,
            'page': page,
            'pages': pages,
            'per_page': per_page,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<email>', methods=['GET'])
@login_required
@permission_required('read')
def api_get_user(email):
    """Get full details of a specific user"""
    try:
        users = get_directory_cache()['users']
        
        user = next((u for u in users if u['email'] == email), None)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get AD status for this user
        ad = get_ad_connector()
        ad_users = ad.get_all_users()
        ad_user = next((u for u in ad_users if u['email'] == email), None)
        
        return jsonify({
            'gws': user,
            'ad': ad_user or {'status': 'not_in_ad'},
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@login_required
@permission_required('create_user')
def api_create_user():
    """Create a new user in GWS"""
    user = get_current_user()
    data = request.get_json()
    
    email = data.get('email', '').strip()
    first_name = data.get('firstName', '').strip()
    last_name = data.get('lastName', '').strip()
    password = data.get('password', '').strip()
    org_unit_path = data.get('orgUnitPath', '/').strip() or '/'
    groups = data.get('groups', [])  # List of group emails
    
    if not all([email, first_name, last_name, password]):
        return jsonify({'error': 'Missing required fields (email, first name, last name, password)'}), 400
    
    try:
        gws = get_gws_connector()
        gws.create_user(email, first_name, last_name, password, org_unit_path)
        
        # Add user to selected groups
        added_groups = []
        for group_email in groups:
            try:
                gws.add_user_to_group(email, group_email)
                added_groups.append(group_email)
            except Exception as group_error:
                print(f"[WARN] Failed to add {email} to {group_email}: {group_error}")
        
        directory_cache.user_created(email, first_name, last_name, org_unit_path, added_groups)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='create_user',
            target=f'user:{email}',
            status='success',
            details={'firstName': first_name, 'lastName': last_name, 'groups': groups},
            source=get_client_ip()
        )
        
        return jsonify({'success': True, 'message': f'User {email} created successfully. They will be prompted to set a password on first login.'})
    except Exception as e:
        error_str = str(e)
        
        # Parse Google Workspace API errors for better messages
        user_friendly_error = error_str
        
        if 'Invalid Password' in error_str:
            user_friendly_error = 'Password does not meet Google Workspace requirements. Use at least 8 chars with uppercase, lowercase, number, and special character.'
        elif 'duplicate' in error_str.lower():
            user_friendly_error = f'User {email} already exists in Google Workspace.'
        elif 'Invalid Email Address' in error_str:
            user_friendly_error = f'Invalid email address: {email}'
        elif 'unauthorized' in error_str.lower():
            user_friendly_error = 'Permission denied. Check GWS service account authorization.'
        elif 'UNAUTHENTICATED' in error_str:
            user_friendly_error = 'Google Workspace authentication failed. Check service account credentials.'
        elif 'DEADLINE_EXCEEDED' in error_str:
            user_friendly_error = 'Google Workspace request timed out. Try again.'
        
        AuditLog.log_action(
            admin_username=user.username,
            action='create_user',
            target=f'user:{email}',
            status='failed',
            details={'error': error_str},
            source=get_client_ip()
        )
        return jsonify({'error': user_friendly_error}), 400

@app.route('/api/users/<email>', methods=['PUT'])
@login_required
@permission_required('edit_user')
def api_update_user(email):
    """Update a user in both GWS and AD (name, password, group membership)"""
    user = get_current_user()
    data = request.get_json()
    
    try:
        gws = get_gws_connector()
        ad = get_ad_connector()
        warnings = []
        
        # Fetch current GWS record now - used as a fallback for name info
        # if we need to create this user in AD to keep the password in sync
        gws_user = gws.service.users().get(userKey=email).execute()
        gws_name = gws_user.get('name', {})
        fallback_first_name = data.get('firstName') or gws_name.get('givenName', '')
        fallback_last_name = data.get('lastName') or gws_name.get('familyName', '')
        fallback_full_name = gws_name.get('fullName', f"{fallback_first_name} {fallback_last_name}".strip())
        fallback_org_unit_path = gws_user.get('orgUnitPath', '/')
        
        updates = {}
        ad_updates = {}
        
        # Handle name updates
        if data.get('firstName'):
            updates['firstName'] = data.get('firstName')
            ad_updates['firstName'] = data.get('firstName')
        if data.get('lastName'):
            updates['lastName'] = data.get('lastName')
            ad_updates['lastName'] = data.get('lastName')
        
        # Handle password update (goes to both GWS and AD)
        if data.get('password'):
            updates['password'] = data.get('password')
            ad_updates['password'] = data.get('password')
        
        # Handle OU change (GWS only - AD gets moved to match
        # automatically on the next sync run via the OU-mirroring logic
        # in sync_engine.py, same as group membership changes)
        new_org_unit_path = data.get('orgUnitPath')
        if new_org_unit_path and new_org_unit_path != fallback_org_unit_path:
            updates['orgUnitPath'] = new_org_unit_path
        
        # Update user in GWS
        if updates:
            gws.update_user(email, updates)
            directory_cache.user_updated(
                email,
                first_name=updates.get('firstName'),
                last_name=updates.get('lastName'),
                org_unit_path=updates.get('orgUnitPath'),
            )
        
        # Update user in AD, or create them there first if they don't
        # exist yet - so GWS and AD never end up with different passwords
        if ad_updates:
            success, error = ad.update_user(email, ad_updates)
            if not success and error and 'not found' in error.lower():
                print(f"[INFO] {email} not found in AD - creating so password stays in sync")
                # DISABLED per admin preference (avoids an extra GWS API
                # call) - was: gws.get_root_org_unit_name()
                created, temp_password, create_error = ad.create_user(
                    email, fallback_first_name, fallback_last_name, fallback_full_name,
                    fallback_org_unit_path, ''
                )
                if created:
                    # create_user() sets its own random temp password -
                    # overwrite it with the password actually requested
                    if 'password' in ad_updates:
                        set_success, set_error = ad.update_user(email, {'password': ad_updates['password']})
                        if not set_success:
                            msg = f"Created {email} in AD but failed to set matching password: {set_error}"
                            print(f"[WARN] {msg}")
                            warnings.append(msg)
                else:
                    msg = f"Failed to create {email} in AD: {create_error}"
                    print(f"[WARN] {msg}")
                    warnings.append(msg)
            elif not success:
                msg = f"Updated in GWS, but failed to update in AD: {error}"
                print(f"[WARN] {msg}")
                warnings.append(msg)
        
        # Handle group membership changes (GWS only - synced to AD via sync process)
        new_groups = data.get('groups', [])
        if new_groups is not None:  # Only process if groups were provided
            # Get current groups
            current_groups = gws.get_group_members_for_user(email) or []
            final_groups = set(current_groups)  # what the user belongs to after this save
            
            # Add to new groups
            for group_email in new_groups:
                if group_email not in current_groups:
                    try:
                        gws.add_group_member(group_email, email)
                        final_groups.add(group_email)
                    except Exception as e:
                        msg = f"Could not add {email} to group {group_email}: {e}"
                        print(f"[WARN] {msg}")
                        warnings.append(msg)
            
            # Remove from old groups
            for group_email in current_groups:
                if group_email not in new_groups:
                    try:
                        gws.remove_group_member(group_email, email)
                        final_groups.discard(group_email)
                    except Exception as e:
                        msg = f"Could not remove {email} from group {group_email}: {e}"
                        print(f"[WARN] {msg}")
                        warnings.append(msg)
            
            directory_cache.user_groups_changed(email, final_groups)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='edit_user',
            target=f'user:{email}',
            status='success' if not warnings else 'partial',
            details={
                'firstName': data.get('firstName'),
                'lastName': data.get('lastName'),
                'passwordChanged': bool(data.get('password')),
                'groupsUpdated': bool(data.get('groups')),
                'warnings': warnings
            },
            source=get_client_ip()
        )
        
        return jsonify({
            'success': True,
            'message': f'User {email} updated successfully',
            'warnings': warnings
        })
    except Exception as e:
        error_str = str(e)
        
        # Parse errors for better messages
        user_friendly_error = error_str
        if 'Invalid Password' in error_str:
            user_friendly_error = 'Password does not meet requirements. Use at least 8 chars with uppercase, lowercase, number, and special char.'
        elif 'duplicate' in error_str.lower():
            user_friendly_error = f'Could not update - resource conflict'
        
        AuditLog.log_action(
            admin_username=user.username,
            action='edit_user',
            target=f'user:{email}',
            status='failed',
            details={'error': error_str},
            source=get_client_ip()
        )
        return jsonify({'error': user_friendly_error}), 400

@app.route('/api/users/<email>', methods=['DELETE'])
@login_required
@permission_required('delete_user')
def api_delete_user(email):
    """Delete a user from GWS"""
    user = get_current_user()
    
    try:
        gws = get_gws_connector()
        gws.delete_user(email)
        
        directory_cache.user_deleted(email)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='delete_user',
            target=f'user:{email}',
            status='success',
            source=get_client_ip()
        )
        
        return jsonify({'success': True, 'message': f'User {email} deleted'})
    except Exception as e:
        AuditLog.log_action(
            admin_username=user.username,
            action='delete_user',
            target=f'user:{email}',
            status='failed',
            details={'error': str(e)},
            source=get_client_ip()
        )
        return jsonify({'error': str(e)}), 500

@app.route('/api/org-units', methods=['GET'])
@login_required
@permission_required('read')
def api_get_org_units():
    """
    Get all GWS organizational units for the OU picker (Add/Edit User
    modals). Includes a synthetic entry for the root OU since GWS's API
    never returns it as part of the sub-OU list.
    """
    try:
        gws = get_gws_connector()
        ous = gws.get_all_org_units()
        # Root isn't returned by orgunits().list() - add it manually so
        # it's selectable too. No extra API call needed (see the
        # disabled get_root_org_unit_name() in gws_connector.py for why
        # we're not fetching its real display name).
        all_ous = [{'path': '/', 'name': 'Root (top level)', 'parentPath': ''}] + ous
        return jsonify({'orgUnits': all_ous})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================================
# API: GROUPS
# =====================================================================

@app.route('/api/groups', methods=['GET'])
@login_required
@permission_required('read')
def api_get_groups():
    """Get all groups from GWS"""
    try:
        groups = get_directory_cache()['groups']
        
        # Pagination
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        per_page = min(limit, 20) if limit <= 20 else limit  # Allow large limits for "all"
        total = len(groups)
        pages = (total + per_page - 1) // per_page if per_page <= 20 else 1
        
        start = (page - 1) * per_page
        end = start + per_page
        paginated_groups = groups[start:end]
        
        return jsonify({
            'groups': paginated_groups,
            'total': total,
            'page': page,
            'pages': pages,
            'per_page': per_page,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/groups/<email>', methods=['GET'])
@login_required
@permission_required('read')
def api_get_group(email):
    """Get full details of a specific group"""
    try:
        cache = get_directory_cache()
        groups = cache['groups']
        
        group = next((g for g in groups if g['email'] == email), None)
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        
        # Copy first so adding 'members' doesn't alter the cached group
        group = dict(group)
        group['members'] = list(cache['group_members_map'].get(email, []))
        
        # Get AD status for this group
        ad = get_ad_connector()
        ad_groups = ad.get_all_groups()
        sam_name = ad.sanitize_samaccountname(group['name'].replace(' ', ''))
        ad_group = next((g for g in ad_groups if g['samAccountName'] == sam_name), None)
        
        return jsonify({
            'gws': group,
            'ad': ad_group or {'status': 'not_in_ad'},
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/groups', methods=['POST'])
@login_required
@permission_required('create_group')
def api_create_group():
    """Create a new group in GWS"""
    user = get_current_user()
    data = request.get_json()
    
    email = data.get('email', '').strip()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    
    if not all([email, name]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        gws = get_gws_connector()
        gws.create_group(email, name, description)
        
        directory_cache.group_created(email, name, description)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='create_group',
            target=f'group:{email}',
            status='success',
            details={'name': name, 'description': description},
            source=get_client_ip()
        )
        
        return jsonify({'success': True, 'message': f'Group {email} created successfully.'})
    except Exception as e:
        error_str = str(e)
        
        # Parse Google Workspace API errors for better messages
        user_friendly_error = error_str
        
        if 'duplicate' in error_str.lower():
            user_friendly_error = f'Group {email} already exists in Google Workspace.'
        elif 'Invalid Email Address' in error_str:
            user_friendly_error = f'Invalid email address: {email}'
        elif 'unauthorized' in error_str.lower():
            user_friendly_error = 'Permission denied. Check GWS service account authorization.'
        elif 'UNAUTHENTICATED' in error_str:
            user_friendly_error = 'Google Workspace authentication failed. Check service account credentials.'
        elif 'DEADLINE_EXCEEDED' in error_str:
            user_friendly_error = 'Google Workspace request timed out. Try again.'
        
        AuditLog.log_action(
            admin_username=user.username,
            action='create_group',
            target=f'group:{email}',
            status='failed',
            details={'error': error_str},
            source=get_client_ip()
        )
        return jsonify({'error': user_friendly_error}), 400

@app.route('/api/groups/<email>', methods=['PUT'])
@login_required
@permission_required('edit_group')
def api_update_group(email):
    """Update a group in GWS"""
    user = get_current_user()
    data = request.get_json()
    
    try:
        gws = get_gws_connector()
        warnings = []
        updates = {
            'name': data.get('name'),
            'description': data.get('description'),
        }
        updates = {k: v for k, v in updates.items() if v}
        
        if updates:
            gws.update_group(email, updates)
            directory_cache.group_updated(email, updates.get('name'), updates.get('description'))
        
        # Handle membership changes (adding/removing users from this
        # group) - same add/remove diff pattern used on the user side
        # when editing which groups a user belongs to, just the other
        # direction: here we're editing who belongs to this group.
        new_members = data.get('members')
        if new_members is not None:
            current_members = get_directory_cache()['group_members_map'].get(email, [])
            final_members = list(current_members)  # members after this save
            
            for member_email in new_members:
                if member_email not in current_members:
                    try:
                        gws.add_group_member(email, member_email)
                        final_members.append(member_email)
                    except Exception as e:
                        msg = f"Could not add {member_email} to this group: {e}"
                        print(f"[WARN] {msg}")
                        warnings.append(msg)
            
            for member_email in current_members:
                if member_email not in new_members:
                    try:
                        gws.remove_group_member(email, member_email)
                        final_members.remove(member_email)
                    except Exception as e:
                        msg = f"Could not remove {member_email} from this group: {e}"
                        print(f"[WARN] {msg}")
                        warnings.append(msg)
            
            directory_cache.group_members_changed(email, final_members)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='edit_group',
            target=f'group:{email}',
            status='success' if not warnings else 'partial',
            details={**updates, 'membersUpdated': new_members is not None, 'warnings': warnings},
            source=get_client_ip()
        )
        
        return jsonify({'success': True, 'message': f'Group {email} updated', 'warnings': warnings})
    except Exception as e:
        AuditLog.log_action(
            admin_username=user.username,
            action='edit_group',
            target=f'group:{email}',
            status='failed',
            details={'error': str(e)},
            source=get_client_ip()
        )
        return jsonify({'error': str(e)}), 500

@app.route('/api/groups/<email>', methods=['DELETE'])
@login_required
@permission_required('delete_group')
def api_delete_group(email):
    """Delete a group from GWS"""
    user = get_current_user()
    
    try:
        gws = get_gws_connector()
        gws.delete_group(email)
        
        directory_cache.group_deleted(email)
        
        AuditLog.log_action(
            admin_username=user.username,
            action='delete_group',
            target=f'group:{email}',
            status='success',
            source=get_client_ip()
        )
        
        return jsonify({'success': True, 'message': f'Group {email} deleted'})
    except Exception as e:
        AuditLog.log_action(
            admin_username=user.username,
            action='delete_group',
            target=f'group:{email}',
            status='failed',
            details={'error': str(e)},
            source=get_client_ip()
        )
        return jsonify({'error': str(e)}), 500

# =====================================================================
# MAIN
# =====================================================================

if __name__ == '__main__':
    # Run Flask development server
    # For production, use a proper WSGI server (Gunicorn, Waitress, etc.)
    # HTTPS: set USE_HTTPS=true in .env once a certificate exists
    # (see README's HTTPS section for how to generate one). Falls back
    # to plain HTTP if the cert/key files aren't found, so this is
    # safe to leave on even before you've generated them.
    ssl_context = None
    if os.environ.get('USE_HTTPS', '').lower() == 'true':
        cert_path = APP_ROOT / 'cert.pem'
        key_path = APP_ROOT / 'key.pem'
        if cert_path.exists() and key_path.exists():
            ssl_context = (str(cert_path), str(key_path))
            print(f"[OK] HTTPS enabled using {cert_path.name}")
        else:
            print(f"[WARNING] USE_HTTPS is true but {cert_path.name}/{key_path.name} not found in {APP_ROOT} - falling back to HTTP")
    
    # Listens on this computer only until you say otherwise. To let other
    # computers on your network reach it, put GWS2AD_HOST=0.0.0.0 in .env
    # (and use HTTPS: see docs/deployment.md). GWS2AD_PORT changes the port.
    host = os.environ.get('GWS2AD_HOST', '127.0.0.1')
    port = int(os.environ.get('GWS2AD_PORT', 443 if ssl_context else 5000))
    print(f"[OK] Open {'https' if ssl_context else 'http'}://{'localhost' if host == '127.0.0.1' else host}:{port}")
    app.run(
        host=host,
        port=port,
        debug=False,      # Set to True for development only
        threaded=True,
        ssl_context=ssl_context,
    )
