"""
auth.py
=======
Login, session management, and permission checking.
"""

import hmac
import secrets
import time
from datetime import datetime
from flask import session, redirect, url_for, request
from functools import wraps
from database import Admin, db

# How long someone has to finish the second sign-in step after the password
PENDING_LOGIN_SECONDS = 300


def login_user(username, password):
    """
    Authenticate user and return admin object if successful.
    Returns None if authentication fails.
    """
    admin = Admin.query.filter_by(username=username, is_active=True).first()
    
    # Only checks the password. The login time is recorded by complete_login()
    # once the whole sign-in (including two-step verification) is finished.
    if admin and admin.check_password(password):
        return admin
    
    return None


def set_session(admin):
    """Store admin info in Flask session"""
    session['user_id'] = admin.id
    session['username'] = admin.username
    session['role'] = admin.role
    session.permanent = True


def complete_login(admin):
    """The whole sign-in is done: record it and start the real session"""
    admin.last_login = datetime.utcnow()
    db.session.commit()
    session.clear()
    set_session(admin)


def start_pending_login(admin, mode):
    """
    The password was right but the second step is still to do. This is
    stored under different session keys than a real login, so none of the
    login_required pages let the person in yet.
    mode is 'verify' (enter a code) or 'enroll' (set up the authenticator app).
    """
    session.clear()
    session['pending_uid'] = admin.id
    session['pending_mode'] = mode
    session['pending_at'] = time.time()
    session.permanent = True


def get_pending_admin(mode):
    """The admin waiting on the second step, or None (nobody, wrong step, or too slow)"""
    uid = session.get('pending_uid')
    if not uid or session.get('pending_mode') != mode:
        return None
    if time.time() - session.get('pending_at', 0) > PENDING_LOGIN_SECONDS:
        return None
    return Admin.query.filter_by(id=uid, is_active=True).first()


def clear_pending_login():
    for key in ('pending_uid', 'pending_mode', 'pending_at'):
        session.pop(key, None)


def csrf_token():
    """A per-session token that forms must send back, so other sites can't submit them"""
    token = session.get('_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf'] = token
    return token


def csrf_valid():
    sent = request.form.get('csrf_token', '')
    return bool(sent) and hmac.compare_digest(session.get('_csrf', ''), sent)


def get_current_user():
    """Get current logged-in admin"""
    if 'user_id' not in session:
        return None
    
    admin = Admin.query.filter_by(id=session.get('user_id')).first()
    # An account only counts as signed in once two-step verification is set
    # up. This also ends the session of anyone whose two-step was just reset
    # or who was already signed in before two-step existed.
    if not admin or not admin.is_active or not admin.two_factor_enabled:
        return None
    return admin


def logout_user():
    """Clear session"""
    session.clear()


def login_required(f):
    """Decorator: require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(action):
    """
    Decorator: require specific permission
    Usage: @permission_required('create_user')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            
            if not user.has_permission(action):
                return {'error': f'Permission denied. You need {action} permission.'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr
