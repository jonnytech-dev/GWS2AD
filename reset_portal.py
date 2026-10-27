"""
reset_portal.py
===============
The self-service password reset page: a second, very small web service that
starts together with GWS2AD, on the same IP address but its own port.

A person who forgot their network (Active Directory) password does this,
with no administrator involved:

    1. types their work email address
    2. gets a 6-digit code at their work email address
    3. types the code
    4. chooses a new password

The new password is set in Active Directory and in Google, the same two places
Edit User changes on the dashboard.

What keeps it safe (details in docs/password-reset-portal.md):
  - The page never says whether an address belongs to an account. Every
    request gets the same answer, and the lookup runs after the answer is sent.
  - The code goes to the work email, not to the page. Codes are random,
    work once, last 10 minutes, and are burned after 5 wrong tries.
  - Requests are limited per address and per computer.
  - Google admins and suspended users cannot use it. They are reset by an administrator.
  - Because the code goes to the work mailbox, whoever can open that mailbox can reset
    both passwords.
  - Nothing is changed unless Google and Active Directory can both be reached first.
    Google (a third party, over the internet) is changed first, then Active Directory.
  - It is served over HTTPS only, on port 8443 by default (RESET_PORTAL_PORT changes it),
    using cert.pem and key.pem. With no certificate it does not start at all: it never
    falls back to plain HTTP, because passwords cross it.
  - The code and the one-time token are stored only as keyed hashes. The new
    password is never stored or logged.
  - The pages use no JavaScript and send strict browser security headers.
  - Every step is written to the audit log (never the code or the password).
"""
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import threading
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText

from flask import Flask, render_template, request, session, redirect, url_for, make_response, abort, send_file
from werkzeug.exceptions import HTTPException

import mode
import passwords
from config import Config, APP_ROOT, SMTP_CONFIG
import branding
from database import db, AuditLog, PasswordResetRequest
from gws_connector import get_gws_connector
from ad_connector import get_ad_connector

# ---------------------------------------------------------------------------
# The rules (change them here, nowhere else)
# ---------------------------------------------------------------------------
CODE_MINUTES = 10               # how long a code works
TOKEN_MINUTES = 10              # how long after a right code the person has to choose a password
MAX_CODE_ATTEMPTS = 5           # wrong codes before that code is burned
MAX_PASSWORD_ATTEMPTS = 5       # refused new passwords before the reset is burned
MAX_REQUESTS_PER_EMAIL = 3      # code requests per address per hour
MAX_REQUESTS_PER_IP = 10        # code requests per computer per hour
MAX_WRONG_CODES_PER_IP = 20     # wrong codes per computer per hour
KEEP_ROWS_DAYS = 7              # older requests are deleted

# True: the lookup and the email happen after the page has been sent, so a slow
# answer can never reveal that an address is real. The tests turn this off.
RUN_IN_BACKGROUND = True

APP_TITLE = 'Reset your password'

# The only files this page serves besides its own pages and the logo
ASSETS = {
    'favicon.svg': (APP_ROOT / 'static' / 'favicon.svg', 'image/svg+xml'),
    'reset.css': (APP_ROOT / 'static' / 'reset.css', 'text/css'),
    'fonts/roboto-latin-wght-normal.woff2': (APP_ROOT / 'static' / 'fonts' / 'roboto-latin-wght-normal.woff2', 'font/woff2'),
}

_KEY = hashlib.sha256(b'gws2ad-reset-portal|' + str(Config.SECRET_KEY).encode()).digest()

_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_CODE = re.compile(r'^[0-9]{6}$')

_wrong_codes = {}               # ip -> [timestamps]; in memory, resets on restart
_wrong_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _utcnow():
    """UTC now, read from time.time() so the tests can move the clock"""
    return datetime.utcfromtimestamp(time.time())


def _fingerprint(kind, *parts):
    """A keyed hash. Codes and tokens are only ever kept in this form."""
    return hmac.new(_KEY, '|'.join((kind,) + parts).encode(), hashlib.sha256).hexdigest()


def clean_email(raw):
    """The address in lowercase if it looks like one, else None"""
    value = (raw or '').strip().lower()
    return value if len(value) <= 254 and _EMAIL.match(value) else None


def show_reasons():
    """
    RESET_SHOW_REASONS=true makes the page say plainly why an address cannot be reset
    (administrator, suspended, not found...). Off by default: those answers tell a stranger
    which addresses exist and which are administrators. With it off, every address gets the
    same answer and the reason is only in the audit log.
    """
    return os.environ.get('RESET_SHOW_REASONS', '').lower() in ('true', '1', 'yes', 'on')


# What the page says for each outcome when RESET_SHOW_REASONS is on. Plain words only:
# never an error code, a server message or a technical detail.
REASON_NOTICES = {
    'admin': ('This is an administrator account', "Administrator accounts can't be reset on this page. Please ask another administrator, or your IT team."),
    'suspended': ('This account is locked', "This account is suspended right now, so it can't be reset here. Please contact your IT team."),
    'not_found': ("We couldn't find that account", "Check the spelling of your work email address and try again. If it is right, please contact your IT team."),
    'no_ad': ("This account isn't ready for password reset", "Your account is not fully set up yet. Please contact your IT team."),
    'limited': ('Too many requests', "Please wait an hour and try again, or contact your IT team."),
    'mail_failed': ("We couldn't send your code", "Something went wrong on our side. Please try again in a few minutes, or contact your IT team."),
    'error': ('Something went wrong', "Please try again in a few minutes, or contact your IT team."),
}


def _reason_key(reason):
    """Turns the audit-log reason from check_eligibility into one of the REASON_NOTICES keys"""
    text = (reason or '').lower()
    if 'admin' in text:
        return 'admin'
    if 'suspended' in text:
        return 'suspended'
    if 'not in google' in text:
        return 'not_found'
    if 'active directory' in text:
        return 'no_ad'
    return 'error'


def client_ip():
    """The computer's address. Behind a reverse proxy, set RESET_TRUST_PROXY=true to use the address the proxy saw."""
    if os.environ.get('RESET_TRUST_PROXY', '').lower() == 'true':
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[-1].strip()[:64]     # the last entry is the one our own proxy added
    return (request.remote_addr or '')[:64]


def audit(action, email, status, details=None, ip=None):
    AuditLog.log_action(admin_username='self-service', action=action, target=f'user:{email}',
                        status=status, details=details, source=ip)


def _too_many_wrong_codes(ip):
    now = time.time()
    with _wrong_lock:
        recent = [t for t in _wrong_codes.get(ip, []) if now - t < 3600]
        _wrong_codes[ip] = recent
        return len(recent) >= MAX_WRONG_CODES_PER_IP


def _note_wrong_code(ip):
    with _wrong_lock:
        _wrong_codes.setdefault(ip, []).append(time.time())


def csrf_token():
    token = session.get('_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf'] = token
    return token


def csrf_valid():
    sent = request.form.get('csrf_token', '')
    return bool(sent) and hmac.compare_digest(session.get('_csrf', ''), sent)


# ---------------------------------------------------------------------------
# Who may reset, and sending mail
# ---------------------------------------------------------------------------
def check_eligibility(email):
    """
    Returns (info, reason). info is None when the person may not reset here,
    and reason says why (for the audit log only, never shown on the page).
    A successful return also proves Google and Active Directory both answered.
    """
    info = get_gws_connector().get_user_security_info(email)
    if not info:
        return None, 'not in Google Workspace'
    if info.get('suspended'):
        return None, 'suspended in Google'
    if info.get('isAdmin') or info.get('isDelegatedAdmin'):
        return None, 'Google admin (reset by an administrator)'
    if not get_ad_connector().has_user(info['email']):
        return None, 'no Active Directory account'
    return info, ''


def send_mail(to, subject, body):
    """Send one plain-text email through the same mail account as the welcome emails"""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_CONFIG['from_address']
    msg['To'] = to
    with smtplib.SMTP(SMTP_CONFIG['smtp_server'], SMTP_CONFIG['smtp_port'], timeout=20) as server:
        server.starttls()
        server.login(SMTP_CONFIG['from_address'], SMTP_CONFIG['password'])
        server.send_message(msg)


def _code_email(email, code):
    return ("Someone asked to reset the Active Directory and Google Workspace password for " + email + ".\n\n"
            "Your code is:  " + code + "\n\n"
            f"It works for {CODE_MINUTES} minutes and only once.\n\n"
            "If this was not you, ignore this email. Your password has not changed. "
            "If you keep getting these, tell your IT team.\n\nIT Department")


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------
def begin_request(email, ip):
    """
    Records the request and applies the limits. Returns the row id, or None when a limit
    was hit (the person still sees the normal answer, but no code is made).
    """
    now = _utcnow()
    hour_ago = now - timedelta(hours=1)
    PasswordResetRequest.query.filter(PasswordResetRequest.created_at < now - timedelta(days=KEEP_ROWS_DAYS)).delete()
    db.session.commit()
    by_email = PasswordResetRequest.query.filter(PasswordResetRequest.email == email,
                                                 PasswordResetRequest.created_at >= hour_ago).count()
    by_ip = PasswordResetRequest.query.filter(PasswordResetRequest.ip == ip,
                                              PasswordResetRequest.created_at >= hour_ago).count()
    if by_email >= MAX_REQUESTS_PER_EMAIL or by_ip >= MAX_REQUESTS_PER_IP:
        audit('reset_rate_limited', email, 'failed', {'by_email': by_email, 'by_ip': by_ip}, ip)
        return None
    row = PasswordResetRequest(email=email, ip=ip, created_at=now)
    db.session.add(row)
    db.session.commit()
    return row.id


def request_outcome(row_id):
    """
    Looks the person up and, if they may reset, makes the code and emails it.
    Returns (code, outcome). code is only set in Demo mode, so the page can show it.
    outcome is 'sent', or one of the REASON_NOTICES keys. Never raises.
    """
    row = None
    try:
        row = db.session.get(PasswordResetRequest, row_id)
        info, reason = check_eligibility(row.email)
        if not info:
            audit('reset_code_requested', row.email, 'failed', {'reason': reason}, row.ip)
            return None, _reason_key(reason)
        code = f'{secrets.randbelow(10 ** 6):06d}'
        row.eligible = True
        row.code_hash = _fingerprint('code', row.email, code)
        row.code_expires_at = _utcnow() + timedelta(minutes=CODE_MINUTES)
        db.session.commit()
        if mode.is_demo():
            audit('reset_code_requested', row.email, 'success', {'sent': 'no (demo mode)'}, row.ip)
            return code, 'sent'
        try:
            send_mail(info['email'], 'Your password reset code', _code_email(row.email, code))
        except Exception as e:                                # the page never sees this; the audit log does
            audit('reset_code_requested', row.email, 'failed', {'error': 'mail not sent: ' + str(e)[:150]}, row.ip)
            return None, 'mail_failed'
        audit('reset_code_requested', row.email, 'success', {'sent': 'work email'}, row.ip)
        return None, 'sent'
    except Exception as e:                                    # the page has already answered; log it for the admin
        db.session.rollback()
        try:
            audit('reset_code_requested', getattr(row, 'email', '?'), 'failed', {'error': str(e)[:200]}, getattr(row, 'ip', None))
        except Exception:
            pass
    return None, 'error'


def finish_request(row_id):
    """request_outcome without the outcome: returns the Demo code, or None"""
    return request_outcome(row_id)[0]


def _usable_row(email):
    """The newest request for this address that still has a live code"""
    return (PasswordResetRequest.query
            .filter(PasswordResetRequest.email == email, PasswordResetRequest.eligible.is_(True),
                    PasswordResetRequest.used.is_(False), PasswordResetRequest.verified_at.is_(None),
                    PasswordResetRequest.code_expires_at > _utcnow())
            .order_by(PasswordResetRequest.id.desc()).first())


def check_code(email, code, ip):
    """Returns the one-time token if the code is right, else None"""
    row = _usable_row(email)
    expected = row.code_hash if row else '0' * 64
    right = hmac.compare_digest(_fingerprint('code', email, code), expected) and row is not None
    if not right:
        _note_wrong_code(ip)
        if row:
            row.attempts += 1
            if row.attempts >= MAX_CODE_ATTEMPTS:
                row.used = True
            db.session.commit()
        audit('reset_code_wrong', email, 'failed', {'attempts': row.attempts if row else 0}, ip)
        return None
    token = secrets.token_urlsafe(32)
    row.verified_at = _utcnow()
    row.token_hash = _fingerprint('token', token)
    row.token_expires_at = _utcnow() + timedelta(minutes=TOKEN_MINUTES)
    db.session.commit()
    audit('reset_code_verified', email, 'success', None, ip)
    return token, row.id


def _row_for_token(row_id, token, email):
    """The request a signed-in token belongs to, if it is still good"""
    row = db.session.get(PasswordResetRequest, row_id) if row_id else None
    if (not row or row.used or row.email != email or not row.token_hash or not token
            or not hmac.compare_digest(_fingerprint('token', token), row.token_hash)
            or not row.token_expires_at or row.token_expires_at < _utcnow()):
        return None
    return row


def change_password(row, new_password, ip):
    """
    Sets the new password in Google and in Active Directory, the same two places Edit User
    changes on the dashboard. Returns (ok, message_for_the_person).

    First it checks that both can be reached (check_eligibility reads from each). Then Google
    goes first: it is a third party over the internet, so it is the one most likely to fail,
    and if it does, nothing has changed anywhere. Active Directory goes second.
    If Active Directory then refuses the password (its rules are stricter), Google already has
    it, so the person is asked to choose another and both are set again on the next try.
    """
    info, reason = check_eligibility(row.email)                  # checked again: things can change in ten minutes
    if not info:
        row.used = True
        db.session.commit()
        audit('reset_password_changed', row.email, 'failed', {'reason': reason}, ip)
        return False, 'This reset can no longer be completed. Please contact your IT team.'
    try:
        get_gws_connector().update_user(info['email'], {'password': new_password})
    except Exception as e:
        text = str(e)
        if 'HttpError 400' in text or 'Invalid' in text or 'Password' in text:
            # Google answered but refused the password (too short, too common, or against its policy)
            row.password_attempts += 1
            if row.password_attempts >= MAX_PASSWORD_ATTEMPTS:
                row.used = True
            db.session.commit()
            audit('reset_password_changed', row.email, 'failed', {'error': 'Google refused the password, nothing was changed: ' + text[:300]}, ip)
            return False, ('Google did not accept that password. Try a longer one, with a mix of letters, numbers and symbols. '
                           'Nothing was changed.')
        db.session.commit()
        audit('reset_password_changed', row.email, 'failed', {'error': 'Google did not take the password, nothing was changed: ' + text[:300]}, ip)
        return False, ('Your password was not changed, because Google could not be reached. '
                       'Nothing was changed. Please try again in a few minutes.')
    try:
        ok, error = get_ad_connector().update_user(info['email'], {'password': new_password})
    except Exception as e:
        ok, error = False, str(e)
    if not ok:
        row.password_attempts += 1
        gave_up = row.password_attempts >= MAX_PASSWORD_ATTEMPTS
        if gave_up:
            row.used = True
        db.session.commit()
        audit('reset_password_changed', row.email, 'failed',
              {'error': 'Google password changed, Active Directory password not: ' + str(error)[:150]}, ip)
        if gave_up:
            return False, ('Your Google password was changed, but your Active Directory (computer sign-in) password could not be. '
                           'Please contact your IT team to finish the reset.')
        return False, ('Active Directory did not accept that password. Try a longer one, with a mix of letters, numbers and symbols. '
                       'Nothing is finished until you see the confirmation page.')
    row.used = True
    db.session.commit()
    audit('reset_password_changed', row.email, 'success', {'changed': 'Google and Active Directory'}, ip)
    if not mode.is_demo():
        notice = ("The Active Directory and Google Workspace passwords for " + row.email + " were just changed using the self-service reset page.\n\n"
                  f"Time: {_utcnow():%Y-%m-%d %H:%M} UTC\nFrom: {ip}\n\n"
                  "If this was you, nothing more is needed. If it was not, contact your IT team right away.\n\nIT Department")
        try:
            send_mail(info['email'], 'Your password was changed', notice)
        except Exception:
            pass                                               # the change is done; a missed notice must not undo it
    return True, ''


# ---------------------------------------------------------------------------
# The web pages
# ---------------------------------------------------------------------------
def create_app():
    portal = Flask(__name__, template_folder=str(APP_ROOT / 'templates'), static_folder=None)   # no /static: only the files listed in ASSETS are served
    portal.config.from_object(Config)
    portal.config.update(
        # Not the dashboard's cookie: browsers share cookies between ports on the same address
        SESSION_COOKIE_NAME='reset_session',
        SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=True,                            # HTTPS only, so the cookie is too
        SECRET_KEY=_KEY,
        MAX_CONTENT_LENGTH=4096,
    )
    db.init_app(portal)

    @portal.context_processor
    def inject():
        return {'csrf_token': csrf_token, 'demo_mode': mode.is_demo(), 'app_title': APP_TITLE, 'brand': branding.get(),
                'who': session.get('reset_email') or session.get('done_email'),
                'code_minutes': CODE_MINUTES, 'min_length': passwords.MIN_LENGTH, 'max_length': passwords.MAX_LENGTH}

    @portal.after_request
    def headers(response):
        if request.endpoint not in ('brand_logo', 'asset'):     # pages are never cached; the logo and style files may be
            response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = ("default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; "
                                                       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        response.headers.pop('Server', None)
        return response

    def page(template, status=200, **ctx):
        session.permanent = True
        return make_response(render_template(template, **ctx), status)

    def bad_form():
        return page('reset/request.html', 400, error='That page expired. Please try again.', email='')

    @portal.errorhandler(Exception)
    def failed(e):
        db.session.rollback()
        if isinstance(e, HTTPException):          # a wrong address, a wrong method, a too-large form
            return page('reset/request.html', e.code or 400, error='', email='')
        return page('reset/request.html', 500, error='Something went wrong. Please try again, or contact your IT team.', email='')

    @portal.route('/', methods=['GET'])
    def start():
        return page('reset/request.html', error='', email='')

    @portal.route('/request', methods=['POST'])
    def ask_for_code():
        if not csrf_valid():
            return bad_form()
        email = clean_email(request.form.get('email'))
        if not email:
            return page('reset/request.html', 400, error='Enter your work email address, for example name@example.com.',
                        email=(request.form.get('email') or '')[:254])
        ip = client_ip()
        session.pop('demo_code', None)
        session.pop('reset_token', None)
        session.pop('reset_row', None)
        session['reset_email'] = email
        row_id = begin_request(email, ip)
        if show_reasons():
            # Says plainly why it cannot be reset. Runs now, not in the background, so it can answer.
            outcome = 'limited' if not row_id else None
            if row_id:
                code, outcome = request_outcome(row_id)
                if code and mode.is_demo():
                    session['demo_code'] = code
            if outcome != 'sent':
                title, text = REASON_NOTICES[outcome]
                session.pop('reset_email', None)
                return page('reset/request.html', 200, error='', email=email, notice={'kind': 'warn', 'title': title, 'text': text})
            return redirect(url_for('enter_code'), 303)
        if row_id:
            if RUN_IN_BACKGROUND and not mode.is_demo():
                def work():
                    with portal.app_context():
                        finish_request(row_id)
                threading.Thread(target=work, daemon=True).start()
            else:
                code = finish_request(row_id)
                if code and mode.is_demo():
                    session['demo_code'] = code
        return redirect(url_for('enter_code'), 303)

    @portal.route('/verify', methods=['GET'])
    def enter_code():
        if not session.get('reset_email'):
            return redirect(url_for('start'))
        return page('reset/verify.html', error='', demo_code=session.get('demo_code'))

    @portal.route('/verify', methods=['POST'])
    def check_the_code():
        email = session.get('reset_email')
        if not email:
            return redirect(url_for('start'))
        if not csrf_valid():
            return bad_form()
        ip = client_ip()
        if _too_many_wrong_codes(ip):
            return page('reset/verify.html', 429, error='Too many tries from this computer. Please wait an hour, or contact your IT team.',
                        demo_code=None)
        code = (request.form.get('code') or '').strip().replace(' ', '')
        result = check_code(email, code, ip) if _CODE.match(code) else None
        if not _CODE.match(code):
            _note_wrong_code(ip)
        if not result:
            return page('reset/verify.html', 400, error='That code is not right, or it has expired. Check the email and try again, '
                        'or start over to get a new code.', demo_code=session.get('demo_code'))
        token, row_id = result
        session.pop('demo_code', None)
        session['reset_token'] = token
        session['reset_row'] = row_id
        return redirect(url_for('choose_password'), 303)

    def current_row():
        return _row_for_token(session.get('reset_row'), session.get('reset_token'), session.get('reset_email'))

    @portal.route('/new-password', methods=['GET'])
    def choose_password():
        if not current_row():
            return redirect(url_for('start'))
        return page('reset/new_password.html', error='')

    @portal.route('/new-password', methods=['POST'])
    def save_password():
        row = current_row()
        if not row:
            return redirect(url_for('start'))
        if not csrf_valid():
            return bad_form()
        new = request.form.get('password') or ''
        problem = passwords.check_new_password(new, request.form.get('confirm') or '', row.email.split('@')[0])
        if problem:
            row.password_attempts += 1
            if row.password_attempts >= MAX_PASSWORD_ATTEMPTS:
                row.used = True
            db.session.commit()
            if row.used:
                return redirect(url_for('start'))
            return page('reset/new_password.html', 400, error=problem)
        ok, message = change_password(row, new, client_ip())
        if not ok:
            if row.used:
                session.clear()
                return page('reset/request.html', 400, error=message, email='')
            return page('reset/new_password.html', 400, error=message)
        email = row.email
        session.clear()
        session['done_email'] = email
        return redirect(url_for('done'), 303)

    @portal.route('/done', methods=['GET'])
    def done():
        page_response = page('reset/done.html')
        session.pop('done_email', None)                       # shown once
        return page_response

    @portal.route('/assets/<path:name>', methods=['GET'])
    def asset(name):
        """The stylesheet and font, and nothing else: the list is fixed, so no path can reach any other file"""
        entry = ASSETS.get(name)
        if not entry:
            abort(404)
        response = send_file(entry[0], mimetype=entry[1], max_age=3600)
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    @portal.route('/brand/logo', methods=['GET'])
    def brand_logo():
        """The organization's logo, if the Owner uploaded one (Settings > Branding)"""
        if not branding.has_logo():
            abort(404)
        response = send_file(branding.LOGO_FILE, mimetype='image/png', max_age=3600)
        response.headers['Cache-Control'] = 'public, max-age=3600'    # the page adds ?v=<version>, so a new logo shows at once
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    return portal


# ---------------------------------------------------------------------------
# Starting it next to the main app
# ---------------------------------------------------------------------------
def _quiet_handler():
    """A request handler that does not announce the web server or Python version"""
    from werkzeug.serving import WSGIRequestHandler

    class QuietHandler(WSGIRequestHandler):
        def version_string(self):
            return 'web'
    return QuietHandler


def find_certificate():
    """The certificate and key next to app.py (the same ones the dashboard uses), or None"""
    cert, key = APP_ROOT / 'cert.pem', APP_ROOT / 'key.pem'
    return (str(cert), str(key)) if cert.exists() and key.exists() else None


def start_in_background(host, ssl_context=None, main_port=None):
    """
    Starts the reset page on its own port in a background thread. Called by app.py.
    RESET_PORTAL=false turns it off. RESET_PORTAL_PORT changes the port (default 8443).

    It is HTTPS only. It uses the certificate it is given, or cert.pem and key.pem next to
    app.py, whether or not the dashboard itself uses HTTPS. With no certificate it does not
    start: it never falls back to plain HTTP. A problem starting it (no certificate, port in
    use) never stops the main app.
    """
    if os.environ.get('RESET_PORTAL', 'true').lower() in ('false', '0', 'no', 'off'):
        print('[OK] Password reset page is off (RESET_PORTAL=false)')
        return None
    ssl_context = ssl_context or find_certificate()
    if not ssl_context:
        print('[WARNING] Password reset page NOT started: it is HTTPS only and cert.pem / key.pem were not found '
              'next to app.py. See docs/password-reset-portal.md')
        return None
    port = int(os.environ.get('RESET_PORTAL_PORT', 8443))
    if main_port is not None and port == main_port:
        print(f'[WARNING] Password reset page not started: RESET_PORTAL_PORT {port} is the same as the main app\'s port')
        return None
    try:
        from werkzeug.serving import make_server
        server = make_server(host, port, create_app(), threaded=True, ssl_context=ssl_context,
                             request_handler=_quiet_handler())
    except Exception as e:
        print(f'[WARNING] Password reset page not started on port {port}: {e}')
        return None
    threading.Thread(target=server.serve_forever, name='reset-portal', daemon=True).start()
    shown = 'localhost' if host == '127.0.0.1' else host
    print(f'[OK] Password reset page: https://{shown}:{port}')
    return server
