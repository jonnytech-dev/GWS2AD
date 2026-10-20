"""
test_support.py
===============
Shared setup for the end-to-end tests (test_twofa_flow.py and
test_accounts_flow.py). This is not a test by itself.

It copies the project into a throwaway folder, makes a database in the OLD
layout (before roles and two-step verification existed) with four accounts
that have the old roles, and starts the real app on it. Your real database,
secrets, Google, and AD are never touched.
"""
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time

# A clock we can move forward, so tests never wait for the next 30-second
# code. Must be in place before the app is imported.
_real_time = time.time
_offset = [0.0]
time.time = lambda: _real_time() + _offset[0]


def advance(seconds):
    _offset[0] += seconds


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the project root
PASSWORD = 'correct horse battery'

# Created in this order, so ids are 1, 2, 3, 4
OLD_ACCOUNTS = [('admin', 'full'), ('boss2', 'full'), ('helper', 'limited'), ('viewer', 'read_only')]


def build(accounts=OLD_ACCOUNTS):
    """Make the throwaway project and import the real app from it. Returns a namespace."""
    tmp = tempfile.mkdtemp(prefix='gws2ad_test_')
    for name in os.listdir(HERE):
        path = os.path.join(HERE, name)
        if name in ('templates', 'static'):
            shutil.copytree(path, os.path.join(tmp, name))
        elif name.endswith('.py') and not name.startswith('test_'):
            shutil.copy(path, tmp)

    from cryptography.fernet import Fernet
    from werkzeug.security import generate_password_hash
    key = Fernet.generate_key().decode()
    with open(os.path.join(tmp, 'secrets.json.enc'), 'wb') as f:
        f.write(Fernet(key.encode()).encrypt(json.dumps({
            'flask_secret_key': 'test-secret-key',
            'admin_username': 'admin',
            'admin_password': 'not-used-because-the-admin-already-exists',
        }).encode()))

    con = sqlite3.connect(os.path.join(tmp, 'gw2ad.db'))
    con.execute('''CREATE TABLE admins (
        id INTEGER PRIMARY KEY, username VARCHAR(80) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL, email VARCHAR(120), role VARCHAR(20) NOT NULL,
        is_active BOOLEAN NOT NULL, created_at DATETIME NOT NULL, last_login DATETIME)''')
    for i, (username, role) in enumerate(accounts, 1):
        con.execute("INSERT INTO admins (username, password_hash, email, role, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                    (username, generate_password_hash(PASSWORD, method='pbkdf2:sha256'), f'{username}@x.org', role,
                     f'2026-01-0{i} 10:00:00'))
    con.commit()
    con.close()

    os.environ['SECRETS_KEY'] = key
    # This used to switch two-step off. It must now do nothing at all.
    os.environ['TWO_FACTOR_REQUIRED'] = 'false'
    os.chdir(tmp)
    sys.path.insert(0, tmp)

    import importlib
    import pyotp
    env = type('Env', (), {})()
    env.tmp = tmp
    env.pyotp = pyotp
    env.appmod = importlib.import_module('app')
    env.flask_app = env.appmod.app
    env.flask_app.config['TESTING'] = True
    import database, twofa, permissions
    env.db, env.Admin, env.Role, env.AuditLog = database.db, database.Admin, database.Role, database.AuditLog
    env.twofa, env.permissions = twofa, permissions
    env.client = env.flask_app.test_client()
    return env


class Helpers:
    """Small wrappers so the tests read like a person using the site"""

    def __init__(self, env, client=None, shared_with=None):
        self.env = env
        self.client = client or env.client
        self.secrets = shared_with.secrets if shared_with else {}        # username -> authenticator secret
        self.passwords = shared_with.passwords if shared_with else {}    # username -> current password

    # --- plain requests
    def GET(self, path, **kw): return self.client.get(path, **kw)
    def POST(self, path, data=None): return self.client.post(path, data=data or {})
    @staticmethod
    def html(resp): return resp.get_data(as_text=True)
    @staticmethod
    def location(resp): return resp.headers.get('Location', '')
    @staticmethod
    def csrf(page): return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    @staticmethod
    def manual_key(page): return re.search(r'class="manual-key">([^<]+)<', page).group(1).replace(' ', '')
    @staticmethod
    def recovery_codes(page): return re.findall(r'class="recovery-code">([A-Z0-9-]+)<', page)

    def code_for(self, secret, steps=0):
        return self.env.pyotp.TOTP(secret).at(int(time.time()) + 30 * steps)

    def wrong_code(self, secret):
        valid = {self.code_for(secret, s) for s in (-1, 0, 1)}
        return next(c for c in ('000000', '111111', '222222') if c not in valid)

    def fresh_code(self, username):
        """A code that has not been used yet for this account"""
        advance(31)
        return self.code_for(self.secrets[username])

    # --- database
    def row(self, username):
        with self.env.flask_app.app_context():
            self.env.db.session.expire_all()
            a = self.env.Admin.query.filter_by(username=username).first()
            if a is None:
                return None
            _ = a.named_role                      # load before detaching
            self.env.db.session.expunge(a)
            return a

    def audit_actions(self):
        with self.env.flask_app.app_context():
            return {a.action for a in self.env.AuditLog.query.all()}

    # --- signing in
    def pw(self, username):
        return self.passwords.get(username, PASSWORD)

    def login_password(self, username, password=None):
        return self.POST('/login', {'username': username, 'password': password or self.pw(username)})

    def logout(self):
        self.GET('/logout')
        self.client.get('/login/cancel')

    def enroll(self, username):
        """Sign in with the password and finish the required two-step setup. Leaves them signed in."""
        self.logout()
        r = self.login_password(username)
        assert '/login/setup' in self.location(r), (username, self.location(r))
        page = self.html(self.GET('/login/setup'))
        secret = self.manual_key(page)
        r = self.POST('/login/setup', {'csrf_token': self.csrf(page), 'code': self.code_for(secret)})
        assert r.status_code == 200 and len(self.recovery_codes(self.html(r))) == 10, username
        self.secrets[username] = secret
        return secret

    def sign_in(self, username):
        """Password then a fresh code. Leaves them signed in."""
        self.logout()
        r = self.login_password(username)
        assert '/login/verify' in self.location(r), (username, self.location(r))
        page = self.html(self.GET('/login/verify'))
        r = self.POST('/login/verify', {'csrf_token': self.csrf(page), 'code': self.fresh_code(username)})
        assert r.status_code == 302 and '/dashboard' in self.location(r), (username, r.status_code, self.location(r))


def run(steps, label=''):
    """Runs the steps in order; later steps depend on earlier ones, so it stops at the first failure."""
    failed = None
    for i, (name, fn) in enumerate(steps, 1):
        try:
            fn()
            print(f"PASS  {i:2d}. {name}")
        except Exception:
            import traceback
            print(f"FAIL  {i:2d}. {name}")
            traceback.print_exc()
            failed = i
            break
    return failed


def finish(failed, total, tmp):
    shutil.rmtree(tmp, ignore_errors=True)
    if failed:
        print(f"\nStopped at step {failed}; later steps depend on it.")
        sys.exit(1)
    print(f"\nAll {total} steps passed")
