"""
config.py
=========
Loads encrypted secrets and Flask configuration.
Never hardcode secrets in this file.
"""

import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load .env file if it exists (for local development)
load_dotenv()

# --- Determine app root directory ---
APP_ROOT = Path(__file__).parent
DATABASE_PATH = APP_ROOT / "gw2ad.db"
LOGS_PATH = APP_ROOT / "logs"
SECRETS_FILE = APP_ROOT / "secrets.json.enc"

# Create logs directory if it doesn't exist
LOGS_PATH.mkdir(exist_ok=True)


def load_secrets():
    """
    Loads and decrypts secrets from secrets.json.enc
    Returns a dict of all configuration values.
    """
    if not SECRETS_FILE.exists():
        raise FileNotFoundError(
            f"Secrets file not found: {SECRETS_FILE}\n"
            "Run setup_secrets.py first to create encrypted config."
        )

    # Get encryption key from environment variable or .env file
    encryption_key = os.getenv('SECRETS_KEY')
    if not encryption_key:
        raise ValueError(
            "SECRETS_KEY environment variable not set.\n"
            "Run setup_secrets.py and follow its instructions."
        )

    try:
        # Decrypt the file
        cipher = Fernet(encryption_key.encode())
        with open(SECRETS_FILE, 'rb') as f:
            encrypted = f.read()
        
        decrypted = cipher.decrypt(encrypted)
        secrets = json.loads(decrypted)
        
        return secrets
    except Exception as e:
        raise ValueError(f"Could not decrypt secrets file: {e}")


# Load secrets at startup. The file only needs the app's own settings
# (secret key, first Owner login). Google / Active Directory / email values
# are optional: without them the app runs in Demo mode on sample data.
try:
    SECRETS = load_secrets()
except Exception as e:
    print(f"[ERROR] Failed to load secrets: {e}")
    print("Exiting. Run 'python setup.py' first (it takes under a minute).")
    exit(1)


# --- Flask Configuration ---
class Config:
    """Base configuration"""
    SECRET_KEY = SECRETS.get('flask_secret_key', 'dev-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
    TEMPLATES_AUTO_RELOAD = True
    
    # Session configuration
    # 15 minutes of inactivity logs the user out. session.permanent=True
    # is set at login (auth.py), and Flask refreshes this expiry on
    # every request by default (SESSION_REFRESH_EACH_REQUEST), so this
    # is a sliding inactivity timeout, not a fixed time-since-login one -
    # 15 minutes of NO activity logs out; continued use never does.
    PERMANENT_SESSION_LIFETIME = 900  # 15 minutes, in seconds
    # Only send the session cookie over HTTPS when HTTPS is actually
    # enabled - hardcoding this to True would silently break login
    # entirely if USE_HTTPS is off, since the browser would refuse to
    # send a Secure cookie back over plain HTTP.
    SESSION_COOKIE_SECURE = os.environ.get('USE_HTTPS', '').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True

    # Two-step verification is always required. There is deliberately no
    # setting that turns it off: the only way to clear it for someone is a
    # reset, which makes them set it up again at their next sign-in.
    SESSION_COOKIE_SAMESITE = 'Lax'


# --- Dashboard Admin Account (bootstrap only) ---
# Used ONCE, the very first time the app starts with an empty database,
# to create the first login. Set by setup_secrets.py's admin username/
# password prompt - required. database.py refuses to start with an
# empty database if these aren't set; there's no generated fallback.
ADMIN_CONFIG = {
    'username': SECRETS.get('admin_username'),
    'password': SECRETS.get('admin_password'),
}


# --- Google Workspace Configuration ---
GWS_CONFIG = {
    'key_path': SECRETS.get('gws_key_path'),
    'subject': SECRETS.get('gws_subject'),
    'customer': SECRETS.get('gws_customer'),
}


# --- Active Directory Configuration ---
# Demo mode needs a base DN to build sample paths from. It is only a
# placeholder: Live mode refuses to start unless a real one is saved
# (see missing_live_settings below).
DEMO_AD_BASE_DN = 'OU=GWS-Sync,DC=demo,DC=example,DC=com'

AD_CONFIG = {
    'server': SECRETS.get('ad_server'),
    # The root everything lives under: every lookup in ad_connector.py
    # searches the whole subtree beneath this DN, and every new
    # user/group/sub-OU gets created somewhere inside it. Your choice:
    #   - Your actual domain root (e.g. "DC=example,DC=com") - the app
    #     can see and manage objects anywhere in the domain, but the
    #     service account needs domain-wide delegated permissions.
    #   - A dedicated OU you create yourself (e.g.
    #     "OU=GWS-Sync,DC=example,DC=com") - the service account only
    #     ever needs permissions delegated on that one OU (least
    #     privilege), but anything created outside it in AD is invisible
    #     to the sync and won't be matched against GWS.
    # Sub-OUs mirroring GWS's org unit structure, plus the Users and
    # Groups OUs below, all get created directly under this DN.
    'base_dn': SECRETS.get('ad_base_dn') or DEMO_AD_BASE_DN,
    # Where NEW users/groups get created. These are just names, not DNs -
    # they get created as top-level OUs directly under base_dn the first
    # time a user/group is created (auto-created if missing). Not
    # user-configurable during setup on purpose - rename them in Active
    # Directory afterward if you want something different.
    'users_ou_name': 'Users',
    'groups_ou_name': 'Groups',
    'bind_dn': SECRETS.get('ad_bind_dn'),
    'bind_password': SECRETS.get('ad_bind_password'),
}


# --- SMTP Configuration ---
SMTP_CONFIG = {
    'from_address': SECRETS.get('smtp_from_address'),
    'password': SECRETS.get('smtp_password'),
    # Defaults suit a Gmail / Google Workspace sender. Change them in
    # setup (or set smtp_server / smtp_port) for any other mail server.
    'smtp_server': SECRETS.get('smtp_server') or 'smtp.gmail.com',
    'smtp_port': int(SECRETS.get('smtp_port') or 587),
}


# What Live mode needs. Demo mode needs none of it.
LIVE_REQUIRED = {
    'GWS_CONFIG': ['key_path', 'subject', 'customer'],
    'AD_CONFIG': ['server', 'base_dn', 'bind_dn', 'bind_password'],
    'SMTP_CONFIG': ['from_address', 'password'],
}
_LIVE_SECRET_NAMES = {
    ('GWS_CONFIG', 'key_path'): 'gws_key_path', ('GWS_CONFIG', 'subject'): 'gws_subject',
    ('GWS_CONFIG', 'customer'): 'gws_customer', ('AD_CONFIG', 'server'): 'ad_server',
    ('AD_CONFIG', 'base_dn'): 'ad_base_dn', ('AD_CONFIG', 'bind_dn'): 'ad_bind_dn',
    ('AD_CONFIG', 'bind_password'): 'ad_bind_password',
    ('SMTP_CONFIG', 'from_address'): 'smtp_from_address', ('SMTP_CONFIG', 'password'): 'smtp_password',
}


def missing_live_settings():
    """Names of saved settings Live mode still needs (empty list = ready). Reads the
    secrets themselves, so the demo placeholder base DN never counts as set."""
    return sorted(name for name in _LIVE_SECRET_NAMES.values() if not SECRETS.get(name))


print("[OK] Configuration loaded")
