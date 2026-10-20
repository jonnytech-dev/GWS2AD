#!/usr/bin/env python3
"""
setup_secrets.py
================
Creates and updates the encrypted settings file (secrets.json.enc).

First run (about a minute, no Google or AD details needed):
    python setup_secrets.py
  Asks for the Owner login and starts the app in Demo mode on sample data.

Later, when you are ready to connect your real systems:
    python setup_secrets.py --live
  Asks for the Google Workspace, Active Directory and email details and adds
  them to the existing file. Then use Settings > Connection to switch to Live.

For scripts and containers, set GWS2AD_OWNER_USERNAME and GWS2AD_OWNER_PASSWORD
and add --non-interactive to the first run.

Nothing is stored in plain text. The file is encrypted with a key kept in
.env (or the SECRETS_KEY environment variable). Never commit either one.
"""
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ROOT = Path(__file__).parent
ENC_FILE = ROOT / "secrets.json.enc"
ENV_FILE = ROOT / ".env"


def _read_key():
    """The saved encryption key, from the environment or .env, or None."""
    key = os.getenv("SECRETS_KEY")
    if key:
        return key
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("SECRETS_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def _load_existing():
    key = _read_key()
    if not (key and ENC_FILE.exists()):
        return None, None
    try:
        return json.loads(Fernet(key.encode()).decrypt(ENC_FILE.read_bytes())), key
    except (InvalidToken, ValueError):
        return None, None


def _save(secrets, key):
    ENC_FILE.write_bytes(Fernet(key.encode()).encrypt(json.dumps(secrets, indent=2).encode()))
    try:
        os.chmod(ENC_FILE, 0o600)
    except OSError:
        pass  # Windows ignores this


def _write_env_key(key):
    lines = []
    if ENV_FILE.exists():
        lines = [l for l in ENV_FILE.read_text().splitlines() if not l.startswith("SECRETS_KEY=")]
    lines.append(f"SECRETS_KEY={key}")
    ENV_FILE.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


def _ask(label, default=""):
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ").strip() or default


def _ask_secret(label, minimum=1):
    while True:
        value = getpass.getpass(f"{label}: ").strip()
        if len(value) >= minimum:
            return value
        print(f"  Too short. Use at least {minimum} characters.")


def _ask_new_password(label, minimum=8):
    """Ask for a password, then ask to confirm it. A wrong confirmation only repeats the confirmation."""
    password = _ask_secret(label, minimum)
    while True:
        if getpass.getpass("Confirm password: ").strip() == password:
            return password
        print("  The passwords do not match. Confirm it again.")


def first_run(non_interactive=False):
    existing, _ = _load_existing()
    if existing is not None or ENC_FILE.exists():
        print("Settings already exist. To add your Google / AD / email details run:")
        print("    python setup_secrets.py --live")
        print("To start over, delete secrets.json.enc and .env first.")
        return False

    print("\nGWS2AD first-time setup\n" + "=" * 40)
    if non_interactive:
        username = os.getenv("GWS2AD_OWNER_USERNAME", "")
        password = os.getenv("GWS2AD_OWNER_PASSWORD", "")
        if not username or len(password) < 8:
            print("[ERROR] Set GWS2AD_OWNER_USERNAME and GWS2AD_OWNER_PASSWORD (8+ characters).")
            return False
    else:
        print("This creates the Owner login for the web app. The app starts in Demo mode,")
        print("so you do not need any Google or Active Directory details yet.\n")
        username = _ask("Owner username", "owner")
        password = _ask_new_password("Owner password (8+ characters)", 8)

    key = Fernet.generate_key().decode()
    _save({
        "flask_secret_key": Fernet.generate_key().decode(),
        "admin_username": username,
        "admin_password": password,
    }, key)
    _write_env_key(key)
    print("\n[OK] Saved. Start the app with:  python app.py")
    print("     Sign in as", username, "- you will be asked to set up two-step verification.")
    print("     When you are ready for real data:  python setup_secrets.py --live\n")
    return True


def add_live_settings():
    secrets, key = _load_existing()
    if secrets is None:
        print("[ERROR] No readable settings file. Run  python setup_secrets.py  first.")
        return False

    print("\nGWS2AD - connect your real systems\n" + "=" * 40)
    print("See docs/going-live.md for how to get each value.\n")

    print("--- Google Workspace ---")
    secrets["gws_key_path"] = _ask("Path to the service account key (.json)", secrets.get("gws_key_path", ""))
    secrets["gws_subject"] = _ask("Super admin email the service account acts as", secrets.get("gws_subject", ""))
    secrets["gws_customer"] = _ask("Customer ID", secrets.get("gws_customer", "my_customer"))

    print("\n--- Active Directory ---")
    secrets["ad_server"] = _ask("Domain controller host name", secrets.get("ad_server", ""))
    print("Base DN: where everything lives. A dedicated OU is safest, e.g. OU=GWS-Sync,DC=corp,DC=example,DC=com")
    secrets["ad_base_dn"] = _ask("Base DN", secrets.get("ad_base_dn", ""))
    secrets["ad_bind_dn"] = _ask("Service account DN or user principal name", secrets.get("ad_bind_dn", ""))
    secrets["ad_bind_password"] = _ask_secret("Service account password") if not secrets.get("ad_bind_password") \
        else (getpass.getpass("Service account password (Enter keeps the saved one): ").strip() or secrets["ad_bind_password"])

    print("\n--- Email (sends new people their account details) ---")
    secrets["smtp_server"] = _ask("Mail server", secrets.get("smtp_server", "smtp.gmail.com"))
    secrets["smtp_port"] = _ask("Port (STARTTLS)", str(secrets.get("smtp_port", "587")))
    secrets["smtp_from_address"] = _ask("Send from address", secrets.get("smtp_from_address", ""))
    secrets["smtp_password"] = _ask_secret("Mail password or Gmail app password") if not secrets.get("smtp_password") \
        else (getpass.getpass("Mail password (Enter keeps the saved one): ").strip() or secrets["smtp_password"])

    missing = [k for k in ("gws_key_path", "gws_subject", "ad_server", "ad_base_dn", "ad_bind_dn",
                           "ad_bind_password", "smtp_from_address", "smtp_password") if not secrets.get(k)]
    if missing:
        print("\n[ERROR] These are still empty, nothing was saved:", ", ".join(missing))
        return False

    _save(secrets, key)
    print("\n[OK] Saved. Restart the app, then sign in as the Owner and open Settings > Connection to run the check and go Live.\n")
    return True


if __name__ == "__main__":
    if "--live" in sys.argv:
        ok = add_live_settings()
    else:
        ok = first_run(non_interactive="--non-interactive" in sys.argv)
    sys.exit(0 if ok else 1)
