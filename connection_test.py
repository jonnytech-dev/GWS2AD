"""
connection_test.py
==================
Checks the saved Google Workspace, Active Directory and email settings
before the Owner switches the app from Demo to Live. Read-only: it signs in
and reads one thing from each, and changes nothing.

Each check returns (name, ok, message) with a plain-English message.
"""
import smtplib

from config import SMTP_CONFIG


def check_google():
    try:
        from gws_connector import GWSConnector
        users = GWSConnector().get_all_users()
        return ('Google Workspace', True, f'Signed in and read {len(users)} user(s).')
    except Exception as e:
        return ('Google Workspace', False, _hint_google(str(e)))


def check_ad():
    try:
        from ad_connector import ADConnector
        ad = ADConnector()
        count = len(ad.get_all_users())
        return ('Active Directory', True, f'Signed in over LDAPS and read {count} user(s) under the base DN.')
    except Exception as e:
        return ('Active Directory', False, str(e))


def check_email():
    try:
        with smtplib.SMTP(SMTP_CONFIG['smtp_server'], SMTP_CONFIG['smtp_port'], timeout=15) as server:
            server.starttls()
            server.login(SMTP_CONFIG['from_address'], SMTP_CONFIG['password'])
        return ('Email', True, 'The mail server accepted the sign-in.')
    except Exception as e:
        return ('Email', False, str(e))


def _hint_google(text):
    low = text.lower()
    if 'unauthorized_client' in low:
        return ('Google refused the delegation. In the Admin console (Security > API controls > Domain-wide delegation) '
                'the service account\'s client ID must be listed with the three Directory scopes. ' + text)
    if 'invalid_grant' in low:
        return ('Google would not let the service account act as the admin address. Check that the "admin to act as" '
                'address is a real super admin in your domain. ' + text)
    if 'no such file' in low or 'errno 2' in low:
        return 'The service account key file was not found at the saved path. ' + text
    return text


def run_all():
    """All three checks. Email is included so a bad password is caught before the first real sync."""
    return [check_google(), check_ad(), check_email()]
