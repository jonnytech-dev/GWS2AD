"""
passwords.py
============
The rules for a new password, kept in one place so setting, changing, and
resetting a password all follow the same rules.
"""

MIN_LENGTH = 12
MAX_LENGTH = 128


def check_new_password(password, confirm, username=''):
    """Returns a message saying what is wrong, or None if the password is fine"""
    if password != confirm:
        return 'The two passwords do not match.'
    if len(password) < MIN_LENGTH:
        return f'Use at least {MIN_LENGTH} characters.'
    if len(password) > MAX_LENGTH:
        return f'Use {MAX_LENGTH} characters or fewer.'
    if username and username.lower() in password.lower():
        return 'The password cannot contain the username.'
    return None
