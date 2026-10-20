"""
loginlock.py
============
Locks an account for 15 minutes after 5 wrong passwords in a row. A
correct password is refused while the lock is on, and the lock does not
extend if someone keeps trying.

Names that are NOT accounts are tracked in memory and treated exactly the
same way. That way the sign-in page behaves identically whether or not a
name exists. If only real accounts ever showed "locked", that message
would tell an attacker which names are real.

(Wrong two-step codes have their own counter, in twofa.py.)
"""
import threading
from datetime import datetime, timedelta, timezone

MAX_FAILED = 5
LOCK_MINUTES = 15
MAX_TRACKED_NAMES = 5000      # memory cap for names that are not accounts
NAME_LENGTH_LIMIT = 80


def _utcnow():
    """Current UTC time without a timezone label, matching the database columns"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------
# Real accounts: the counters live on the account in the database
# (these change the object; the caller saves it)
# ---------------------------------------------------------------------
def lock_seconds_left(admin, now=None):
    now = now or _utcnow()
    until = admin.login_locked_until
    if until and until > now:
        return int((until - now).total_seconds()) + 1
    return 0


def register_failure(admin, now=None):
    now = now or _utcnow()
    admin.login_failed_attempts = (admin.login_failed_attempts or 0) + 1
    if admin.login_failed_attempts >= MAX_FAILED:
        admin.login_locked_until = now + timedelta(minutes=LOCK_MINUTES)
        admin.login_failed_attempts = 0


def register_success(admin):
    admin.login_failed_attempts = 0
    admin.login_locked_until = None


def unlock(admin):
    """Clears every lock on the account: wrong passwords and wrong codes"""
    register_success(admin)
    admin.twofa_failed_attempts = 0
    admin.twofa_locked_until = None


# ---------------------------------------------------------------------
# Names that are not accounts: kept in memory only
# ---------------------------------------------------------------------
class UnknownNames:
    def __init__(self, max_entries=MAX_TRACKED_NAMES):
        self._max = max_entries
        self._data = {}
        self._mutex = threading.Lock()

    @staticmethod
    def _key(name):
        return (name or '')[:NAME_LENGTH_LIMIT]

    def lock_seconds_left(self, name, now=None):
        now = now or _utcnow()
        with self._mutex:
            entry = self._data.get(self._key(name))
            if entry and entry['locked_until'] and entry['locked_until'] > now:
                return int((entry['locked_until'] - now).total_seconds()) + 1
        return 0

    def register_failure(self, name, now=None):
        now = now or _utcnow()
        with self._mutex:
            entry = self._data.setdefault(self._key(name), {'count': 0, 'locked_until': None, 'seen': now})
            entry['count'] += 1
            entry['seen'] = now
            if entry['count'] >= MAX_FAILED:
                entry['locked_until'] = now + timedelta(minutes=LOCK_MINUTES)
                entry['count'] = 0
            if len(self._data) > self._max:
                self._prune(now)

    def _prune(self, now):
        """Keeps memory bounded when someone tries thousands of made-up names"""
        stale = timedelta(minutes=LOCK_MINUTES)
        for key in [k for k, e in self._data.items()
                    if not (e['locked_until'] and e['locked_until'] > now) and now - e['seen'] > stale]:
            del self._data[key]
        extra = len(self._data) - self._max
        if extra > 0:
            # least recently seen first, but names that are locked right now go last
            def keep_order(item):
                entry = item[1]
                return (bool(entry['locked_until'] and entry['locked_until'] > now), entry['seen'])
            for key, _ in sorted(self._data.items(), key=keep_order)[:extra]:
                del self._data[key]

    def size(self):
        with self._mutex:
            return len(self._data)
