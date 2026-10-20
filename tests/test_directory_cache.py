"""
test_directory_cache.py
=======================
Checks the directory cache logic. It does NOT touch Google or the web app:
it uses a pretend Google that is slow to show new changes, the way the real
one can be for a few seconds after a create or delete.

Run it from the project folder:
    python test_directory_cache.py          (or the venv's python.exe)

It prints PASS or FAIL for each check and exits with an error code if any
check fails.
"""
import contextlib
import io
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from directory_cache import DirectoryCache


class Clock:
    """A clock we control, so tests don't have to wait."""
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, seconds): self.t += seconds


class FakeGoogle:
    """Pretend Google. After create_group, the group list hides it for 30 seconds."""
    def __init__(self, clock):
        self.clock = clock
        self.calls = 0
        self.groups = {'it@x.com': 'IT', 'av@x.com': 'AV'}            # the truth
        self.visible_groups = dict(self.groups)                        # what list() shows
        self.members = {'it@x.com': ['a@x.com'], 'av@x.com': []}
        self.users = [{'email': 'a@x.com', 'firstName': 'A', 'lastName': 'One',
                       'fullName': 'A One', 'orgUnitPath': '/', 'suspended': False}]
        self.lag_until = 0
        self.fail_members_for = set()

    def create_group(self, email, name):
        self.groups[email] = name
        self.members[email] = []
        self.lag_until = self.clock() + 30

    def get_all_users(self):
        self.calls += 1
        return [dict(u) for u in self.users]

    def get_all_groups(self):
        self.calls += 1
        if self.clock() >= self.lag_until:
            self.visible_groups = dict(self.groups)
        return [{'email': e, 'name': n, 'description': ''} for e, n in self.visible_groups.items()]

    def get_group_members(self, email):
        self.calls += 1
        if email in self.fail_members_for:
            raise RuntimeError("Google said no")
        return list(self.members.get(email, []))


def make(**kw):
    clock = Clock()
    google = FakeGoogle(clock)
    return clock, google, DirectoryCache(lambda: google, clock=clock, **kw)

def emails(snap, key='groups'): return sorted(x['email'] for x in snap[key])
def user(snap, email): return next(u for u in snap['users'] if u['email'] == email)
def group(snap, email): return next(g for g in snap['groups'] if g['email'] == email)


# ---------------------------------------------------------------- checks
def t_old_way_pins_stale_data():
    clock, g, c = make(); c.snapshot()
    g.create_group('test@x.com', 'test'); c.invalidate()
    assert 'test@x.com' not in emails(c.snapshot())         # the bug: rebuilt while Google lagged
    clock.advance(31)                                       # Google caught up; short re-check passed
    assert 'test@x.com' in emails(c.snapshot())             # ...and the safety net healed it

def t_new_group_shows_instantly_without_asking_google():
    clock, g, c = make(); c.snapshot(); calls = g.calls
    g.create_group('test@x.com', 'test'); c.group_created('test@x.com', 'test')
    snap = c.snapshot()
    assert 'test@x.com' in emails(snap) and g.calls == calls
    assert group(snap, 'test@x.com')['memberCount'] == 0

def t_deleted_group_disappears_everywhere():
    clock, g, c = make(); c.snapshot(); c.group_deleted('it@x.com'); snap = c.snapshot()
    assert 'it@x.com' not in emails(snap) and 'it@x.com' not in snap['group_members_map']
    assert user(snap, 'a@x.com')['memberOf'] == []

def t_member_changes_update_chips_and_counts():
    clock, g, c = make(); c.snapshot()
    c.group_members_changed('av@x.com', ['a@x.com']); c.group_members_changed('it@x.com', [])
    snap = c.snapshot(); u = user(snap, 'a@x.com')
    assert u['memberOf'] == ['av@x.com'] and u['memberOfNames'] == ['AV']
    assert {x['email']: x['memberCount'] for x in snap['groups']} == {'it@x.com': 0, 'av@x.com': 1}

def t_group_rename_updates_user_chips():
    clock, g, c = make(); c.snapshot()
    c.group_updated('it@x.com', name='IT Support')
    assert user(c.snapshot(), 'a@x.com')['memberOfNames'] == ['IT Support']

def t_user_create_edit_groups_delete():
    clock, g, c = make(); c.snapshot()
    c.user_created('b@x.com', 'B', 'Two', '/Staff', ['it@x.com', 'nope@x.com'])
    b = user(c.snapshot(), 'b@x.com')
    assert b['memberOf'] == ['it@x.com'] and b['fullName'] == 'B Two' and b['orgUnitPath'] == '/Staff'
    c.user_updated('b@x.com', first_name='Bee', suspended=True)
    b = user(c.snapshot(), 'b@x.com'); assert b['fullName'] == 'Bee Two' and b['suspended'] is True
    c.user_groups_changed('b@x.com', ['av@x.com', 'nope@x.com'])
    assert user(c.snapshot(), 'b@x.com')['memberOf'] == ['av@x.com']
    c.user_deleted('b@x.com'); snap = c.snapshot()
    assert all(u['email'] != 'b@x.com' for u in snap['users'])
    assert all('b@x.com' not in m for m in snap['group_members_map'].values())

def t_repeats_and_missing_things_are_harmless():
    clock, g, c = make(); c.snapshot()
    c.group_created('it@x.com', 'IT again')                  # already exists
    c.group_deleted('ghost@x.com')                           # never existed
    c.user_deleted('ghost@x.com'); c.user_updated('ghost@x.com', first_name='X')
    snap = c.snapshot()
    assert emails(snap) == ['av@x.com', 'it@x.com'] and group(snap, 'it@x.com')['name'] == 'IT'

def t_snapshots_never_change_under_a_reader():
    clock, g, c = make(); old = c.snapshot(); c.group_deleted('it@x.com')
    assert 'it@x.com' in emails(old)

def t_normal_cache_expires_after_ten_minutes():
    clock, g, c = make(); c.snapshot(); n = g.calls
    clock.advance(599); c.snapshot(); assert g.calls == n
    clock.advance(2);   c.snapshot(); assert g.calls > n

def t_rebuild_right_after_a_change_rechecks_soon():
    clock, g, c = make(); c.group_created('t@x.com', 't')    # cache was empty
    c.snapshot(); n = g.calls
    clock.advance(15); c.snapshot(); assert g.calls == n
    clock.advance(6);  c.snapshot(); assert g.calls > n

def t_many_simultaneous_requests_cause_one_rebuild():
    clock, g, c = make()
    threads = [threading.Thread(target=c.snapshot) for _ in range(20)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert g.calls == 1 + 1 + 2                              # users + groups + 2 member lists

def t_change_made_outside_the_app_waits_for_refresh():
    clock, g, c = make(); c.snapshot()
    g.members['av@x.com'].append('a@x.com')                  # someone edits in Google Admin
    assert user(c.snapshot(), 'a@x.com')['memberOf'] == ['it@x.com']   # expected: not seen yet
    c.invalidate(provisional=False)                          # what a sync does
    assert sorted(user(c.snapshot(), 'a@x.com')['memberOf']) == ['av@x.com', 'it@x.com']
    g.members['av@x.com'].remove('a@x.com'); clock.advance(601)        # or just wait 10 minutes
    assert user(c.snapshot(), 'a@x.com')['memberOf'] == ['it@x.com']

def t_one_failing_group_does_not_break_the_rebuild():
    clock, g, c = make(); g.fail_members_for = {'av@x.com'}
    snap = c.snapshot()
    assert snap['group_members_map']['av@x.com'] == [] and snap['group_members_map']['it@x.com'] == ['a@x.com']


CHECKS = [
    ("Old clear-and-rebuild way pins stale data (the bug), then heals", t_old_way_pins_stale_data),
    ("New group shows instantly, with zero Google calls", t_new_group_shows_instantly_without_asking_google),
    ("Deleted group disappears from lists, map, and user chips", t_deleted_group_disappears_everywhere),
    ("Member changes update user chips and member counts", t_member_changes_update_chips_and_counts),
    ("Renaming a group updates the chips on its users", t_group_rename_updates_user_chips),
    ("User create / edit / change groups / delete stays consistent", t_user_create_edit_groups_delete),
    ("Repeated or missing items are harmless", t_repeats_and_missing_things_are_harmless),
    ("A snapshot already handed out never changes", t_snapshots_never_change_under_a_reader),
    ("Normal cache expires after 10 minutes", t_normal_cache_expires_after_ten_minutes),
    ("A rebuild right after a change re-checks Google within ~20s", t_rebuild_right_after_a_change_rechecks_soon),
    ("20 simultaneous requests on an empty cache cause one rebuild", t_many_simultaneous_requests_cause_one_rebuild),
    ("Change made outside the app shows up after a sync or 10 minutes", t_change_made_outside_the_app_waits_for_refresh),
    ("One group failing to load does not break the rebuild", t_one_failing_group_does_not_break_the_rebuild),
]

if __name__ == '__main__':
    failed = 0
    for i, (name, fn) in enumerate(CHECKS, 1):
        try:
            with contextlib.redirect_stdout(io.StringIO()):   # hide the cache's own log lines
                fn()
            print(f"PASS  {i:2d}. {name}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {i:2d}. {name}  ->  {type(e).__name__}: {e}")
    print(f"\n{len(CHECKS) - failed} of {len(CHECKS)} checks passed")
    sys.exit(1 if failed else 0)
