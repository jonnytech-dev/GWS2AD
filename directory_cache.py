"""
directory_cache.py
==================
In-memory cache of Google Workspace users, groups, and group membership.

WHY IT EXISTS
  Building the full picture means one Google call per group (to get its
  members), which is slow. This cache does that work once and reuses it
  for the Users table, the Groups table, and every Edit modal.

HOW IT STAYS CORRECT
  Google's list endpoints are eventually consistent: for a few seconds
  after a create or delete, a list call can still return the old data.
  If we cleared the cache and immediately rebuilt it from Google after a
  change, we could save that outdated list and keep serving it.

  So after a change the app tells this cache what it just did (for
  example "group X was created") and the cache updates itself in place.
  It never has to trust Google's list right after a write. As a safety
  net the cache also expires on a timer and is rebuilt from Google.

USAGE
  cache = DirectoryCache(get_gws_connector)
  data = cache.snapshot()      # {'users': [...], 'groups': [...], 'group_members_map': {...}}
  cache.group_created(email, name, description)
  cache.group_deleted(email)
  ... see the methods below.

Reads never see a half-updated cache: every change builds a new copy and
swaps it in, so a request that already has a snapshot is unaffected.
"""

import threading
import time


class DirectoryCache:
    def __init__(self, get_connector, ttl_seconds=600, settle_seconds=90,
                 provisional_ttl_seconds=20, clock=time.time):
        # How to get a Google Workspace connector (called on each rebuild).
        self._get_connector = get_connector
        # How long a normal rebuild stays valid before the safety-net rebuild.
        self._ttl = ttl_seconds
        # A rebuild within this many seconds of a change is treated as
        # provisional: Google may not have caught up yet, so it expires
        # quickly (provisional_ttl_seconds) and gets rebuilt again.
        self._settle = settle_seconds
        self._provisional_ttl = provisional_ttl_seconds
        self._clock = clock

        self._lock = threading.RLock()
        self._state = None          # {'users', 'groups', 'group_members_map'} or None
        self._expires_at = 0.0
        self._last_write_at = -1e12

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def snapshot(self):
        """
        Returns the current data, rebuilding it from Google first if the
        cache is empty or expired. If several requests arrive at once on
        an empty cache, only one rebuilds; the rest wait and reuse it.
        Treat the returned data as read-only.
        """
        with self._lock:
            if self._state is None or self._clock() >= self._expires_at:
                self._rebuild()
            return self._state

    def invalidate(self, provisional=True):
        """
        Throws the cache away so the next read rebuilds it from Google.
        provisional=True means "something just changed" (the rebuild may
        see Google lagging, so it expires quickly). Use provisional=False
        for a plain full refresh with no recent change.
        """
        with self._lock:
            if provisional:
                self._last_write_at = self._clock()
            self._state = None
            print("[CACHE] Cleared - next read rebuilds from Google")

    # ------------------------------------------------------------------
    # Group changes
    # ------------------------------------------------------------------
    def group_created(self, email, name, description=''):
        def apply(users, groups, members):
            if not any(g['email'] == email for g in groups):
                groups.append({'email': email, 'name': name, 'description': description or ''})
            members.setdefault(email, [])
        self._patch(apply, f"group created: {email}")

    def group_deleted(self, email):
        def apply(users, groups, members):
            groups[:] = [g for g in groups if g['email'] != email]
            members.pop(email, None)
        self._patch(apply, f"group deleted: {email}")

    def group_updated(self, email, name=None, description=None):
        def apply(users, groups, members):
            for g in groups:
                if g['email'] == email:
                    if name:
                        g['name'] = name
                    if description is not None:
                        g['description'] = description
        self._patch(apply, f"group edited: {email}")

    def group_members_changed(self, group_email, member_emails):
        """Sets the full member list of one group."""
        def apply(users, groups, members):
            if group_email in members:
                members[group_email] = list(dict.fromkeys(member_emails))
        self._patch(apply, f"group members changed: {group_email}")

    # ------------------------------------------------------------------
    # User changes
    # ------------------------------------------------------------------
    def user_created(self, email, first_name, last_name, org_unit_path='/', group_emails=()):
        def apply(users, groups, members):
            if not any(u['email'] == email for u in users):
                users.append({
                    'email': email,
                    'firstName': first_name,
                    'lastName': last_name,
                    'fullName': f"{first_name} {last_name}".strip(),
                    'orgUnitPath': org_unit_path or '/',
                    'suspended': False,
                })
            for g_email in group_emails:
                if g_email in members and email not in members[g_email]:
                    members[g_email].append(email)
        self._patch(apply, f"user created: {email}")

    def user_deleted(self, email):
        def apply(users, groups, members):
            users[:] = [u for u in users if u['email'] != email]
            for g_email in members:
                members[g_email] = [m for m in members[g_email] if m != email]
        self._patch(apply, f"user deleted: {email}")

    def user_updated(self, email, first_name=None, last_name=None,
                     org_unit_path=None, suspended=None):
        def apply(users, groups, members):
            for u in users:
                if u['email'] != email:
                    continue
                if first_name:
                    u['firstName'] = first_name
                if last_name:
                    u['lastName'] = last_name
                if first_name or last_name:
                    u['fullName'] = f"{u['firstName']} {u['lastName']}".strip()
                if org_unit_path:
                    u['orgUnitPath'] = org_unit_path
                if suspended is not None:
                    u['suspended'] = suspended
        self._patch(apply, f"user edited: {email}")

    def user_groups_changed(self, email, group_emails):
        """Sets the full list of groups one user belongs to."""
        wanted = set(group_emails)
        def apply(users, groups, members):
            for g_email in members:
                present = email in members[g_email]
                if g_email in wanted and not present:
                    members[g_email].append(email)
                elif g_email not in wanted and present:
                    members[g_email] = [m for m in members[g_email] if m != email]
        self._patch(apply, f"user's groups changed: {email}")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _patch(self, apply, description):
        """
        Applies a change to a copy of the cached data, then swaps the
        copy in. If nothing is cached yet there is nothing to update:
        the next read builds from Google (and is treated as provisional).
        """
        with self._lock:
            self._last_write_at = self._clock()
            if self._state is None:
                print(f"[CACHE] {description} (cache empty - next read rebuilds)")
                return
            users = [dict(u) for u in self._state['users']]
            groups = [dict(g) for g in self._state['groups']]
            members = {k: list(v) for k, v in self._state['group_members_map'].items()}
            apply(users, groups, members)
            self._state = self._assemble(users, groups, members)
            print(f"[CACHE] Updated in place - {description}")

    def _rebuild(self):
        started = self._clock()
        gws = self._get_connector()
        users = gws.get_all_users()
        groups = gws.get_all_groups()

        members = {}
        for group in groups:
            try:
                members[group['email']] = list(gws.get_group_members(group['email']))
            except Exception as e:
                print(f"[WARN] Could not get members for group {group['email']}: {e}")
                members[group['email']] = []

        self._state = self._assemble(users, groups, members)

        now = self._clock()
        provisional = (now - self._last_write_at) < self._settle
        self._expires_at = now + (self._provisional_ttl if provisional else self._ttl)
        note = " (provisional - a change was just made, will re-check soon)" if provisional else ""
        print(f"[CACHE] Rebuilt from Google: {len(users)} users, {len(groups)} groups "
              f"in {now - started:.1f}s{note}")

    @staticmethod
    def _assemble(users, groups, members):
        """
        Builds the final cached data from the three base lists, filling in
        each user's groups (memberOf / memberOfNames) and each group's
        memberCount. Always works on copies of the dicts it is given.
        """
        group_names = {g['email']: g['name'] for g in groups}

        memberships = {}
        for g_email, member_list in members.items():
            for m in member_list:
                memberships.setdefault(m, []).append(g_email)

        out_users = []
        for u in users:
            u = dict(u)
            emails = memberships.get(u['email'], [])
            u['memberOf'] = list(emails)
            u['memberOfNames'] = [group_names.get(e, e) for e in emails]
            out_users.append(u)

        out_groups = []
        for g in groups:
            g = dict(g)
            g['memberCount'] = len(members.get(g['email'], []))
            out_groups.append(g)

        return {
            'users': out_users,
            'groups': out_groups,
            'group_members_map': {k: list(v) for k, v in members.items()},
        }
