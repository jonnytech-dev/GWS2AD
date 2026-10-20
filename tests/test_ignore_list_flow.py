"""
test_ignore_list_flow.py
========================
The Ignore list page (Settings), the "N ignored" link on the dashboard, who may see or change the list,
and what the dashboard status counts as a difference (including group membership changes).
Runs on the REAL app with the Demo connectors.

    python tests/test_ignore_list_flow.py
"""
import json
import re
import test_support as T

env = T.build()
H = T.Helpers(env)


def api(method, path, body=None):
    r = H.client.open(path, method=method, json=body)
    return r.status_code, (r.get_json(silent=True) or {})


def reset():
    from mock_connectors import reset_demo_data
    reset_demo_data()
    with env.flask_app.app_context():
        env.db.session.execute(env.db.text('DELETE FROM ignored_sync_items'))
        env.db.session.commit()


def page():
    r = H.GET('/settings/ignored')
    assert r.status_code == 200, r.status_code
    return H.html(r)


def remove(item_type, identifier, token=True):
    form = {'type': item_type, 'identifier': identifier}
    if token:
        form['csrf_token'] = H.csrf(page())
    return H.POST('/settings/ignored/remove', form)


def sign_in():
    H.enroll('admin')


def an_empty_list_says_so():
    reset()
    html = page()
    assert 'Nothing is ignored' in html and 'id="ignoreTable"' not in html
    assert 'href="/settings/ignored"' in html and '>Ignore list</a>' in html      # the tab


def items_show_with_type_who_and_when():
    api('POST', '/api/ignored-items', {'type': 'user', 'identifier': 'old.contractor@example.com'})
    api('POST', '/api/ignored-items', {'type': 'group', 'identifier': 'oldgroup'})
    api('POST', '/api/ignored-items', {'type': 'ou', 'identifier': 'ou=old interns,ou=gws-sync,dc=demo,dc=example,dc=com'})
    html = page()
    for text in ('old.contractor@example.com', 'oldgroup', 'ou=old interns,ou=gws-sync'):
        assert text in html, text
    assert html.count('class="type-tag type-') == 3 and 'type-ou' in html
    assert html.count('>admin</td>') == 3, 'who added each one'
    assert re.search(r'<td>20\d\d-\d\d-\d\d</td>', html), 'when'
    assert html.count('>Stop ignoring</button>') == 3
    assert 'id="ignoreSearch"' in html and 'id="ignoreType"' in html


def names_are_escaped():
    api('POST', '/api/ignored-items', {'type': 'user', 'identifier': '<script>alert(1)</script>@x.org', 'reason': '<b>why</b>'})
    html = page()
    assert '<script>alert(1)' not in html and '&lt;script&gt;alert(1)' in html
    assert '<b>why</b>' not in html and '&lt;b&gt;why&lt;/b&gt;' in html
    remove('user', '<script>alert(1)</script>@x.org')


def removing_from_the_page_works_and_is_audited():
    r = remove('group', 'oldgroup')
    assert r.status_code == 302 and 'notice=ignore_removed' in H.location(r), H.location(r)
    after = H.html(H.GET(H.location(r)))
    assert 'Removed from the ignore list' in after and 'oldgroup' not in after
    assert 'old.contractor@example.com' in after, 'only the one item goes'
    assert 'remove_ignored_item' in H.audit_actions()
    # an identifier with commas and equals signs (an OU) survives the round trip
    r = remove('ou', 'ou=old interns,ou=gws-sync,dc=demo,dc=example,dc=com')
    assert r.status_code == 302 and 'ou=old interns' not in page()


def bad_requests_are_refused():
    assert remove('computer', 'x').status_code == 400
    assert remove('user', '').status_code == 400
    assert remove('user', 'old.contractor@example.com', token=False).status_code == 400
    assert 'old.contractor@example.com' in page(), 'a refused request changes nothing'
    assert remove('user', 'nobody@example.com').status_code == 302, 'removing something that is not there is harmless'


def the_dashboard_shows_how_many_are_ignored():
    reset()
    assert api('GET', '/api/sync-status')[1]['ignored_count'] == 0
    api('POST', '/api/ignored-items', {'type': 'user', 'identifier': 'old.contractor@example.com'})
    assert api('GET', '/api/sync-status')[1]['ignored_count'] == 1
    html = H.html(H.GET('/dashboard'))
    assert 'id="ignoredLink"' in html and 'href="/settings/ignored"' in html
    assert 'id="confirmSyncBtn"' in html


def the_dashboard_status_counts_group_membership_changes():
    """A member added or removed in Google is a difference. The status must not say Synced while the preview lists it."""
    from mock_connectors import get_mock_gws
    reset()
    s, r = api('POST', '/api/sync')
    assert s == 200 and r['success'], r
    s, status = api('GET', '/api/sync-status')
    assert status['status'] == 'synced', status

    gws = get_mock_gws()
    group = next(g['email'] for g in gws.get_all_groups() if gws.get_group_members(g['email']))
    newcomer = next(u['email'] for u in gws.get_all_users() if u['email'] not in gws.get_group_members(group))
    gws.add_group_member(group, newcomer)                            # a change made in Google only

    s, preview = api('GET', '/api/sync-preview')
    assert len(preview['group_membership_changes']) == 1, preview['group_membership_changes']
    s, status = api('GET', '/api/sync-status')
    assert status['status'] == 'out_of_sync', status
    assert '1 group membership change' in status['last_error'], status['last_error']

    s, r = api('POST', '/api/sync')
    assert s == 200 and r['success'], r
    assert api('GET', '/api/sync-status')[1]['status'] == 'synced', 'applying the change clears it'

    gws.remove_group_member(group, newcomer)                         # and a removal counts the same way
    status = api('GET', '/api/sync-status')[1]
    assert status['status'] == 'out_of_sync' and '1 group membership change' in status['last_error'], status
    api('POST', '/api/sync')
    assert api('GET', '/api/sync-status')[1]['status'] == 'synced'


def a_view_only_account_cannot_see_or_change_the_list():
    H.enroll('viewer')
    assert H.GET('/settings/ignored').status_code == 403
    assert H.POST('/settings/ignored/remove', {'type': 'user', 'identifier': 'x'}).status_code == 403
    assert 'Ignore list' not in H.html(H.GET('/settings/profile'))
    assert 'id="ignoredLink"' not in H.html(H.GET('/dashboard'))
    H.sign_in('admin')
    assert 'old.contractor@example.com' in page(), 'nothing was removed by the refused request'


def a_preview_only_account_can_read_but_not_change():
    with env.flask_app.app_context():
        env.db.session.execute(env.db.text("UPDATE admins SET custom_permissions = :p WHERE username = 'viewer'"),
                               {'p': json.dumps(['preview_sync'])})
        env.db.session.commit()
    H.sign_in('viewer')
    html = page()
    assert 'old.contractor@example.com' in html
    assert '>Stop ignoring</button>' not in html and '/settings/ignored/remove' not in html
    assert H.POST('/settings/ignored/remove', {'type': 'user', 'identifier': 'old.contractor@example.com'}).status_code == 403
    assert 'Ignore list' in H.html(H.GET('/settings/profile'))
    H.sign_in('admin')
    assert 'old.contractor@example.com' in page()


def save_note(item_type, identifier, note, token=True):
    form = {'type': item_type, 'identifier': identifier, 'note': note}
    if token:
        form['csrf_token'] = H.csrf(page())
    return H.POST('/settings/ignored/note', form)


def a_note_says_why_and_shows_everywhere():
    reset()
    s, r = api('POST', '/api/ignored-items', {'type': 'user', 'identifier': 'old.contractor@example.com', 'reason': '  Contractor,   keep until June  '})
    assert s == 200
    assert 'Why:</span> Contractor, keep until June' in page(), 'spaces are tidied'
    p = api('GET', '/api/sync-preview')[1]
    mine = [u for u in p['users_to_delete'] if u['email'] == 'old.contractor@example.com'][0]
    assert mine['ignored'] and mine['note'] == 'Contractor, keep until June'
    assert [i for i in api('GET', '/api/ignored-items')[1]['ignored_items'] if i['identifier'] == 'old.contractor@example.com'][0]['reason'] == 'Contractor, keep until June'


def old_default_text_and_empty_notes_count_as_no_note():
    api('POST', '/api/ignored-items', {'type': 'group', 'identifier': 'g1', 'reason': 'Ignored via sync preview'})
    api('POST', '/api/ignored-items', {'type': 'group', 'identifier': 'g2', 'reason': '   '})
    html = page()
    assert 'Ignored via sync preview' not in html
    assert html.count('Add a note') == 2 and html.count('Edit note') == 1
    items = {i['identifier']: i['reason'] for i in api('GET', '/api/ignored-items')[1]['ignored_items']}
    assert items['g1'] is None and items['g2'] is None


def notes_have_a_length_limit():
    ok = 'x' * 200
    assert api('POST', '/api/ignored-items', {'type': 'group', 'identifier': 'g3', 'reason': ok})[0] == 200
    s, r = api('POST', '/api/ignored-items', {'type': 'group', 'identifier': 'g4', 'reason': ok + 'y'})
    assert s == 400 and 'too long' in r['error']
    assert 'g4' not in page()


def a_note_can_be_added_changed_and_cleared_from_the_page():
    r = save_note('group', 'g1', 'Shared mailbox')
    assert r.status_code == 302 and 'notice=ignore_note_saved' in H.location(r)
    assert 'Why:</span> Shared mailbox' in page()
    save_note('group', 'g1', 'Shared mailbox, still used')
    assert 'Shared mailbox, still used' in page() and html_count('Why:</span> Shared mailbox</div>') == 0
    save_note('group', 'g1', '')
    assert 'Shared mailbox' not in page()
    assert 'edit_ignored_note' in H.audit_actions()


def html_count(text):
    return page().count(text)


def note_edits_are_checked():
    assert save_note('group', 'g1', 'z' * 201).status_code == 400
    assert save_note('group', 'nope', 'x').status_code == 404, 'only items on the list can get a note'
    assert save_note('computer', 'g1', 'x').status_code == 400
    assert save_note('group', 'g1', 'x', token=False).status_code == 400
    save_note('user', 'old.contractor@example.com', '<script>alert(1)</script>')
    html = page()
    assert '<script>alert(1)' not in html and '&lt;script&gt;alert(1)' in html


def only_people_who_can_change_the_list_can_edit_notes():
    H.sign_in('viewer')                         # preview-only from the earlier step
    html = page()
    assert 'Edit note' not in html and 'Add a note' not in html and 'name="note"' not in html
    assert H.POST('/settings/ignored/note', {'type': 'group', 'identifier': 'g1', 'note': 'x'}).status_code == 403
    H.sign_in('admin')


STEPS = [
    ("Sign in as the Owner", sign_in),
    ("An empty list says so, and the tab is there", an_empty_list_says_so),
    ("Items show with type, who added them and when", items_show_with_type_who_and_when),
    ("Names and notes are escaped", names_are_escaped),
    ("Removing from the page works and is audited", removing_from_the_page_works_and_is_audited),
    ("Bad requests are refused and change nothing", bad_requests_are_refused),
    ("The dashboard shows how many are ignored", the_dashboard_shows_how_many_are_ignored),
    ("A view-only account cannot see or change the list", a_view_only_account_cannot_see_or_change_the_list),
    ("A preview-only account can read the list but not change it", a_preview_only_account_can_read_but_not_change),
    ("A note says why, and shows on the page, in the preview data and in the API", a_note_says_why_and_shows_everywhere),
    ("The old default text and empty notes count as no note", old_default_text_and_empty_notes_count_as_no_note),
    ("Notes are limited to 200 characters", notes_have_a_length_limit),
    ("A note can be added, changed and cleared from the page", a_note_can_be_added_changed_and_cleared_from_the_page),
    ("Note edits are checked: length, unknown items, type, CSRF, escaping", note_edits_are_checked),
    ("Only people who can change the list can edit notes", only_people_who_can_change_the_list_can_edit_notes),
    ("The dashboard status counts group membership changes, not only creates, updates and deletes", the_dashboard_status_counts_group_membership_changes),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
