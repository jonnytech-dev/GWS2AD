"""
test_reset_portal_flow.py
=========================
The self-service password reset page (reset_portal.py): a person asks for a code,
gets it at their work email, enters it, and chooses a new password, which is set
in Active Directory and in Google. Runs the real pages on the Demo connectors, and
for the mail steps pretends to be Live with a stand-in for the mail server.

    python tests/test_reset_portal_flow.py
"""
import glob
import json
import os
import re
import socket
import time
import urllib.request

import test_support as T

env = T.build()
import reset_portal as rp                                    # copied into the throwaway project by build()
from mock_connectors import get_mock_gws, get_mock_ad, reset_demo_data

rp.RUN_IN_BACKGROUND = False
portal = rp.create_app()
portal.config['TESTING'] = True

PASSWORD = 'a brand new passphrase 42'
_next_ip = [10]


class Person:
    """One visitor with their own cookies and their own address"""

    def __init__(self):
        _next_ip[0] += 1
        self.ip = f'10.9.0.{_next_ip[0]}'
        self.c = portal.test_client()
        self.c.environ_base['REMOTE_ADDR'] = self.ip
        self.c.environ_base['wsgi.url_scheme'] = 'https'

    def get(self, path):
        return self.c.get(path)

    def post(self, path, data):
        return self.c.post(path, data=data)

    @staticmethod
    def html(r):
        return r.get_data(as_text=True)

    @staticmethod
    def token(page):
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def ask(self, email):
        """Types an address on the first page. Returns the page they land on."""
        page = self.html(self.get('/'))
        r = self.post('/request', {'csrf_token': self.token(page), 'email': email})
        assert r.status_code == 303, (r.status_code, self.html(r)[:300])
        return self.html(self.get(r.headers['Location']))

    def enter(self, code):
        page = self.html(self.get('/verify'))
        return self.post('/verify', {'csrf_token': self.token(page), 'code': code})

    def choose(self, password, confirm=None):
        page = self.html(self.get('/new-password'))
        return self.post('/new-password', {'csrf_token': self.token(page), 'password': password,
                                           'confirm': password if confirm is None else confirm})


def rows(email=None):
    with portal.app_context():
        q = rp.PasswordResetRequest.query
        if email:
            q = q.filter_by(email=email)
        return q.order_by(rp.PasswordResetRequest.id).all()


def clear_rows():
    with portal.app_context():
        rp.PasswordResetRequest.query.delete()
        rp.db.session.commit()
    rp._wrong_codes.clear()


def demo_code(page):
    m = re.search(r'here is your code: <strong>(\d{6})</strong>', page)
    return m.group(1) if m else None


def audit_actions(email=None):
    with portal.app_context():
        q = env.AuditLog.query.filter_by(admin_username='self-service')
        return [(a.action, a.status, a.target, a.details) for a in q.order_by(env.AuditLog.id).all()
                if not email or a.target == f'user:{email}']


def sameness(page):
    """A page with the one-off token taken out, so two pages can be compared"""
    page = re.sub(r'<strong>[^<@]+@[^<]+</strong>', '<strong>ADDRESS</strong>', page)     # the page repeats what the person typed
    return re.sub(r'name="csrf_token" value="[^"]+"', 'name="csrf_token" value="X"', page)


# --- Live-like: no Demo code on the page, and a stand-in mail server ---------------------------
class Wrap:
    """The sample Google, with chosen people changed (say, suspended)"""
    changes = {}

    def __init__(self, inner):
        self.inner = inner

    def get_user_security_info(self, email):
        info = self.inner.get_user_security_info(email)
        if info and info['email'] in Wrap.changes:
            info = {**info, **Wrap.changes[info['email']]}
        return info

    def __getattr__(self, name):
        return getattr(self.inner, name)


class FakeMail:
    sent = []
    fail = False

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        pass

    def login(self, *a):
        pass

    def send_message(self, msg):
        if FakeMail.fail:
            raise OSError('boom: smtp.internal.example refused 535 5.7.8 credentials')
        FakeMail.sent.append({'to': msg['To'], 'subject': msg['Subject'], 'body': msg.get_payload()})


_real = {}


def go_live():
    _real.update(demo=rp.mode.is_demo, smtp=rp.smtplib.SMTP, gws=rp.get_gws_connector, ad=rp.get_ad_connector)
    rp.mode.is_demo = lambda: False
    rp.smtplib.SMTP = FakeMail
    rp.get_gws_connector = lambda: Wrap(get_mock_gws())
    rp.get_ad_connector = lambda: get_mock_ad()
    FakeMail.sent.clear()
    FakeMail.fail = False


def go_demo():
    rp.mode.is_demo = _real['demo']
    rp.smtplib.SMTP = _real['smtp']
    rp.get_gws_connector = _real['gws']
    rp.get_ad_connector = _real['ad']
    Wrap.changes = {}


def code_in_mail(to):
    mails = [m for m in FakeMail.sent if m['to'] == to and 'code' in m['subject']]
    assert mails, (to, FakeMail.sent)
    return re.search(r'Your code is:\s+(\d{6})', mails[-1]['body']).group(1)


# --- the steps ------------------------------------------------------------------------------
def start_page_is_plain_and_locked_down():
    reset_demo_data()
    rp._wrong_codes.clear()
    p = Person()
    r = p.get('/')
    html = p.html(r)
    assert r.status_code == 200 and 'Send me a code' in html and 'type="email"' in html
    assert '<script' not in html.lower(), 'no JavaScript at all'
    h = r.headers
    assert 'no-store' in h['Cache-Control'] and h['X-Frame-Options'] == 'DENY' and h['X-Content-Type-Options'] == 'nosniff'
    assert "default-src 'none'" in h['Content-Security-Policy'] and "frame-ancestors 'none'" in h['Content-Security-Policy']
    assert 'reset_session=' in h.get('Set-Cookie', ''), 'its own cookie, not the dashboard\'s'
    assert 'Secure' in h['Set-Cookie'] and 'SameSite=Strict' in h['Set-Cookie']
    assert 'max-age' in h['Strict-Transport-Security']
    assert 'Demo mode' in html


def a_wrong_address_shape_is_refused_before_anything_happens():
    p = Person()
    page = p.html(p.get('/'))
    for bad in ('', 'not an address', 'a@b', "x*)(uid=*@example.com", 'a b@example.com', 'x' * 300 + '@example.com'):
        r = p.post('/request', {'csrf_token': p.token(page), 'email': bad})
        assert r.status_code == 400 and 'Enter your work email address' in p.html(r), repr(bad)
    assert not rows(), 'nothing was recorded'


def demo_mode_shows_the_code_and_the_right_code_opens_the_next_page():
    p = Person()
    page = p.ask('praman@example.com')
    code = demo_code(page)
    assert code and 'no email is sent' in page
    r = p.enter(code)
    assert r.status_code == 303 and r.headers['Location'].endswith('/new-password'), r.status_code
    assert 'Choose your new password' in p.html(p.get('/new-password'))


def stored_values_are_only_hashes():
    row = rows('praman@example.com')[0]
    assert row.eligible and row.verified_at and len(row.code_hash) == 64 and len(row.token_hash) == 64
    assert row.code_expires_at > row.created_at


def a_new_password_must_follow_the_rules():
    p = Person()
    code = demo_code(p.ask('smarin@example.com'))
    assert p.enter(code).status_code == 303
    for pw, confirm, expect in (('short', None, 'at least'), (PASSWORD, 'something else entirely', 'do not match'),
                                ('my smarin password 123', None, 'cannot contain the username')):
        r = p.choose(pw, confirm)
        assert r.status_code == 400 and expect in p.html(r), (pw, p.html(r)[:400])
    assert get_mock_ad().users['smarin@example.com'].get('passwordChanges', 0) == 0
    assert get_mock_gws()._user('smarin@example.com').get('passwordChanges', 0) == 0


def the_password_is_set_in_active_directory_and_in_google_and_only_once():
    p = Person()
    code = demo_code(p.ask('lwalsh@example.com'))
    assert p.enter(code).status_code == 303
    r = p.choose(PASSWORD)
    assert r.status_code == 303 and r.headers['Location'].endswith('/done')
    assert 'has been changed' in p.html(p.get('/done'))
    assert get_mock_ad().users['lwalsh@example.com']['passwordChanges'] == 1, 'Active Directory'
    assert get_mock_gws()._user('lwalsh@example.com')['passwordChanges'] == 1, 'Google'
    # the same visit cannot be used again
    assert p.get('/new-password').status_code == 302
    assert p.post('/new-password', {'csrf_token': 'x', 'password': PASSWORD, 'confirm': PASSWORD}).status_code in (302, 400)
    assert get_mock_ad().users['lwalsh@example.com']['passwordChanges'] == 1
    stranger = Person()                                       # a new browser holding the used code
    assert stranger.get('/verify').status_code == 302, 'no request in this browser, so back to the start'
    assert stranger.post('/verify', {'csrf_token': 'x', 'code': code}).status_code == 302
    assert [a for a in audit_actions('lwalsh@example.com') if a[0] == 'reset_password_changed' and a[1] == 'success']


def wrong_codes_burn_the_code_after_five_tries():
    p = Person()
    page = p.ask('abello@example.com')
    code = demo_code(page)
    wrong = '000000' if code != '000000' else '111111'
    for i in range(5):
        r = p.enter(wrong)
        assert r.status_code == 400 and 'not right, or it has expired' in p.html(r)
    r = p.enter(code)                                         # even the right one is now useless
    assert r.status_code == 400, 'the code was burned'
    assert rows('abello@example.com')[0].used


def a_code_stops_working_after_ten_minutes():
    p = Person()
    code = demo_code(p.ask('jokafor@example.com'))
    T.advance(11 * 60)
    r = p.enter(code)
    assert r.status_code == 400 and 'expired' in p.html(r)


def a_password_must_be_chosen_within_ten_minutes_of_the_code():
    p = Person()
    code = demo_code(p.ask('dkim@example.com'))
    assert p.enter(code).status_code == 303
    T.advance(11 * 60)
    assert p.get('/new-password').status_code == 302, 'the token ran out'
    assert get_mock_ad().users['dkim@example.com'].get('passwordChanges', 0) == 0


def requests_are_limited_per_address_and_per_computer():
    reset_demo_data()
    clear_rows()                                              # start the counting from nothing
    for i in range(3):
        assert demo_code(Person().ask('praman@example.com')), i
    fourth = Person().ask('praman@example.com')
    assert not demo_code(fourth), 'a fourth request in an hour gets no code'
    assert 'on its way' in fourth, 'but the person sees the same page'
    assert any(a[0] == 'reset_rate_limited' for a in audit_actions('praman@example.com'))
    one = Person()
    for i in range(rp.MAX_REQUESTS_PER_IP):
        one.ask(f'user{i}@example.com')
    assert len(rows('user0@example.com')) == 1
    one.ask('lastone@example.com')
    assert not rows('lastone@example.com'), 'the eleventh request from one computer is dropped'


def a_wrong_or_borrowed_token_does_not_open_the_password_page():
    clear_rows()
    p = Person()
    code = demo_code(p.ask('dkim@example.com'))
    assert p.enter(code).status_code == 303
    with p.c.session_transaction() as sess:
        sess['reset_token'] = 'not-the-real-token'
    assert p.get('/new-password').status_code == 302
    assert get_mock_ad().users['dkim@example.com'].get('passwordChanges', 0) == 0


def too_many_wrong_codes_from_one_computer_locks_that_computer_out():
    rp._wrong_codes.clear()
    p = Person()
    p.ask('abello@example.com')
    for i in range(rp.MAX_WRONG_CODES_PER_IP):
        p.enter('123456')
    r = p.enter('123456')
    assert r.status_code == 429 and 'Too many tries' in p.html(r)
    rp._wrong_codes.clear()


def pages_without_a_form_token_do_nothing():
    reset_demo_data()
    rp._wrong_codes.clear()
    p = Person()
    p.get('/')
    assert p.post('/request', {'email': 'praman@example.com'}).status_code == 400
    assert p.post('/request', {'csrf_token': 'wrong', 'email': 'praman@example.com'}).status_code == 400
    before = len(rows())
    p.ask('lwalsh@example.com')
    assert p.post('/verify', {'code': '123456'}).status_code == 400
    assert len(rows()) == before + 1


def live_like_every_kind_of_address_gets_the_same_answer():
    reset_demo_data()
    clear_rows()
    go_live()
    try:
        Wrap.changes = {'jokafor@example.com': {'suspended': True}}
        pages = {}
        for label, email in (('works', 'dkim@example.com'), ('unknown', 'nobody@example.com'),
                             ('super admin', 'malvarez@example.com'), ('not in AD', 'nfischer@example.com'),
                             ('suspended', 'jokafor@example.com')):
            pages[label] = sameness(Person().ask(email))
        for label, page in pages.items():
            assert page == pages['works'], f'{label} gets a different page'
        assert 'here is your code' not in pages['works'], 'the code is never on the page when it is emailed'
        eligible = [r.email for r in rows() if r.eligible]
        assert eligible == ['dkim@example.com'], eligible
        reasons = {a[2]: json.loads(a[3])['reason'] for a in audit_actions() if a[1] == 'failed' and a[3] and 'reason' in a[3]}
        assert 'Google admin' in reasons['user:malvarez@example.com']
        assert 'suspended' in reasons['user:jokafor@example.com']
        assert 'no Active Directory account' in reasons['user:nfischer@example.com']
        assert 'not in Google' in reasons['user:nobody@example.com']
    finally:
        go_demo()


def live_like_the_code_goes_to_the_work_email_and_both_passwords_change():
    reset_demo_data()
    clear_rows()
    go_live()
    try:
        p = Person()
        page = p.ask('smarin@example.com')
        assert 'here is your code' not in page
        assert [m['to'] for m in FakeMail.sent] == ['smarin@example.com'], FakeMail.sent
        code = code_in_mail('smarin@example.com')
        assert p.enter('000000' if code != '000000' else '111111').status_code == 400
        assert p.enter(code).status_code == 303
        assert p.choose(PASSWORD).status_code == 303
        assert get_mock_ad().users['smarin@example.com']['passwordChanges'] == 1
        assert get_mock_gws()._user('smarin@example.com')['passwordChanges'] == 1
        notices = [m for m in FakeMail.sent if 'was changed' in m['subject']]
        assert [m['to'] for m in notices] == ['smarin@example.com'], 'the work mailbox is told; the recovery one is never used'
        assert not any('example.net' in m['to'] for m in FakeMail.sent), 'the recovery address is never mailed'
        assert all(PASSWORD not in m['body'] and code not in m['body'] for m in notices)
    finally:
        go_demo()


def if_google_cannot_be_reached_nothing_is_changed_anywhere():
    reset_demo_data()
    clear_rows()
    p = Person()
    code = demo_code(p.ask('abello@example.com'))
    assert code
    real = get_mock_gws().update_user
    get_mock_gws().update_user = lambda *a, **k: (_ for _ in ()).throw(Exception('Google is down'))
    try:
        assert p.enter(code).status_code == 303
        r = p.choose(PASSWORD)
        assert r.status_code == 400 and 'Nothing was changed' in p.html(r)
        assert get_mock_ad().users['abello@example.com'].get('passwordChanges', 0) == 0, 'Active Directory was not touched'
        assert any('nothing was changed' in (a[3] or '') for a in audit_actions('abello@example.com'))
    finally:
        get_mock_gws().update_user = real
    r = p.choose(PASSWORD)                                    # Google is back: the same visit can finish
    assert r.status_code == 303
    assert get_mock_ad().users['abello@example.com']['passwordChanges'] == 1
    assert get_mock_gws()._user('abello@example.com')['passwordChanges'] == 1


def if_active_directory_refuses_the_person_can_choose_another_and_both_are_set():
    reset_demo_data()
    clear_rows()
    p = Person()
    code = demo_code(p.ask('jokafor@example.com'))
    real = get_mock_ad().update_user
    get_mock_ad().update_user = lambda *a, **k: (False, 'too simple')
    try:
        assert p.enter(code).status_code == 303
        r = p.choose(PASSWORD)
        assert r.status_code == 400 and 'did not accept' in p.html(r)
        assert any('Active Directory password not' in (a[3] or '') for a in audit_actions('jokafor@example.com'))
    finally:
        get_mock_ad().update_user = real
    assert p.choose(PASSWORD + '!').status_code == 303
    assert get_mock_ad().users['jokafor@example.com']['passwordChanges'] == 1
    assert get_mock_gws()._user('jokafor@example.com')['passwordChanges'] == 2, 'Google was set again with the new choice'


def google_is_changed_before_active_directory():
    reset_demo_data()
    clear_rows()
    order = []
    g, a = get_mock_gws(), get_mock_ad()
    rg, ra = g.update_user, a.update_user
    g.update_user = lambda *x, **k: (order.append('google'), rg(*x, **k))[1]
    a.update_user = lambda *x, **k: (order.append('ad'), ra(*x, **k))[1]
    try:
        p = Person()
        assert p.enter(demo_code(p.ask('dkim@example.com'))).status_code == 303
        assert p.choose(PASSWORD).status_code == 303
    finally:
        g.update_user, a.update_user = rg, ra
    assert order == ['google', 'ad'], order


def the_pages_never_name_the_admin_panel_or_the_web_server():
    clear_rows()
    p = Person()
    pages = {'start': p.html(p.get('/'))}
    code = demo_code(p.ask('dkim@example.com'))
    pages['verify'] = p.html(p.get('/verify'))
    assert p.enter(code).status_code == 303
    pages['new-password'] = p.html(p.get('/new-password'))
    r = p.choose(PASSWORD)
    pages['done'] = p.html(p.get('/done'))
    for name, html in pages.items():
        low = html.lower()
        assert 'gws' not in low and 'admin panel' not in low and 'dashboard' not in low, name
    css = p.get('/assets/reset.css')
    assert css.status_code == 200 and 'gws' not in css.get_data(as_text=True).lower()
    assert 'Server' not in p.get('/').headers and 'werkzeug' not in str(p.get('/').headers).lower()
    assert p.get('/assets/fonts/roboto-latin-wght-normal.woff2').status_code == 200
    for path in ('/static/style.css', '/static/reset.css', '/assets/style.css', '/assets/../app.py', '/assets/fonts/Roboto-LICENSE.txt',
                 '/admin', '/login', '/settings', '/api/users'):
        assert p.get(path).status_code in (404, 405), path


def each_step_shows_which_email_is_being_reset():
    clear_rows()
    p = Person()
    assert 'Resetting the password for' not in p.html(p.get('/'))
    code = demo_code(p.ask('dkim@example.com'))
    verify = p.html(p.get('/verify'))
    assert 'Resetting the password for</span> <strong>dkim@example.com</strong>' in verify and 'Not you?' in verify
    assert p.enter(code).status_code == 303
    assert '<strong>dkim@example.com</strong>' in p.html(p.get('/new-password'))
    assert p.choose(PASSWORD).status_code == 303
    done = p.html(p.get('/done'))
    assert 'Password changed for</span> <strong>dkim@example.com</strong>' in done and 'Not you?' not in done
    assert 'dkim@example.com' not in p.html(p.get('/done')), 'shown once, then forgotten'


def with_the_reasons_switch_on_the_page_says_plainly_why():
    clear_rows()
    go_live()
    os.environ['RESET_SHOW_REASONS'] = 'true'
    try:
        Wrap.changes = {'jokafor@example.com': {'suspended': True}}
        cases = (('malvarez@example.com', 'administrator account'), ('jokafor@example.com', 'This account is locked'),
                 ('nobody@example.com', 'find that account'), ('nfischer@example.com', 'ready for password reset'))
        for email, expect in cases:
            p = Person()
            page = p.html(p.get('/'))
            r = p.post('/request', {'csrf_token': p.token(page), 'email': email})
            html = p.html(r)
            assert r.status_code == 200 and expect in html and 'class="notice notice-warn"' in html, (email, r.status_code, html[:300])
            assert f'value="{email}"' in html, 'the address stays in the box so it can be corrected'
            assert 'Traceback' not in html and 'Exception' not in html and 'reason' not in html.lower()
            assert p.get('/verify').status_code == 302, 'no code page for an address that cannot be reset'
        good = Person()
        page = good.html(good.get('/'))
        assert good.post('/request', {'csrf_token': good.token(page), 'email': 'dkim@example.com'}).status_code == 303
        FakeMail.fail = True                                   # the mail server refuses: say so kindly, show nothing technical
        p = Person()
        page = p.html(p.get('/'))
        r = p.post('/request', {'csrf_token': p.token(page), 'email': 'smarin@example.com'})
        html = p.html(r)
        assert 'send your code' in html and 'boom' not in html and '535' not in html and 'smtp' not in html.lower(), html[:500]
        FakeMail.fail = False
        for i in range(rp.MAX_REQUESTS_PER_EMAIL):
            p = Person()
            page = p.html(p.get('/'))
            p.post('/request', {'csrf_token': p.token(page), 'email': 'abello@example.com'})
        p = Person()
        page = p.html(p.get('/'))
        assert 'Too many requests' in p.html(p.post('/request', {'csrf_token': p.token(page), 'email': 'abello@example.com'}))
    finally:
        os.environ.pop('RESET_SHOW_REASONS', None)
        go_demo()


def with_the_switch_off_a_mail_failure_looks_like_any_other_request():
    clear_rows()
    go_live()
    try:
        FakeMail.fail = True
        ok_page = sameness(Person().ask('unknown.person@example.com'))
        failed_page = sameness(Person().ask('smarin@example.com'))
        assert ok_page == failed_page, 'a failing mail server must not be visible to the person'
        assert any('mail not sent' in (a[3] or '') for a in audit_actions('smarin@example.com')), 'but the audit log has it'
    finally:
        go_demo()


def a_super_admin_made_after_the_code_was_sent_is_stopped_at_the_last_step():
    reset_demo_data()
    clear_rows()
    rp._wrong_codes.clear()
    go_live()
    try:
        p = Person()
        p.ask('lwalsh@example.com')
        code = code_in_mail('lwalsh@example.com')
        assert p.enter(code).status_code == 303
        Wrap.changes = {'lwalsh@example.com': {'isAdmin': True}}
        r = p.choose(PASSWORD)
        assert r.status_code == 400 and 'can no longer be completed' in p.html(r)
        assert get_mock_ad().users['lwalsh@example.com'].get('passwordChanges', 0) == 0
    finally:
        go_demo()


def nothing_secret_is_written_to_the_audit_log_or_the_log_files():
    seen = json.dumps(audit_actions())
    logs = ''.join(open(f, errors='ignore').read() for f in glob.glob(os.path.join(env.tmp, 'logs', '*')))
    for text in (seen, logs):
        assert PASSWORD not in text, 'the new password is never logged'
        assert not re.search(r'"code": "\d{6}"', text)
    assert 'reset_password_changed' in seen and 'reset_code_requested' in seen


def the_ldap_lookup_cannot_be_tricked_by_special_characters():
    from ad_connector import ADConnector

    class FakeConn:
        entries = []
        last = ''

        def search(self, base, flt, **kw):
            FakeConn.last = flt
    a = ADConnector.__new__(ADConnector)
    a.conn = FakeConn()
    a._find_user_dn('x*)(uid=*@example.com', retries=1)
    assert '(uid=' not in FakeConn.last and '\\2a' in FakeConn.last and '\\29' in FakeConn.last, FakeConn.last


def the_mail_goes_out_after_the_page_has_answered_when_run_in_the_background():
    reset_demo_data()
    clear_rows()
    go_live()
    rp.RUN_IN_BACKGROUND = True
    try:
        p = Person()
        p.ask('dkim@example.com')
        for _ in range(50):
            if any(m['to'] == 'dkim@example.com' for m in FakeMail.sent):
                break
            time.sleep(0.1)
        assert any(m['to'] == 'dkim@example.com' for m in FakeMail.sent), 'the background step sent it'
    finally:
        rp.RUN_IN_BACKGROUND = False
        go_demo()


def it_starts_as_its_own_https_service_and_never_as_plain_http():
    import ssl
    import subprocess
    import urllib.error
    import werkzeug.serving as ws

    def free_port():
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
    d = os.path.join(env.tmp, 'certs')
    os.makedirs(d, exist_ok=True)
    cert, key = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
                    '-days', '2', '-subj', '/CN=localhost'], check=True, capture_output=True)
    port = free_port()
    os.environ['RESET_PORTAL_PORT'] = str(port)
    os.environ.pop('RESET_PORTAL', None)
    server = rp.start_in_background('127.0.0.1', (cert, key), main_port=5000)
    try:
        assert server is not None
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        body = urllib.request.urlopen(f'https://127.0.0.1:{port}/', timeout=5, context=ctx).read().decode()
        assert 'Send me a code' in body
        raw = urllib.request.urlopen(f'https://127.0.0.1:{port}/', timeout=5, context=ctx)
        assert 'Server' not in raw.headers or raw.headers['Server'] == 'web', raw.headers.get('Server')
        assert 'Python' not in str(raw.headers) and 'Werkzeug' not in str(raw.headers)
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=5).read()
            assert False, 'plain HTTP must not be answered'
        except (urllib.error.URLError, ConnectionError, OSError, Exception) as e:
            assert not isinstance(e, AssertionError), 'plain HTTP must not be answered'
    finally:
        server.shutdown()
        server.server_close()
    # no certificate: it does not start, and nothing is opened on any port
    opened = []
    real_make = ws.make_server
    class Dummy:
        def serve_forever(self):
            pass
    ws.make_server = lambda *a, **k: (opened.append((a, k)), Dummy())[1]
    real_find = rp.find_certificate
    rp.find_certificate = lambda: None
    try:
        assert rp.start_in_background('127.0.0.1', None, main_port=5000) is None and not opened, 'no certificate, no service'
        rp.find_certificate = lambda: (cert, key)               # a certificate next to app.py is enough, even if the dashboard is on HTTP
        os.environ.pop('RESET_PORTAL_PORT')
        rp.start_in_background('127.0.0.1', None, main_port=5000)
        assert opened and opened[0][0][1] == 8443 and opened[0][1]['ssl_context'] == (cert, key), 'port 8443, HTTPS'
    finally:
        ws.make_server = real_make
        rp.find_certificate = real_find
    os.environ['RESET_PORTAL_PORT'] = str(port)
    assert rp.start_in_background('127.0.0.1', (cert, key), main_port=port) is None, 'never on the main app\'s port'
    os.environ['RESET_PORTAL'] = 'false'
    assert rp.start_in_background('127.0.0.1', (cert, key), main_port=5000) is None, 'RESET_PORTAL=false turns it off'
    os.environ.pop('RESET_PORTAL')
    os.environ.pop('RESET_PORTAL_PORT')


STEPS = [
    ("The start page is plain, has no scripts and sends strict browser headers", start_page_is_plain_and_locked_down),
    ("A badly shaped address is refused before anything happens", a_wrong_address_shape_is_refused_before_anything_happens),
    ("Demo mode shows the code, and the right code opens the new-password page", demo_mode_shows_the_code_and_the_right_code_opens_the_next_page),
    ("Codes and tokens are stored only as hashes", stored_values_are_only_hashes),
    ("A new password must follow the rules", a_new_password_must_follow_the_rules),
    ("The password is set in Active Directory and in Google, and only once", the_password_is_set_in_active_directory_and_in_google_and_only_once),
    ("Five wrong codes burn the code", wrong_codes_burn_the_code_after_five_tries),
    ("A code stops working after ten minutes", a_code_stops_working_after_ten_minutes),
    ("The new password must be chosen within ten minutes of the code", a_password_must_be_chosen_within_ten_minutes_of_the_code),
    ("Requests are limited per address and per computer", requests_are_limited_per_address_and_per_computer),
    ("A wrong token does not open the password page", a_wrong_or_borrowed_token_does_not_open_the_password_page),
    ("Too many wrong codes locks that computer out", too_many_wrong_codes_from_one_computer_locks_that_computer_out),
    ("Forms without the right token do nothing", pages_without_a_form_token_do_nothing),
    ("Live: every kind of address gets the same answer", live_like_every_kind_of_address_gets_the_same_answer),
    ("Live: the code goes to the work email and both passwords change", live_like_the_code_goes_to_the_work_email_and_both_passwords_change),
    ("If Google cannot be reached, nothing is changed anywhere", if_google_cannot_be_reached_nothing_is_changed_anywhere),
    ("If Active Directory refuses, the person chooses another and both are set", if_active_directory_refuses_the_person_can_choose_another_and_both_are_set),
    ("Google is changed before Active Directory", google_is_changed_before_active_directory),
    ("The pages never name the admin panel or the web server", the_pages_never_name_the_admin_panel_or_the_web_server),
    ("Each step shows which email is being reset", each_step_shows_which_email_is_being_reset),
    ("With the reasons switch on, the page says plainly why", with_the_reasons_switch_on_the_page_says_plainly_why),
    ("With the switch off, a mail failure looks like any other request", with_the_switch_off_a_mail_failure_looks_like_any_other_request),
    ("A person who becomes a Google admin mid-reset is stopped at the last step", a_super_admin_made_after_the_code_was_sent_is_stopped_at_the_last_step),
    ("Neither codes nor passwords reach the audit log or log files", nothing_secret_is_written_to_the_audit_log_or_the_log_files),
    ("The LDAP lookup cannot be tricked by special characters", the_ldap_lookup_cannot_be_tricked_by_special_characters),
    ("When run in the background, the mail is sent after the page answers", the_mail_goes_out_after_the_page_has_answered_when_run_in_the_background),
    ("It starts as its own HTTPS service and never as plain HTTP", it_starts_as_its_own_https_service_and_never_as_plain_http),
]

if __name__ == '__main__':
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
