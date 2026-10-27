"""
test_branding_flow.py
=====================
Settings > Branding (Owner only): upload a logo and set the organization name, and the password reset page
shows them. Pictures are checked and rewritten as clean PNGs; anything else is refused.

    python tests/test_branding_flow.py
"""
import io
import os
import re
import test_support as T

env = T.build()
H = T.Helpers(env)
import branding
import reset_portal as rp
from PIL import Image

rp.RUN_IN_BACKGROUND = False
portal = rp.create_app()
portal.config['TESTING'] = True


def picture(fmt='PNG', size=(600, 300), color=(14, 90, 55)):
    buf = io.BytesIO()
    Image.new('RGB', size, color).save(buf, format=fmt)
    return buf.getvalue()


def form(extra=None, logo=None, name='Example Org', token=True):
    data = {'org_name': name}
    if token:
        data['csrf_token'] = H.csrf(H.html(H.GET('/settings/branding')))
    if logo is not None:
        data['logo'] = (io.BytesIO(logo[1]), logo[0])
    data.update(extra or {})
    return H.client.post('/settings/branding', data=data, content_type='multipart/form-data')


def reset_start_page():
    c = portal.test_client()
    c.environ_base['wsgi.url_scheme'] = 'https'
    return c, c.get('/').get_data(as_text=True)


def sign_in():
    H.enroll('admin')
    branding.remove_logo()
    if branding.META_FILE.exists():
        branding.META_FILE.unlink()


def with_nothing_set_the_page_shows_a_placeholder_and_the_new_wording():
    html = H.html(H.GET('/settings/branding'))
    assert 'No logo yet' in html and 'name="logo"' in html
    c, page = reset_start_page()
    assert 'class="brand-logo placeholder"' in page and '<img' not in page and 'viewBox="0 0 56 52"' in page, 'the GWS2AD triangle is the fallback'
    assert 'Active Directory' in page and 'Google Workspace' in page and 'Reset your password' in page
    assert 'network password' not in page.lower()
    assert c.get('/brand/logo').status_code == 404


def a_real_picture_is_stored_as_a_clean_png_and_shown():
    r = form(logo=('logo.jpg', picture('JPEG', (1600, 800))))
    assert r.status_code == 302 and 'branding_saved' in H.location(r), r.status_code
    raw = branding.LOGO_FILE.read_bytes()
    assert raw[:8] == b'\x89PNG\r\n\x1a\n'
    im = Image.open(io.BytesIO(raw))
    assert im.format == 'PNG' and max(im.size) <= 480 and im.size == (480, 240), im.size   # shrunk, proportions kept
    c, page = reset_start_page()
    assert re.search(r'<img class="brand-logo" src="/brand/logo\?v=\d+" alt="Example Org">', page), page[:900]
    assert '<p class="brand-name">Example Org</p>' in page and 'Reset your password | Example Org' in page
    r = c.get('/brand/logo')
    assert r.status_code == 200 and r.mimetype == 'image/png' and r.headers['X-Content-Type-Options'] == 'nosniff'
    assert H.GET('/settings/branding/logo').status_code == 200


def the_sign_in_page_and_the_dashboard_show_it_too():
    anon = env.flask_app.test_client()
    page = anon.get('/login').get_data(as_text=True)
    assert re.search(r'<img class="logo-img" src="/branding/logo\?v=\d+" alt="Example Org">', page), page[:600]
    assert '<svg' not in page.split('login-logo')[1].split('</div>')[0], 'the GWS2AD triangle is replaced'
    r = anon.get('/branding/logo')                                         # public: the sign-in page needs it before sign-in
    assert r.status_code == 200 and r.mimetype == 'image/png' and r.headers['X-Content-Type-Options'] == 'nosniff'
    dash = H.html(H.GET('/dashboard'))
    assert '<img class="logo-img" src="/branding/logo' in dash and 'navbar-subtitle">Example Org<' in dash


def the_name_alone_can_change_without_a_new_file():
    before = branding.LOGO_FILE.read_bytes()
    r = form(name='  Acme   <b>Corp</b> \n Inc ')
    assert r.status_code == 302
    assert branding.LOGO_FILE.read_bytes() == before, 'the logo was left alone'
    assert branding.org_name() == 'Acme b Corp /b Inc'
    c, page = reset_start_page()
    assert '<b>' not in page and 'Acme b Corp /b Inc' in page


def files_that_are_not_pictures_are_refused_and_change_nothing():
    before = branding.LOGO_FILE.read_bytes()
    bad = {
        'a web page named .png': ('logo.png', b'<html><script>alert(1)</script></html>'),
        'an svg': ('logo.svg', b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
        'a program named .jpg': ('logo.jpg', b'MZ\x90\x00' + b'\x00' * 200),
        'a cut-off png': ('logo.png', picture('PNG')[:60]),
        'too big': ('logo.png', b'\x89PNG\r\n\x1a\n' + b'0' * (branding.MAX_UPLOAD_BYTES + 10)),
        'a bmp': ('logo.bmp', picture('BMP')),
    }
    for label, f in bad.items():
        r = form(logo=f, name='Should Not Save')
        assert r.status_code == 400, (label, r.status_code)
        assert 'alert alert-error' in H.html(r), label
        assert branding.LOGO_FILE.read_bytes() == before, label
        assert branding.org_name() != 'Should Not Save', label


def a_picture_that_is_huge_in_pixels_is_refused():
    big = io.BytesIO()
    Image.new('1', (6000, 6000)).save(big, format='PNG')              # tiny file, 36 million pixels
    assert len(big.getvalue()) < branding.MAX_UPLOAD_BYTES
    r = form(logo=('big.png', big.getvalue()))
    assert r.status_code == 400


def metadata_and_hidden_data_do_not_survive():
    buf = io.BytesIO()
    im = Image.new('RGB', (100, 100), (200, 0, 0))
    from PIL import PngImagePlugin
    info = PngImagePlugin.PngInfo()
    info.add_text('Comment', 'SECRET-MARKER')
    im.save(buf, format='PNG', pnginfo=info)
    assert b'SECRET-MARKER' in buf.getvalue()
    form(logo=('x.png', buf.getvalue()))
    assert b'SECRET-MARKER' not in branding.LOGO_FILE.read_bytes()


def removing_the_logo_brings_the_placeholder_back():
    token = H.csrf(H.html(H.GET('/settings/branding')))
    assert H.POST('/settings/branding/remove-logo', {}).status_code == 400, 'needs the form token'
    r = H.POST('/settings/branding/remove-logo', {'csrf_token': token})
    assert r.status_code == 302 and not branding.has_logo()
    c, page = reset_start_page()
    assert 'placeholder' in page and '<img' not in page
    assert env.flask_app.test_client().get('/branding/logo').status_code == 404
    assert '<svg' in env.flask_app.test_client().get('/login').get_data(as_text=True).split('login-logo')[1], 'GWS2AD logo is back'


def only_the_owner_and_only_with_the_form_token():
    before = branding.LOGO_FILE.read_bytes()
    assert form(token=False, logo=('y.png', picture(color=(1, 2, 3)))).status_code == 400
    assert branding.LOGO_FILE.read_bytes() == before, 'no token, no change'
    H.logout()
    assert H.GET('/settings/branding').status_code == 302, 'signed out'
    assert H.POST('/settings/branding', {'org_name': 'x'}).status_code == 302
    assert branding.LOGO_FILE.read_bytes() == before and branding.org_name() != 'x'


def changes_are_in_the_audit_log():
    form(logo=('x.png', picture()))
    actions = H.audit_actions()
    assert 'save_branding' in actions, actions


STEPS = [
    ("With nothing set, the reset page shows a placeholder and the new wording", with_nothing_set_the_page_shows_a_placeholder_and_the_new_wording),
    ("A real picture is stored as a clean PNG and shown on the reset page", a_real_picture_is_stored_as_a_clean_png_and_shown),
    ("The sign-in page and the dashboard show it too", the_sign_in_page_and_the_dashboard_show_it_too),
    ("The name can change without a new file, and tags are stripped", the_name_alone_can_change_without_a_new_file),
    ("Files that are not pictures are refused and change nothing", files_that_are_not_pictures_are_refused_and_change_nothing),
    ("A picture that is huge in pixels is refused", a_picture_that_is_huge_in_pixels_is_refused),
    ("Metadata and hidden data do not survive", metadata_and_hidden_data_do_not_survive),
    ("Removing the logo brings the placeholder back", removing_the_logo_brings_the_placeholder_back),
    ("Changes are in the audit log", changes_are_in_the_audit_log),
    ("Only the signed-in Owner, and only with the form token", only_the_owner_and_only_with_the_form_token),
]

if __name__ == '__main__':
    sign_in()
    print(f"(working in a throwaway copy: {env.tmp})\n")
    T.finish(T.run(STEPS), len(STEPS), env.tmp)
