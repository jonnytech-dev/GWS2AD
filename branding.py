"""
branding.py
===========
Your organization's logo and name, shown on the password reset page.

The Owner sets them in Settings > Branding. They are kept in a folder called
"branding" next to app.py:

    branding/logo.png       the logo (always PNG, see save_logo)
    branding/branding.json  {"org_name": "..."}

Nothing here is secret. The folder is left out of git so each install keeps its own.

The uploaded file is never served as it was sent. It is opened as an image, shrunk,
and written out again as a fresh PNG. That removes anything hidden in the file
(scripts, metadata) and means only a real picture can be stored.
"""
import io
import json
import os
import re

from config import APP_ROOT

BRAND_DIR = APP_ROOT / 'branding'
LOGO_FILE = BRAND_DIR / 'logo.png'
META_FILE = BRAND_DIR / 'branding.json'

MAX_UPLOAD_BYTES = 2 * 1024 * 1024       # 2 MB
MAX_PIXELS = 25_000_000                  # refuse huge images before decoding them
MAX_SIDE = 480                           # stored logo fits in a 480 x 480 box
MAX_NAME_LENGTH = 60
ALLOWED_FORMATS = {'PNG', 'JPEG', 'WEBP', 'GIF'}   # not SVG: an SVG can carry scripts


def org_name():
    try:
        data = json.loads(META_FILE.read_text(encoding='utf-8'))
        return clean_name(data.get('org_name', ''))
    except Exception:
        return ''


def clean_name(value):
    """One line of plain text, no control characters, at most MAX_NAME_LENGTH long"""
    value = re.sub(r'[\x00-\x1f\x7f<>]', ' ', str(value or ''))
    return re.sub(r'\s+', ' ', value).strip()[:MAX_NAME_LENGTH]


def has_logo():
    return LOGO_FILE.is_file()


def logo_version():
    """Changes whenever the logo does, so browsers fetch the new one"""
    try:
        return int(LOGO_FILE.stat().st_mtime)
    except OSError:
        return 0


def get():
    return {'org_name': org_name(), 'has_logo': has_logo(), 'logo_version': logo_version()}


def save_org_name(value):
    BRAND_DIR.mkdir(exist_ok=True)
    META_FILE.write_text(json.dumps({'org_name': clean_name(value)}), encoding='utf-8')


def save_logo(raw):
    """
    Checks the uploaded bytes are a real image and stores a clean PNG copy.
    Raises ValueError with a message that is fine to show the person.
    """
    from PIL import Image, UnidentifiedImageError
    if not raw:
        raise ValueError('Choose an image file first.')
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError('That file is too big. Use an image under 2 MB.')
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        probe = Image.open(io.BytesIO(raw))
        fmt = probe.format
        if probe.width * probe.height > MAX_PIXELS:
            raise ValueError('That picture is too large. Use one under 5000 pixels on each side.')
        probe.verify()                                     # checks the file is complete and not damaged
        img = Image.open(io.BytesIO(raw))                  # verify() leaves the first copy unusable
        if fmt not in ALLOWED_FORMATS:
            raise ValueError('Use a PNG, JPG, WEBP or GIF image. SVG files are not accepted.')
        img.seek(0)                                        # first frame only, for GIFs
        img = img.convert('RGBA')
    except ValueError:
        raise
    except (UnidentifiedImageError, Exception):
        raise ValueError('That file is not a picture we can read. Use a PNG, JPG, WEBP or GIF image.')
    img.thumbnail((MAX_SIDE, MAX_SIDE))
    out = io.BytesIO()
    img.save(out, format='PNG', optimize=True)             # a fresh file: no metadata, nothing hidden
    BRAND_DIR.mkdir(exist_ok=True)
    tmp = LOGO_FILE.with_suffix('.tmp')
    tmp.write_bytes(out.getvalue())
    os.replace(tmp, LOGO_FILE)


def remove_logo():
    try:
        LOGO_FILE.unlink()
    except FileNotFoundError:
        pass
