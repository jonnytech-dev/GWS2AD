"""
mode.py
=======
Whether the app is running against sample data (Demo) or against your real
Google Workspace and Active Directory (Live).

The choice lives in a small file next to the app, so it survives restarts
and needs no database. A fresh install has no file, which means Demo: the
app is safe to try with no credentials and can't change anything real.

Only the Owner can switch it (see the Settings > Connection page).
"""
import json
import os
import threading
from pathlib import Path

DEMO = 'demo'
LIVE = 'live'

_FILE = Path(__file__).parent / 'connection_mode.json'
_lock = threading.Lock()


def get_mode():
    """'demo' unless the Owner has switched to 'live'. Anything unreadable means demo."""
    try:
        with open(_FILE, 'r', encoding='utf-8') as f:
            value = json.load(f).get('mode')
        return LIVE if value == LIVE else DEMO
    except (OSError, ValueError, AttributeError):
        return DEMO


def is_demo():
    return get_mode() == DEMO


def set_mode(mode, changed_by=''):
    """Save the mode. Written to a temp file first so a crash can't leave half a file."""
    if mode not in (DEMO, LIVE):
        raise ValueError("mode must be 'demo' or 'live'")
    with _lock:
        tmp = str(_FILE) + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump({'mode': mode, 'changed_by': changed_by}, f)
        os.replace(tmp, _FILE)
