"""
file_logger.py
===============
Writes durable, human-readable log files to the logs/ folder for every
admin action (user/group CRUD, login, ignore-list changes, etc.) and
every sync run - a persistent record alongside (not instead of) the
console output and the AuditLog database table, so previous activity
can be reviewed later without digging through the database.
"""

import json
import re
from datetime import datetime
from config import LOGS_PATH


def _safe_filename_part(text):
    """Strip characters that aren't safe to use in a filename."""
    return re.sub(r'[^A-Za-z0-9_.-]', '_', text)


def write_action_log(action, admin_username, target, status, details=None, source=None):
    """
    Write a log file for a single admin action - creating/editing/
    deleting a user or group, logging in, changing the ignore list,
    toggling email, etc. Named after the action and the exact moment
    it happened, so files sort chronologically and are identifiable
    at a glance without opening them.
    A failure here is logged to console but never allowed to break the
    actual operation it's recording.
    """
    timestamp = datetime.now()
    filename = f"{_safe_filename_part(action)}-{timestamp.strftime('%Y-%m-%d_%H-%M-%S_%f')}.log"
    filepath = LOGS_PATH / filename
    
    lines = [
        f"Action:    {action}",
        f"Timestamp: {timestamp.isoformat()}",
        f"Admin:     {admin_username}",
        f"Target:    {target}",
        f"Status:    {status}",
        f"Source:    {source or 'unknown'}",
        "",
        "Details:",
        json.dumps(details, indent=2, default=str) if details else "(none)",
    ]
    
    try:
        LOGS_PATH.mkdir(exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
    except Exception as e:
        print(f"[WARNING] Could not write action log file: {e}")


def write_sync_log(sync_log_lines, status):
    """
    Write the FULL, unabridged sync log - every create/update/delete/
    move/failure line - to its own file. The AuditLog database entry
    for a sync only keeps a short summary to avoid database bloat, but
    this file keeps everything that happened during that run.
    """
    timestamp = datetime.now()
    filename = f"sync-{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.log"
    filepath = LOGS_PATH / filename
    
    try:
        LOGS_PATH.mkdir(exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Sync run: {timestamp.isoformat()}\n")
            f.write(f"Status: {status}\n")
            f.write("=" * 70 + "\n\n")
            f.write('\n'.join(sync_log_lines))
            f.write('\n')
    except Exception as e:
        print(f"[WARNING] Could not write sync log file: {e}")
