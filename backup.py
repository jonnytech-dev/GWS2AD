"""
backup.py
=========
Writes a snapshot of GWS users, groups, and org units to a local file
before each sync runs - a point-in-time record of what things looked
like right before that sync could change anything.
"""

import json
from datetime import datetime
from config import APP_ROOT

BACKUP_DIR = APP_ROOT / "data_backup"


def create_pre_sync_backup(gws_connector):
    """
    Snapshot GWS users (with group membership), groups (with members),
    and org units into one timestamped, strictly valid JSON file under
    data_backup/. Top-level keys are ordered users, then groups, then
    ous - Python dicts preserve insertion order, and json.dump respects
    that, so this ordering is guaranteed in the output file.
    Returns the path to the file written.
    """
    BACKUP_DIR.mkdir(exist_ok=True)
    
    timestamp = datetime.utcnow()
    filename = f"backup-{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.json"
    filepath = BACKUP_DIR / filename
    
    # --- Users (with group membership) ---
    users = gws_connector.get_all_users()
    membership_map = gws_connector.get_user_group_membership_map()
    users_data = []
    for user in users:
        groups_for_user = membership_map.get(user.get('email'), [])
        users_data.append({
            'email': user.get('email'),
            'firstName': user.get('firstName'),
            'lastName': user.get('lastName'),
            'fullName': user.get('fullName'),
            'orgUnitPath': user.get('orgUnitPath'),
            'groups': [g['email'] for g in groups_for_user],
        })
    
    # --- Groups (with members) ---
    groups = gws_connector.get_all_groups()
    groups_data = []
    for group in groups:
        try:
            members = gws_connector.get_group_members(group['email'])
        except Exception:
            members = []
        groups_data.append({
            'email': group.get('email'),
            'name': group.get('name'),
            'description': group.get('description'),
            'memberCount': len(members),
            'members': members,
        })
    
    # --- Organizational Units ---
    ous_data = gws_connector.get_all_org_units()
    
    backup_data = {
        'timestamp': timestamp.isoformat() + 'Z',
        'users': users_data,
        'groups': groups_data,
        'ous': ous_data,
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(backup_data, f, indent=2)
    
    return str(filepath)
