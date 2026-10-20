"""
unlock_account.py
=================
Ends a lock on one account (wrong passwords or wrong two-step codes) without
waiting the 15 minutes. This is the only way to unlock the Owner, because
nobody else can change the Owner's account.

Run it on the server, in the project folder, with the project's Python:

    python unlock_account.py --list         show which accounts are locked
    python unlock_account.py <username>     unlock one account

Anyone who can run this already has full access to the server, so it asks for
no password. Every unlock is written to the audit log.
"""
import sys

from flask import Flask

from config import Config
from database import db, Admin, AuditLog, _add_missing_admin_columns
import loginlock


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0

    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        _add_missing_admin_columns()

        if argv[0] == '--list':
            locked = [a for a in Admin.query.order_by(Admin.username).all() if a.is_locked]
            if not locked:
                print("No accounts are locked.")
            for a in locked:
                print(f"{a.username:20s} {a.role_label}")
            return 0

        admin = Admin.query.filter_by(username=argv[0]).first()
        if not admin:
            print(f"No account named '{argv[0]}'. Run with --list to see locked accounts.")
            return 1

        loginlock.unlock(admin)
        db.session.commit()
        AuditLog.log_action(
            admin_username='(server console)',
            action='account_unlocked',
            target=f'admin:{argv[0]}',
            status='success',
            details={'by': 'unlock_account.py'},
            source='localhost'
        )
        print(f"Done. '{argv[0]}' is unlocked.")
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
