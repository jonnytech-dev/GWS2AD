"""
reset_2fa.py
============
Emergency tool: turns two-step verification OFF for one admin, so they can
set it up again at their next sign-in. Use it when someone has lost their
phone AND their recovery codes.

Run it on the server, in the project folder, with the project's Python:

    python reset_2fa.py --list          show who has two-step verification
    python reset_2fa.py <username>      reset one admin

Anyone who can run this already has full access to the server, so it asks
for no password. Every reset is written to the audit log.
"""
import sys

from flask import Flask

from config import Config
from database import db, Admin, AuditLog, _add_missing_admin_columns
import twofa


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0

    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        _add_missing_admin_columns()   # safe to run even if the app hasn't started since the update

        if argv[0] == '--list':
            admins = Admin.query.order_by(Admin.username).all()
            print(f"{'USERNAME':20s} {'ROLE':10s} {'ACTIVE':7s} {'TWO-STEP':9s} {'RECOVERY CODES LEFT'}")
            for a in admins:
                left = twofa.recovery_codes_left(a.recovery_codes) if a.two_factor_enabled else '-'
                print(f"{a.username:20s} {a.role:10s} {str(a.is_active):7s} "
                      f"{'on' if a.two_factor_enabled else 'off':9s} {left}")
            return 0

        username = argv[0]
        admin = Admin.query.filter_by(username=username).first()
        if not admin:
            print(f"No admin named '{username}'. Run with --list to see the names.")
            return 1

        if not (admin.two_factor_enabled or admin.totp_pending_secret):
            print(f"Two-step verification is already off for '{username}'. Nothing to do.")
            return 0

        answer = input(f"Turn off two-step verification for '{username}'? [y/N]: ").strip().lower()
        if answer != 'y':
            print("Cancelled. Nothing was changed.")
            return 1

        twofa.reset(admin)
        db.session.commit()
        AuditLog.log_action(
            admin_username='(server console)',
            action='2fa_reset',
            target=f'admin:{username}',
            status='success',
            details={'by': 'reset_2fa.py'},
            source='localhost'
        )
        print(f"Done. '{username}' will be asked to set up two-step verification at the next sign-in.")
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
