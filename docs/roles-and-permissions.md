# Roles and permissions

Who can sign in, and what each person can do, is decided by the rules in `permissions.py`. That file has no web or database code,
so the rules are tested on their own (`tests/test_permissions.py`) and again through the real pages (`tests/test_accounts_flow.py`).

## Roles

| Role | How many | What it can do |
|---|---|---|
| **Owner** | Exactly one. The database itself refuses a second | Everything. Cannot be deleted, deactivated, demoted or edited by anyone, including the Owner. The only one who can switch Demo / Live and turn on the Admin switches below |
| **Admin** | Any number | Everything on the dashboard: users, groups, sync (a "super user" of the data). **Accounts and Roles in Settings are hidden** unless the Owner turns on a switch |
| **Custom** | Any number | Only the permissions ticked for that one account |
| **Named role** | Any number | A reusable set of permissions you create (for example "Help Desk"). Anyone in it gets exactly its permissions, and editing the role updates everyone in it at once |

### The two Admin switches

Both are **off** when an Admin is created and only the Owner can change them.

| Switch | Lets that Admin |
|---|---|
| **Can manage admins** | See, add, edit and delete other Admin accounts |
| **Can manage staff** | See, add, edit and delete Custom and named-role accounts, and manage Roles |

"Staff" means anyone who is not an Admin or the Owner.

## Permissions

| Permission | Allows |
|---|---|
| Add users | Create new Google Workspace users |
| Edit users | Change a user's name, password, groups and OU |
| Delete users | Delete users from Google Workspace |
| Add groups | Create groups |
| Edit groups | Change a group, including who is in it |
| Delete groups | Delete groups from Google Workspace |
| Preview sync | See what a sync would change (look only). Also lets you read Settings > Ignore list |
| Run sync | Apply a sync to AD. Includes changing the ignore list (Keep in AD, Stop ignoring, editing notes) and the email on/off setting. Implies Preview sync |

Everyone who can sign in can **view** the dashboard. Buttons a person cannot use are hidden, and the server refuses the request
anyway if someone calls the API directly. That is tested for every account type against every route.

Managing accounts is never a permission a role can hold; it comes only from being the Owner or an Admin with the matching switch.

## Rules that cannot be bent

- Nobody can give a permission they do not have themselves.
- Nobody can edit or delete their own account's role, and nobody can touch the Owner.
- An Admin with **only** "manage staff" cannot see or change other Admins; one with **only** "manage admins" cannot see or change staff.
- A role that people still use cannot be deleted. Move them first.
- Role names cannot be `owner`, `admin` or `custom`.
- Deactivating an account ends its live session immediately.

## Creating accounts

Settings > Accounts > New account. Whoever creates an account **types the password twice**: there are no temporary passwords for admin accounts.
The new person must set up two-step verification at their first sign-in and cannot use anything until they do.

## Sensitive actions ask for your code

Creating, editing, deleting or resetting an account, changing a role, changing the Demo / Live mode and similar actions need **your own** current 6-digit code,
so a stolen browser session cannot quietly make them. Each code works once.

## Usernames and email

People can change their own username and email under Settings > Profile, but only by giving their current password. Username rules: 3 to 40
letters, numbers, dots, dashes, underscores. A name that appears in the activity history cannot be taken by someone else, so old log entries
can never look like they belong to a new person. The Branding tab (logo and name for the password reset page) is Owner only. Email is a contact detail only: it is not verified and not used for password recovery.

## Locked out?

- Wrong password five times, or wrong two-step code five times: locked for 15 minutes. An Owner or manager can unlock early (Settings > Accounts > the person > Unlock).
- Lost phone **and** recovery codes: someone with server access runs `python reset_2fa.py <username>`; they set it up again at next sign-in.
- Locked out as the Owner with nobody else able to help: `python unlock_account.py <username>` on the server.

Both tools need access to the server, ask for no password because of that, and write to the audit log.
