# Going Live: connecting your real Google Workspace and Active Directory

This is the one-time setup. Do it in order. When you finish, `python setup_secrets.py --live` stores the values and
**Settings > Connection** switches the app over. Nothing here is needed for Demo mode.

You will need: a Google Workspace **super admin**, someone who can create a Google Cloud project, and a Domain Admin
on your Active Directory.

Placeholders used below: `example.com` (your domain), `gws2ad-sa` (the Google service account),
`svc_gws2ad` (the AD service account), `dc01.corp.example.com` (a domain controller).

---

## Part 1. Google Cloud: a service account

The app signs in to Google as a **service account**: a dedicated, revocable identity. If its key leaks you disable it on its own,
without touching anyone's personal login.

### 1.1 Create a project and turn on the Admin SDK API

1. Open the [Google Cloud console](https://console.cloud.google.com/) and create a project (any name, for example `gws2ad`).
2. **APIs & Services > Library**, search **Admin SDK API**, and **Enable** it. Without it the service account has nothing to call.

### 1.2 Create the service account

1. **IAM & Admin > Service Accounts > Create service account.** Name it, for example, `gws2ad-sa`. No project roles are needed.
2. Open the account and note its **numeric Client ID** (under "Advanced settings" or "Details"). You need it in Part 2.

### 1.3 Create a JSON key

1. In the service account, **Keys > Add key > Create new key > JSON**. A `.json` file downloads.
2. Move it to a folder only the app can read, for example `keys/sa-key.json` inside the app folder (`keys/` is git-ignored).
   **Treat it exactly like a password**: anyone with this file can act as the service account.

> **"Service account key creation is disabled"?** Many organizations block this with the organization policy
> `iam.disableServiceAccountKeyCreation`. An organization policy administrator must temporarily allow it for your project.
> Turning the policy back on afterwards does not affect keys that already exist, only new ones.

---

## Part 2. Google Workspace admin console: domain-wide delegation

Creating the service account gives it no Workspace access. Delegation is Google's explicit step that says
"this service account may act on these specific things."

1. Sign in to `admin.google.com` as a super admin.
2. **Security > Access and data control > API controls > Manage Domain Wide Delegation > Add new.**
3. **Client ID:** the numeric ID from step 1.2.
4. **OAuth scopes** (comma separated):

   ```
   https://www.googleapis.com/auth/admin.directory.user,
   https://www.googleapis.com/auth/admin.directory.group,
   https://www.googleapis.com/auth/admin.directory.orgunit.readonly
   ```

   | Scope | Why |
   |---|---|
   | `admin.directory.user` (full) | The dashboard creates, edits and deletes users, so read-only is not enough |
   | `admin.directory.group` (full) | Same, including group membership |
   | `admin.directory.orgunit.readonly` | The app only reads your OU tree to mirror it into AD. It never creates or edits OUs in Google |

5. **Authorize.**

### The admin the app acts as

A service account has no Workspace identity of its own. It must act **as a real admin**. Pick a super admin
(a dedicated one such as `gws2ad-admin@example.com` is best) and give that address when `setup_secrets.py --live` asks for it.
It must stay a super admin and stay enabled; if it is demoted or suspended, Google calls start failing with permission errors.

### Customer ID

Leave it as `my_customer` unless you manage more than one Workspace customer.

---

## Part 3. Active Directory

### 3.1 Choose a base DN

Everything the app reads and writes lives under one DN, the **base DN**. Two choices:

- **A dedicated OU (recommended).** Create, for example, `OU=GWS-Sync,DC=corp,DC=example,DC=com`.
  Delegate the service account permissions on that OU only. The app cannot see or touch anything else, so a
  stolen credential or a sync mistake is contained to one branch.
- **The domain root** (`DC=corp,DC=example,DC=com`). The app can see everything, and the service account needs
  rights across the domain. Anything in AD with no matching Google user can be a candidate for deletion at sync, so be careful.

The app creates its own structure inside the base DN: `OU=Users`, `OU=Groups` and sub-OUs mirroring Google
(see [how-it-works.md](how-it-works.md#organizational-units)). You do not have to pre-create them.

### 3.2 Create the service account

A dedicated, unprivileged account, never a person's admin login. In PowerShell on a domain controller or admin workstation:

```powershell
New-ADUser -Name "svc_gws2ad" -SamAccountName "svc_gws2ad" `
  -UserPrincipalName "svc_gws2ad@corp.example.com" `
  -Path "OU=Service Accounts,DC=corp,DC=example,DC=com" `
  -AccountPassword (Read-Host -AsSecureString "Password") `
  -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true
```

- **Password never expires:** the account runs unattended. A normal expiry would eventually lock the app out of AD.
- **"User must change password at next logon" unchecked:** nothing ever logs in interactively as this account, so that flag would break authentication permanently.

The value you give `setup_secrets.py --live` as the "service account DN or user principal name" is this account's DN
(`CN=svc_gws2ad,OU=Service Accounts,DC=corp,DC=example,DC=com`) or its UPN.

### 3.3 Delegate permissions

In **Active Directory Users and Computers**: right-click the base DN (your dedicated OU, or the domain root) > **Delegate Control...** >
add `svc_gws2ad`, then:

1. On the task page tick the common tasks:
   - Create, delete, and manage user accounts
   - Reset user passwords and force password change at next logon
   - Create, delete, and manage groups
   - Modify the membership of a group
2. Run **Delegate Control** a second time and choose **Create a custom task to delegate** > "Only the following objects in the folder" >
   tick **Organizational Unit objects** with "Create selected objects in this folder" and "Delete selected objects in this folder" (the delete right is how the sync removes empty OUs Google no longer has), then
   grant **Full Control** (or at minimum read/write all properties). The wizard's common tasks do not include OUs, so this second pass is needed.

Two settings that are easy to get wrong:

- **Organizational Unit objects is its own checkbox.** Without it, creating a mirrored OU fails with `insufficientAccessRights` and any user
  in a sub-OU fails to create, while users at the Google root work fine.
- **Apply to "This object and all descendant objects",** not "child objects". Child objects only reaches one level down, which
  leaves anything nested two or more levels deep outside the permission.

The account needs nothing anywhere else in the domain.

### 3.4 LDAPS (port 636)

The app connects with **LDAPS only**. AD refuses to set a password over unencrypted LDAP, and the app never falls back to it.

- The domain controller needs a certificate for LDAPS (any domain controller with a certificate from an Enterprise CA, or a manually installed one, will serve LDAPS).
- The computer running the app must be able to reach `dc01.corp.example.com:636` and **trust the certificate**. On a domain-joined Windows server using an Enterprise CA, that is automatic.
- Quick check from the app server: `Test-NetConnection dc01.corp.example.com -Port 636`.

### 3.5 If the app runs as a Windows service or task on a domain controller

A special case with its own steps (log on as a batch job via GPO, NTFS rights). See [deployment.md](deployment.md).

---

## Part 4. Email (optional but useful)

New AD users get a temporary password. If the dashboard's **Email notifications** toggle is on, the app emails it to the person; if
off, the sync shows each password once on screen.

- Use a **dedicated mailbox** (for example `it-noreply@example.com`), not a personal one, so a leaked credential can only send as that one address.
- For Gmail / Google Workspace: turn on **2-Step Verification** for that mailbox, then create an **App Password**
  (Google Account > Security > App passwords). A normal password will not work: Google blocks regular passwords from non-Google apps.
- Defaults are `smtp.gmail.com` port `587` with STARTTLS. Any SMTP server that supports STARTTLS works; `setup_secrets.py --live` asks for server and port.

---

## Part 5. Save the settings and switch

```bash
python setup_secrets.py --live
```

You will be asked for: the service account key path, the admin to act as, the customer ID, the domain controller host name, base DN,
service account DN or UPN and password, and the mail server details. They are stored encrypted in `secrets.json.enc`.
Re-run the command any time to change values (Enter keeps a saved password).

Then restart the app, sign in as the **Owner**, open **Settings > Connection**:

1. **Run connection check.** Each line shows a tick or a cross with the reason.
2. **Go Live**, entering your current 6-digit code. It re-runs the checks first and stays in Demo if any fail.

**Suggested first Live run:** keep the base DN on a throwaway test OU, run a sync preview, read every line, sync, and check
the result in Active Directory Users and Computers. Widen the base DN later if you want to.

### What each Google error usually means

| Message | Cause |
|---|---|
| `unauthorized_client` | The delegation entry is missing, has the wrong Client ID, or is missing a scope. Re-check Part 2 and give Google a few minutes |
| `invalid_grant` / "Not Authorized to access this resource" | The "admin to act as" is not a super admin, is suspended, or is not in your domain |
| `Errno 2` / "No such file" | The key path is wrong, or the account running the app cannot read it |
| `accessNotConfigured` / "API has not been used" | The Admin SDK API is not enabled in the project (Part 1.1) |
