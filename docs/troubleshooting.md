# Troubleshooting

**Start here:** Settings > Connection > *Run connection check* (Live mode, Owner). It signs in to Google, AD and the mail server and says which fails and why.
Logs are in `logs/` and each sync prints a timestamped log in the dashboard.

## The app will not start

| Symptom | Fix |
|---|---|
| `Failed to load secrets` / `Secrets file not found` | Run `python setup_secrets.py`. For a moved install, copy `secrets.json.enc` **and** `.env` together |
| `SECRETS_KEY environment variable not set` | `.env` is missing or not in the app folder. A service must start in the app folder |
| `Could not decrypt secrets file` | `.env` and `secrets.json.enc` do not belong together. Restore both from the same backup, or run setup again |
| `No dashboard admin account is configured` | The database is empty and the secrets have no Owner. Run `python setup_secrets.py` |
| Import errors | The virtual environment is not active (your prompt should show `(venv)`), or run `pip install -r requirements.txt` again. Python 3.10+ |
| I changed the Owner password in setup but the old one still works | The Owner is created only on first start. Change it in Settings > Profile, or delete `gw2ad.db` to start fresh |
| Nothing at `http://localhost:5000` from another computer | By default it listens on this computer only. Set `GWS2AD_HOST=0.0.0.0` in `.env` (and use HTTPS) |

## Demo mode

| Symptom | Fix |
|---|---|
| The sample data changed or vanished | It lives in memory and resets on restart. Settings > Connection > Reset |
| Settings has no Connection tab | Only the Owner sees it |
| "Live mode needs ... saved first" | Run `python setup_secrets.py --live`, restart, try again |
| "Live mode was not turned on because a check failed" | Read the lines under the message. Each says what failed |

## Google Workspace

| Message | Meaning |
|---|---|
| `unauthorized_client` | Delegation entry missing or wrong Client ID or scopes. See [going-live.md](going-live.md#part-2-google-workspace-admin-console-domain-wide-delegation). Changes can take a few minutes |
| `invalid_grant` / Not Authorized | The admin to act as is not a super admin, is suspended, or is not in your domain |
| No such file | Wrong key path, or the account running the app cannot read it |
| API not enabled | Turn on the Admin SDK API in the Google Cloud project |
| Key creation blocked | The organization policy `iam.disableServiceAccountKeyCreation` must be allowed temporarily |
| New users or groups do not appear right away | Google lags a few seconds. The app compensates; a sync or a few seconds fixes the rest |

## Active Directory

| Symptom | Fix |
|---|---|
| Failed to connect | LDAPS must work: `Test-NetConnection <dc> -Port 636`. The DC needs a certificate and this machine must trust it. Check host name, bind DN and password |
| Sync: `insufficientAccessRights` | The service account lacks rights on the base DN. See [going-live.md](going-live.md#33-delegate-permissions) |
| Root-level users sync, sub-OU users fail, the sub-OU is never created | The **Organizational Unit objects** delegation is missing (a separate checkbox). Pre-creating the OU by hand does not help, since the app also creates a `Users` OU inside it |
| An OU that Google no longer has is not deleted | It is only deleted when empty. The sync log says `still contains N object(s)`. Check for an ignored user or group, a computer, or another ignored OU inside it. If the log says `Could not delete OU ... insufficientAccessRights`, the delegation lacks "Delete selected objects" for OU objects |
| Sub-OUs two levels deep fail | The delegation applies to "child objects" only. Re-apply to "This object and all descendant objects" |
| A user keeps being flagged "to create" though they exist | The base DN does not cover where they live, or they have neither `mail` nor `userPrincipalName` set |
| Password could not be set | It must go over LDAPS and meet your domain's password policy |
| Intermittent `SSL: RECORD_LAYER_FAILURE` under load | Each web thread now has its own connector. If it persists, suspect SSL inspection by a firewall or proxy; test `Invoke-WebRequest https://www.googleapis.com` from the server |

## Email

| Symptom | Fix |
|---|---|
| New users are not emailed | Is the dashboard's **Email notifications** toggle on? In Demo mode email is never sent |
| Login refused by the mail server | Gmail needs 2-Step Verification and an **App Password**, not the account password |
| Cannot connect | Allow outbound TCP to the mail server's port (587 by default) |
| A temporary password was lost | They are shown once and never stored. Set a new one with **Edit User** |

## Password reset page

| Symptom | Fix |
|---|---|
| Page does not load | Is `RESET_PORTAL` off? Is `cert.pem` / `key.pem` next to `app.py`? Without them it does not start (HTTPS only). Is port 8443 open in the firewall? Check the start-up lines for "Password reset page" |
| "Not started: same port" | `RESET_PORTAL_PORT` equals the main port. Pick another |
| No code arrives | The page always says it was sent. See the audit log (`self-service`) for the real reason: admin, suspended, not in Google or AD. Check the mail settings too |
| Google changed but Active Directory did not | The audit log says so. Use **Edit User** to set the password again |
| "Google could not be reached" | Nothing was changed. Check the server's internet access and try again |

## Sign-in

| Symptom | Fix |
|---|---|
| "Your 6-digit code is not correct" | Check the phone's clock is automatic. Codes last 30 seconds and each works once; wait for the next one |
| Locked for 15 minutes | Wait, or an Owner / account manager unlocks you (Settings > Accounts), or on the server `python unlock_account.py <username>` |
| Lost the phone | Use a recovery code. If you have none, on the server: `python reset_2fa.py <username>` |
| Signed out after a while | Inactivity timeout is 15 minutes |
| Pages look wrong after an update | Hard-refresh (Ctrl+F5). Stylesheets are versioned, but a stale cache can linger |
| Cannot sign in over HTTPS but HTTP worked, or the reverse | With `USE_HTTPS=true` the session cookie is Secure and is not sent over HTTP |
