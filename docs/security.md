# Security model

GWS2AD holds the keys to your Google Workspace and can create, change and delete accounts in Active Directory, so the web app in
front of it is the sensitive part. This page says what is protected, how, and what is **not**.

## What is protected, and how

### Signing in

- **Two-step verification is mandatory, for everyone, with no off switch.** A password alone never gets anyone in: until an account has paired an authenticator app it can use nothing,
  and the only way to clear it for someone is a reset that makes them set it up again at their next sign-in.
- **Standard TOTP** (RFC 6238): 6 digits, 30-second steps, one step of clock drift allowed. Works with any authenticator app.
- **Each code works once.** Replaying one, even within its 30 seconds, is refused.
- **Lockouts.** Five wrong passwords, or five wrong codes, lock the account for 15 minutes. The lock is stored in the database and survives restarts.
  A wrong username gets the same message as a wrong password, and unknown names are tracked in memory (capped) so a locked-out unknown name behaves like a real one. People cannot discover which usernames exist.
- **Recovery codes.** Ten, shown once at setup, each usable once. Stored only as keyed hashes (HMAC-SHA-256), never in a form that can be read back.
- **Authenticator secrets are encrypted at rest** with a key derived (HKDF) from the app's secret key.
- **Passwords** are hashed (PBKDF2-SHA-256 through Werkzeug), 12 to 128 characters, cannot contain the username, and a new one must differ from the old.
- **Sessions** end after 15 minutes of inactivity, the cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when HTTPS is on. Deactivating an account ends its live session at once.

### Doing things

- **Sensitive actions re-ask for your own current code:** account and role changes, unlocks, resets, deletes, and the Demo / Live switch. A stolen browser session cannot quietly do them.
- **The server enforces permissions on every request.** Hidden buttons are a convenience; calling the API directly without the permission is refused. The tests exercise every route for every kind of account.
- **CSRF tokens** protect every form. The JSON `/api/...` routes rely on the `SameSite=Lax` session cookie and accept JSON bodies only (see limitations).
- **One Owner**, enforced by a unique database index. Nobody can touch the Owner's account, and nobody can grant a permission they do not hold.
- **Username and email changes need the current password.** Names that appear in the audit history cannot be reused.
- **Pages that show secrets** (QR code, recovery codes, temporary passwords) are sent with `Cache-Control: no-store`, so the browser does not keep them.
- **Audit log** of sign-ins, failures, account and role changes, syncs, mode switches and resets, both in the database and in log files. Secrets and temporary passwords are never written to either.

### Secrets

- Credentials live in `secrets.json.enc` (Fernet), with the key in `.env`, kept apart.
- **Demo mode needs none.** The Google, AD and mail values are only entered with `setup_secrets.py --live` on the server, never typed into the web interface.
- A temporary password for a new user is shown once, or emailed, and not stored.
- Nothing in this repository is a real credential. `.gitignore` excludes the secrets file, `.env`, databases, keys and certificates.

### Reaching Google and AD

- **Google:** a service account with domain-wide delegation, limited to the user and group scopes plus **read-only** OUs. Revocable on its own.
- **AD:** a dedicated, unprivileged service account, delegated on one OU (recommended). **LDAPS only**: passwords are never set over unencrypted LDAP.
- **Sync deletes things.** AD users, groups and (empty) OUs under the base DN that are not in Google are removed unless on the ignore list. A dedicated base-DN OU limits the blast radius;
  the preview and a pre-sync backup of Google data are the safety net. Review the preview every time.

### Demo mode cannot change anything real

Demo connectors hold data in memory and never open a network connection; email is never sent. The mode defaults to Demo, and a missing or damaged
mode file means Demo. Switching to Live is Owner-only, needs the Owner's code, and requires every connection check to pass.

## Known limitations

Honest list. Some are fine for a small internal tool and some you may want to fix before wider use.

1. **`X-Forwarded-For` is trusted blindly** for the IP shown in the audit log (`auth.get_client_ip`). Anyone who can reach the app directly can write any address into it. Only trust it behind a reverse proxy that sets it.
2. **No per-IP rate limiting.** Lockout is per account, so someone who knows a username can lock that person out for 15 minutes, repeatedly. It stops guessing, and it can be abused to annoy. Put the app on a network only admins can reach.
3. **Email is a contact detail only** for dashboard accounts. The separate [password reset page](password-reset-portal.md) lets Google users reset their own AD and Google passwords with a code sent to their work email, so whoever can open that mailbox can reset both passwords. Google admins are excluded. The page is HTTPS only and does not start without a certificate.
4. **The JSON API has no CSRF tokens.** It depends on `SameSite=Lax` cookies and JSON-only bodies, which together stop the ordinary cross-site tricks, but token-based protection would be stronger.
5. **No `Content-Security-Policy`, frame or HSTS headers** are set by the app. Add them at a reverse proxy if you expose it beyond a trusted network.
6. **It uses Flask's built-in server.** That is adequate for a handful of admins on an internal network. For more, run it behind a production server / reverse proxy.
7. **Single instance only.** The directory cache and the unknown-name tracking live in process memory, and SQLite is the database. Do not run several copies against one database.
8. **The first Owner password you typed during setup stays (encrypted) in `secrets.json.enc`.** It is only read on the very first start. Changing your password in the app does not change that stored copy, so never reuse the setup password anywhere else.
9. **Anyone with write access to the app folder on the server** can flip the mode file, read the database, or run the emergency tools. Protect the folder with NTFS permissions ([deployment.md](deployment.md)).
10. **Tested with stand-ins, not your directory.** See the README's note on trying Live on a test OU first.

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
