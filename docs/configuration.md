# Configuration

## Files

| File | Holds | In git? |
|---|---|---|
| `secrets.json.enc` | The app's settings and credentials, encrypted (Fernet) | **Never** |
| `.env` | `SECRETS_KEY` (decrypts the file above) plus optional switches | **Never** |
| `connection_mode.json` | `demo` or `live` | No (git-ignored) |
| `gw2ad.db` | Accounts, roles, audit log, sync status, settings | **Never** |
| `keys/` | Your Google service account key | **Never** |
| `.env.example` | A template listing the optional switches | Yes |

The key and the encrypted file are kept apart on purpose: having only one of them tells an attacker nothing. Back up
`.env` somewhere safe. Without it `secrets.json.enc` cannot be read, and you would run `setup_secrets.py` again.

## `setup_secrets.py`

| Command | What it does |
|---|---|
| `python setup_secrets.py` | First run. Asks for the Owner username and password only. Creates `secrets.json.enc` and `.env`. Refuses to overwrite existing settings |
| `python setup_secrets.py --live` | Adds the Google, AD and mail settings to the existing file |
| `python setup_secrets.py --non-interactive` | First run for scripts and containers. Reads `GWS2AD_OWNER_USERNAME` and `GWS2AD_OWNER_PASSWORD` (8+ characters) |

> The Owner login from setup is used **once**, the first time the app starts with an empty database. Re-running setup with a
> different password does not change an existing database. Change it in the app (Settings > Profile), or delete `gw2ad.db` to start clean.
> Passwords chosen in the app must be 12 to 128 characters.

## Settings inside `secrets.json.enc`

| Key | Needed for | Meaning |
|---|---|---|
| `flask_secret_key` | always | Signs login sessions. Generated for you |
| `admin_username`, `admin_password` | first start | The first Owner |
| `gws_key_path` | Live | Path to the service account JSON key |
| `gws_subject` | Live | The super admin the service account acts as |
| `gws_customer` | Live | Customer ID, usually `my_customer` |
| `ad_server` | Live | Domain controller host name (LDAPS on port 636) |
| `ad_base_dn` | Live | Where everything lives, for example `OU=GWS-Sync,DC=corp,DC=example,DC=com` |
| `ad_bind_dn`, `ad_bind_password` | Live | The AD service account (DN or UPN) and its password |
| `smtp_server`, `smtp_port` | Live (default `smtp.gmail.com`, `587`) | Mail server, STARTTLS |
| `smtp_from_address`, `smtp_password` | Live | Sender and its (app) password |

The Settings > Connection page lists which Live values are still missing. Secrets are never typed into the web page.

## `.env` switches

| Variable | Default | Meaning |
|---|---|---|
| `SECRETS_KEY` | (set by setup) | Decryption key for `secrets.json.enc` |
| `GWS2AD_HOST` | `127.0.0.1` | Interface to listen on. `0.0.0.0` lets other computers reach it. Use HTTPS if you do |
| `GWS2AD_PORT` | `5000` (`443` with HTTPS) | Port |
| `RESET_PORTAL` | on | `false` turns off the self-service password reset page |
| `RESET_PORTAL_PORT` | `8443` | Port of the reset page. Always HTTPS, needs `cert.pem` and `key.pem` |
| `RESET_TRUST_PROXY` | off | `true` behind a reverse proxy that sets `X-Forwarded-For` |
| `RESET_SHOW_REASONS` | off | `true` shows a friendly refusal reason on the reset page (see the reset portal doc for the trade-off) |
| `USE_HTTPS` | off | `true` serves HTTPS using `cert.pem` and `key.pem` next to `app.py`. Also marks the session cookie `Secure` |

## Fixed in the code

| Setting | Value | Where |
|---|---|---|
| Idle sign-out | 15 minutes, sliding (every action resets it) | `config.py`, `PERMANENT_SESSION_LIFETIME` |
| Wrong passwords, or wrong two-step codes, before a lock | 5 | `loginlock.py`, `twofa.py` |
| Lock length | 15 minutes | same |
| Password length | 12 to 128 | `passwords.py` |
| Recovery codes | 10 per person | `twofa.py` |
| `Users` / `Groups` OU names in AD | `Users`, `Groups` | `config.py` `AD_CONFIG` |
| App name shown in pages | `GWS2AD` | `app.py` `APP_NAME` |

## In the app

- **Email notifications** (dashboard): on emails each new person their username and temporary password; off shows temporary passwords once on screen. Needs the "Run sync" permission to change.
- **Ignore list** (sync preview and Settings > Ignore list): AD users, groups and OUs that a sync must not delete. In the preview, click **Keep in AD** (and say why, if you like; notes are up to 200 characters); ignored items move to an "Ignored" section at the bottom, where **Stop ignoring** undoes it. Settings > Ignore list shows all of them (type, who added it, when, note) with search, a type filter, **Edit note** and **Stop ignoring**. Needs "Preview sync" to read and "Run sync" to change.
- **Settings > Connection** (Owner only): Run connection check, Go Live / Use Demo, Reset sample data.
