# Deployment

Demo mode runs anywhere with `python app.py`. This page is for running GWS2AD for real, unattended, on a Windows server
(the setup it was built and tested for). On Linux the same ideas apply with systemd instead of NSSM / Task Scheduler.

**Best practice:** run it on a dedicated **member server**, not on a domain controller. A DC works, but any account with logon rights
there has a bigger blast radius, and it needs extra steps (below).

## 1. Install

```powershell
cd C:\Tools\GWS2AD            # wherever you cloned it
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python setup_secrets.py
python setup_secrets.py --live      # when you are ready (see going-live.md)
```

Put your Google key in `keys\` and run `python app.py` once to confirm it starts and you can sign in. Always **sign in**, not just load the page:
signing in is what proves the app can write to its database.

## 2. Run it as its own low-privilege account

Create the AD service account described in [going-live.md](going-live.md#32-create-the-service-account), or a separate local one, and run the app as it.
Do not run it as Administrator. If the app is compromised, the attacker should only get that account's small reach.

### Permissions the account needs on the server

- **NTFS Modify on the app folder, recursively.** The app writes `gw2ad.db`, `logs\`, `data_backup\` and `connection_mode.json` during normal use.
  Read-only access lets pages load but nothing work, because even sign-in writes to the database.
- **Log on as a batch job** (needed for Scheduled Tasks). A Windows service instead needs **Log on as a service**; the Services console grants it when you pick the account there, so check it if the service refuses to start.
  On a member server: `secpol.msc` > Local Policies > User Rights Assignment > *Log on as a batch job* > add the account.
  **On a domain controller**, a local `secpol.msc` change is overridden by the GPO that governs DCs, so set it there instead:
  Group Policy Management > *Domain Controllers* OU > *Default Domain Controllers Policy* > Edit > Computer Configuration > Policies > Windows Settings >
  Security Settings > Local Policies > User Rights Assignment > *Log on as a batch job* > add the account (keep existing entries). Then `gpupdate /force` on the DC.

## 3. Start at boot

### Option A: Windows service with NSSM

```powershell
winget install nssm              # or download from https://nssm.cc
# as Administrator, from the app folder:
powershell -ExecutionPolicy Bypass -File install-windows-service.ps1
```

The script asks for the service name, app folder, Python path (the venv's `python.exe`) and the service account, then installs and starts it.

### Option B: Scheduled Task (nothing extra to install)

Task Scheduler > Create Task (not Basic):

1. **General:** name it, "Run whether user is logged on or not", the service account as the user. Leave "Run with highest privileges" **unchecked**.
2. **Triggers:** At startup. **On a domain controller add a 2-minute delay**: AD's own services take a moment after boot, and the account cannot authenticate until they are up.
3. **Actions:** Program `C:\Tools\GWS2AD\venv\Scripts\python.exe`, arguments `app.py`, start in `C:\Tools\GWS2AD`.
4. **Settings:** restart on failure (for example every minute, 3 times).

### Manage it

```powershell
Get-Service GWS2AD-Flask ; Restart-Service GWS2AD-Flask                 # service
Start-ScheduledTask -TaskName "GWS2AD-Flask" ; Stop-ScheduledTask ...   # task
```

## 4. HTTPS (do this before letting anyone else reach it)

The sign-in page and every session cookie cross the network. Use HTTPS for anything beyond `localhost`.

### Which certificate?

| Situation | Use |
|---|---|
| Try it, or a single user | `python generate_cert.py`: self-signed. Browsers warn once per person |
| You have Active Directory Certificate Services | `python generate_csr.py`, then submit to your CA. No browser warnings, because the domain already trusts the CA |
| You already have a PFX from your CA | `python convert_pfx_to_pem.py` splits it into `cert.pem` and `key.pem` |

All of them end with `cert.pem` and `key.pem` next to `app.py`. Then add to `.env`:

```
USE_HTTPS=true
GWS2AD_HOST=0.0.0.0        # only if other computers need to reach it
```

With HTTPS on, the app listens on **443** (set `GWS2AD_PORT` to change it), and the session cookie is marked `Secure`.
If the files are missing it warns and falls back to HTTP.

### With an internal CA (what it was built for)

- **DNS:** an A record such as `gws2ad.example.com` pointing at the server.
- **Certificate:** the common name / subject alternative name must match that DNS name exactly, key size **2048-bit RSA** or more, private key exportable if you are exporting a PFX.
- **Enterprise CA:** every request must name its template. Submit with
  `certreq -submit -attrib "CertificateTemplate:WebServer" request.req response.cer`, then `certreq -accept response.cer`
  so the certificate links to the private key it belongs to (if the private-key icon is missing in `certlm.msc`, that step was skipped).
  `generate_csr.py` avoids the PFX step: it keeps the private key on this machine and prints exact submission instructions.

### Firewall

```powershell
New-NetFirewallRule -DisplayName "GWS2AD HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -RemoteAddress <admin subnet>
```

Restrict the rule to your admin network. This tool should never be reachable from the internet. Opening 443 does not extend an existing
rule for port 5000; they are separate.

## 5. Back up

Keep copies, stored apart from each other, of: `.env` (decryption key), `secrets.json.enc`, `gw2ad.db`, and your Google key.
`data_backup\` holds a pre-sync snapshot of Google data for every sync; prune old ones when you like.

## 6. Check it

- Sign in, run **Sync Workspace to AD** and read the preview.
- After a reboot, confirm it came back on its own.
- Settings > Connection > **Run connection check** shows Google, AD and mail at a glance.
