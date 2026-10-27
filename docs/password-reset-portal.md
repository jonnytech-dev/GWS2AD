# Password reset page

A small second web page that starts together with GWS2AD, on the same computer but a different port. People use it to reset their own password, so an admin does not have to.

## What the person sees

1. They open the reset page and type their work email address.
2. A 6-digit code is emailed to their **work email address**.
3. They type the code, then choose a new password.
4. The new password is set in **Google and in Active Directory**, so it is one password for both.

The work mailbox gets a short "your password was changed" notice. It never contains the password or the code. The Google recovery email is not used at all.

### Nothing is changed unless both can be changed

1. Before any change, the page reads the account from Google and from Active Directory. If either cannot be reached, nothing happens.
2. **Google is changed first**, because it is a third party over the internet and the most likely to fail. If it fails, Active Directory is not touched and nothing has changed. The person is told to try again in a few minutes, and the same visit can finish.
3. Active Directory is changed second. If it refuses the password (its rules are stricter), the person is asked to choose another, and both are set again on the next try. Nothing is finished until the confirmation page.

Two systems cannot be changed in one atomic step, and Google's old password is not known, so it cannot be rolled back. If Active Directory keeps refusing, the person is told to contact IT and the audit log shows "Google password changed, Active Directory password not". Use **Edit User** to finish.

## Your logo and name

The Owner sets these in **Settings > Branding**:
- **Logo:** PNG, JPG, WEBP or GIF, under 2 MB. SVG is refused, because an SVG can carry scripts. The upload is opened as a picture, shrunk to fit 480 x 480 and saved again as a clean PNG, so nothing hidden in the file is kept.
- **Organization name:** shown under the logo and in the browser tab.

With no logo the page shows the GWS2AD triangle, the same one the dashboard uses. The same logo and name also appear on the dashboard sign-in and two-step pages and in the dashboard header, so staff can see they are on your organization's pages. Without one, those pages keep the GWS2AD triangle. The files live in a `branding` folder next to `app.py` (`logo.png` and `branding.json`). It is left out of git, so every install keeps its own. Back it up with the rest of the folder if you care about it. Deleting that folder resets the page to the placeholder.

## Who can use it

Everyone except Google administrators (super admins and delegated admins). Those accounts must be reset by a person. Also refused, quietly: suspended accounts, accounts that do not exist in Google, and accounts that have no Active Directory account.

The page gives the **same answer** for every address, so it never reveals whether an account exists. The real reason is written to the audit log under the name `self-service`.

## Ports and addresses

| Setting (`.env`) | Default | Meaning |
|---|---|---|
| `RESET_PORTAL` | on | `false` turns the page off |
| `RESET_PORTAL_PORT` | `8443` | Port for the reset page. It may not equal the main app's port |
| `RESET_TRUST_PROXY` | off | `true` if a reverse proxy in front sets `X-Forwarded-For`. Used for per-computer limits. Only turn on behind a proxy you control |
| `RESET_SHOW_REASONS` | off | `true` shows a plain reason when a reset is refused (administrator account, locked account, account not found, not ready, too many requests, code could not be sent). Never shows error codes. Off by default because it tells anonymous visitors which accounts exist and which are administrators. The real reason is always in the audit log |

It listens on the same interface as GWS2AD (`GWS2AD_HOST`).

### HTTPS only

The page is **always HTTPS, never plain HTTP**, because passwords cross it. It uses `cert.pem` and `key.pem` next to `app.py` (see [deployment.md](deployment.md) to make them). It uses them even if the dashboard itself is still on HTTP. **With no certificate it does not start**, and the start-up log says so. It never falls back to HTTP. The session cookie is `Secure`, and the page sends an HSTS header.

The certificate must cover the name people type (for example `reset.example.com`). With a self-signed certificate, browsers warn.

### DNS cannot carry a port

A DNS name such as `reset.example.com` points to an IP address only. It cannot say "port 8443". Pick one:

- **Reverse proxy (recommended).** Point the name at a proxy on port 443 that forwards to the reset page over HTTPS. Caddy example:

  ```
  reset.example.com {
      reverse_proxy https://127.0.0.1:8443 {
          transport http { tls_insecure_skip_verify }
      }
  }
  ```

  (`tls_insecure_skip_verify` is only for a self-signed certificate on the loopback hop.) nginx: `proxy_pass https://127.0.0.1:8443;` plus `proxy_set_header X-Forwarded-For $remote_addr;` inside a `server_name reset.example.com;` block. IIS: URL Rewrite with Application Request Routing to the same target. Then set `RESET_TRUST_PROXY=true`. The connection from the proxy to the page stays HTTPS.
- **Type the port.** Give people `https://reset.example.com:8443`. Simple, but easy to mistype.

Either way, the certificate must cover the reset hostname.

Open the reset port (8443 by default) in the Windows firewall for the network people use. Do not expose it to the internet unless you accept the risk below.

## Protections

- Codes last 10 minutes, are used once, and 5 wrong tries burn the code. After the code is accepted the person has 10 minutes to choose a password.
- At most 3 code requests per address and 10 per computer in an hour. A computer with 20 wrong codes is locked out for an hour.
- Codes and tokens are stored only as keyed hashes. Neither codes nor passwords are logged.
- Forms carry a one-off token, the cookie is `SameSite=Strict` with its own name (`gws2ad_reset`), pages send strict security headers and use no JavaScript.
- The admin check is repeated at the last step, so someone promoted to admin mid-reset is stopped.

## Know this before you turn it on

- **Whoever can open the work mailbox can reset both passwords.** A person who forgot their password may already be signed in to their mail; someone who walks up to an unlocked, signed-in computer could use it too.
- Not intended for the open internet without a reverse proxy and rate limits at the proxy.

## Page design and hardening

- The landing page explains what the page does and has the email box right on it. Every later step shows the address being reset, with a "Not you?" link.
- Nothing on the pages mentions the admin dashboard. The session cookie is `reset_session`, there is no `/static` folder, only `/assets/reset.css` and the font are served (a fixed whitelist), and the `Server` header is removed.
- Visitors never see server errors or codes, only friendly sentences.

## Demo mode

No email is sent. The code is shown on the page so you can try it. It still needs a certificate (`python generate_cert.py` makes a self-signed one). Sample people to try:

| Address | Result |
|---|---|
| `praman@example.com` and most others | Works. Both mock passwords change |
| `malvarez@example.com` | Refused: Google administrator |

## Tests

`tests/test_reset_portal_flow.py` covers the whole flow, the limits, expiry, the refusals, the Live email path and the Google and AD failure cases.
