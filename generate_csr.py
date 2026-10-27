#!/usr/bin/env python3
"""
generate_csr.py
================
Generates a private key (saved directly as key.pem - ready to use,
nothing to extract later) and a Certificate Signing Request (CSR) to
submit to your internal CA (e.g. Active Directory Certificate
Services). The CA only ever sees the CSR's public key - your private
key never leaves this machine, and there's no PFX to split afterward.

Run this ONCE:
    python generate_csr.py

Creates:
  - key.pem   → your private key. Ready to use as-is once the app is
                configured for HTTPS - don't regenerate this after
                submitting the CSR, or it won't match the issued cert.
  - request.csr → submit THIS to your CA. See the printed instructions
                  for how, depending on whether your CA has the Web
                  Enrollment role installed.

After your CA issues the certificate, save what it gives you back as
cert.pem in this same folder (see printed instructions for exact
format), then set USE_HTTPS=true in .env and restart the app.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
import re

APP_ROOT = Path(__file__).parent

_NAME = re.compile(r'^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')


def parse_hostnames(text, default):
    """
    "a.example.com, b.example.com" -> ['a.example.com', 'b.example.com'].
    The first name is the main one. Every name goes in the certificate, so one certificate
    works for all of them. Raises ValueError for anything that is not a plain host name.
    """
    names = [n.strip().lower() for n in (text or '').replace(';', ',').replace(' ', ',').split(',') if n.strip()]
    names = names or [default]
    for n in names:
        if not _NAME.match(n):
            raise ValueError(f"'{n}' is not a valid host name (example: gws2ad.example.com)")
    return list(dict.fromkeys(names))


def main():
    print("=" * 70)
    print("GWS2AD - Certificate Signing Request Generator")
    print("=" * 70)
    print()
    print("Type every name people will use, separated by commas. One certificate will cover all of them.")
    print("Example: gws2ad.example.com, reset.example.com")
    while True:
        try:
            hostnames = parse_hostnames(input("Host name(s) [gws2ad.example.com]: "), "gws2ad.example.com")
            break
        except ValueError as e:
            print(f"  {e}")
    hostname = hostnames[0]
    print("Names in the request: " + ", ".join(hostnames))

    if (APP_ROOT / "key.pem").exists():
        print()
        print("key.pem already exists. A new key would stop your current certificate from working,")
        print("because a certificate only works with the key it was made for.")
        if input("Type YES to replace it, or press Enter to stop: ").strip() != "YES":
            print("Stopped. Nothing was changed. Move key.pem somewhere safe first if you want a fresh one.")
            return

    print()
    print("Generating a 2048-bit private key...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    key_path = APP_ROOT / "key.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"[OK] Created {key_path} - keep this, don't regenerate it later")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in hostnames]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    csr_path = APP_ROOT / "request.csr"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(f"[OK] Created {csr_path}")

    print()
    print("=" * 70)
    print("NEXT: Submit request.csr to your CA")
    print("=" * 70)
    print()
    print("If your CA has the Web Enrollment role installed:")
    print("  1. Open http://<your-CA-server>/certsrv")
    print("  2. Click 'Request a certificate' -> 'Advanced certificate request'")
    print("  3. Click the option to submit a base-64-encoded request")
    print(f"  4. Open {csr_path.name} in Notepad, copy all its contents")
    print("     (including the BEGIN/END lines) into the 'Saved Request' box")
    print("  5. Select a template that allows CSR submission - typically")
    print("     'Web Server' (ask whoever manages your CA if unsure)")
    print("  6. Submit, then download the issued certificate as Base-64")
    print("     encoded, and save it as cert.pem in this same folder")
    print()
    print("If Web Enrollment isn't installed, from an elevated prompt on")
    print("a machine that can reach the CA:")
    print(f"  certreq -submit -attrib \"CertificateTemplate:WebServer\" {csr_path.name} cert.pem")
    print()
    print("Either way: once cert.pem exists next to key.pem, add")
    print("USE_HTTPS=true to .env and restart the app.")


if __name__ == "__main__":
    main()
