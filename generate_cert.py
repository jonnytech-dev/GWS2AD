#!/usr/bin/env python3
"""
generate_cert.py
=================
One-time script to generate a self-signed certificate for HTTPS.

Run this ONCE:
    python generate_cert.py

Creates cert.pem and key.pem next to this script. Set USE_HTTPS=true
in your .env file to have app.py use them.

This is a SELF-SIGNED certificate - browsers will show a security
warning the first time each admin visits the dashboard, since it
isn't issued by a trusted Certificate Authority. That's expected and
fine for an internal admin tool; each admin just needs to click
through the warning once (or, if you have Active Directory
Certificate Services set up, you could instead request a properly
trusted internal certificate there instead of using this script).
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
import datetime
import re
import ipaddress

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


def generate_self_signed_cert(hostname, ip_addresses=None, days_valid=825):
    """
    Generate a self-signed cert/key pair covering the given hostname
    (and optionally IP addresses, e.g. the server's own IP) so it's
    valid whether admins connect by name or by IP.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    hostnames = [hostname] if isinstance(hostname, str) else list(hostname)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0]),
    ])

    san_entries = [x509.DNSName(n) for n in hostnames]
    if ip_addresses:
        for ip in ip_addresses:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                print(f"[WARNING] '{ip}' isn't a valid IP address, skipping")

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )

    return cert, key


def main():
    print("=" * 70)
    print("GWS2AD - Self-Signed Certificate Generator")
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
    print("Names in the certificate: " + ", ".join(hostnames))

    ip_input = input("Also cover a specific IP address? (optional, press Enter to skip): ").strip()
    ip_addresses = [ip_input] if ip_input else []

    cert, key = generate_self_signed_cert(hostnames, ip_addresses)

    cert_path = APP_ROOT / "cert.pem"
    key_path = APP_ROOT / "key.pem"

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print()
    print(f"[OK] Created {cert_path}")
    print(f"[OK] Created {key_path}")
    print()
    print("Next steps:")
    print("  1. Add USE_HTTPS=true to your .env file")
    print(f"  2. Restart the app - it will bind to port 443 and serve https://{hostname}")
    print("  3. Each admin's browser will show a security warning the first")
    print("     time they visit, since this cert isn't from a trusted CA -")
    print("     that's expected for a self-signed cert on an internal tool.")


if __name__ == "__main__":
    main()
