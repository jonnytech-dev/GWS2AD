#!/usr/bin/env python3
"""
convert_pfx_to_pem.py
======================
One-time helper to convert a PFX/PKCS12 certificate - the format a
cert issued by Active Directory Certificate Services (or exported from
certreq/MMC) usually comes as - into the separate cert.pem/key.pem
files app.py expects for HTTPS.

Run this ONCE:
    python convert_pfx_to_pem.py

Prompts for the .pfx file path and its export password, then writes
cert.pem and key.pem next to this script. Set USE_HTTPS=true in .env
and restart the app afterward.
"""

from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from pathlib import Path
import getpass

APP_ROOT = Path(__file__).parent


def main():
    print("=" * 70)
    print("GWS2AD - PFX to PEM Converter")
    print("=" * 70)
    print()
    pfx_path = input("Path to your .pfx file: ").strip().strip('"')
    pfx_password = getpass.getpass("PFX export password (blank if none): ")

    try:
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
    except FileNotFoundError:
        print(f"[ERROR] Could not find a file at: {pfx_path}")
        return

    try:
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            pfx_data, pfx_password.encode() if pfx_password else None
        )
    except Exception as e:
        print(f"[ERROR] Could not read that PFX file: {e}")
        print("        Double-check the file path and password.")
        return

    if not private_key or not certificate:
        print("[ERROR] That file didn't contain both a private key and a certificate.")
        return

    cert_path = APP_ROOT / "cert.pem"
    key_path = APP_ROOT / "key.pem"

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))
        # Include any intermediate/chain certs bundled in the PFX too
        if additional_certs:
            for extra_cert in additional_certs:
                f.write(extra_cert.public_bytes(Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))

    print()
    print(f"[OK] Created {cert_path}")
    print(f"[OK] Created {key_path}")
    print()
    print("Next steps:")
    print("  1. Add USE_HTTPS=true to your .env file")
    print("  2. Restart the app")


if __name__ == "__main__":
    main()
