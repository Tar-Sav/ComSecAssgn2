import os
import json
import sys
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def setup():
    publisher_dir = Path("publisher")
    verifier_dir = Path("verifier")

    private_key_file = publisher_dir / "private_key.pem"
    public_key_file = verifier_dir / "public_key.pem"

    if private_key_file.exists() or public_key_file.exists():
        print("ERROR: Keys already exist.")
        return

    publisher_id = input("Enter publisher ID: ").strip()

    if not publisher_id:
        print("ERROR: Publisher ID cannot be empty.")
        return

    passphrase = getpass("Enter passphrase: ")

    publisher_dir.mkdir(exist_ok=True)
    verifier_dir.mkdir(exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode()
        )
    )

    with open(private_key_file, "wb") as f:
        f.write(encrypted_private_key)

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(public_key_file, "wb") as f:
        f.write(public_key_pem)

    trusted_publishers = [
        {
            "publisher_id": publisher_id,
            "public_key_path": str(public_key_file),
            "enabled": True
        }
    ]

    with open("trusted_publishers.json", "w") as f:
        json.dump(trusted_publishers, f, indent=4)

    print("\nSetup completed successfully!")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 release_guard.py setup")
        return

    command = sys.argv[1]

    if command == "setup":
        setup()
    else:
        print("Unknown command.")

if __name__ == "__main__":
    main()

