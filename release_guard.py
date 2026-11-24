
import json
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def setup():
    publisher_dir = Path("publisher")
    verifier_dir = Path("verifier")

    private_key_file = publisher_dir / "private_key.pem"
    public_key_file = verifier_dir / "public_key.pem"
    registry_file = Path("trusted_publishers.json")

    # Prevent accidental overwriting of existing keys or registry
    if private_key_file.exists() or public_key_file.exists():
        print("ERROR: Key files already exist. Setup cancelled.")
        return False

    if registry_file.exists():
        print("ERROR: trusted_publishers.json already exists.")
        print("Existing publisher records will not be overwritten.")
        return False

    # Obtain publisher information
    publisher_id = input("Enter publisher ID: ").strip()

    if not publisher_id:
        print("ERROR: Publisher ID cannot be empty.")
        return False

    # Obtain encryption passphrase
    passphrase = getpass("Enter private key passphrase: ")

    if not passphrase:
        print("ERROR: Passphrase cannot be empty.")
        return False

    confirm_passphrase = getpass("Confirm private key passphrase: ")

    if passphrase != confirm_passphrase:
        print("ERROR: Passphrases do not match.")
        return False

    try:
        # Generate Ed25519 key pair
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Encrypt private key
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            )
        )

        # Export public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create directories
        publisher_dir.mkdir(parents=True, exist_ok=True)
        verifier_dir.mkdir(parents=True, exist_ok=True)

        # Save keys
        private_key_file.write_bytes(encrypted_private_key)
        public_key_file.write_bytes(public_key_pem)

        # Create trusted publisher registry
        trusted_publishers = [
            {
                "publisher_id": publisher_id,
                "public_key_path": str(public_key_file),
                "enabled": True
            }
        ]

        with registry_file.open("w", encoding="utf-8") as file:
            json.dump(trusted_publishers, file, indent=4)

        print("\nSetup completed successfully!")
        print("Publisher ID:", publisher_id)
        print("Private key saved securely.")
        print("Public key registered.")

        return True

    except Exception as error:
        # Remove partially created files if setup fails
        for file_path in (
            private_key_file,
            public_key_file,
            registry_file
        ):
            try:
                file_path.unlink(missing_ok=True)
            except OSError:
                pass

        print("ERROR: Setup failed:", error)
        return False
