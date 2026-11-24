
import json
from pathlib import Path

from getpass import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import Hashing_Algorithm
import Write_To_Json
from audit_logging import log_attempt


PRIVATE_KEY_FILE = Path("publisher/private_key.pem")
REGISTRY_FILE = Path("trusted_publishers.json")


def sign(directory, publisher_id=None):
    """Create a release manifest and digitally sign it."""

    release_folder = Path(directory)
    publisher_id = publisher_id or "unknown"

    result = "REJECTED"
    reason = "Signing failed"

    try:
        # 1. Validate release folder
        if not release_folder.is_dir():
            raise ValueError("Release folder does not exist")

        payload_folder = release_folder / "payload"

        if not payload_folder.is_dir():
            raise ValueError("Payload folder is missing")

        # 2. Validate publisher registry
        if not REGISTRY_FILE.is_file():
            raise ValueError("Trusted publisher registry is missing")

        with REGISTRY_FILE.open("r", encoding="utf-8") as file:
            registry = json.load(file)

        if not isinstance(registry, list):
            raise ValueError("Invalid publisher registry")

        if publisher_id == "unknown":
            publisher_id = input("Enter publisher ID: ").strip()

        publisher = next(
            (
                entry for entry in registry
                if isinstance(entry, dict)
                and entry.get("publisher_id") == publisher_id
            ),
            None
        )

        if publisher is None:
            raise ValueError("Publisher is not registered")

        if publisher.get("enabled") is not True:
            raise ValueError("Publisher is disabled")

        # 3. Check private key exists
        if not PRIVATE_KEY_FILE.is_file():
            raise ValueError("Publisher private key is missing")

        # 4. Load private key BEFORE modifying release files
        passphrase = getpass("Enter private key passphrase: ")

        if not passphrase:
            raise ValueError("Passphrase cannot be empty")

        try:
            with PRIVATE_KEY_FILE.open("rb") as file:
                private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=passphrase.encode("utf-8")
                )
        except (ValueError, TypeError):
            raise ValueError("Incorrect passphrase or invalid private key")

        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Private key must be Ed25519")

        # 5. Calculate hashes using relative payload paths
        file_hashes = {}

        for file_path in sorted(payload_folder.rglob("*")):

            if file_path.is_symlink():
                raise ValueError(
                    "Symbolic links are not allowed in payload"
                )

            if file_path.is_file():
                relative_path = file_path.relative_to(
                    payload_folder
                ).as_posix()

                file_hashes[relative_path] = (
                    Hashing_Algorithm.hashFile(str(file_path))
                )

        if not file_hashes:
            raise ValueError("Payload contains no files")

        # 6. Create manifest
        manifest_path = Write_To_Json.write_manifest(
            release_folder,
            publisher_id,
            file_hashes
        )

        # 7. Sign the exact manifest bytes
        manifest_bytes = manifest_path.read_bytes()
        signature = private_key.sign(manifest_bytes)

        # 8. Save signature
        signature_path = release_folder / "signature.sig"
        signature_path.write_bytes(signature)

        result = "ACCEPTED"
        reason = "Release signed successfully"

        print("ACCEPTED: " + reason)

        return result, reason, publisher_id

    except Exception as error:
        reason = str(error)

        print("REJECTED: " + reason)

        return result, reason, publisher_id

    finally:
        try:
            log_attempt(
                "sign",
                directory,
                publisher_id,
                result,
                reason
            )
        except Exception as log_error:
            print("WARNING: Could not write audit log:", log_error)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 Sign.py <release-folder>")
    else:
        sign(sys.argv[1])
