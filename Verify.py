
import os
import json
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from Hashing_Algorithm import hashFile
from audit_logging import log_attempt


REGISTRY_FILE = Path("trusted_publishers.json")


def verify(release):
    """Verify a signed software release."""

    release_folder = Path(release)
    publisher_id = "unknown"

    result = "REJECTED"
    reason = "Verification failed"

    try:
        manifest_path = release_folder / "manifest.json"
        signature_path = release_folder / "signature.sig"
        payload_folder = release_folder / "payload"

        # CHECK 1: Validate manifest and required release files

        if not manifest_path.is_file():
            raise ValueError(
                "INVALID_MANIFEST: manifest.json is missing"
            )

        if not signature_path.is_file():
            raise ValueError(
                "INVALID_MANIFEST: signature.sig is missing"
            )

        if not payload_folder.is_dir():
            raise ValueError(
                "INVALID_MANIFEST: payload folder is missing"
            )

        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError(
                "INVALID_MANIFEST: manifest JSON is invalid"
            )

        if not isinstance(manifest, dict):
            raise ValueError(
                "INVALID_MANIFEST: manifest must be an object"
            )

        required_fields = {
            "publisher_id",
            "release_name",
            "files"
        }

        if not required_fields.issubset(manifest):
            raise ValueError(
                "INVALID_MANIFEST: required fields are missing"
            )

        if not isinstance(manifest["publisher_id"], str):
            raise ValueError(
                "INVALID_MANIFEST: invalid publisher ID"
            )

        if not isinstance(manifest["release_name"], str):
            raise ValueError(
                "INVALID_MANIFEST: invalid release name"
            )

        files = manifest["files"]

        if not isinstance(files, dict):
            raise ValueError(
                "INVALID_MANIFEST: files must be a dictionary"
            )

        publisher_id = manifest["publisher_id"]

        for path, digest in files.items():
            if not isinstance(path, str) or not isinstance(digest, str):
                raise ValueError(
                    "INVALID_MANIFEST: invalid file entry"
                )

            if (
                len(digest) != 64
                or any(c not in "0123456789abcdefABCDEF"
                       for c in digest)
            ):
                raise ValueError(
                    "INVALID_MANIFEST: invalid SHA-256 hash"
                )

        # CHECK 2: Validate trusted publisher

        if not REGISTRY_FILE.is_file():
            raise ValueError(
                "UNKNOWN_PUBLISHER: trusted registry missing"
            )

        try:
            with REGISTRY_FILE.open("r", encoding="utf-8") as file:
                registry = json.load(file)
        except (json.JSONDecodeError, OSError):
            raise ValueError(
                "UNKNOWN_PUBLISHER: registry is unreadable"
            )

        if not isinstance(registry, list):
            raise ValueError(
                "UNKNOWN_PUBLISHER: invalid registry format"
            )

        publisher = next(
            (
                entry for entry in registry
                if isinstance(entry, dict)
                and entry.get("publisher_id") == publisher_id
            ),
            None
        )

        if publisher is None:
            raise ValueError(
                "UNKNOWN_PUBLISHER: publisher is not trusted"
            )

        if publisher.get("enabled") is not True:
            raise ValueError(
                "PUBLISHER_DISABLED: publisher is disabled"
            )

        # CHECK 3: Verify Ed25519 signature

        public_key_path = publisher.get("public_key_path")

        if not isinstance(public_key_path, str):
            raise ValueError(
                "BAD_SIGNATURE: public key path is invalid"
            )

        public_key_path = Path(public_key_path)

        if not public_key_path.is_file():
            raise ValueError(
                "BAD_SIGNATURE: trusted public key is missing"
            )

        try:
            with public_key_path.open("rb") as file:
                public_key = serialization.load_pem_public_key(
                    file.read()
                )
        except (ValueError, OSError, TypeError):
            raise ValueError(
                "BAD_SIGNATURE: public key cannot be loaded"
            )

        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError(
                "BAD_SIGNATURE: public key is not Ed25519"
            )

        try:
            signature = signature_path.read_bytes()
            public_key.verify(signature, manifest_bytes)
        except Exception:
            raise ValueError(
                "BAD_SIGNATURE: signature verification failed"
            )

        # CHECK 4: Validate manifest paths

        payload_base = payload_folder.resolve()

        for relative_path in files:
            if (
                not relative_path
                or "\\" in relative_path
                or ":" in relative_path
            ):
                raise ValueError(
                    "UNSAFE_PATH: invalid path " + relative_path
                )

            pure_path = PurePosixPath(relative_path)

            if (
                pure_path.is_absolute()
                or ".." in pure_path.parts
                or "." in pure_path.parts
            ):
                raise ValueError(
                    "UNSAFE_PATH: unsafe path " + relative_path
                )

            full_path = payload_folder.joinpath(
                *pure_path.parts
            ).resolve()

            try:
                full_path.relative_to(payload_base)
            except ValueError:
                raise ValueError(
                    "UNSAFE_PATH: path escapes payload"
                )

        # Reject symbolic links in the payload

        for root, dirs, filenames in os.walk(
            payload_folder,
            followlinks=False
        ):
            for name in dirs + filenames:
                item = Path(root) / name

                if item.is_symlink():
                    raise ValueError(
                        "UNSAFE_PATH: symbolic links are not allowed"
                    )

        # CHECK 5: Check missing files and hashes

        for relative_path, expected_hash in files.items():
            full_path = payload_folder.joinpath(
                *PurePosixPath(relative_path).parts
            )

            if not full_path.is_file():
                raise ValueError(
                    "MISSING_FILE: " + relative_path
                )

            actual_hash = hashFile(str(full_path))

            if actual_hash.lower() != expected_hash.lower():
                raise ValueError(
                    "HASH_MISMATCH: " + relative_path
                )

        # Check for extra files

        actual_files = set()

        for root, dirs, filenames in os.walk(
            payload_folder,
            followlinks=False
        ):
            for filename in filenames:
                actual_path = Path(root) / filename

                relative_path = actual_path.relative_to(
                    payload_folder
                ).as_posix()

                actual_files.add(relative_path)

        expected_files = set(files.keys())

        extra_files = actual_files - expected_files

        if extra_files:
            raise ValueError(
                "EXTRA_FILE: " + ", ".join(sorted(extra_files))
            )

        # All checks passed

        result = "ACCEPTED"
        reason = "All verification checks passed"

        print("ACCEPTED")
        return result, reason, publisher_id

    except Exception as error:
        reason = str(error)

        print("REJECTED: " + reason)

        return result, reason, publisher_id

    finally:
        try:
            log_attempt(
                "verify",
                release,
                publisher_id,
                result,
                reason
            )
        except Exception as log_error:
            print("WARNING: Could not write audit log:", log_error)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 Verify.py <release-folder>")
    else:
        verify(sys.argv[1])
