
import json
from pathlib import Path


def write_manifest(release_folder, publisher_id, file_hashes):
    """
    Create manifest.json in the release folder.

    file_hashes must contain relative payload paths
    and their SHA-256 hashes.
    """

    release_folder = Path(release_folder)

    manifest = {
        "publisher_id": publisher_id,
        "release_name": release_folder.name,
        "files": file_hashes
    }

    manifest_path = release_folder / "manifest.json"

    with manifest_path.open("w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4)

    return manifest_path
