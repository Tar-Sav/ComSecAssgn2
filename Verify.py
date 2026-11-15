import os
import json
import Hashing_Algorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def verify(release):
    manifest_path = os.path.join(release, "manifest.json")
    signPath = os.path.join(release, "signature.sig")
    payload = os.path.join(release, "payload")

    if not (os.path.isfile(manifest_path) and os.path.isfile(signPath) and os.path.isdir(payload)):
        print("REJECTED as the files or file manifest.json, signature.sig or payload is missing")
        return "REJECTED", "missing release files"

    manifestBytes = open(manifest_path, "rb").read()
    manifest = json.loads(manifestBytes)
    registry = json.load(open("trusted_publishers.json"))

    publisher = registry.get(manifest["publisher_Id"])
    if publisher is None:
        print("REJECTED as publisher is not trusted")
        return "REJECTED", "untrusted publisher"
    if not publisher["enabled"]:
        print("REJECTED as publisher is disabled")
        return "REJECTED", "disabled publisher"

    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(publisher["public_key"]))
    try:
        key.verify(open(signPath, "rb").read(), manifestBytes)
    except Exception:
        print("REJECTED, Invalid signature")
        return "REJECTED", "invalid signature"

    base = os.path.abspath(payload)
    for path in manifest["files"]:
        full = os.path.abspath(os.path.join(payload, path))
        if not full.startswith(base + os.sep):
            print("REJECTED as path is not safe " + path)
            return "REJECTED", "unsafe path " + path

    for path, digest in manifest["files"].items():
        full = os.path.join(payload, path)
        if not os.path.isfile(full):
            print("REJECTED as theres a missing file " + path)
            return "REJECTED", "missing file " + path
        
        if Hashing_Algorithm.hashFile(full) != digest:
            print("REJECTED as theres a hash mismatch for " + path)
            return "REJECTED", "hash mismatch " + path
    for root, dirs, files in os.walk(payload):
        for file in files:
            rel = os.path.relpath(os.path.join(root, file), payload).replace("\\", "/")
            if rel not in manifest["files"]:
                print("REJECTED as theres an extra file " + rel)
                return "REJECTED", "extra file " + rel

    print("ACCEPTED")
    return "ACCEPTED", "Everything is Inorder"
