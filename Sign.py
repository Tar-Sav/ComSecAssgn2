import hashlib
import os
import json
from getpass import getpass
from inspect import signature

from cryptography.hazmat.primitives import serialization, padding, hashes


def sign(directory):
    if os.path.isdir(directory):
        hashdict = {}
        for root, dirs, files in os.walk(directory):
            if "payload" in dirs:
                break
            else:
                print("No Payload folder found in {}",format(root))
                return

        for root, dirs, files in os.walk(os.path.join(directory, "payload")):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    digest = hashFile(file_path)
                    hashdict[file_path] = digest
        writeHashes(hashdict, directory)

    elif os.path.isfile(directory):
        print("Please point to the release folder")
    else:
        print("path does not exist")

def hashFile(filePath):
    with open(filePath, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
        return digest.hexdigest()

def writeHashes(hashdict, directory):
    publisher_id = getPublisherID()
    release_name = directory.split("\\")[-2]
    data = {"publisher_id": publisher_id,
            "release name": release_name,
            }
    data.update(hashdict)
    with open(os.path.join(directory, 'manifest.json'), 'w', encoding='utf-8') as outfile:
        json.dump(data, outfile, ensure_ascii=False, indent=4)
    print("Manifest written to manifest.json...")
    signFiles(directory)
    print("Files signed...")

def getPublisherID():
    with open("trusted_publishers.json", "r") as f:
        data = json.load(f)
    publisherId = data[0]["publisher_id"]
    return publisherId

def signFiles(directory):
    password = getpass("Enter Password: ")
    with open("publisher\\private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password.encode())
    with open(os.path.join(directory, 'manifest.json'), "rb") as manifest_file:
        manifestBytes = manifest_file.read()

    signature = private_key.sign(
        manifestBytes
    )
    with open(os.path.join(directory, "signature.sig"), "wb") as sig_file:
        sig_file.write(signature)
