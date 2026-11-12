import os

import Hashing_Algorithm
import Write_To_Json


def sign(directory):
    if os.path.isdir(directory):
        hashdict = {}
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    digest = Hashing_Algorithm.hashFile(file_path)
                    hashdict[file_path] = digest
        Write_To_Json.writeHashes(hashdict)

    elif os.path.isfile(directory):
        print("Please point to the payload folder")
    else:
        print("path does not exist")
