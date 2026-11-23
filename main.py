import re

import Verify
from release_guard import setup
from Sign import sign

sign_cmd = r"^sign\s+(.+)$"
setup_cmd = r"^setup"
verify_cmd = r"^verify\s+(.+)$"
while True:
    cmd = input("Welcome to __________. Enter  your command  \n ->")
    signMatch = re.match(sign_cmd, cmd, re.IGNORECASE)
    setupMatch = re.match(setup_cmd, cmd, re.IGNORECASE)
    verifyMatch = re.match(verify_cmd, cmd, re.IGNORECASE)
    if signMatch:
        directory = signMatch.group(1).strip()
        sign(directory)
    elif setupMatch:
        setup()
    elif verify_cmd:
        directory = verifyMatch.group(1).strip()
        Verify.verify(directory)
    else:
        print("Invalid command")