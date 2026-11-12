import re

from Setup import setup
from Sign import sign

sign_cmd = r"^sign\s+(.+)$"
setup_cmd = r"^setup"
while True:
    cmd = input("Welcome to __________. Enter  your command  \n ->")
    signMatch = re.match(sign_cmd, cmd, re.IGNORECASE)
    setupMatch = re.match(setup_cmd, cmd, re.IGNORECASE)
    if signMatch:
        directory = sign.group(1).strip()
        sign(directory)
    elif setupMatch:
        setup()
    else:
        print("Invalid command")