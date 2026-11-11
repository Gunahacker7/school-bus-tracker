#!/usr/bin/env python3
"""
Set the School Bus Tracker staff passcode — run this ONCE on the machine
that hosts the app files, before any real deployment:

    python3 set_passcode.py

It asks for the new passcode (typed hidden, never stored in plaintext and
never sent anywhere), then:
  1. Updates the SHA-256 passcode hash inside index.html
     (the STAFF_PASSCODE_SHA256 constant the app checks locally).
  2. Writes bus_tracker.env next to server.py containing the same hash
     (BUS_TRACKER_PASSCODE_HASH) plus a random BUS_TRACKER_SECRET if one
     is not already set, so server logins use the new passcode too.

Start server.py from this same folder afterwards; it picks up
bus_tracker.env automatically. Keep bus_tracker.env private — it holds
the server secret.
"""

import getpass
import hashlib
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    pin = os.environ.get("SBT_NEW_PIN")
    if pin is None:
        pin = getpass.getpass("New staff passcode (6-16 characters): ")
        confirm = getpass.getpass("Repeat passcode: ")
        if pin != confirm:
            print("Passcodes do not match. Nothing changed.")
            return 1
    if not (6 <= len(pin) <= 16):
        print("Passcode must be 6-16 characters. Nothing changed.")
        return 1

    digest = hashlib.sha256(pin.encode("utf-8")).hexdigest()

    html_path = os.path.join(HERE, "index.html")
    with open(html_path, encoding="utf-8") as fh:
        html = fh.read()
    new_html, count = re.subn(
        r'const STAFF_PASSCODE_SHA256 = "[0-9a-f]{64}";',
        f'const STAFF_PASSCODE_SHA256 = "{digest}";',
        html,
    )
    if count != 1:
        print("Could not find the STAFF_PASSCODE_SHA256 constant in index.html. Nothing changed.")
        return 1
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(new_html)

    env_path = os.path.join(HERE, "bus_tracker.env")
    values = {}
    if os.path.exists(env_path):
        with open(env_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    values[key.strip()] = val.strip()
    values["BUS_TRACKER_PASSCODE_HASH"] = digest
    if not values.get("BUS_TRACKER_SECRET"):
        values["BUS_TRACKER_SECRET"] = secrets.token_hex(32)
    with open(env_path, "w", encoding="utf-8") as fh:
        for key, val in values.items():
            fh.write(f"{key}={val}\n")

    print("Done.")
    print(" - index.html: passcode hash updated.")
    print(" - bus_tracker.env: written (keep this file private).")
    print("Start server.py from this folder; it picks up the new passcode automatically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
