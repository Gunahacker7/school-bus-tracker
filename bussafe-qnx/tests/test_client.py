#!/usr/bin/env python3
"""
test_client.py — end-to-end exercise of the bussafe_monitor protocol.

Usage: test_client.py [host] [port]   (defaults 127.0.0.1 14570,
where 14570 is the QEMU hostfwd to the guest's 4570)

Sends a fixed command script, prints the full transcript, and checks
each reply against the expected line. Exit code 0 = all checks pass.
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 14570

# (command, expected substring in reply block)
SCRIPT = [
    ("PING",            "OK PONG"),
    ("BOARD STU001",    "ERR NO_ROUTE"),          # no route yet
    ("STARTROUTE R1",   "OK ROUTE_STARTED R1"),
    ("ADDSTUDENT STU001", "OK EXPECTED STU001"),
    ("ADDSTUDENT STU002", "OK EXPECTED STU002"),
    ("ADDSTUDENT STU003", "OK EXPECTED STU003"),
    ("BOARD STU001",    "OK BOARDED STU001"),
    ("BOARD STU002",    "OK BOARDED STU002"),
    ("BOARD STU002",    "ERR ALREADY_ONBOARD STU002"),
    ("ALIGHT STU001",   "OK ALIGHTED STU001"),
    ("ALIGHT STU001",   "ERR NOT_ONBOARD STU001"),
    ("ALIGHT STU999",   "ERR UNKNOWN_STUDENT STU999"),
    ("STATUS",          "COUNT TOTAL 3 ONBOARD 1 ALIGHTED 1 EXPECTED 1"),
    ("ENDROUTE",        "ALERT STILL_ONBOARD STU002"),
    ("ENDROUTE",        "ERR NO_ROUTE"),          # route already ended
    ("STATUS",          "ROUTE NONE INACTIVE"),
    ("QUIT",            "OK BYE"),
]

# ENDROUTE's first call must also contain these:
ENDROUTE_EXTRA = ["OK ROUTE_ENDED R1", "ALERT NEVER_BOARDED STU003", "ALERTS 2"]


def read_block(f):
    lines = []
    while True:
        line = f.readline()
        if not line:
            break
        line = line.rstrip("\n").rstrip("\r")
        if line == ".":
            break
        lines.append(line)
    return lines


def main():
    passed = failed = 0
    with socket.create_connection((HOST, PORT), timeout=30) as s:
        f = s.makefile("r", encoding="utf-8", newline="\n")
        greeting = read_block(f)
        print(f"<< GREETING: {' | '.join(greeting)}")
        for cmd, expect in SCRIPT:
            print(f">> {cmd}")
            s.sendall((cmd + "\n").encode())
            block = read_block(f)
            for ln in block:
                print(f"<< {ln}")
            ok = any(expect in ln for ln in block)
            if cmd == "ENDROUTE" and expect.startswith("ALERT STILL"):
                for extra in ENDROUTE_EXTRA:
                    if not any(extra in ln for ln in block):
                        ok = False
                        print(f"!! MISSING expected line: {extra}")
            print(f"-- {'PASS' if ok else 'FAIL'} (expected: {expect})")
            if ok:
                passed += 1
            else:
                failed += 1
    print(f"RESULT: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
