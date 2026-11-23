#!/usr/bin/env python3
"""
restart_test.py — BusSafe persistence / mid-route restart recovery test.

phase1: build a mid-route state (route R2 active; STU101 ALIGHTED,
        STU102 ONBOARD, STU103 EXPECTED), capture the STATUS block and
        save it to restart_expected.txt.
        >>> the operator then kills (SIGKILL) and restarts the service <<<
phase2: reconnect, take STATUS again and require it to match the saved
        block EXACTLY; then ENDROUTE and require the safety sweep to
        reflect the recovered state (STILL_ONBOARD STU102,
        NEVER_BOARDED STU103, ALERTS 2).

Usage: restart_test.py phase1|phase2 [host] [port]
Defaults: 127.0.0.1 14570 (QEMU hostfwd to guest 4570).
Exit code 0 = all checks in the phase pass.
"""
import socket
import sys
import os

PHASE = sys.argv[1] if len(sys.argv) > 1 else "phase1"
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 14570
EXPECT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "restart_expected.txt")

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    print(f"-- {'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else ""))
    if ok:
        passed += 1
    else:
        failed += 1


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=15)
        self.buf = b""
        self.greeting = self.read_block()
        print(f"<< GREETING: {' | '.join(self.greeting)}")

    def read_block(self):
        lines = []
        while True:
            while b"\n" not in self.buf:
                chunk = self.s.recv(4096)
                if not chunk:
                    return lines
                self.buf += chunk
            raw, self.buf = self.buf.split(b"\n", 1)
            line = raw.rstrip(b"\r").decode("utf-8", "replace")
            if line == ".":
                return lines
            lines.append(line)

    def cmd(self, text):
        print(f">> {text}")
        self.s.sendall((text + "\n").encode())
        block = self.read_block()
        for ln in block:
            print(f"<< {ln}")
        return block

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def expect(block, needle, name):
    check(name, any(needle in ln for ln in block), f"expected '{needle}'")


def phase1():
    c = Conn()
    expect(c.cmd("STARTROUTE R2"), "OK ROUTE_STARTED R2", "start route R2")
    expect(c.cmd("ADDSTUDENT STU101"), "OK EXPECTED STU101", "add STU101")
    expect(c.cmd("ADDSTUDENT STU102"), "OK EXPECTED STU102", "add STU102")
    expect(c.cmd("ADDSTUDENT STU103"), "OK EXPECTED STU103", "add STU103")
    expect(c.cmd("BOARD STU101"), "OK BOARDED STU101", "board STU101")
    expect(c.cmd("BOARD STU102"), "OK BOARDED STU102", "board STU102")
    expect(c.cmd("ALIGHT STU101"), "OK ALIGHTED STU101", "alight STU101")
    status = c.cmd("STATUS")
    with open(EXPECT_FILE, "w") as fh:
        fh.write("\n".join(status) + "\n")
    print(f"Saved pre-kill STATUS ({len(status)} lines) to {EXPECT_FILE}")
    check("pre-kill STATUS captured", len(status) >= 5)
    c.close()


def phase2():
    with open(EXPECT_FILE) as fh:
        expected = [ln.rstrip("\n") for ln in fh if ln.strip()]
    c = Conn()
    status = c.cmd("STATUS")
    check("STATUS after restart matches pre-kill STATUS exactly",
          status == expected,
          "match" if status == expected else f"got {status} want {expected}")
    block = c.cmd("ENDROUTE")
    expect(block, "OK ROUTE_ENDED R2", "endroute recovered route R2")
    expect(block, "ALERT STILL_ONBOARD STU102", "alert: STU102 still onboard")
    expect(block, "ALERT NEVER_BOARDED STU103", "alert: STU103 never boarded")
    expect(block, "ALERTS 2", "alert count = 2")
    c.close()


if __name__ == "__main__":
    if PHASE == "phase1":
        phase1()
    elif PHASE == "phase2":
        phase2()
    else:
        print("usage: restart_test.py phase1|phase2 [host] [port]")
        sys.exit(2)
    print(f"RESULT {PHASE}: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
