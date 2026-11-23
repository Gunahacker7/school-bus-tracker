#!/usr/bin/env python3
"""
robust_test.py — BusSafe robustness suite.

Feeds the service malformed/garbage/oversized input, empty lines,
abrupt disconnects and rapid connect/disconnect cycles. The service
must reply with clean ERR lines where applicable, never crash, never
hang (every read is timeout-guarded), and still serve a full normal
session afterwards.

Usage: robust_test.py [host] [port]   (defaults 127.0.0.1 14570)
Exit code 0 = all checks pass.
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 14570
TIMEOUT = 10

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    print(f"-- {'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else ""))
    if ok:
        passed += 1
    else:
        failed += 1


class Conn:
    """Raw-bytes connection; read_block returns decoded lines of one
    reply block ('.'-terminated). Raises socket.timeout on a hang."""

    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        self.s.settimeout(TIMEOUT)
        self.buf = b""
        self.greeting = self.read_block()

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

    def send(self, data: bytes):
        self.s.sendall(data)

    def cmd(self, text: str):
        self.send((text + "\n").encode())
        return self.read_block()

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def has(block, needle):
    return any(needle in ln for ln in block)


def main():
    # 1. Connect and disconnect without sending anything.
    try:
        c = Conn()
        greet_ok = has(c.greeting, "READY")
        c.close()
        check("connect + immediate disconnect (no bytes)", greet_ok)
    except Exception as e:  # noqa: BLE001
        check("connect + immediate disconnect (no bytes)", False, repr(e))

    # 2. Partial line (no LF), then disconnect.
    try:
        c = Conn()
        c.send(b"PIN")
        c.close()
        check("partial line then disconnect", True)
    except Exception as e:  # noqa: BLE001
        check("partial line then disconnect", False, repr(e))

    # 3-8. Malformed input on one connection; each must get a clean reply.
    c = Conn()
    try:
        check("empty line -> ERR EMPTY", has(c.cmd(""), "ERR EMPTY"))
    except Exception as e:  # noqa: BLE001
        check("empty line -> ERR EMPTY", False, repr(e))
    try:
        check("whitespace-only line -> ERR EMPTY", has(c.cmd("   "), "ERR EMPTY"))
    except Exception as e:  # noqa: BLE001
        check("whitespace-only line -> ERR EMPTY", False, repr(e))
    try:
        c.send(b"\r\n")
        check("CRLF empty line -> ERR EMPTY", has(c.read_block(), "ERR EMPTY"))
    except Exception as e:  # noqa: BLE001
        check("CRLF empty line -> ERR EMPTY", False, repr(e))
    try:
        check("garbage command -> ERR UNKNOWN_COMMAND",
              has(c.cmd("XYZQW blah"), "ERR UNKNOWN_COMMAND"))
    except Exception as e:  # noqa: BLE001
        check("garbage command -> ERR UNKNOWN_COMMAND", False, repr(e))
    try:
        check("missing argument -> ERR BADARG", has(c.cmd("BOARD"), "ERR BADARG"))
    except Exception as e:  # noqa: BLE001
        check("missing argument -> ERR BADARG", False, repr(e))
    try:
        check("lowercase ping still works", has(c.cmd("ping"), "OK PONG"))
    except Exception as e:  # noqa: BLE001
        check("lowercase ping still works", False, repr(e))

    # 9. Oversized line (5000 chars): truncated, clean error, conn alive.
    try:
        c.send(b"A" * 5000 + b"\n")
        block = c.read_block()
        check("oversized 5000-char line -> ERR UNKNOWN_COMMAND",
              has(block, "ERR UNKNOWN_COMMAND"))
        check("same connection still serves PING after oversized line",
              has(c.cmd("PING"), "OK PONG"))
    except Exception as e:  # noqa: BLE001
        check("oversized 5000-char line", False, repr(e))

    # 10. Binary garbage incl. NUL bytes: some ERR reply, conn alive.
    try:
        c.send(b"\x00\x01\x02\xff\xfe\n")
        block = c.read_block()
        check("binary garbage -> ERR reply",
              len(block) > 0 and block[0].startswith("ERR"),
              f"got {block[:1]}")
        check("same connection still serves PING after binary garbage",
              has(c.cmd("PING"), "OK PONG"))
    except Exception as e:  # noqa: BLE001
        check("binary garbage handling", False, repr(e))
    c.close()

    # 11. Rapid connect/disconnect cycles x20 (greeting each time).
    ok_cycles = 0
    try:
        for _ in range(20):
            cc = Conn()
            if has(cc.greeting, "READY"):
                ok_cycles += 1
            cc.close()
    except Exception as e:  # noqa: BLE001
        check("rapid connect/disconnect x20", False, repr(e))
    check("rapid connect/disconnect x20", ok_cycles == 20, f"{ok_cycles}/20 greetings")

    # 12. Full normal session afterwards: service fully functional.
    try:
        c = Conn()
        check("post-abuse PING", has(c.cmd("PING"), "OK PONG"))
        check("post-abuse STARTROUTE R3", has(c.cmd("STARTROUTE R3"), "OK ROUTE_STARTED R3"))
        check("post-abuse BOARD X1", has(c.cmd("BOARD X1"), "OK BOARDED X1"))
        block = c.cmd("ENDROUTE")
        check("post-abuse ENDROUTE alert",
              has(block, "ALERT STILL_ONBOARD X1") and has(block, "ALERTS 1"))
        check("post-abuse STATUS inactive", has(c.cmd("STATUS"), "ROUTE NONE INACTIVE"))
        check("post-abuse QUIT", has(c.cmd("QUIT"), "OK BYE"))
        c.close()
    except Exception as e:  # noqa: BLE001
        check("post-abuse normal session", False, repr(e))

    print(f"RESULT: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
