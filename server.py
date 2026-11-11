#!/usr/bin/env python3
"""
S. N. S School Bus Tracker - Authenticated REST + SQLite Backend Server (P0.3)

Security fixes applied (2026-11-11 audit):
- Removed the `stf_*_hmac` token-shape bypass in verify_token (any forged
  token of that shape was accepted). Only real HMAC signatures now pass.
- Tokens now expire (TOKEN_MAX_AGE_SECONDS) and future-dated tokens are
  rejected.
- GET /api/fleet now requires a valid staff token (was world-readable:
  full rosters + GPS of minors exposed without auth).
- Login role is server-fixed to "staff" (client can no longer pick a role).
- Login rate limiting: per-IP lockout after repeated passcode failures
  (the 4-digit demo passcode space is only 10,000 combinations).
- HMAC secret is no longer hardcoded: set BUS_TRACKER_SECRET in the
  environment. If unset, a random per-boot secret is generated (tokens
  stop working across restarts) and a warning is printed.
- Staff passcode is set with set_passcode.py (writes bus_tracker.env with
  a SHA-256 hash + a generated server secret), or via the BUS_TRACKER_PASSCODE
  / BUS_TRACKER_PASSCODE_HASH environment variables. The default "1234" is
  demo-only and prints a warning at startup.
- Request bodies are size-capped and malformed JSON returns HTTP 400
  instead of crashing the handler.
- ThreadingHTTPServer: one slow request no longer blocks every bus.
- CORS: wildcard removed. Origins are allow-listed via
  BUS_TRACKER_CORS_ORIGIN (comma-separated). Default allows local dev
  origins only (localhost/127.0.0.1 on any port, and "null" for file://
  pages during local demos).
- fleet_state upserts now also refresh corridor/plate on conflict.
- audit_events retention is capped so stored payloads (PII) do not grow
  forever.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DB_PATH = os.environ.get("BUS_TRACKER_DB", "bus_tracker.db")

def _load_local_env_file():
    """Read simple KEY=VALUE lines from bus_tracker.env next to this file
    (created by set_passcode.py). Real environment variables win."""
    values = {}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bus_tracker.env")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                values[key.strip()] = val.strip()
    except FileNotFoundError:
        pass
    return values


_LOCAL_ENV = _load_local_env_file()


def _config(name):
    return os.environ.get(name) or _LOCAL_ENV.get(name) or ""


_secret_env = _config("BUS_TRACKER_SECRET")
if _secret_env:
    SECRET_KEY = _secret_env.encode("utf-8")
else:
    SECRET_KEY = secrets.token_hex(32).encode("utf-8")
    print(
        "WARNING: BUS_TRACKER_SECRET is not set. Using a random per-boot "
        "secret; all issued tokens will stop working when the server restarts."
    )

_passcode_hash_env = _config("BUS_TRACKER_PASSCODE_HASH")
_passcode_env = _config("BUS_TRACKER_PASSCODE")
if _passcode_hash_env:
    STAFF_PASSCODE_HASH = _passcode_hash_env.lower()
elif _passcode_env:
    STAFF_PASSCODE_HASH = hashlib.sha256(_passcode_env.encode("utf-8")).hexdigest()
else:
    STAFF_PASSCODE_HASH = hashlib.sha256(b"1234").hexdigest()
    print(
        "WARNING: using the DEMO staff passcode (1234). "
        "Run set_passcode.py before any real deployment."
    )

TOKEN_MAX_AGE_SECONDS = 12 * 60 * 60  # staff tokens expire after 12 hours
TOKEN_FUTURE_SKEW_SECONDS = 300
MAX_BODY_BYTES = 1_000_000
AUDIT_RETENTION_ROWS = 10_000

# Login rate limiting (per client IP)
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 600
LOGIN_LOCKOUT_SECONDS = 600
_login_failures = {}  # ip -> [failure timestamps]
_login_lockouts = {}  # ip -> lockout-until timestamp

_cors_env = os.environ.get("BUS_TRACKER_CORS_ORIGIN", "").strip()
if _cors_env:
    ALLOWED_ORIGINS = {o.strip() for o in _cors_env.split(",") if o.strip()}
else:
    ALLOWED_ORIGINS = set()  # empty => allow any localhost/127.0.0.1 port + "null"


def _origin_allowed(origin: str) -> bool:
    if not origin:
        return False
    if ALLOWED_ORIGINS:
        return origin in ALLOWED_ORIGINS
    if origin == "null":
        return True
    return origin.startswith("http://localhost") or origin.startswith(
        "http://127.0.0.1"
    )


def issue_token(role: str = "staff") -> str:
    ts = str(int(time.time()))
    payload = f"{role}:{ts}"
    sig = hmac.new(SECRET_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"stf_{role}_{ts}_{sig}"


def verify_token(token: str) -> bool:
    if not token:
        return False
    if token.startswith("Bearer "):
        token = token[7:].strip()
    parts = token.split("_")
    if len(parts) != 4 or parts[0] != "stf":
        return False
    _, role, ts, sig = parts
    expected = hmac.new(SECRET_KEY, f"{role}:{ts}".encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        issued_at = int(ts)
    except ValueError:
        return False
    now = int(time.time())
    if issued_at > now + TOKEN_FUTURE_SKEW_SECONDS:
        return False
    if now - issued_at > TOKEN_MAX_AGE_SECONDS:
        return False
    return True


def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS fleet_state (
            bus_id TEXT PRIMARY KEY,
            corridor TEXT NOT NULL,
            plate TEXT NOT NULL,
            state_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bus_id TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.commit()
    return conn


class BusTrackerAPIHandler(BaseHTTPRequestHandler):
    db_conn = None

    def _cors_headers(self):
        origin = self.headers.get("Origin", "")
        if _origin_allowed(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send_json(self, status_code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json(200, {"ok": True})

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length).decode("utf-8")
        if not raw:
            return {}
        return json.loads(raw)

    def _require_auth(self) -> bool:
        auth_header = self.headers.get("Authorization", "")
        if not verify_token(auth_header):
            self._send_json(401, {"error": "Unauthorized: valid staff bearer token required"})
            return False
        return True

    def _login_locked_out(self, ip: str) -> bool:
        until = _login_lockouts.get(ip, 0)
        if until and time.time() < until:
            return True
        if until:
            _login_lockouts.pop(ip, None)
        return False

    def _record_login_failure(self, ip: str):
        now = time.time()
        fails = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        fails.append(now)
        _login_failures[ip] = fails
        if len(fails) >= LOGIN_MAX_FAILURES:
            _login_lockouts[ip] = now + LOGIN_LOCKOUT_SECONDS
            _login_failures[ip] = []

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send_json(200, {"status": "ok", "service": "school-bus-tracker-api"})
            return
        if parsed.path == "/api/fleet":
            if not self._require_auth():
                return
            cur = self.db_conn.cursor()
            cur.execute("SELECT bus_id, corridor, plate, state_json, updated_at FROM fleet_state")
            rows = cur.fetchall()
            fleet = {
                r[0]: {
                    "busId": r[0],
                    "corridor": r[1],
                    "plate": r[2],
                    "state": json.loads(r[3]),
                    "updatedAt": r[4],
                }
                for r in rows
            }
            self._send_json(200, {"ok": True, "fleet": fleet})
            return
        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            body = self._read_body()
        except (ValueError, RecursionError) as exc:
            message = str(exc)
            status = 413 if "too large" in message else 400
            self._send_json(status, {"error": f"Invalid request body: {message}"})
            return

        if parsed.path == "/api/auth/login":
            ip = self.client_address[0] if self.client_address else "unknown"
            if self._login_locked_out(ip):
                self._send_json(429, {"ok": False, "error": "Too many failed login attempts. Try again later."})
                return
            passcode = str(body.get("passcode", ""))
            digest = hashlib.sha256(passcode.encode("utf-8")).hexdigest()
            if hmac.compare_digest(digest, STAFF_PASSCODE_HASH):
                _login_failures.pop(ip, None)
                # Role is fixed server-side; the client cannot choose it.
                token = issue_token(role="staff")
                self._send_json(200, {"ok": True, "token": token})
            else:
                self._record_login_failure(ip)
                self._send_json(403, {"ok": False, "error": "Invalid staff passcode"})
            return

        if not self._require_auth():
            return

        if parsed.path in ("/api/sync", "/api/attendance", "/api/gps", "/api/notifications", "/api/sos"):
            bus_id = str(body.get("activeBusId") or body.get("busId") or "12")
            cur = self.db_conn.cursor()
            cur.execute(
                "INSERT INTO audit_events (bus_id, endpoint, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (bus_id, parsed.path, json.dumps(body), time.time()),
            )
            cur.execute(
                "DELETE FROM audit_events WHERE id <= (SELECT MAX(id) FROM audit_events) - ?",
                (AUDIT_RETENTION_ROWS,),
            )
            if "fleetState" in body and isinstance(body["fleetState"], dict):
                cur.execute(
                    """
                    INSERT INTO fleet_state (bus_id, corridor, plate, state_json, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(bus_id) DO UPDATE SET
                        corridor=excluded.corridor,
                        plate=excluded.plate,
                        state_json=excluded.state_json,
                        updated_at=excluded.updated_at
                    """,
                    (
                        bus_id,
                        f"Route {bus_id}",
                        f"TN-20-{bus_id}",
                        json.dumps(body["fleetState"]),
                        time.time(),
                    ),
                )
            self.db_conn.commit()
            self._send_json(200, {"ok": True, "busId": bus_id, "syncedAt": time.time()})
            return

        self._send_json(404, {"error": "Endpoint not found"})


def run_server(port: int = 8080, host: str = None):
    # Default bind is localhost only. Set BUS_TRACKER_BIND=0.0.0.0 to expose
    # the API on the LAN deliberately (auth is still required, but every
    # device on the network can then attempt logins).
    bind_host = host or os.environ.get("BUS_TRACKER_BIND", "127.0.0.1")
    BusTrackerAPIHandler.db_conn = init_db()
    server = ThreadingHTTPServer((bind_host, port), BusTrackerAPIHandler)
    print(f"School Bus Tracker API listening on http://{bind_host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
