# Live School Bus Tracker — S. N. S Matriculation School

Live school bus tracking and student pickup attendance web app for
**S. N. S Matriculation School**, Avalurpet Rd, Tiruvannamalai, Kunnumuringi,
Tamil Nadu 606604.

**Live app:** https://school-bus-tracker-gunasekar-e-s-projects.vercel.app

## What it does

- Live routes for Buses 12, 15 and 18 with stop-by-stop student pickup attendance
- Student roster: Krishna, Varshika, Keshika, Vignesh, Monika, Santhosh, Umai, Priya
- GPS position simulation with Haversine geofencing and ETAs
- Parent view: QR boarding pass, sibling switcher, one-tap "not riding today"
- Parent alerts via native call / SMS / WhatsApp deep links, plus SOS
- Trip reports, term bus-fee pass tracker, lost & found board
- Optional authenticated backend (`server.py`, Python + SQLite) for fleet sync
- **Multi-school profiles (Orbix Round 2, 21–22 Nov 2026):** any school sets its own name, address and tagline in School Settings (admin role, staff-gated) — the header, trip reports and fee receipt rebrand instantly, and the profile syncs to other devices via the backend. A 5-step "Add your school" guide deep-links to the existing tools. S. N. S Matriculation School stays the shipped pilot.
- **Parent trip summary (Orbix Round 2):** one tap in Parent Watch copies a WhatsApp-ready status text for the watched child (school, child, bus, stop, status, time). SOS alerts pin to the top of the parent alert feed, and every feed entry carries its school name.
- **About this project panel (Orbix Round 2):** problem, pilot, tech and build notes in the app footer (collapsed by default); the Tamil/English toggle is now in Parent Watch as well as the header.

## Run it

Frontend only (standalone, data stays in the browser):

```bash
# open index.html, or serve it:
python3 -m http.server 8000
```

With the sync backend:

```bash
python3 set_passcode.py   # set a real staff passcode first (writes bus_tracker.env)
python3 server.py         # serves http://127.0.0.1:8080
```

## Deploying the backend (Orbix Round 2)

`render.yaml` at the repo root is the Render blueprint: pure-stdlib Python
web service, `python3 server.py`, `BUS_TRACKER_BIND=0.0.0.0`, CORS
allow-listed to the live Vercel origin. Set `BUS_TRACKER_SECRET` (a fresh
random value) and `BUS_TRACKER_PASSCODE_HASH` (the SHA-256 staff passcode
hash from the local `bus_tracker.env` — only the hash travels) in the
Render dashboard; `server.py` reads the assigned port from `PORT`. Paste
the live backend URL into the app's API URL field (Settings section) so
staff and parents share one synced fleet. Until a backend URL is set, the
app runs fully in standalone `localStorage` mode — offline-first by design.

## Architecture

Two parts that work independently or together:

- **Frontend — `index.html`**: one self-contained HTML/CSS/JavaScript file
  (no build step). It holds the routes, stops and rosters for Buses 12, 15
  and 18, tracks pickup attendance stop-by-stop, simulates GPS movement
  with Haversine geofencing and ETAs, and keeps its state in the browser.
  Used standalone, all data stays on the device.
- **Backend — `server.py` (optional)**: a small authenticated REST API on
  Python's `ThreadingHTTPServer` with a SQLite database. Staff log in with
  a passcode and receive an HMAC-signed token; the app then syncs fleet
  state to `/api/sync` (and sibling endpoints) and reads the shared fleet
  back from `/api/fleet`. Sync payloads are also appended to an
  `audit_events` table with capped retention.
- **`set_passcode.py`**: one-time provisioning tool that installs the staff
  passcode hash into both the frontend and the backend config.

## Tech stack

- HTML5, CSS and vanilla JavaScript in a single file (Tailwind via CDN)
- Python 3 standard library only — `http.server`, `sqlite3`, `hashlib`,
  `hmac` (see `requirements.txt`; nothing to install)
- Browser `localStorage` for standalone state; SQLite for backend sync
- `unittest` for the automated test suite

## Security

- **No default passcode, fail closed**: the staff passcode is stored only
  as a SHA-256 hash. If no passcode is configured, `server.py` refuses to
  start — there is no fallback credential anywhere.
- Real HMAC-signed staff tokens with 12-hour expiry; future-dated tokens
  rejected and forged token shapes never accepted — the signature must
  verify.
- Login role is fixed server-side to "staff"; login attempts are
  rate-limited per IP (lockout after repeated failures).
- `/api/fleet` and all sync endpoints require a valid staff token.
- Server secret comes from `bus_tracker.env` / environment, never
  hardcoded; request bodies are size-capped and malformed JSON returns
  HTTP 400 instead of crashing the handler.
- CORS is allow-listed (local development origins by default), and the
  server binds to localhost unless explicitly configured otherwise.
- No weak hash fallbacks in the browser passcode check (fails closed)
- All user data is rendered escaped (XSS-safe); CSV exports are sanitized
  against formula injection and scrub session data
- `bus_tracker.env` holds secrets — never commit it (it is in `.gitignore`)

## Testing

```bash
python3 test_suite.py
```

20 tests in two groups: static/functional checks on the frontend and
backend units (XSS escaping, per-bus datasets, token issue/verify,
SQLite persistence, CSV sanitization, SEO metadata, rebrand, mobile
responsiveness), plus behavioural security tests that boot the real
server on an ephemeral port (fleet endpoint requires auth, login flow
and fixed role, malformed-JSON handling, sync round-trip). One live
login test additionally needs the staff passcode exported as
`BUS_TRACKER_PASSCODE`; it skips itself when that is not set.

## Project structure

```text
school-bus-tracker/
├── index.html          # Single-file web app (routes, rosters, attendance, GPS)
├── server.py           # Optional authenticated REST + SQLite sync backend
├── render.yaml         # Render blueprint for the hosted sync backend (R2)
├── set_passcode.py     # One-time staff passcode provisioning tool
├── test_suite.py       # unittest suite: functional + live-server security tests
├── requirements.txt    # No third-party dependencies (stdlib only)
├── LICENSE             # MIT
└── bus_tracker.env     # Local secrets — created by set_passcode.py, never committed
```

## Author

Gunasekar E · Chennai

## License

MIT — see [LICENSE](LICENSE).
