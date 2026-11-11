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

## Security notes

- Real HMAC-signed staff tokens with 12-hour expiry; forged token shapes rejected
- `/api/fleet` requires authentication; login is rate-limited
- Server secret comes from `bus_tracker.env` / environment, never hardcoded
- No weak hash fallbacks in the browser passcode check (fails closed)
- All user data is rendered escaped (XSS-safe); exports scrub session data
- `bus_tracker.env` holds secrets — never commit it

## Tests

```bash
python3 test_suite.py   # 18 tests: functional, live-server security, SEO, rebrand
```

## Author

Gunasekar E · Chennai
