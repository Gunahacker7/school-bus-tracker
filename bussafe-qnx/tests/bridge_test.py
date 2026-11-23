#!/usr/bin/env python3
"""
bridge_test.py — end-to-end test of the tracker <-> QNX BusSafe bridge.

Drives the School Bus Tracker through its own HTTP API with payloads in
exactly the shapes the web UI sends (BackendSyncClient batches:
{events: [...], activeBusId, fleetState}), then verifies the effects on
the QNX monitor side through the bridge's read surfaces.

Scenario (bus 12, roster S101/S102/S103):
  1. sync: S101 checks in            -> monitor BOARD S101 (route starts)
  2. sync: S102 checks in            -> monitor BOARD S102
  3. sync: S101 checks out           -> monitor ALIGHT S101
  4. GET /api/qnx/status             -> monitor STATUS mirrors the above
  5. sync: trip_completed            -> monitor ENDROUTE sweep
  6. GET /api/qnx/alerts             -> STILL_ONBOARD S102, NEVER_BOARDED S103
  7. GET /api/fleet                  -> alerts merged into state alertFeed

Usage: bridge_test.py [base_url]   (default http://127.0.0.1:18099)
Passcode comes from TRACKER_PASSCODE (default "bridge-test-pass").
Exit code 0 = all checks pass.
"""
import json
import os
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18099"
PASSCODE = os.environ.get("TRACKER_PASSCODE", "bridge-test-pass")

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    print(f"-- {'PASS' if ok else 'FAIL'}: {name}" + (f" | {detail}" if detail else ""))
    if ok:
        passed += 1
    else:
        failed += 1


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def stops(s101, s102, s103):
    return [
        {
            "id": 0, "name": "Avadi Depot (Start)", "lat": 13.1143, "lng": 80.0948,
            "roster": [
                {"id": "S101", "name": "Varshika", "grade": "Class 4-A", "status": s101},
                {"id": "S102", "name": "Keshika", "grade": "Class 6-B", "status": s102},
            ],
        },
        {
            "id": 1, "name": "Thirumullaivoyal", "lat": 13.1305, "lng": 80.0810,
            "roster": [
                {"id": "S103", "name": "Vignesh", "grade": "Class 3-A", "status": s103},
            ],
        },
    ]


def fleet_state(s101, s102, s103):
    st = stops(s101, s102, s103)
    return {
        "schemaVersion": 2,
        "fleetStateByBus": {"12": {"busStops": st, "alertFeed": []}},
        "busStops": st,
        "currentStopIndex": 0,
        "activeBusId": "12",
        "alertFeed": [],
    }


_evt = [0]


def event(endpoint, payload):
    _evt[0] += 1
    return {
        "id": f"evt_test_{_evt[0]}",
        "endpoint": endpoint,
        "method": "POST",
        "payload": payload,
        "busId": "12",
        "timestamp": "2026-11-23T00:00:00.000Z",
    }


def sync(token, events, state):
    status, resp = call(
        "POST", "/api/sync",
        {"events": events, "activeBusId": "12", "fleetState": state},
        token,
    )
    print(f">> POST /api/sync events={[e['endpoint'] for e in events]} -> {status} {resp}")
    return status


def main():
    status, resp = call("POST", "/api/auth/login", {"passcode": PASSCODE})
    token = resp.get("token", "")
    check("login", status == 200 and bool(token), f"status={status}")
    if not token:
        return 1

    # 1. S101 checks in
    sync(token,
         [event("/attendance", {"studentId": "S101", "status": "boarded", "stopId": 0})],
         fleet_state("boarded", "waiting", "waiting"))
    time.sleep(1)
    # 2. S102 checks in
    sync(token,
         [event("/attendance", {"studentId": "S102", "status": "boarded", "stopId": 0})],
         fleet_state("boarded", "boarded", "waiting"))
    time.sleep(1)
    # 3. S101 checks out (boarded -> waiting, the tracker's check-out)
    sync(token,
         [event("/attendance", {"studentId": "S101", "status": "waiting", "stopId": 0})],
         fleet_state("waiting", "boarded", "waiting"))
    time.sleep(1)

    # 4. Bridge status mirrors the monitor
    status, resp = call("GET", "/api/qnx/status", token=token)
    print(f">> GET /api/qnx/status -> {status} {json.dumps(resp)[:600]}")
    route = (resp.get("routes") or {}).get("12") or {}
    students = route.get("students") or {}
    check("bridge connected to monitor", resp.get("connected") is True)
    check("bridge route active", route.get("active") is True, f"route={route}")
    check(
        "bridge student states mirror monitor",
        students.get("S101") == "ALIGHTED"
        and students.get("S102") == "ONBOARD"
        and students.get("S103") == "EXPECTED",
        f"students={students}",
    )
    # The poll cadence (2s in this test rig) can lag the last ALIGHT by one
    # cycle; wait for a fresh poll before judging the snapshot.
    last = {}
    for _ in range(6):
        time.sleep(1)
        status, resp = call("GET", "/api/qnx/status", token=token)
        last = (resp.get("lastStatus") or {}).get("12") or {}
        if "ALIGHTED 1" in str(last.get("count", "")):
            break
    print(f">> GET /api/qnx/status (post-poll) lastStatus={json.dumps(last)[:300]}")
    check(
        "polled STATUS snapshot matches",
        "COUNT TOTAL 3 ONBOARD 1 ALIGHTED 1 EXPECTED 1" in str(last.get("count", "")),
        f"count={last.get('count')}",
    )

    # 5. Trip completes -> ENDROUTE sweep in the monitor
    sync(token,
         [event("/notifications", {"type": "trip_completed",
                                   "message": "Bus arrived safely at school. Trip completed."})],
         fleet_state("waiting", "boarded", "waiting"))
    time.sleep(1)

    # 6. Alerts captured
    status, resp = call("GET", "/api/qnx/alerts", token=token)
    print(f">> GET /api/qnx/alerts -> {status} {json.dumps(resp)[:600]}")
    kinds = {(a.get("kind"), a.get("studentId")) for a in resp.get("alerts", [])}
    check("alert STILL_ONBOARD S102", ("STILL_ONBOARD", "S102") in kinds, f"kinds={kinds}")
    check("alert NEVER_BOARDED S103", ("NEVER_BOARDED", "S103") in kinds, f"kinds={kinds}")

    # 7. Alerts merged into the tracker state endpoint
    status, resp = call("GET", "/api/fleet", token=token)
    feed = (((resp.get("fleet") or {}).get("12") or {}).get("state") or {}).get("alertFeed") or []
    texts = [i.get("text", "") for i in feed if isinstance(i, dict)]
    print(f">> GET /api/fleet alertFeed -> {[t for t in texts if 'QNX' in t]}")
    check("fleet alertFeed carries QNX still-onboard alert",
          any("still on board" in t and "S102" in t for t in texts))
    check("fleet alertFeed carries QNX never-boarded alert",
          any("never boarded" in t and "S103" in t for t in texts))

    print(f"RESULT: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
