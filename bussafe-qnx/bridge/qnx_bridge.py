#!/usr/bin/env python3
"""
qnx_bridge.py — School Bus Tracker <-> QNX BusSafe monitor bridge.

Forwards boarding-safety events from the tracker server to the QNX 8.0
`bussafe_monitor` service (BusSafe QNX hackathon entry) over its line-based
TCP protocol, and surfaces the monitor's end-of-route safety alerts back
into the tracker (GET /api/qnx/alerts, GET /api/qnx/status, and merged into
the alertFeed of GET /api/fleet responses).

Scope honesty: this is a BOARDING-safety bridge only. It mirrors the
tracker's boarding records into the monitor; it does not add any drop-off
tracking that the tracker itself does not have.

Event mapping (tracker -> monitor):
  route start (first boarding activity for a bus, roster taken from the
  synced fleetState)            -> STARTROUTE RTE-<bus> + ADDSTUDENT <id>...
  attendance status "boarded" (incl. QR scan / board-all reconciliation)
                                  -> BOARD <student_id>
  attendance status back to "waiting" for a student the monitor holds as
  ONBOARD (the tracker's check-out / un-board transition)
                                  -> ALIGHT <student_id>
  "/notifications" event type "trip_completed"
                                  -> ENDROUTE (safety sweep); ALERT lines
                                     are captured into the alert surface

Resilience contract: the bridge NEVER breaks the tracker. Every monitor
operation is timeout-guarded and wrapped; on failure the bridge logs,
backs off (circuit breaker), and the tracker keeps working exactly as
before. Connections are short-lived (one per operation batch) because the
monitor serves clients sequentially.

Configuration (environment variables only):
  BUSSAFE_BRIDGE_ENABLED  1/true/yes/on enables the bridge (default: off,
                          so stock tracker behaviour is unchanged)
  BUSSAFE_HOST            monitor host (default 127.0.0.1; with the QEMU
                          dev recipe this is the hostfwd to the guest)
  BUSSAFE_PORT            monitor port (default 14570, the QEMU hostfwd;
                          the guest itself listens on 4570)
  BUSSAFE_POLL_SECONDS    STATUS poll interval (default 5)
"""

import os
import socket
import threading
import time

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


ENABLED = _env_bool("BUSSAFE_BRIDGE_ENABLED")
HOST = os.environ.get("BUSSAFE_HOST", "127.0.0.1").strip() or "127.0.0.1"
PORT = int(os.environ.get("BUSSAFE_PORT", "14570") or "14570")
POLL_SECONDS = float(os.environ.get("BUSSAFE_POLL_SECONDS", "5") or "5")

CONNECT_TIMEOUT = 2.0     # seconds; QEMU slirp accepts then EOFs when down
BREAKER_SECONDS = 5.0     # after a failure, fail fast for this long
MAX_ALERTS = 50
MAX_LOG_LINES = 200


def _token(raw) -> str:
    """Make an id safe for the monitor's whitespace-delimited protocol."""
    return "".join(ch if not ch.isspace() else "-" for ch in str(raw)).strip() or "?"


# --------------------------------------------------------------------------
# Monitor client (short-lived connections, reply blocks end with ".")
# --------------------------------------------------------------------------

class MonitorUnavailable(Exception):
    pass


class MonitorClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._down_until = 0.0

    def run(self, commands):
        """Run a batch of commands on one fresh connection.

        Returns a list of reply blocks (each a list of lines). Raises
        MonitorUnavailable on any transport problem.
        """
        if time.time() < self._down_until:
            raise MonitorUnavailable("circuit breaker open")
        sock = None
        try:
            sock = socket.create_connection(
                (self.host, self.port), timeout=CONNECT_TIMEOUT
            )
            sock.settimeout(CONNECT_TIMEOUT)
            fh = sock.makefile("r", encoding="utf-8", newline="\n")
            greeting = self._read_block(fh)
            if not greeting or not greeting[0].startswith("BUSSAFE"):
                raise MonitorUnavailable(f"bad greeting: {greeting!r}")
            blocks = []
            for cmd in commands:
                sock.sendall((cmd + "\n").encode("utf-8"))
                blocks.append(self._read_block(fh))
            return blocks
        except MonitorUnavailable:
            self._down_until = time.time() + BREAKER_SECONDS
            raise
        except (OSError, ValueError) as exc:
            self._down_until = time.time() + BREAKER_SECONDS
            raise MonitorUnavailable(str(exc)) from exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    @staticmethod
    def _read_block(fh):
        lines = []
        while True:
            line = fh.readline()
            if not line:
                raise MonitorUnavailable("monitor closed the connection")
            line = line.rstrip("\n").rstrip("\r")
            if line == ".":
                break
            lines.append(line)
        return lines


# --------------------------------------------------------------------------
# Bridge
# --------------------------------------------------------------------------

class QnxBridge:
    def __init__(self, client: MonitorClient):
        self.client = client
        self.lock = threading.RLock()
        # bus_id -> {"route_id", "active", "students": {sid: monitor-state},
        #            "tracker_status": {sid: tracker-status},
        #            "names": {sid: display name}, "absent": set(sid)}
        self.buses = {}
        self.alerts = []          # alertFeed-shaped dicts, newest last
        self.last_status = {}     # bus_id -> STATUS snapshot dict
        self.connected = False
        self.log_lines = []
        self._poll_started = False

    # -- logging -----------------------------------------------------------
    def log(self, message: str) -> None:
        line = f"[qnx-bridge] {message}"
        print(line, flush=True)
        self.log_lines.append(line)
        if len(self.log_lines) > MAX_LOG_LINES:
            del self.log_lines[: len(self.log_lines) - MAX_LOG_LINES]

    # -- roster / state helpers --------------------------------------------
    def _bus(self, bus_id: str) -> dict:
        bus = self.buses.get(bus_id)
        if bus is None:
            bus = {
                "route_id": f"RTE-{_token(bus_id)}",
                "active": False,
                "students": {},
                "tracker_status": {},
                "names": {},
                "absent": set(),
            }
            self.buses[bus_id] = bus
        return bus

    def _ingest_fleet_state(self, bus_id: str, fleet_state) -> None:
        """Refresh the roster cache from a synced fleetState payload."""
        if not isinstance(fleet_state, dict):
            return
        by_bus = fleet_state.get("fleetStateByBus")
        stops = None
        if isinstance(by_bus, dict) and isinstance(by_bus.get(bus_id), dict):
            stops = by_bus[bus_id].get("busStops")
        if stops is None:
            stops = fleet_state.get("busStops")
        if not isinstance(stops, list):
            return
        bus = self._bus(bus_id)
        for stop in stops:
            if not isinstance(stop, dict):
                continue
            roster = stop.get("roster")
            if not isinstance(roster, list):
                continue
            for student in roster:
                if not isinstance(student, dict) or "id" not in student:
                    continue
                sid = _token(student["id"])
                if student.get("name"):
                    bus["names"][sid] = str(student["name"])
                status = str(student.get("status") or "")
                previous = bus["tracker_status"].get(sid)
                bus["tracker_status"][sid] = status
                if status == "absent":
                    bus["absent"].add(sid)
                # Snapshot reconciliation: a status flip observed in the
                # synced state is a real boarding transition (covers the
                # board-all-at-stop flow, which carries no student ids).
                if previous is not None and previous != status:
                    if previous == "waiting" and status == "boarded":
                        self._board(bus_id, sid)
                    elif previous == "boarded" and status == "waiting":
                        self._alight(bus_id, sid)

    # -- monitor operations --------------------------------------------------
    def _ensure_route(self, bus_id: str) -> bool:
        bus = self._bus(bus_id)
        if bus["active"]:
            return True
        commands = [f"STARTROUTE {bus['route_id']}"]
        roster = [
            sid
            for sid in bus["tracker_status"]
            if sid not in bus["absent"]
        ]
        for sid in roster:
            commands.append(f"ADDSTUDENT {sid}")
        try:
            blocks = self.client.run(commands)
        except MonitorUnavailable as exc:
            self.connected = False
            self.log(f"route start for bus {bus_id} deferred (monitor down: {exc})")
            return False
        self.connected = True
        started = any(
            line.startswith(f"OK ROUTE_STARTED {bus['route_id']}")
            for line in blocks[0]
        )
        if not started:
            # Another bus may own the monitor's single active route.
            self.log(f"route start for bus {bus_id} not accepted: {blocks[0]}")
            return False
        bus["active"] = True
        for sid in roster:
            bus["students"][sid] = "EXPECTED"
        self.log(f"route {bus['route_id']} started, roster {roster}")
        return True

    def _board(self, bus_id: str, sid: str) -> None:
        bus = self._bus(bus_id)
        if bus["students"].get(sid) == "ONBOARD":
            return
        if not self._ensure_route(bus_id):
            return
        try:
            blocks = self.client.run([f"BOARD {sid}"])
        except MonitorUnavailable as exc:
            self.connected = False
            self.log(f"BOARD {sid} (bus {bus_id}) failed: {exc}")
            return
        self.connected = True
        reply = blocks[0]
        if any(line.startswith(f"OK BOARDED {sid}") for line in reply):
            bus["students"][sid] = "ONBOARD"
            self.log(f"BOARD {sid} (bus {bus_id}) -> monitor OK")
        elif any("ALREADY_ONBOARD" in line for line in reply):
            bus["students"][sid] = "ONBOARD"
        else:
            self.log(f"BOARD {sid} (bus {bus_id}) unexpected reply: {reply}")

    def _alight(self, bus_id: str, sid: str) -> None:
        bus = self._bus(bus_id)
        if bus["students"].get(sid) != "ONBOARD":
            return
        try:
            blocks = self.client.run([f"ALIGHT {sid}"])
        except MonitorUnavailable as exc:
            self.connected = False
            self.log(f"ALIGHT {sid} (bus {bus_id}) failed: {exc}")
            return
        self.connected = True
        reply = blocks[0]
        if any(line.startswith(f"OK ALIGHTED {sid}") for line in reply):
            bus["students"][sid] = "ALIGHTED"
            self.log(f"ALIGHT {sid} (bus {bus_id}) -> monitor OK")
        elif any("NOT_ONBOARD" in line for line in reply):
            bus["students"][sid] = "ALIGHTED"
        else:
            self.log(f"ALIGHT {sid} (bus {bus_id}) unexpected reply: {reply}")

    def _end_route(self, bus_id: str) -> None:
        bus = self._bus(bus_id)
        if not bus["active"]:
            return
        try:
            blocks = self.client.run(["ENDROUTE"])
        except MonitorUnavailable as exc:
            self.connected = False
            self.log(f"ENDROUTE (bus {bus_id}) failed: {exc}")
            return
        self.connected = True
        bus["active"] = False
        reply = blocks[0]
        captured = 0
        for line in reply:
            parts = line.split()
            if len(parts) == 3 and parts[0] == "ALERT":
                kind, sid = parts[1], parts[2]
                self._record_alert(bus_id, kind, sid)
                captured += 1
        self.log(
            f"ENDROUTE {bus['route_id']} -> sweep captured {captured} alert(s): {reply}"
        )
        bus["students"] = {}

    def _record_alert(self, bus_id: str, kind: str, sid: str) -> None:
        bus = self._bus(bus_id)
        name = bus["names"].get(sid, sid)
        if kind == "STILL_ONBOARD":
            text = (
                f"🚌 QNX BusSafe: {name} ({sid}) is still on board Bus {bus_id} "
                "at trip end — check the bus now."
            )
        elif kind == "NEVER_BOARDED":
            text = (
                f"🚌 QNX BusSafe: {name} ({sid}) never boarded Bus {bus_id} "
                "on this trip — verify with the stop / parent."
            )
        else:
            text = f"🚌 QNX BusSafe alert {kind}: {name} ({sid}), Bus {bus_id}."
        self.alerts.append(
            {
                "time": time.strftime("%I:%M %p"),
                "type": "urgent",
                "text": text,
                "school": "",
                "pinned": True,
                "source": "qnx-bussafe",
                "busId": bus_id,
                "studentId": sid,
                "kind": kind,
            }
        )
        if len(self.alerts) > MAX_ALERTS:
            del self.alerts[: len(self.alerts) - MAX_ALERTS]

    # -- entry point used by server.py ---------------------------------------
    def observe_request(self, path: str, body) -> None:
        """Observe one tracker POST (sync batch or direct endpoint call).

        Never raises: any problem is logged and swallowed so the tracker
        request path is unaffected.
        """
        if not isinstance(body, dict):
            return
        try:
            with self.lock:
                bus_id = str(body.get("activeBusId") or body.get("busId") or "12")
                # Roster first: a route start triggered by the events below
                # can only register students the bridge already knows from
                # the synced fleetState. (An earlier revision ingested after
                # the events and started the route with an empty roster —
                # caught by the Day 2 bridge e2e test, see DAY2-BRIDGE-LOG.)
                # Snapshot reconciliation is state-guarded, and the explicit
                # events are replayed afterwards, so ordering stays correct.
                if "fleetState" in body:
                    self._ingest_fleet_state(bus_id, body.get("fleetState"))
                events = body.get("events")
                if isinstance(events, list) and events:
                    for event in events:
                        self._observe_event(bus_id, event)
                elif path in ("/api/attendance", "/api/notifications"):
                    # Direct endpoint post: the body itself is the event.
                    self._observe_event(
                        bus_id,
                        {"endpoint": path[len("/api"):], "payload": body},
                    )
        except Exception as exc:  # the bridge must never break the tracker
            self.log(f"observe_request swallowed error: {exc!r}")

    def _observe_event(self, default_bus_id: str, event) -> None:
        if not isinstance(event, dict):
            return
        endpoint = str(event.get("endpoint") or "")
        payload = event.get("payload")
        if not isinstance(payload, dict):
            return
        bus_id = str(event.get("busId") or payload.get("busId") or default_bus_id)
        if endpoint == "/attendance":
            action = str(payload.get("action") or "")
            sid_raw = payload.get("studentId")
            status = str(payload.get("status") or "")
            if action == "add_student" and sid_raw:
                sid = _token(sid_raw)
                bus = self._bus(bus_id)
                bus["tracker_status"].setdefault(sid, "waiting")
                if payload.get("name"):
                    bus["names"][sid] = str(payload["name"])
                return
            if not sid_raw:
                # board_all_stop carries no ids; the fleetState snapshot
                # reconciliation in _ingest_fleet_state handles it.
                return
            sid = _token(sid_raw)
            if status == "boarded":
                self._board(bus_id, sid)
            elif status == "waiting":
                self._alight(bus_id, sid)
            elif status == "absent":
                self._bus(bus_id)["absent"].add(sid)
                self.log(
                    f"student {sid} (bus {bus_id}) marked absent in tracker; "
                    "monitor has no absent state — if not yet boarded it will "
                    "surface as NEVER_BOARDED at the sweep"
                )
        elif endpoint == "/notifications":
            if str(payload.get("type") or "") == "trip_completed":
                self._end_route(bus_id)

    # -- STATUS polling --------------------------------------------------------
    def poll_once(self) -> None:
        try:
            blocks = self.client.run(["STATUS"])
        except MonitorUnavailable:
            self.connected = False
            return
        self.connected = True
        lines = blocks[0]
        route_line = next((l for l in lines if l.startswith("ROUTE ")), "")
        count_line = next((l for l in lines if l.startswith("COUNT ")), "")
        students = [l for l in lines if l.startswith("STUDENT ")]
        parts = route_line.split()
        route_id = parts[1] if len(parts) > 1 else "NONE"
        for bus_id, bus in self.buses.items():
            if bus["route_id"] == route_id:
                self.last_status[bus_id] = {
                    "route": route_line,
                    "count": count_line,
                    "students": students,
                    "raw": lines,
                    "updatedAt": time.time(),
                }

    def _poll_loop(self) -> None:
        while True:
            try:
                with self.lock:
                    self.poll_once()
            except Exception as exc:
                self.log(f"poll swallowed error: {exc!r}")
            time.sleep(POLL_SECONDS)

    def start_polling(self) -> None:
        if self._poll_started:
            return
        self._poll_started = True
        thread = threading.Thread(
            target=self._poll_loop, name="qnx-bridge-poll", daemon=True
        )
        thread.start()
        self.log(
            f"bridge polling STATUS every {POLL_SECONDS:g}s via {HOST}:{PORT}"
        )

    # -- read surfaces ---------------------------------------------------------
    def status_payload(self) -> dict:
        with self.lock:
            return {
                "ok": True,
                "enabled": True,
                "connected": self.connected,
                "monitor": f"{HOST}:{PORT}",
                "routes": {
                    bus_id: {
                        "routeId": bus["route_id"],
                        "active": bus["active"],
                        "students": dict(bus["students"]),
                    }
                    for bus_id, bus in self.buses.items()
                },
                "lastStatus": self.last_status,
                "alertCount": len(self.alerts),
                "recentLog": self.log_lines[-20:],
            }

    def alerts_payload(self) -> dict:
        with self.lock:
            return {"ok": True, "alerts": list(self.alerts)}

    def merge_alerts_into_fleet(self, fleet: dict) -> dict:
        """Append this bridge's alerts to each bus state's alertFeed.

        Works on the response dict only; stored tracker state is untouched.
        """
        if not self.alerts:
            return fleet
        with self.lock:
            for bus_id, entry in fleet.items():
                state = entry.get("state")
                if not isinstance(state, dict):
                    continue
                feed = state.get("alertFeed")
                if not isinstance(feed, list):
                    feed = []
                    state["alertFeed"] = feed
                known = {
                    item.get("text")
                    for item in feed
                    if isinstance(item, dict)
                }
                for alert in self.alerts:
                    if alert["busId"] == bus_id and alert["text"] not in known:
                        feed.append(dict(alert))
        return fleet


# --------------------------------------------------------------------------
# Module singleton used by server.py
# --------------------------------------------------------------------------

BRIDGE = QnxBridge(MonitorClient(HOST, PORT)) if ENABLED else None


def observe_request(path: str, body) -> None:
    if BRIDGE is not None:
        BRIDGE.observe_request(path, body)


def merge_alerts_into_fleet(fleet: dict) -> dict:
    if BRIDGE is None:
        return fleet
    return BRIDGE.merge_alerts_into_fleet(fleet)


def status_payload() -> dict:
    if BRIDGE is None:
        return {"ok": True, "enabled": False}
    return BRIDGE.status_payload()


def alerts_payload() -> dict:
    if BRIDGE is None:
        return {"ok": True, "enabled": False, "alerts": []}
    return BRIDGE.alerts_payload()


if ENABLED and BRIDGE is not None:
    BRIDGE.log(f"bridge enabled -> monitor at {HOST}:{PORT}")
    BRIDGE.start_polling()
