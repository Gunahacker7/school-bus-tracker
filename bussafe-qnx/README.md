# BusSafe QNX

**A boarding-safety monitor for school buses, running natively on QNX 8.0.**

Built for the **QNX Global Hackathon 2026** (Automotive & Mobility).

A child who boards a school bus but never gets off is every transport
manager's nightmare — and paper registers, spreadsheets and driver memory
all miss it. BusSafe QNX closes that gap: a small, hardened C service on
QNX 8.0 tracks every student's boarding state during a route, and the
moment a route ends it runs a **safety sweep**:

- `ALERT STILL_ONBOARD <student>` — boarded, but never alighted
- `ALERT NEVER_BOARDED <student>` — expected, but never boarded

Scope is deliberately honest: **boarding safety only**. The system does
not claim drop-off or door-to-door tracking.

## Architecture

```
┌────────────────────────┐   sync batches    ┌──────────────────────┐
│  School Bus Tracker    │ ────────────────▶ │  Tracker backend     │
│  web UI (attendant     │                   │  (Python, SQLite)    │
│  check-in / QR pass)   │ ◀──────────────── │                      │
└────────────────────────┘   alert feed      └──────────┬───────────┘
                                                        │ qnx_bridge.py
                                                        │ (TCP, line protocol)
                                                        ▼
                                             ┌──────────────────────┐
                                             │  bussafe_monitor     │
                                             │  native C service    │
                                             │  on QNX 8.0 (QEMU)   │
                                             │  state file on disk  │
                                             └──────────────────────┘
```

- **`monitor/bussafe_monitor.c`** — the QNX native service (single file,
  ~16 KB of C). Per-student state machine `EXPECTED → ONBOARD → ALIGHTED`,
  route lifecycle, the end-of-route sweep, and **persistence**: state is
  written atomically (temp file + rename) to `/data/var/bussafe/state`
  on every state-changing event and reloaded at startup, so a crashed or
  killed service recovers the route exactly. A corrupt state file is
  logged and ignored — it can never block startup.
- **`bridge/qnx_bridge.py`** — connects the existing School Bus Tracker
  app to the monitor. It observes the tracker's own sync traffic,
  translates check-in/check-out into `BOARD`/`ALIGHT` commands, starts
  and ends routes, and surfaces sweep alerts back into the tracker's
  alert feed (`GET /api/fleet`) and read endpoints (`GET /api/qnx/alerts`,
  `GET /api/qnx/status`). It is environment-flagged (`BUSSAFE_BRIDGE_ENABLED`,
  **default off**) and failure-isolated: if the monitor is down, the
  tracker behaves exactly as before.
- **`tests/`** — the verification suites described below.

## The monitor protocol

Line-based TCP, guest port **4570** (override: `BUSSAFE_PORT` env or
argv[1]; state path override: `BUSSAFE_STATE` env or argv[2]).
On connect the service sends `BUSSAFE 1.1 READY`. Every reply block ends
with a line containing only `.`.

| Command | Success reply | Notes |
|---|---|---|
| `PING` | `OK PONG` | liveness |
| `STARTROUTE <route_id>` | `OK ROUTE_STARTED <id>` | `ERR ROUTE_ACTIVE` if a route is running |
| `ADDSTUDENT <student_id>` | `OK EXPECTED <id>` | roster registration |
| `BOARD <student_id>` | `OK BOARDED <id>` | `ERR ALREADY_ONBOARD` on double-board |
| `ALIGHT <student_id>` | `OK ALIGHTED <id>` | `ERR NOT_ONBOARD` / `ERR UNKNOWN_STUDENT` guards |
| `STATUS` | `ROUTE …` + `COUNT …` + one `STUDENT …` line each | full snapshot |
| `ENDROUTE` | `OK ROUTE_ENDED <id>` + `ALERT …` lines + `ALERTS <n>` | runs the safety sweep |
| `QUIT` | `OK BYE` | closes the connection |

Errors are `ERR <CODE> <message>`. Malformed input — empty lines,
garbage, oversized lines, binary bytes — always gets a clean error
reply; the service never crashes or hangs on bad input (proven by the
robustness suite below).

## Build

You need the **QNX Software Development Platform 8.0** (free via the
QNX Everywhere programme) on a Linux host:

```sh
. ~/qnx/sdp800/qnxsdp-env.sh          # your SDP path may differ
qcc -V gcc_ntox86_64 -Wall -Wextra -o bussafe_monitor monitor/bussafe_monitor.c -lsocket
```

(`-lsocket` is required on QNX for the socket API.)

## Run (QEMU reference setup)

The reference environment is a QNX 8.0 x86-64 target image built with
`mkqnximage`, run under QEMU (TCG is fine; no KVM needed):

```sh
qemu-system-x86_64 -m 512 -smp 1 -cpu max \
  -drive file=disk-qemu.vmdk,if=ide,index=0,format=vmdk -snapshot \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::14570-:4570 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:d0:2d:5b \
  -display none
```

In the guest (the service runs as an unprivileged user):

```sh
mkdir -p /data/var/bussafe
./bussafe_monitor            # listens on 4570, state in /data/var/bussafe/state
```

Smoke test from the host:

```sh
python3 tests/test_client.py            # 17-check protocol suite
```

## Run the tests

All suites talk to the monitor through the QEMU host-forward
(`127.0.0.1:14570` → guest `:4570`) and print PASS/FAIL per check.

| Suite | What it proves | Expected |
|---|---|---|
| `tests/test_client.py` | Full protocol: lifecycle, guards (double-board, alight-without-board, unknown student), the alert sweep | **17/17** |
| `tests/restart_test.py` | Persistence: build a route, snapshot `STATUS`, then restart the monitor (in our runs it was SIGKILLed mid-route) and compare — the recovered `STATUS` must match line for line, and the sweep on the recovered state must be correct | **13/13** (8 + 5) |
| `tests/robust_test.py` | Abuse: empty/whitespace/CRLF lines, garbage commands, missing args, a 5000-char line, binary garbage with NULs, connect/disconnect churn (20 rapid cycles), then a full normal session on the same service life | **19/19** |
| `tests/bridge_test.py` | End-to-end integration: drives the School Bus Tracker through its own HTTP API (check in 2, check out 1, complete the trip) and verifies the monitor-side effects and the alerts in the tracker feed. Needs the tracker running with the bridge enabled | **9/9** |

`restart_test.py` expects to control the monitor process for the kill /
restart cycle — see the header comment in the file for its exact usage.

Verified results from our runs (QNX 8.0 under QEMU, monitor v1.1):
**17/17 + 13/13 + 19/19 + 9/9, plus bridge-down resilience 5/5** (tracker
fully functional with the monitor stopped) and corrupt-state recovery.

## The demo

**Watch the demo video (1:27, unlisted):**
https://www.youtube.com/watch?v=jlcmSMxtBw8
— on the author's tech channel:
https://www.youtube.com/channel/UCyvAavfB1xugxCh0ynjrRrA

The demo video shows a live morning route driven through the real
tracker UI: route start and roster registration in the monitor, two
check-ins, one check-out, the drive to school — and the end-of-route
sweep firing `ALERT STILL_ONBOARD` for the student who never checked
out, visible in both the QNX monitor log and the tracker's alert feed.
Nothing in the demo is mocked; the UI, bridge, monitor and alerts are
the real system running.

## License

MIT — see `LICENSE`. The QNX monitor and bridge are original work for
this hackathon; the School Bus Tracker app they integrate with is the
author's earlier project (also MIT).
