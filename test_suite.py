#!/usr/bin/env python3
"""
Automated Functional, Security (XSS / Auth / CSV), Backend API & Mobile Responsiveness Test Suite (P2.2)

Fixes applied (2026-11-11 audit):
- Path resolution: the suite now finds index.html / server.py next to itself
  OR one level up, so it runs in the delivered flat project folder (before,
  it crashed unless the files sat in a specific parent layout).
- Added BEHAVIOURAL security tests against a live server instance. The old
  suite only checked that strings existed in the source, which is why it
  reported 8/8 PASS while the server accepted forged `stf_*_hmac` tokens
  and exposed /api/fleet without auth.
"""

import hashlib
import hmac
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))


def _find_project_file(name: str) -> str:
    """Locate a project file next to this suite or one directory up.

    Falls back to the path next to this file when it exists in neither
    place, so callers fail with a clear file-not-found error.
    """
    for base in (_HERE, os.path.dirname(_HERE)):
        candidate = os.path.join(base, name)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(_HERE, name)


sys.path.insert(0, os.path.dirname(_find_project_file("server.py")))
import server


class SchoolBusTrackerTestSuite(unittest.TestCase):
    """Static source checks plus in-process backend unit tests.

    Most tests assert that security-critical patterns are present (or
    absent) in index.html, and exercise server.py's token and database
    functions directly. Live HTTP behaviour is covered separately by
    LiveServerSecurityTests.
    """

    @classmethod
    def setUpClass(cls):
        """Load index.html once for all source-pattern assertions."""
        with open(_find_project_file("index.html"), "r", encoding="utf-8") as f:
            cls.html = f.read()

    def test_p0_1_xss_escaping_and_no_plaintext_pin(self):
        """P0.1: Verify escapeHtml() is implemented and plaintext value='1234' is removed from DOM."""
        self.assertIn("function escapeHtml(raw)", self.html)
        self.assertNotIn('value="1234"', self.html)
        self.assertIn("STAFF_PASSCODE_SHA256", self.html)
        self.assertIn("function requireStaffAuth(", self.html)

    def test_p0_2_separate_bus_12_15_18_datasets(self):
        """P0.2: Verify Buses 12, 15, and 18 have independent stops, coordinates, and rosters."""
        self.assertIn("function getDefaultStops()", self.html)
        self.assertIn("function getBus15DefaultStops()", self.html)
        self.assertIn("function getBus18DefaultStops()", self.html)
        self.assertIn("Ambattur OT Bus Stand (Start)", self.html)
        self.assertIn("Thirumullaivoyal Arch (Start)", self.html)
        self.assertIn("fleetStateByBus", self.html)

    def test_p0_3_authenticated_backend_and_sqlite_persistence(self):
        """P0.3: Verify HMAC token issuance/verification and SQLite fleet state persistence."""
        token = server.issue_token("staff")
        self.assertTrue(server.verify_token(token))
        self.assertTrue(server.verify_token(f"Bearer {token}"))
        self.assertFalse(server.verify_token("stf_staff_12345_forgedsignature"))

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_file = tmp.name
        try:
            conn = server.init_db(db_file)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO fleet_state VALUES (?, ?, ?, ?, ?)",
                ("15", "Ambattur Corridor", "TN-20-CD-7821", json.dumps({"currentStopIndex": 2}), 1000.0),
            )
            conn.commit()
            cur.execute("SELECT corridor, state_json FROM fleet_state WHERE bus_id='15'")
            row = cur.fetchone()
            self.assertEqual(row[0], "Ambattur Corridor")
            self.assertEqual(json.loads(row[1])["currentStopIndex"], 2)
            conn.close()
        finally:
            if os.path.exists(db_file):
                os.remove(db_file)

    def test_p1_1_student_totals_unique_ids_and_boundary_clamping(self):
        """P1.1: Verify Stop 3 student count is fixed (4), generateUniqueStudentId & clampStopIndices exist."""
        self.assertIn("function generateUniqueStudentId()", self.html)
        self.assertIn("function clampStopIndices()", self.html)
        self.assertIn("stop.students = stop.roster.length", self.html)

    def test_p1_2_real_gps_watch_haversine_and_native_tel_sms_links(self):
        """P1.2: Verify watchPosition, Haversine distance formula, and tel:/sms:/wa.me deep links."""
        self.assertIn("navigator.geolocation.watchPosition", self.html)
        self.assertIn("function calculateHaversineKm(", self.html)
        self.assertIn('id="realTelLink" href="tel:', self.html)
        self.assertIn('id="realSmsLink" href="sms:', self.html)
        self.assertIn('id="realWaLink" href="https://wa.me/', self.html)

    def test_p1_3_csv_formula_sanitization_and_trip_completion_stop(self):
        """P1.3: Verify CSV formula-injection guard, schema validator, and trip completion timer stop."""
        self.assertIn("function sanitizeCsvCell(val)", self.html)
        self.assertIn("function validateLoadedState(parsed)", self.html)
        self.assertIn("function stopAutoTimer()", self.html)

    def test_p2_1_o1_roster_lookup_cache_and_document_fragment(self):
        """P2.1: Verify O(1) Map lookup (studentIndexMap), DocumentFragment batching, and visibilitychange."""
        self.assertIn("let studentIndexMap = new Map()", self.html)
        self.assertIn("document.createDocumentFragment()", self.html)
        self.assertIn("document.addEventListener('visibilitychange'", self.html)

    def test_p2_2_mobile_responsiveness_and_viewport_audit(self):
        """P2.2: Verify mobile viewport meta, safe-area support, phone-shell-mode, and bottom tab bar."""
        self.assertRegex(self.html, r'<meta name="viewport"[^>]*viewport-fit=cover')
        self.assertIn('id="mobileBottomNav"', self.html)
        self.assertIn("body.phone-shell-mode", self.html)
        self.assertIn('id="runAutomatedTestsBtn"', self.html)

    # --- Behavioural security tests (added 2026-11-11) ---

    def test_sec_1_forged_token_shapes_rejected(self):
        """Forged tokens that merely LOOK like staff tokens must be rejected."""
        self.assertFalse(server.verify_token("stf_x_hmac"))
        self.assertFalse(server.verify_token("stf_admin_9999999999_hmac"))
        self.assertFalse(server.verify_token("Bearer stf_anything_hmac"))
        self.assertFalse(server.verify_token(""))
        self.assertFalse(server.verify_token("stf_staff_notanumber_abcdefabcdefabcdefabcdef"))

    def test_sec_2_expired_and_future_tokens_rejected(self):
        """Tokens older than the max age, or dated in the future, must fail."""

        def craft(ts):
            payload = f"staff:{ts}"
            sig = hmac.new(server.SECRET_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
            return f"stf_staff_{ts}_{sig}"

        old_ts = int(time.time()) - server.TOKEN_MAX_AGE_SECONDS - 60
        self.assertFalse(server.verify_token(craft(old_ts)))
        future_ts = int(time.time()) + server.TOKEN_FUTURE_SKEW_SECONDS + 3600
        self.assertFalse(server.verify_token(craft(future_ts)))
        self.assertTrue(server.verify_token(craft(int(time.time()))))

    def test_sec_4_no_weak_hash_fallback_backdoor(self):
        """The FNV-1a fallback + magic constant let anyone forge the passcode
        digest on non-secure contexts. Both must stay removed."""
        self.assertNotIn("0x23300f2d", self.html)
        self.assertNotIn("Math.imul", self.html)
        self.assertIn("crypto.subtle unavailable", self.html)

    def test_seo_1_meta_and_structured_data(self):
        """SEO basics: description, canonical, Open Graph and JSON-LD."""
        self.assertIn('name="description"', self.html)
        self.assertIn('rel="canonical"', self.html)
        self.assertIn('property="og:title"', self.html)
        self.assertIn("application/ld+json", self.html)

    def test_rename_sns_school_and_roster(self):
        """Rebrand: S. N. S Matriculation School + the 8 supplied student names;
        no Sunrise or old demo roster names may remain."""
        self.assertIn("S. N. S Matriculation School", self.html)
        self.assertIn("Avalurpet Rd, Tiruvannamalai, Kunnumuringi, Tamil Nadu 606604", self.html)
        self.assertNotIn("Sunrise", self.html)
        for name in ("Krishna", "Varshika", "Keshika", "Vignesh", "Monika", "Santhosh", "Umai", "Priya"):
            self.assertIn(f'name: "{name}"', self.html)
        self.assertIn('name: "Krishna (Your Child)"', self.html)
        for old in ("Pranav", "Diya", "Aarav", "Ananya", "Harini"):
            self.assertNotIn(old, self.html)

    def test_responsive_scroll_padding_for_fixed_chrome(self):
        """Sticky header + fixed bottom nav must never cover a scrolled-to
        control: html needs scroll-padding on both ends (2026-11-11)."""
        with open(_find_project_file("index.html"), "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("scroll-padding-bottom: 110px", src)
        self.assertIn("scroll-padding-top: 110px", src)
        self.assertIn("scroll-padding-top: 245px", src)  # tall mobile header

    def test_responsive_no_maxcontent_flex_traps(self):
        """Responsive fix (2026-11-11): shrink-0 on wrapping flex rows made them
        claim max-content width (1352px) and stretch the whole page sideways.
        The banner + sibling rows must flex/wrap, selects must shrink, and the
        global overflow-x safety net must be present."""
        self.assertNotIn('flex flex-wrap items-center gap-2 shrink-0', self.html)
        self.assertIn('overflow-x: clip', self.html)
        self.assertIn('id="removeStudentSelect" class="flex-1 min-w-0', self.html)
        self.assertIn('id="guideBannerTitle"', self.html)
        self.assertIn('space-y-1 flex-1 min-w-0', self.html)

    def test_sec_3_frontend_auth_fixes_present(self):
        """Frontend must not fabricate tokens, accept stf_ PINs, print the demo PIN,
        and must persist the sync outbox and log in via the real API."""
        self.assertNotIn('enteredPin.startsWith("stf_")', self.html)
        self.assertNotIn('sessionAuthToken = "stf_" +', self.html)
        self.assertNotIn("Demo PIN:", self.html)
        self.assertIn("/auth/login", self.html)
        self.assertIn("campustrack_outbox_queue", self.html)

    # --- Orbix Round 2 tests (added 2026-11-21) ---

    def test_r2_1_school_profile_config(self):
        """R2 (a): school is a configurable entity — profile object with the SNS
        pilot as default, School Settings panel, persistence + sync payload,
        and the 5-step Add-your-school onboarding with deep links."""
        self.assertIn("const DEFAULT_SCHOOL_PROFILE = {", self.html)
        self.assertIn('name: "S. N. S Matriculation School"', self.html)
        self.assertIn('id="schoolSettingsSection"', self.html)
        self.assertIn('id="schoolNameInput"', self.html)
        self.assertIn('id="schoolAddressInput"', self.html)
        self.assertIn('id="schoolTaglineInput"', self.html)
        self.assertIn('id="saveSchoolProfileBtn"', self.html)
        self.assertIn('id="restorePilotSchoolBtn"', self.html)
        self.assertIn("schoolProfile: { ...schoolProfile }", self.html)
        self.assertIn("parsed.schoolProfile", self.html)
        self.assertIn("schoolHeaderLine", self.html)
        self.assertIn("${schoolProfile.name}", self.html)
        self.assertEqual(self.html.count("data-onboard-target="), 5)
        for target in ("schoolSettingsSection", "fleetSwitcherSection",
                       "routeCustomizerCard", "pinLockBanner"):
            self.assertIn(f'data-onboard-target="{target}"', self.html)

    def test_r2_2_parent_summary_and_sos_pin(self):
        """R2 (c): copyable WhatsApp trip summary, SOS pinned to the parent feed,
        feed entries carrying the school name, and status-change timestamps."""
        self.assertIn('id="copyTripSummaryBtn"', self.html)
        self.assertIn("function buildParentTripSummary()", self.html)
        self.assertIn("function pushAlert(type, text, opts)", self.html)
        self.assertIn("{ pinned: true }", self.html)
        self.assertIn("orderedFeed", self.html)
        self.assertIn("PINNED SOS", self.html)
        self.assertIn("statusChangedAt = getFormattedTime()", self.html)
        self.assertIn("school: schoolProfile.name", self.html)
        self.assertIn("item.school", self.html)

    def test_r2_3_about_panel_and_language_toggle(self):
        """R2 (d): About this project panel (collapsed by default) and the second
        Tamil/English toggle in Parent Watch sharing one toggle function."""
        self.assertIn('id="aboutProjectSection"', self.html)
        self.assertIn('id="toggleAboutProjectBtn"', self.html)
        self.assertIn('id="aboutProjectBody" class="hidden', self.html)
        self.assertIn("Orbix Round 2 build", self.html)
        self.assertIn('id="langToggleParentBtn"', self.html)
        self.assertIn("function toggleLanguage()", self.html)
        self.assertIn("langToggleParentText", self.html)

    def test_r2_4_render_deploy_ready(self):
        """R2 (b): server reads the PORT env var; render.yaml ships the deploy
        manifest; README documents the Round 2 features accurately."""
        with open(_find_project_file("server.py"), "r", encoding="utf-8") as f:
            server_src = f.read()
        self.assertIn('os.environ.get("PORT"', server_src)
        with open(_find_project_file("render.yaml"), "r", encoding="utf-8") as f:
            render_yaml = f.read()
        self.assertIn("startCommand: python3 server.py", render_yaml)
        self.assertIn("BUS_TRACKER_BIND", render_yaml)
        self.assertIn("0.0.0.0", render_yaml)
        self.assertIn("school-bus-tracker-gunasekar-e-s-projects.vercel.app", render_yaml)
        with open(_find_project_file("README.md"), "r", encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("Multi-school profiles (Orbix Round 2", readme)
        self.assertIn("Parent trip summary (Orbix Round 2)", readme)
        self.assertIn("About this project panel (Orbix Round 2)", readme)
        self.assertIn("render.yaml", readme)


class LiveServerSecurityTests(unittest.TestCase):
    """Boot the real HTTP server on an ephemeral port and probe it."""

    @classmethod
    def setUpClass(cls):
        """Boot the real HTTP server on an ephemeral localhost port."""
        fd, cls.db_file = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        server.BusTrackerAPIHandler.db_conn = server.init_db(cls.db_file)
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.BusTrackerAPIHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        """Stop the test server and remove its temporary database."""
        cls.httpd.shutdown()
        cls.httpd.server_close()
        if os.path.exists(cls.db_file):
            os.remove(cls.db_file)

    def _request(self, method: str, path: str, body=None, headers: dict = None):
        """Send one HTTP request to the test server.

        body may be a dict (JSON-encoded here), a raw string/bytes payload
        (used for the malformed-JSON test), or None. Returns a
        (status_code, response_text) tuple.
        """
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = body if isinstance(body, (str, bytes)) else (json.dumps(body) if body is not None else None)
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        conn.close()
        return resp.status, data

    def test_live_1_fleet_requires_auth(self):
        """GET /api/fleet must 401 without/with a forged token, 200 with a real one."""
        status, _ = self._request("GET", "/api/fleet")
        self.assertEqual(status, 401)
        status, _ = self._request("GET", "/api/fleet", headers={"Authorization": "Bearer stf_x_hmac"})
        self.assertEqual(status, 401)
        token = server.issue_token("staff")
        status, data = self._request("GET", "/api/fleet", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 200)
        self.assertIn('"fleet"', data)

    def test_live_2_login_flow_and_fixed_role(self):
        """Login rejects a wrong passcode and always issues a staff-role token."""
        passcode = os.environ.get("BUS_TRACKER_PASSCODE")
        if not passcode:
            self.skipTest(
                "BUS_TRACKER_PASSCODE is not set; export the passcode chosen "
                "via set_passcode.py to run the live login test"
            )
        status, _ = self._request("POST", "/api/auth/login", {"passcode": "wrong-passcode"})
        self.assertEqual(status, 403)
        status, data = self._request(
            "POST", "/api/auth/login", {"passcode": passcode, "role": "admin"}
        )
        self.assertEqual(status, 200)
        token = json.loads(data)["token"]
        # Server must ignore the client-chosen role and always issue "staff".
        self.assertEqual(token.split("_")[1], "staff")
        self.assertTrue(server.verify_token(token))

    def test_live_3_malformed_json_returns_400_not_crash(self):
        """A malformed JSON body returns HTTP 400 and the server stays alive."""
        token = server.issue_token("staff")
        status, _ = self._request(
            "POST",
            "/api/sync",
            body="{not valid json",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 400)
        # Server must still be alive afterwards.
        status, _ = self._request("GET", "/api/health")
        self.assertEqual(status, 200)

    def test_live_4_sync_roundtrip(self):
        """State posted to /api/sync is readable back from /api/fleet."""
        token = server.issue_token("staff")
        status, _ = self._request(
            "POST",
            "/api/sync",
            {"activeBusId": "12", "fleetState": {"currentStopIndex": 1}},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 200)
        status, data = self._request(
            "GET", "/api/fleet", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(status, 200)
        fleet = json.loads(data)["fleet"]
        self.assertEqual(fleet["12"]["state"]["currentStopIndex"], 1)

    def test_live_5_school_profile_sync_roundtrip(self):
        """R2 (a): a schoolProfile inside the /api/sync fleetState is stored
        server-side and comes back from /api/fleet for a second device."""
        token = server.issue_token("staff")
        profile = {
            "name": "Demo Public School",
            "address": "Test Rd, Demo Town",
            "tagline": "Every child accounted for",
        }
        status, _ = self._request(
            "POST",
            "/api/sync",
            {"activeBusId": "12", "fleetState": {"currentStopIndex": 1, "schoolProfile": profile}},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 200)
        status, data = self._request(
            "GET", "/api/fleet", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(status, 200)
        fleet = json.loads(data)["fleet"]
        self.assertEqual(fleet["12"]["state"]["schoolProfile"]["name"], "Demo Public School")
        self.assertEqual(fleet["12"]["state"]["schoolProfile"]["tagline"], "Every child accounted for")


if __name__ == "__main__":
    unittest.main(verbosity=2)
