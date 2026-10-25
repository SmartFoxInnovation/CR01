import json
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from cr01_sc.app import create_server, is_loopback_host
from cr01_sc import __version__
from cr01_sc.native_demo import NativeDemoUnavailable, engine_path


class RunningServer:
    def __init__(self, access_token=None, repo_root=None):
        self.server = create_server("127.0.0.1", 0, access_token=access_token, repo_root=repo_root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.base_url = f"http://{host}:{port}"
        with self.request("/api/v1/health") as response:
            if response.status != 200:
                raise RuntimeError("showcase test server did not become ready")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def live(self, body=None):
        with self.request("/api/v1/session") as response:
            session = json.load(response)
        return self.request("/api/v1/validate", method="POST", body=body or {"seed": 9700},
                            headers={"X-CR01-Action-Token": session["action_token"], "Origin": self.base_url})

    def request(self, path, *, method="GET", body=None, headers=None):
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request_headers = dict(headers or {})
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
        for attempt in range(3):
            request = urllib.request.Request(
                f"{self.base_url}{path}",
                data=payload,
                headers=request_headers,
                method=method,
            )
            try:
                return urllib.request.urlopen(request, timeout=10)
            except urllib.error.HTTPError:
                raise
            except (ConnectionAbortedError, ConnectionResetError, urllib.error.URLError):
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise AssertionError("unreachable")


class ShowcaseHttpTests(unittest.TestCase):
    def test_logo_is_local_png_with_existing_security_headers(self):
        with RunningServer(access_token="test-token-with-more-than-24-characters") as app:
            with app.request("/assets/cr01-logo.png") as response:
                payload = response.read()
                self.assertEqual(response.headers.get_content_type(), "image/png")
                self.assertEqual(int(response.headers["Content-Length"]), len(payload))
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                self.assertEqual(hashlib.sha256(payload).hexdigest(),
                                 "51cdfa0b047ba8069b4b67fa2735b448ef21eaf204ed87fa293c6dcb3b154d4c")
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                app.request("/assets/not-a-public-image.png")
            self.assertEqual(rejected.exception.code, 404)
            self.assertEqual(rejected.exception.headers.get_content_type(), "application/json")
            rejected.exception.close()
            with app.request("/assets/app.css") as response:
                css = response.read().decode("utf-8")
                mobile = css.split("@media (max-width: 920px)", 1)[1].split("@media (max-width: 680px)", 1)[0]
                self.assertRegex(mobile, r"\.rail-nav a\s*\{[^}]*font-size:\s*0;[^}]*gap:\s*0;")

    def test_missing_native_engine_returns_safe_503_and_ignores_client_executable(self):
        with tempfile.TemporaryDirectory() as directory, RunningServer(repo_root=directory) as app:
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                app.live({"seed": 9700, "executable": str(engine_path())})
            self.assertEqual(rejected.exception.code, 503)
            error = json.load(rejected.exception)
            rejected.exception.close()
            self.assertEqual(error["error"]["code"], "native_engine_unavailable")
            self.assertNotIn(directory, json.dumps(error))
            self.assertNotIn("checks", error)

    @unittest.skipUnless(engine_path().is_file(), "Native build required")
    def test_native_live_failure_releases_action_gate_and_next_request_recovers(self):
        with RunningServer() as app:
            with patch("cr01_sc.app.run_live_validation", side_effect=NativeDemoUnavailable("internal detail")):
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    app.live()
                self.assertEqual(rejected.exception.code, 503)
                self.assertNotIn("internal detail", rejected.exception.read().decode())
                rejected.exception.close()
            with app.live() as response:
                report = json.load(response)
                self.assertEqual(report["summary"]["status"], "pass")
                self.assertEqual(report["summary"]["total_checks"], 13)
                self.assertEqual(report["engine"]["implementation"], "C++")

    def test_busy_action_does_not_start_another_native_run(self):
        with RunningServer() as app, patch("cr01_sc.app.run_live_validation") as run:
            app.server.validation_gate.acquire()
            try:
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    app.live()
                self.assertEqual(rejected.exception.code, 429)
                rejected.exception.close()
                run.assert_not_called()
            finally:
                app.server.validation_gate.release()

    def test_unsupported_api_method_still_returns_json(self):
        with RunningServer() as app:
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                app.request("/api/v1/status", method="PATCH")
            self.assertEqual(rejected.exception.headers.get_content_type(), "application/json")
            self.assertEqual(json.load(rejected.exception)["error"]["code"], "http_error")
            rejected.exception.close()

    def test_remote_factory_cannot_bypass_token_requirement(self):
        with self.assertRaises(ValueError):
            create_server("0.0.0.0", 0)

    def test_loopback_rejects_dns_rebinding_host(self):
        with RunningServer() as app:
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                app.request("/api/v1/session", headers={"Host": "attacker.invalid"})
            self.assertEqual(rejected.exception.code, 400)
            self.assertEqual(json.load(rejected.exception)["error"]["code"], "host_rejected")
            rejected.exception.close()

    def test_static_ui_and_status_api_have_security_headers(self):
        with RunningServer() as app:
            with app.request("/") as response:
                html = response.read().decode("utf-8")
                self.assertIn("CR01 // Evidence Console", html)
                self.assertIn(f"/assets/app.css?v={__version__}", html)
                self.assertIn("Source-available validation edition", html)
                self.assertIn("PolyForm Noncommercial 1.0.0", html)
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                self.assertNotIn("Python", response.headers["Server"])

            with app.request("/api/v1/status") as response:
                status = json.load(response)
                self.assertEqual(response.headers.get_content_type(), "application/json")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(status["schema"], "CR01-SHOWCASE-v1")
            with app.request("/assets/app.js") as response:
                script = response.read().decode("utf-8")
                timer = script.split("const timer = window.setInterval", 1)[1].split("return {", 1)[0]
                self.assertNotIn('classList.add("pass")', timer)
                failure = script.split("fail() {", 1)[1].split("};", 1)[0]
                self.assertIn('classList.remove("running", "pass")', failure)

    def test_live_action_requires_same_origin_action_token(self):
        with RunningServer() as app:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                app.request("/api/v1/validate", method="POST", body={"seed": 9700})

            self.assertEqual(raised.exception.code, 403)
            error = json.loads(raised.exception.read().decode("utf-8"))
            raised.exception.close()
            self.assertEqual(error["error"]["code"], "action_token_required")

    def test_configured_bearer_protects_evidence_api(self):
        token = "test-token-with-more-than-24-characters"
        with RunningServer(access_token=token) as app:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                app.request("/api/v1/status")
            self.assertEqual(raised.exception.code, 401)
            raised.exception.close()

            with app.request(
                "/api/v1/session",
                headers={"Authorization": f"Bearer {token}"},
            ) as response:
                session = json.load(response)
                self.assertTrue(session["bearer_required"])
                self.assertGreaterEqual(len(session["action_token"]), 32)

    def test_health_is_minimal_and_unprotected(self):
        with RunningServer(access_token="test-token-with-more-than-24-characters") as app:
            with app.request("/api/v1/health") as response:
                health = json.load(response)
                self.assertEqual(health["status"], "ok")
                self.assertNotIn("action_token", health)

    def test_loopback_detection_is_fail_closed(self):
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("example.internal"))


if __name__ == "__main__":
    unittest.main()
