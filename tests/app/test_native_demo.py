"""Real native visual workflow, plus no-fallback and resource-failure regressions."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cr01_sc.evidence import run_live_validation
from cr01_sc.native import NativePeer as RealPeer, generate_native_identity, write_native_pin
from cr01_sc.native_demo import NativeDemoUnavailable, UNAVAILABLE, engine_path, run_native_demo
from tools.native import COMPILER, compile_native


class NativeDemoFailureTests(unittest.TestCase):
    def test_missing_engine_is_explicit_and_never_uses_reference(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("sys.modules", {
                "cr01_sc.demo": None, "cr01_sc.channel": None, "cr01_sc.handshake": None,
                "cr01_sc.primitives": None}):
            with self.assertRaises(NativeDemoUnavailable) as raised:
                run_live_validation(repo_root=directory)
            self.assertEqual(str(raised.exception), UNAVAILABLE)
            self.assertNotIn(directory, str(raised.exception))

    def test_native_demo_has_no_reference_or_python_crypto_imports(self):
        import cr01_sc.native_demo as module
        source = ast.parse(Path(module.__file__).read_text())
        for node in ast.walk(source):
            names = [node.module or ""] if isinstance(node, ast.ImportFrom) else (
                [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
            self.assertFalse(any(name.split(".")[0] in {"demo", "channel", "handshake", "primitives", "cryptography", "tools"}
                                 for name in names))

    def test_wrapper_timeout_validation_precedes_process_creation(self):
        for value in (0, -1, True, None, float("nan"), float("inf"), 21):
            with self.subTest(timeout=value), patch("cr01_sc.native.subprocess.Popen") as popen, patch("cr01_sc.native.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    RealPeer(Path("unused"), "initiator", Path("unused"), Path("unused"), response_timeout=value)
                with self.assertRaises(ValueError):
                    generate_native_identity(Path("unused"), Path("unused"), timeout=value)
                with self.assertRaises(ValueError):
                    write_native_pin(Path("unused"), Path("unused"), b"p"*1952, timeout=value)
                popen.assert_not_called()
                run.assert_not_called()


@unittest.skipUnless(COMPILER.is_file(), "MSYS2 UCRT64 compiler required")
class NativeVisualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="cr01-native-visual-tests-")
        cls.exe = compile_native(Path(cls.build.name) / "cr01sc.exe")

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def tracked(self, peers):
        def create(*args, **kwargs):
            peer = RealPeer(*args, **kwargs)
            peers.append(peer)
            return peer
        return create

    def assert_clean(self, peers):
        for peer in peers:
            self.assertIsNotNone(peer.process.poll())
            self.assertTrue(all(handle.closed for handle in (peer.process.stdin, peer.process.stdout, peer.process.stderr)))
            identity = Path(peer.process.args[peer.process.args.index("--identity") + 1])
            self.assertFalse(identity.exists())
            self.assertFalse(identity.parent.exists())

    def test_live_checks_execute_native_only_and_clean_every_process(self):
        peers = []
        with patch("cr01_sc.native_demo.engine_path", return_value=self.exe), patch(
                "cr01_sc.native_demo.NativePeer", side_effect=self.tracked(peers)), patch.dict("sys.modules", {
                    "cr01_sc.demo": None, "cr01_sc.channel": None, "cr01_sc.handshake": None,
                    "cr01_sc.primitives": None, "cryptography": None}):
            report = run_live_validation(seed=123)
        self.assertEqual(report["schema"], "CR01-LIVE-VALIDATION-v2")
        self.assertEqual(report["summary"]["passed_checks"], 13)
        self.assertEqual(report["summary"]["total_checks"], 13)
        self.assertEqual(report["engine"]["native_peer_processes"], 9)
        self.assertEqual(len(peers), 9)
        self.assertTrue(all(peer.transport == "binary" for peer in peers))
        self.assertEqual(report["engine"]["executable_sha256"], hashlib.sha256(self.exe.read_bytes()).hexdigest())
        self.assertFalse(report["engine"]["python_reference_used"])
        self.assertTrue(all(report["handshake"]["attacks"].values()))
        self.assertEqual(len(report["handshake"]["attacks"]), 8)
        encoded = json.dumps(report)
        for forbidden in ('"private_key"', '"shared_secret"', '"confirmation_mac"', '"context_secret"', '.pem', 'BEGIN PRIVATE', 'cr01-native-demo-'):
            self.assertNotIn(forbidden, encoded)
        self.assert_clean(peers)

    def test_failure_during_confirmation_closes_peers_and_removes_keys(self):
        peers = []
        with patch("cr01_sc.native_demo.NativePeer", side_effect=self.tracked(peers)), patch.object(
                RealPeer, "confirm", side_effect=RuntimeError("injected native failure")):
            with self.assertRaises(NativeDemoUnavailable) as raised:
                run_native_demo(executable=self.exe)
        self.assertEqual(str(raised.exception), UNAVAILABLE)
        self.assertEqual(len(peers), 2)
        self.assert_clean(peers)

    def test_crash_or_local_codec_error_is_not_a_successful_rejection(self):
        for exception in (RuntimeError("endpoint exited"), ValueError("invalid binary request")):
            peers, count = [], [0]
            def create(*args, **kwargs):
                peer = self.tracked(peers)(*args, **kwargs)
                receive = peer.receive
                def faulty(*values, **fields):
                    count[0] += 1
                    if count[0] == 3:  # First negative probe, not a successful round trip.
                        if isinstance(exception, RuntimeError):
                            peer.process.terminate()  # Actual test-owned native child crash.
                            peer.process.wait(timeout=10)
                            return receive(*values, **fields)
                        raise exception
                    return receive(*values, **fields)
                peer.receive = faulty
                return peer
            with self.subTest(error=type(exception).__name__), patch("cr01_sc.native_demo.NativePeer", side_effect=create):
                with self.assertRaises(NativeDemoUnavailable):
                    run_native_demo(executable=self.exe)
            self.assert_clean(peers)

    def test_bad_observed_session_state_cannot_produce_a_ready_result(self):
        peers = []
        def create(*args, **kwargs):
            peer = self.tracked(peers)(*args, **kwargs)
            command = peer.command
            def changed(op, *values, **fields):
                result = command(op, *values, **fields)
                if peer is peers[0] and op == "status" and result.get("phase") == "established":
                    result["session_id"] = b"x" * 16
                return result
            peer.command = changed
            return peer
        with patch("cr01_sc.native_demo.NativePeer", side_effect=create):
            result = run_native_demo(executable=self.exe)
        self.assertEqual(result["summary"]["status"], "failed")
        self.assertFalse(result["summary"]["context_match"])
        self.assert_clean(peers)

    def test_request_id_never_determines_identity_or_session(self):
        first = run_native_demo(executable=self.exe, request_id=9700)
        second = run_native_demo(executable=self.exe, request_id=9700)
        self.assertNotEqual(first["transcript"]["identity_pins"], second["transcript"]["identity_pins"])
        self.assertNotEqual(first["transcript"]["records"]["session_id"], second["transcript"]["records"]["session_id"])

    def test_unlaunchable_engine_is_not_a_python_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "not-an-engine.exe"
            executable.write_bytes(b"invalid executable")
            with self.assertRaises(NativeDemoUnavailable) as raised:
                run_native_demo(executable=executable)
            self.assertEqual(str(raised.exception), UNAVAILABLE)
