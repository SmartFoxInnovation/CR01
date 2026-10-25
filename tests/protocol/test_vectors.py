"""Public known inputs verified by Python and native OpenSSL record adapter."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from cr01_sc.channel import RecordChannel, _CONSTRUCTION_TOKEN
from cr01_sc.native import native_environment
from tools.native import COMPILER, openssl_flags

ROOT = Path(__file__).resolve().parents[2]


class V2VectorTests(unittest.TestCase):
    def test_separate_verifier_rejects_changed_public_fixture(self):
        from tools.vectors import verify
        document = json.loads((ROOT / "reports/vectors.json").read_text())
        checked = verify(document)
        self.assertEqual(checked["checked_vectors"], 8)
        self.assertEqual(checked["authentication_mutations_rejected"], 16)
        document["vectors"][0]["frame"] = "00"
        with self.assertRaises(ValueError):
            verify(document)

    def fixtures(self):
        return json.loads((ROOT / "reports/vectors.json").read_text())["vectors"]

    def test_public_vectors_python_and_explicit_wrong_direction(self):
        for vector in self.fixtures():
            key, sid = bytes.fromhex(vector["key"]), bytes.fromhex(vector["session_id"])
            direction, sequence = vector["direction"], vector["sequence"]
            sender = RecordChannel(_CONSTRUCTION_TOKEN, sid, key, b"z" * 32, direction)
            receiver = RecordChannel(_CONSTRUCTION_TOKEN, sid, b"z" * 32, key, 1 - direction)
            # A public fixture constructs state internally; this is not a resume API.
            sender._next = sequence
            frame = sender.send(bytes.fromhex(vector["plaintext"]), bytes.fromhex(vector["aad"]))
            self.assertEqual(frame.hex(), vector["frame"])
            self.assertEqual(receiver.receive(frame), bytes.fromhex(vector["plaintext"]))
            with self.assertRaises(ValueError):
                sender.receive(frame)
            sender.close()
            receiver.close()

    @unittest.skipUnless(COMPILER.is_file(), "Native compiler/OpenSSL prefix not configured")
    def test_public_vectors_native_and_mutation_rejection(self):
        env = native_environment()
        with tempfile.TemporaryDirectory(prefix="cr01-v2-native-") as temp:
            exe = Path(temp) / "v2-vectors.exe"
            built = subprocess.run([str(COMPILER), "-std=c++20", "-O2", "-Wall", "-Wextra", "-Wpedantic",
                str(ROOT / "tests/native/cpp/vector_tests.cpp"), *openssl_flags(), "-o", str(exe)],
                capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for vector in self.fixtures():
                args = [str(exe), vector["key"], vector["session_id"], vector["frame"], vector["plaintext"], vector["aad"]]
                result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                for index in (0, 4, 24, -1):
                    frame = bytearray.fromhex(vector["frame"])
                    frame[index] ^= 1
                    bad = [*args]
                    bad[3] = frame.hex()
                    result = subprocess.run(bad, capture_output=True, text=True, env=env, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
