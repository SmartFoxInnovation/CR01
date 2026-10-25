import tempfile
import unittest
from pathlib import Path

from tools.locks import generate_release_locks


ROOT = Path(__file__).resolve().parents[2]


class ReleaseLockTests(unittest.TestCase):
    def test_release_locks_publish_exact_runtime_and_native_versions(self):
        with tempfile.TemporaryDirectory(prefix="cr01-release-locks-test-") as temp_name:
            paths = (ROOT / "requirements.lock", ROOT / "config/native-packages.lock",
                     ROOT / "config/native-packages.lock.json")
            before = [path.read_bytes() for path in paths]
            result = generate_release_locks(Path(temp_name))
            self.assertEqual(before, [path.read_bytes() for path in paths])
            self.assertFalse(result["summary"]["canonical_locks_updated"])
            self.assertTrue((Path(temp_name) / "requirements.lock").is_file())

            expected = "ready" if all(package["version"] for package in result["native_packages"]) else "incomplete"
            self.assertEqual(result["summary"]["status"], expected)
            self.assertGreaterEqual(result["summary"]["python_runtime_package_count"], 1)
            self.assertGreaterEqual(result["summary"]["native_package_count"], 1)
            lock_text = (ROOT / "requirements.lock").read_text(encoding="utf-8")
            native_lock_text = (ROOT / "config" / "native-packages.lock").read_text(encoding="utf-8")
            self.assertIn("cryptography==", lock_text)
            self.assertIn("mingw-w64-ucrt-x86_64-openssl=", native_lock_text)


if __name__ == "__main__":
    unittest.main()
