import unittest

from tools.dependencies import generate_third_party_license_report


class ThirdPartyLicenseReportTests(unittest.TestCase):
    def test_report_tracks_runtime_and_native_dependency_sets(self):
        report = generate_third_party_license_report()

        python_packages = {
            item["name"].lower(): item
            for item in report["python_runtime_packages"]
        }
        native_packages = {
            item["name"]: item
            for item in report["native_packages"]
        }

        self.assertIn("cryptography", python_packages)
        self.assertIn("cffi", python_packages)
        self.assertIn("pycparser", python_packages)
        self.assertGreaterEqual(len(python_packages["cryptography"]["license_files"]), 1)

        self.assertIn("mingw-w64-ucrt-x86_64-openssl", native_packages)
        self.assertIn("mingw-w64-ucrt-x86_64-gcc", native_packages)
        self.assertIn("mingw-w64-ucrt-x86_64-gcc-libs", native_packages)
        self.assertIn("mingw-w64-ucrt-x86_64-libwinpthread", native_packages)
        self.assertEqual(report["summary"]["generator"], "tools/dependencies.py")


if __name__ == "__main__":
    unittest.main()
