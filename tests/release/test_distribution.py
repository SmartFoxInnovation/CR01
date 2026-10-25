import hashlib
import ast
import json
import re
import tempfile
import tomllib
import unittest
import zipfile
import subprocess
import struct
from html.parser import HTMLParser
from unittest.mock import patch
from pathlib import Path
from urllib.parse import unquote, urlsplit
from posixpath import normpath

from tools.build_release import (
    LICENSE_ID,
    MANIFEST_NAME,
    build_release,
    collect_release_paths,
    verify_release,
    ReleaseError,
    validate_receipt,
    validation_input_hashes,
    _safe_member_name,
)
from tools.validate import portable_command, validation_steps, run_validation


ROOT = Path(__file__).resolve().parents[2]


class ValidationReleaseTests(unittest.TestCase):
    def test_one_approved_logo_is_shared_by_readme_and_app(self):
        name = "src/python/cr01_sc/web/cr01-logo.png"
        paths = set(collect_release_paths())
        self.assertEqual({path for path in paths if path.endswith(".png")}, {name})
        payload = (ROOT / name).read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         "51cdfa0b047ba8069b4b67fa2735b448ef21eaf204ed87fa293c6dcb3b154d4c")
        self.assertEqual(payload[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", payload[16:24]), (1774, 887))
        self.assertEqual(validation_input_hashes()[name], hashlib.sha256(payload).hexdigest())

        class Images(HTMLParser):
            def __init__(self):
                super().__init__()
                self.images = []

            def handle_starttag(self, tag, attributes):
                if tag == "img":
                    self.images.append(dict(attributes))

        readme = Images()
        readme.feed((ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertEqual(len(readme.images), 1)
        self.assertEqual(readme.images[0]["src"], name)
        self.assertEqual(readme.images[0]["alt"], "CR01 logo")
        self.assertIn(readme.images[0]["src"], paths)
        app = Images()
        app.feed((ROOT / "src/python/cr01_sc/web/index.html").read_text(encoding="utf-8"))
        self.assertEqual(len(app.images), 2)
        self.assertTrue(all(image["src"] == "/assets/cr01-logo.png" and image["alt"] == "CR01"
                            for image in app.images))
        with (ROOT / "pyproject.toml").open("rb") as handle:
            package = tomllib.load(handle)
        self.assertIn("web/*", package["tool"]["setuptools"]["package-data"]["cr01_sc"])

    def test_readme_warning_stays_above_logo(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertLess(text.index("Not production-ready"), text.index("<img "))
        self.assertLess(text.index("no side-channel assurance"), text.index("<img "))
        self.assertLess(text.index("<img "), text.index("## Try it"))

    def test_src_install_and_binary_boundary(self):
        import cr01_sc
        from cr01_sc import native
        from cr01_sc._paths import default_project_root
        self.assertEqual(Path(cr01_sc.__file__).resolve().parent, ROOT / "src/python/cr01_sc")
        self.assertEqual(default_project_root(), ROOT)
        self.assertTrue(callable(native.NativePeer))
        self.assertFalse(hasattr(native, "compile_native"))
        self.assertEqual({path for path in collect_release_paths() if path.startswith("bin/")}, {"bin/README.md"})
        for name in ("native.py", "binary.py"):
            source = ast.parse((ROOT / "src/python/cr01_sc" / name).read_text())
            for node in ast.walk(source):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith("tools"))
                elif isinstance(node, ast.Import):
                    self.assertFalse(any(alias.name.startswith("tools") for alias in node.names))

    def test_current_package_has_no_historical_imports_or_modules(self):
        paths = set(collect_release_paths())
        self.assertEqual({path for path in paths if path.startswith("src/python/cr01_sc/") and path.endswith(".py")}, {
            "src/python/cr01_sc/__init__.py", "src/python/cr01_sc/channel.py", "src/python/cr01_sc/handshake.py", "src/python/cr01_sc/demo.py",
            "src/python/cr01_sc/primitives.py", "src/python/cr01_sc/app.py", "src/python/cr01_sc/evidence.py", "src/python/cr01_sc/reporting.py",
            "src/python/cr01_sc/native.py", "src/python/cr01_sc/binary.py", "src/python/cr01_sc/_paths.py",
            "src/python/cr01_sc/native_demo.py"})
        self.assertFalse(any(path.startswith(("cr01_rsa/", "history/", "code/")) for path in paths))
        self.assertEqual(len([path for path in paths if path.startswith("reports/") and path.endswith(".json")]), 8)
        for path in sorted(path for path in paths if path.endswith(".py")):
            for node in ast.walk(ast.parse((ROOT / path).read_text(encoding="utf-8"))):
                imports = [alias.name for alias in node.names] if isinstance(node, ast.Import) else (
                    [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
                self.assertFalse(any(name.split(".")[0] in {"cr01_rsa", "history", "code"} for name in imports), path)

    def test_timed_out_validation_writes_a_failed_receipt(self):
        with tempfile.TemporaryDirectory() as temp, patch("tools.validate.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["test"], 600)):
            receipt = run_validation(Path(temp))
            self.assertEqual(receipt["status"], "fail")
            self.assertEqual(receipt["steps"][0]["exit_code"], 124)
            self.assertTrue((Path(temp) / "validation.json").is_file())

    def test_zip_paths_are_safe_on_windows_and_posix(self):
        for name in ("/absolute", "root/../escape", "root\\..\\escape", "C:/escape", "root//file", "root/./file"):
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                _safe_member_name(name)

    def test_license_and_package_metadata_define_source_available_boundary(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]

        self.assertIn("PolyForm Noncommercial License 1.0.0", license_text)
        self.assertIn("Any noncommercial purpose is a permitted purpose.", license_text)
        self.assertIn("Personal use for research, experiment, and testing", license_text)
        self.assertNotIn("Business Source License", license_text)
        self.assertEqual(project["license"]["text"], LICENSE_ID)
        self.assertNotIn("License :: OSI Approved :: Apache Software License", project["classifiers"])
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Required Notice:", notice)
        self.assertIn("Commercial use requires an explicit commercial license", notice)

    def test_reader_release_labels_match_package_and_do_not_pin_security_policy(self):
        from cr01_sc import __version__
        with (ROOT / "pyproject.toml").open("rb") as handle:
            version = tomllib.load(handle)["project"]["version"]
        self.assertEqual(__version__, version)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"Release {version} · protocol v2.", readme)
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("This is a research preview. No security-maintenance commitment is made.", security)
        self.assertNotRegex(security, r"(?i)\bversion\s+\d+\.\d+\.\d+")
        for name in ("README.md", "NOTICE", "docs/GUIDE.md", "docs/VALIDATION.md", "reports/README.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            for found in re.findall(r"(?im)^(?:Version|Release)\s+(\d+\.\d+\.\d+)", text):
                self.assertEqual(found, version, name)
        self.assertIn(f"CR01-SC {version} is a v2 research preview.",
                      (ROOT / "docs/RESULTS.md").read_text(encoding="utf-8"))
        self.assertIn(f"dist/{version}-cr01-sc-technical-preview.zip",
                      (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8"))
        page = (ROOT / "src/python/cr01_sc/web/index.html").read_text(encoding="utf-8")
        for asset in ("app.css", "app.js"):
            self.assertIn(f"/assets/{asset}?v={version}", page)
        self.assertIn('id="product-label"', page)
        script = (ROOT / "src/python/cr01_sc/web/app.js").read_text(encoding="utf-8")
        self.assertIn('`CR01-SC ${snapshot.product.version}`', script)

    def test_release_allowlist_excludes_history_local_reports_and_agent_state(self):
        paths = set(collect_release_paths())
        self.assertIn("src/python/cr01_sc/channel.py", paths)
        self.assertIn("tests/protocol/test_channel.py", paths)
        self.assertIn("src/cpp/main.cpp", paths)
        self.assertIn("src/cpp/crypto.hpp", paths)
        self.assertIn("tests/native/cpp/endpoint_tests.cpp", paths)
        for path in ("src/cpp/channel_binary.hpp", "src/python/cr01_sc/binary.py",
                     "tools/benchmarks/transport.py", "tests/benchmarks/cpp/transport.cpp",
                     "tests/native/test_binary.py", "reports/benchmarks/transport.json"):
            self.assertIn(path, paths)
        for path in ("src/cpp/channel_v2_gcm.hpp", "src/cpp/channel_v2_flight.hpp",
                     "tools/benchmarks/tls.py",
                     "tests/benchmarks/cpp/tls_main.cpp", "tests/benchmarks/cpp/tls_support.hpp",
                     "tests/benchmarks/test_comparison.py", "reports/benchmarks/tls_aes.json",
                     "docs/PROTOCOL.md", "docs/GUIDE.md"):
            self.assertIn(path, paths)
        self.assertIn("reports/interop.json", paths)
        self.assertIn("reports/demo.json", paths)
        self.assertIn("src/cpp/channel_v2_plaintext.hpp",paths)
        self.assertIn(".github/workflows/validation.yml", paths)
        self.assertIn("docs/RESULTS.md", paths)
        self.assertIn("docs/VALIDATION.md", paths)
        self.assertNotIn("LICENSES/Apache-2.0.txt", paths)
        self.assertFalse(any("__pycache__" in path or path.endswith((".pyc", ".pyo")) for path in paths))
        self.assertNotIn("code/stations.txt", paths)
        self.assertFalse(any(path.startswith("code/") for path in paths))
        self.assertFalse(any(path.startswith(".agent/") for path in paths))
        self.assertFalse(any(path.startswith("reports/third_party_licenses/") for path in paths))
        self.assertFalse(any(path.startswith("reports/release_locks/") for path in paths))
        self.assertNotIn("reports/SECURITY_ANALYSIS.md", paths)
        self.assertNotIn("reports/wire_fuzz/wire_fuzz_assessment.md", paths)
        self.assertIn("reports/validation.json", paths)
        # Includes the reproducible TLS scaffold and compact comparison receipt,
        # not megabytes of raw sample arrays or operational key material.
        # Keep the source/evidence cap; only the named logo and PDF have separate
        # bounded budgets, not a generic binary allowance.
        images = {"src/python/cr01_sc/web/cr01-logo.png"}
        onepager = {"docs/HANDSHAKE.pdf"}
        self.assertEqual({path for path in paths if path.endswith(".pdf")}, onepager)
        self.assertLess(sum((ROOT / path).stat().st_size for path in paths - images - onepager), 1_750_000)
        self.assertLessEqual(sum((ROOT / path).stat().st_size for path in images), 1_200_000)
        self.assertLessEqual((ROOT / "docs/HANDSHAKE.pdf").stat().st_size, 1_200_000)

    def test_reader_entry_warns_before_run_commands(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        opening = readme.split("## Try it", 1)[0]
        self.assertIn("Not production-ready", opening)
        self.assertIn("no side-channel assurance", opening)
        self.assertIn("constant-time", opening)
        self.assertLess(len(readme.split()), 500)
        for name in ("README.md", "SECURITY.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("mailto:cr01@smart-fox-innovation.com", text)
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertLess(len(security.split()), 350)
        self.assertIn("No security-maintenance commitment", security)

    def test_bundle_has_one_entry_and_four_guides_not_a_release_diary(self):
        paths = set(collect_release_paths())
        self.assertEqual({path for path in paths if path.startswith("docs/")}, {
            "docs/GUIDE.md", "docs/RESULTS.md", "docs/PROTOCOL.md", "docs/VALIDATION.md", "docs/HANDSHAKE.pdf",
        })
        pdf = (ROOT / "docs/HANDSHAKE.pdf").read_bytes()
        self.assertEqual(hashlib.sha256(pdf).hexdigest(), "b216cb1306d420eca57cc06ab629ab24efcadd3763a80f7b63d87809c89df16c")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"/Count 1", pdf)
        self.assertIn(b"release 0.15.2", pdf)
        self.assertIn("](docs/HANDSHAKE.pdf)", (ROOT / "README.md").read_text(encoding="utf-8"))
        native_readme = (ROOT / "src/cpp/README.md").read_text(encoding="utf-8")
        self.assertNotIn("earlier micro-record experiment", native_readme)
        self.assertNotIn("Published performance measurements", native_readme)
        self.assertIn("Included performance measurements are Windows-only.", native_readme)
        for name in ("PRODUCT_CARD.md", "VALIDATION_RELEASE.md", "COMMERCIAL_USE.md",
                     "CONTRIBUTING.md", "RELEASE_CHECKLIST.md", "CITATION.cff"):
            self.assertNotIn(name, paths)
        self.assertEqual({path for path in paths if "/" not in path and path.endswith(".md")},
                         {"README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"})

    def test_packaged_markdown_links_resolve_within_delivered_inventory(self):
        paths = set(collect_release_paths())
        for source in sorted(path for path in paths if path.endswith(".md")):
            text = (ROOT / source).read_text(encoding="utf-8")
            for target in re.findall(r"\]\(([^\s)]+)\)", text):
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc:
                    continue
                relative = unquote(parsed.path)
                destination = normpath(str(Path(source).parent.as_posix()) + "/" + relative) if relative else source
                with self.subTest(source=source, target=target):
                    self.assertIn(destination, paths)
                    if parsed.fragment and destination.endswith(".md"):
                        headings = re.findall(r"(?m)^#{1,6} (.+)$",
                                              (ROOT / destination).read_text(encoding="utf-8"))
                        anchors = {re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-")
                                   for heading in headings}
                        self.assertIn(unquote(parsed.fragment), anchors)

    def test_validation_input_inventory_binds_code_tests_and_fixed_vectors(self):
        hashes = validation_input_hashes()
        for path in ("src/python/cr01_sc/handshake.py", "src/cpp/crypto.hpp",
                     "tests/protocol/test_channel.py", "tools/validate.py",
                     "reports/vectors.json", "LICENSE", "README.md", "SECURITY.md",
                     "docs/GUIDE.md", "docs/RESULTS.md", "docs/PROTOCOL.md", "docs/VALIDATION.md", "docs/HANDSHAKE.pdf",
                     "src/cpp/channel_binary.hpp", "src/python/cr01_sc/binary.py",
                     "reports/benchmarks/transport.json"):
            self.assertEqual(hashes[path], hashlib.sha256((ROOT / path).read_bytes()).hexdigest())
        self.assertNotIn("reports/validation.json", hashes)

    def test_validation_receipt_rejects_stale_failed_and_incomplete_evidence(self):
        names = [name for name, _ in validation_steps(Path("validation-output"))]
        receipt = {"schema": "CR01-SC-VALIDATION-v2", "status": "pass",
                   "steps": [{"name": name, "status": "pass", "exit_code": 0} for name in names],
                   "summary": {"passed_steps": 4, "executed_steps": 4, "expected_steps": 4,
                               "native_second_implementation_requested": False},
                   "validation_input_sha256": {"source.py": "current"}, "source_drift": []}
        validate_receipt(receipt, {"source.py": "current"})
        with self.assertRaises(ReleaseError):
            validate_receipt(receipt, {"source.py": "changed"})
        for key, value in (("status", "fail"), ("steps", receipt["steps"][:-1]),
                           ("source_drift", ["source.py"])):
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                validate_receipt({**receipt, key: value}, {"source.py": "current"})

    def test_native_receipt_requires_full_endpoint_gate_not_only_vectors(self):
        names = [name for name, _ in validation_steps(Path("validation-output"), include_native=True)]
        receipt = {"schema": "CR01-SC-VALIDATION-v2", "status": "pass",
                   "steps": [{"name": name, "status": "pass", "exit_code": 0} for name in names],
                   "summary": {"passed_steps": 5, "executed_steps": 5, "expected_steps": 5,
                               "native_second_implementation_requested": True},
                   "validation_input_sha256": {"source.py": "current"}, "source_drift": []}
        validate_receipt(receipt, {"source.py": "current"})
        receipt["steps"][-1]["name"] = "unrelated-native-check"
        with self.assertRaises(ReleaseError):
            validate_receipt(receipt, {"source.py": "current"})

    def test_release_build_is_deterministic_and_manifest_verified(self):
        with tempfile.TemporaryDirectory(prefix="cr01-validation-a-") as first_name, tempfile.TemporaryDirectory(
            prefix="cr01-validation-b-"
        ) as second_name:
            first, first_checksum, first_manifest = build_release(Path(first_name))
            second, second_checksum, second_manifest = build_release(Path(second_name))

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_checksum.read_text(encoding="ascii").split()[0], hashlib.sha256(first.read_bytes()).hexdigest())
            self.assertEqual(first_manifest, second_manifest)
            verified = verify_release(first)
            self.assertEqual(verified["license"]["spdx"], LICENSE_ID)
            self.assertFalse(verified["license"]["commercial_use"])
            self.assertNotIn("production_use", verified["license"])
            self.assertFalse(verified["security_status"]["production_ready"])

            with zipfile.ZipFile(first) as bundle:
                names = bundle.namelist()
                self.assertEqual(sum(name.endswith(f"/{MANIFEST_NAME}") for name in names), 1)
                self.assertFalse(any("code/stations.txt" in name for name in names))
                self.assertFalse(any(name.endswith((".pem", ".key", ".p12", ".pfx")) for name in names))
                manifest_name = next(name for name in names if name.endswith(f"/{MANIFEST_NAME}"))
                manifest = json.loads(bundle.read(manifest_name))
                self.assertEqual(manifest["file_count"], len(manifest["files"]))

    def test_public_validation_commands_are_portable_and_bounded(self):
        with tempfile.TemporaryDirectory(prefix="cr01-validation-output-") as temp_name:
            steps = validation_steps(Path(temp_name), include_native=False)
            native_steps = validation_steps(Path(temp_name), include_native=True)

        self.assertEqual(len(steps), 4)
        self.assertEqual(len(native_steps), 5)
        self.assertEqual(native_steps[-1][0], "native_v2_endpoints")
        normalized = portable_command(steps[0][1])
        self.assertEqual(normalized[0], "{python}")
        self.assertNotIn(str(ROOT), " ".join(normalized))


if __name__ == "__main__":
    unittest.main()
