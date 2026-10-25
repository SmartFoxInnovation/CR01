import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cr01_sc import __version__
from cr01_sc.native_demo import engine_path
from cr01_sc.evidence import EvidenceStore, REPORT_PATHS, SCHEMAS, run_live_validation, validate_demo_seed


class ShowcaseEvidenceTests(unittest.TestCase):
    def populated(self, root):
        source = root / "src/python/cr01_sc/channel.py"
        source.parent.mkdir(parents=True)
        source.write_text("# test source\n", encoding="utf-8")
        binding = {"src/python/cr01_sc/channel.py": hashlib.sha256(source.read_bytes()).hexdigest()}
        documents = {
            "primitives": {"summary": {"passed_checks": 11, "total_checks": 11}},
            "demo": {"summary": {"status": "ready"}, "attacks": {"replay": True},
                     "engine": {"implementation": "C++", "python_reference_used": False}},
            "vectors": {"vectors": [{}] * 8},
            "interop": {"status": "pass", "tests_run": 55, "failures": 0, "errors": 0, "skipped": 0},
            "validation": {"status": "pass", "unit_test_count": 100},
            "comparison": {"status": "pass"},
            "transport": {"status": "pass"},
            "lifecycle": {"status": "pass", "quick": False, "repeats": 5, "summary": {"candidate": {
                "cold_start_pair_ready_ms": {"median_ms": 100},
                **{name: {"median_mean_ms": 1} for name in ("warm_up", "fresh_handshake", "running_1m")}}}},
        }
        for name, document in documents.items():
            document.update(schema=SCHEMAS[name], source_sha256=binding)
            path = root / REPORT_PATHS[name]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(document), encoding="utf-8")
        return documents

    def test_snapshot_uses_current_report_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.populated(root)
            snapshot = EvidenceStore(root).build_snapshot()
        self.assertEqual(snapshot["schema"], "CR01-SHOWCASE-v1")
        self.assertEqual(snapshot["product"]["status"], "evidence-ready")
        self.assertEqual(snapshot["product"]["version"], __version__)
        self.assertFalse(snapshot["product"]["license"]["commercial_use_granted"])
        self.assertTrue(snapshot["report_health"]["checks_passed"])
        self.assertEqual(snapshot["report_health"]["available"], 8)
        self.assertEqual({row["id"] for row in snapshot["headline"]},
                         {"primitives", "demo", "interop", "validation", "vectors"})
        self.assertTrue(all(len(source["sha256"]) == 64 for source in snapshot["sources"]))

    def test_missing_reports_degrade_without_inventing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = EvidenceStore(directory).build_snapshot()
        self.assertEqual(snapshot["product"]["status"], "partial-evidence")
        self.assertFalse(snapshot["report_health"]["complete"])
        self.assertEqual(snapshot["report_health"]["available"], 0)
        self.assertTrue(all(row["value"] == "unavailable" for row in snapshot["headline"]))
        self.assertEqual(snapshot["performance"]["rows"], [])
        self.assertEqual(snapshot["lifecycle"]["rows"], [])

    def test_reader_document_bindings_are_allowed_but_unknown_documents_are_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = self.populated(root)
            hashes = {}
            for name in ("README.md", "SECURITY.md", "docs/GUIDE.md", "docs/RESULTS.md", "docs/PROTOCOL.md", "docs/VALIDATION.md", "docs/HANDSHAKE.pdf"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# reader fixture\n", encoding="utf-8")
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            documents["validation"]["source_sha256"] = hashes
            path = root / REPORT_PATHS["validation"]
            path.write_text(json.dumps(documents["validation"]), encoding="utf-8")
            self.assertTrue(EvidenceStore(root).build_snapshot()["report_health"]["checks_passed"])
            pdf = root / "docs/HANDSHAKE.pdf"
            original = pdf.read_bytes()
            pdf.write_bytes(original + b"changed")
            self.assertFalse(EvidenceStore(root).build_snapshot()["report_health"]["checks_passed"])
            pdf.write_bytes(original)
            (root / "SECURITY.md").write_text("changed", encoding="utf-8")
            self.assertFalse(EvidenceStore(root).build_snapshot()["report_health"]["checks_passed"])
            for name in ("docs/unknown.md", "docs/unknown.pdf", "other.md"):
                unknown = root / name
                unknown.write_text("# not an admitted reader file\n", encoding="utf-8")
                self.assertFalse(EvidenceStore(root)._binding_matches({"source_sha256": {
                    name: hashlib.sha256(unknown.read_bytes()).hexdigest()}}))

    def test_lifecycle_rejects_quick_missing_nonfinite_and_failed_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = self.populated(root)
            self.assertEqual(len(EvidenceStore(root).build_snapshot()["lifecycle"]["rows"]), 4)
            for change in ({"quick": True}, {"status": "fail"}, {"summary": {}},
                           {"summary": {"candidate": {"cold_start_pair_ready_ms": {"median_ms": float('nan')}}}}):
                bad = {**docs["lifecycle"], **change}
                (root / REPORT_PATHS["lifecycle"]).write_text(json.dumps(bad), encoding="utf-8")
                snapshot = EvidenceStore(root).build_snapshot()
                self.assertEqual(snapshot["lifecycle"]["rows"], [])
                self.assertFalse(snapshot["report_health"]["checks_passed"])

    def test_stale_malformed_and_unbound_reports_fail_closed(self):
        for bad in ("stale", "malformed", "unbound", "traversal", "empty-path"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                documents = self.populated(root)
                path = root / REPORT_PATHS["primitives"]
                if bad == "stale":
                    (root / "src/python/cr01_sc/channel.py").write_text("# changed\n", encoding="utf-8")
                elif bad == "malformed":
                    path.write_text("[]", encoding="utf-8")
                else:
                    binding = {} if bad == "unbound" else {
                        "../outside" if bad == "traversal" else "": "0" * 64}
                    documents["primitives"]["source_sha256"] = binding
                    path.write_text(json.dumps(documents["primitives"]), encoding="utf-8")
                snapshot = EvidenceStore(root).build_snapshot()
                self.assertEqual(snapshot["product"]["status"], "partial-evidence")
                self.assertFalse(next(row for row in snapshot["sources"] if row["id"] == "primitives")["available"])

    def test_empty_or_zero_checks_never_pass(self):
        for summary in ({}, {"passed_checks": 0, "total_checks": 0},
                        {"passed_checks": True, "total_checks": True}):
            self.assertFalse(EvidenceStore._passed("primitives", {"summary": summary}))
        self.assertFalse(EvidenceStore._passed("demo", {"summary": {"status": "ready"}, "attacks": {}}))
        self.assertFalse(EvidenceStore._passed("interop", {"status": "pass", "tests_run": 0,
                                                         "failures": 0, "errors": 0, "skipped": 0}))

    def test_failed_native_methods_are_not_shown_as_all_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = self.populated(root)
            documents["interop"].update(status="fail", failures=1)
            (root / REPORT_PATHS["interop"]).write_text(json.dumps(documents["interop"]), encoding="utf-8")
            snapshot = EvidenceStore(root).build_snapshot()
        self.assertEqual(snapshot["product"]["status"], "partial-evidence")
        self.assertEqual(next(row for row in snapshot["headline"] if row["id"] == "interop")["value"], "54 / 55")

    def test_complexity_keeps_algorithm_boundaries_explicit(self):
        snapshot = EvidenceStore().build_snapshot()
        items = {item["id"]: item for item in snapshot["complexity"]["items"]}
        self.assertEqual(set(items), {"aes256-context", "mlkem768", "mldsa65"})
        self.assertEqual(items["aes256-context"]["primary"]["expression"], "2^256")
        self.assertEqual(items["aes256-context"]["quantum_model"]["expression"], "2^128")
        # Parameter observations disappear when a receipt becomes stale.
        if items["mlkem768"]["ciphertext_bytes"] is not None:
            self.assertEqual(items["mlkem768"]["ciphertext_bytes"], 1088)
        if items["mldsa65"]["signature_bytes"] is not None:
            self.assertEqual(items["mldsa65"]["signature_bytes"], 3309)
        self.assertIn("not interchangeable", snapshot["complexity"]["boundary"])

    def test_seed_validation_is_bounded(self):
        self.assertEqual(validate_demo_seed(9700), 9700)
        for invalid in (True, -1, 2_147_483_648, 1.5, "9700"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_demo_seed(invalid)

    @unittest.skipUnless(engine_path().is_file(), "Native build required")
    def test_live_validation_is_bounded_and_secret_free(self):
        result = run_live_validation(seed=9700)

        self.assertEqual(result["summary"]["status"], "pass")
        self.assertEqual(result["summary"]["passed_checks"], result["summary"]["total_checks"])
        self.assertFalse(result["summary"]["writes_reports"])
        self.assertEqual(result["summary"]["total_checks"], 13)
        self.assertEqual(result["engine"]["implementation"], "C++")
        self.assertFalse(result["engine"]["python_reference_used"])
        self.assertEqual(result["handshake"]["summary"]["version"], 2)
        self.assertFalse(result["handshake"]["summary"]["toy_core_used"])

        serialized = json.dumps(result).lower()
        self.assertNotIn('"context_secret"', serialized)
        self.assertNotIn('"private_key"', serialized)
        self.assertNotIn('"shared_secret"', serialized)
        self.assertNotIn('"confirmation_mac"', serialized)


if __name__ == "__main__":
    unittest.main()

