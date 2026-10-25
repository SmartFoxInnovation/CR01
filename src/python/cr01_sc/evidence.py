"""Current CR01-SC evidence only. Missing or stale results never count as passes."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import time

from . import __version__

from ._paths import default_project_root

REPO_ROOT = default_project_root()
REPORT_PATHS = {
    "primitives": Path("reports/primitives.json"),
    "demo": Path("reports/demo.json"),
    "vectors": Path("reports/vectors.json"),
    "interop": Path("reports/interop.json"),
    "validation": Path("reports/validation.json"),
    "comparison": Path("reports/benchmarks/tls_aes.json"),
    "transport": Path("reports/benchmarks/transport.json"),
    "lifecycle": Path("reports/benchmarks/lifecycle.json"),
}
SCHEMAS = {
    "primitives": "CR01-PRIMITIVE-CHECKS-v1",
    "demo": "CR01-NATIVE-DEMO-v1",
    "vectors": "CR01-V2-PUBLIC-RECORD-VECTORS-v1",
    "interop": "CR01-NATIVE-V2-INTEROP-v1",
    "validation": "CR01-SC-VALIDATION-v2",
    "comparison": "CR01-MATCHED-TLS-AES-COMPACT-v1",
    "transport": "CR01-V2-TRANSPORT-BENCH-v1",
    "lifecycle": "CR01-LIFECYCLE-v1",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fraction(passed, total):
    if type(passed) is not int or type(total) is not int or total <= 0:
        return "unavailable"
    return f"{passed} / {total}"


def all_passed(summary):
    passed, total = summary.get("passed_checks"), summary.get("total_checks")
    return type(total) is int and total > 0 and type(passed) is int and passed == total


def power(bits):
    exponent = math.floor(bits * math.log10(2))
    return {"expression": f"2^{bits}", "scientific": f"{10 ** (bits * math.log10(2) - exponent):.3f} x 10^{exponent}"}


class EvidenceStore:
    def __init__(self, repo_root=REPO_ROOT):
        self.repo_root = Path(repo_root).resolve()

    def _binding_matches(self, document):
        hashes = document.get("source_sha256", document.get("validation_input_sha256"))
        if not isinstance(hashes, dict) or not hashes:
            return False
        for name, expected in hashes.items():
            if not isinstance(name, str) or not isinstance(expected, str):
                return False
            relative = PurePosixPath(name)
            if not relative.parts or relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
                return False
            if relative.parts[0] not in {"src", "config", "tools", "tests", "reports"} and name not in {
                "pyproject.toml", "requirements.txt", "requirements.lock", "LICENSE", "NOTICE", "Makefile", "bin/README.md",
                "README.md", "SECURITY.md", "docs/GUIDE.md", "docs/RESULTS.md", "docs/PROTOCOL.md", "docs/VALIDATION.md", "docs/HANDSHAKE.pdf",
            }:
                return False
            candidate = (self.repo_root / name).resolve()
            try:
                candidate.relative_to(self.repo_root)
                if candidate.stat().st_size > 10 * 1024 * 1024:
                    return False
                actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
            except (OSError, ValueError):
                return False
            if actual != expected:
                return False
        return True

    def _load_report(self, report_id):
        relative = REPORT_PATHS[report_id]
        path = (self.repo_root / relative).resolve()
        path.relative_to(self.repo_root)
        source = {"id": report_id, "path": relative.as_posix(), "available": False,
                  "modified_at": None, "run_at": None, "sha256": None, "error": None}
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("oversized report")
            raw = path.read_bytes()
            report = json.loads(raw.decode("utf-8"))
            if not isinstance(report, dict) or report.get("schema") != SCHEMAS[report_id]:
                raise ValueError("unexpected report schema")
            if report_id != "vectors" and not self._binding_matches(report):
                raise ValueError("source binding missing or stale")
        except FileNotFoundError:
            source["error"] = "report missing"
            return None, source
        except (OSError, ValueError, UnicodeError):
            source["error"] = "report invalid or source-stale"
            return None, source
        source.update(available=True, sha256=hashlib.sha256(raw).hexdigest(),
                      modified_at=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                      run_at=report.get("generated_at", report.get("finished_at")))
        return report, source

    @staticmethod
    def _passed(name, report):
        if not report:
            return False
        if name == "primitives":
            return all_passed(report.get("summary", {}))
        if name == "demo":
            return (report.get("engine", {}).get("implementation") == "C++" and
                    report.get("engine", {}).get("python_reference_used") is False and
                    report.get("summary", {}).get("status") == "ready") and bool(report.get("attacks")) and all(
                value is True for value in report["attacks"].values())
        if name == "vectors":
            return len(report.get("vectors", [])) == 8
        if name == "interop":
            return report.get("status") == "pass" and report.get("tests_run", 0) > 0 and all(
                report.get(key) == 0 for key in ("failures", "errors", "skipped"))
        if name == "lifecycle":
            return (report.get("status") == "pass" and report.get("quick") is False and
                    type(report.get("repeats")) is int and report["repeats"] >= 3 and
                    len(EvidenceStore._lifecycle_rows(report)) == 4)
        return report.get("status") == "pass"

    @staticmethod
    def _lifecycle_rows(report):
        if not report or report.get("status") != "pass" or report.get("quick") is not False:
            return []
        summary = report.get("summary", {}).get("candidate", {})
        rows = []
        for key, field, label, boundary in (
            ("cold_start_pair_ready_ms", "median_ms", "Cold start", "Start two processes, until both are ready."),
            ("warm_up", "median_mean_ms", "Warm-up", "First in-process handshake after loading identities."),
            ("fresh_handshake", "median_mean_ms", "Fresh handshake", "New session on a warmed engine."),
            ("running_1m", "median_mean_ms", "Running session · 1 MiB", "Encrypt, authenticate, check and clean up one record."),
        ):
            value = summary.get(key, {}).get(field)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                return []
            rows.append({"id": key, "label": label, "milliseconds": value, "boundary": boundary})
        return rows

    def build_snapshot(self):
        docs, sources = {}, []
        for name in REPORT_PATHS:
            docs[name], source = self._load_report(name)
            sources.append(source)
        available = sum(source["available"] for source in sources)
        checks_ok = all(self._passed(name, docs[name]) for name in REPORT_PATHS)
        primitive = (docs["primitives"] or {}).get("summary", {})
        demo = docs["demo"] or {}
        attacks = demo.get("attacks", {})
        interop = docs["interop"] or {}
        interop_total = interop.get("tests_run")
        interop_failed = [interop.get(key) for key in ("failures", "errors", "skipped")]
        interop_passed = (interop_total - sum(interop_failed)
                          if type(interop_total) is int and all(type(value) is int and value >= 0 for value in interop_failed)
                          else None)
        validation = docs["validation"] or {}
        comparison = docs["comparison"] or {}
        metrics = [
            ("primitives", fraction(primitive.get("passed_checks"), primitive.get("total_checks")), "primitive checks", "Python crypto backend"),
            ("demo", fraction(sum(value is True for value in attacks.values()), len(attacks)), "rejection checks", "Tampering, replay and restart"),
            ("interop", fraction(interop_passed, interop_total), "native endpoint tests", "JSON and binary transports"),
            ("validation", str(validation.get("unit_test_count", "unavailable")), "regression tests", "Current test suite"),
            ("vectors", str(len((docs["vectors"] or {}).get("vectors", []))) if docs["vectors"] else "unavailable", "public test vectors", "Synthetic keys"),
        ]
        families = []
        for name, value, label, qualifier in metrics:
            families.append({"id": name, "label": label, "result": value,
                             "status": "pass" if self._passed(name, docs[name]) else "partial",
                             "description": qualifier,
                             "boundary": "See SECURITY.md.",
                             "source": REPORT_PATHS[name].as_posix()})
        rows = []
        labels = {"cr01": "CR01-SC v2", "tls-classical": "TLS 1.3 classical",
                  "tls-hybrid": "TLS 1.3 hybrid", "tls-pq": "TLS 1.3 hybrid + ML-DSA",
                  "aes-primitive": "Preallocated AES-GCM", "aes-reuse": "Framed AES, reused context",
                  "aes-fresh": "Framed AES, fresh context"}
        for panel in comparison.get("summary", []):
            if panel.get("panel") not in {"in-process", "primitive-only"}:
                continue
            record = next((item for item in panel.get("records", []) if item.get("payload_bytes") == 1024), None)
            if not record:
                continue
            cost = record.get("median_mean_ms")
            if type(cost) not in (int, float) or cost <= 0 or not math.isfinite(cost):
                continue
            profile = panel["profile"]
            rows.append({"id": profile, "label": labels.get(profile, profile),
                         "role": "cr01" if profile == "cr01" else "comparison",
                         "available": True, "round_trip_ms": cost, "messages_per_second": 1000 / cost,
                         "overhead_bytes": record.get("encoded_bytes", 1024) - 1024})
        rows.sort(key=lambda row: row["round_trip_ms"])
        return {
            "schema": "CR01-SHOWCASE-v1", "generated_at": utc_now(),
            "product": {"name": "CR01-SC Evidence Console", "protocol": "CR01-SC", "version": __version__,
                        "posture": "research technical preview", "status": "evidence-ready" if checks_ok else "partial-evidence",
                        "tagline": "Protocol demo and test results.",
                        "live_backend": "C++ via cr01_sc.native (CRB1)",
                        "license": {"spdx": "PolyForm-Noncommercial-1.0.0", "commercial_use_granted": False,
                                    "use_boundary": "noncommercial study and validation"}},
            "report_health": {"available": available, "expected": len(REPORT_PATHS),
                              "complete": available == len(REPORT_PATHS), "checks_passed": checks_ok,
                              "note": "Report hashes are checked against the current source."},
            "headline": [{"id": name, "value": value, "label": label, "qualifier": qualifier,
                          "tone": "positive" if self._passed(name, docs[name]) else "caution"}
                         for name, value, label, qualifier in metrics],
            "evidence_families": families, "sources": sources,
            "performance": {"standard": "Matched local comparison", "payload_bytes": 1024,
                            "repeats": comparison.get("repeats"), "rows": rows,
                            "boundary": "Seal + authenticated receive; median run means. Different trust/record/API contracts; not network capacity."},
            "lifecycle": {"rows": self._lifecycle_rows(docs["lifecycle"]),
                          "source": REPORT_PATHS["lifecycle"].as_posix(),
                          "boundary": "Five runs. Stages measured separately; OS caches are not flushed."},
            "complexity": self._complexity(docs["primitives"]),
            "protocol_layers": [
                {"step": "01", "name": "Establish", "primitive": "ML-KEM-768", "purpose": "Fresh shared secret per handshake."},
                {"step": "02", "name": "Authenticate", "primitive": "ML-DSA-65 + exact pins", "purpose": "Bind identities, roles, policy and application."},
                {"step": "03", "name": "Confirm", "primitive": "Mutual Finished", "purpose": "Open the channel after peer confirmation."},
                {"step": "04", "name": "Protect", "primitive": "HKDF + AES-256-GCM", "purpose": "Directional keys and authenticated records."},
                {"step": "05", "name": "Restart", "primitive": "Fresh full handshake", "purpose": "No traffic-key restore or counter reset."}],
            "quantum_readiness": self._quantum(self._passed("primitives", docs["primitives"])),
            "maturity": [{"use": "Noncommercial evaluation", "state": "research preview", "tone": "caution"},
                         {"use": "Production deployment", "state": "not production-ready", "tone": "blocked"}],
            "enterprise": {"evaluation_assets": ["Current v2 source and public vectors", "Python/C++ interoperability tests", "Reproducible local benchmarks"],
                           "deployment_profiles": [{"name": "Local demo", "fit": "Synthetic data only.", "controls": "Loopback by default."},
                                                   {"name": "Technical review", "fit": "Inspect the protocol and reproduce the tests.", "controls": "Source and reports included."},
                                                   {"name": "Deployment", "fit": "Not production-ready.", "controls": "Independent design, side-channel and operational review required."}],
                           "boundary": "Evaluation surface only. No commercial grant, certification or production approval."},
        }

    @staticmethod
    def _complexity(primitives):
        results = (primitives or {}).get("results", [])
        def observed(name, field):
            row = next((item for item in results if item.get("name") == name), {})
            match = re.search(rf"(?:^|;)\s*{field}=(\d+)", str(row.get("details", "")))
            return int(match.group(1)) if match else None
        return {"default_id": "aes256-context", "items": [
            {"id": "aes256-context", "name": "AES-256", "role": "Payload encryption", "status": "active",
             "primary": power(256), "quantum_model": power(128), "quantum_label": "idealized Grover query scale",
             "notes": ["Key-space size does not establish key entropy.", "Idealized search scale is not protocol security.",
                       "Nonce discipline and endpoint security still matter."]},
            {"id": "mlkem768", "name": "ML-KEM-768", "role": "Shared-secret establishment", "status": "active",
             "ciphertext_bytes": observed("mlkem768_self_consistency", "ciphertext_bytes"),
             "notes": ["A lattice parameter is not an exhaustive-keysearch count.", "Backend self-consistency is not independent cryptanalysis."]},
            {"id": "mldsa65", "name": "ML-DSA-65", "role": "Pinned-identity authentication", "status": "active",
             "signature_bytes": observed("mldsa65_self_consistency", "signature_bytes"),
             "notes": ["Exact peer pins require authenticated provisioning.", "Signature checks do not establish secure key custody."]},
        ], "boundary": "Primitive parameters and protocol assurance are not interchangeable."}

    @staticmethod
    def _quantum(primitives_ok):
        return {"headline": "The custom session protocol has no quantum-security proof.",
                "short_claim": "Research preview — not production-ready",
                "why": ["ML-KEM-768 for key exchange.", "ML-DSA-65 for peer authentication.", "AES-256-GCM for records."],
                "not_claimed": ["No quantum-security or formal composition proof.", "No independent audit, side-channel assurance or certification.",
                                "Not production-ready."],
                "gates": [{"name": "Local primitive checks", "state": "complete" if primitives_ok else "unavailable", "owner": "local tests"},
                          {"name": "Independent design review", "state": "required", "owner": "external"},
                          {"name": "Side-channel and memory review", "state": "required", "owner": "external"},
                          {"name": "Deployment/key-lifecycle assessment", "state": "required", "owner": "operator"}],
                "standards": [{"id": "FIPS 203", "name": "ML-KEM", "status": "Algorithm specification, not CR01 certification",
                               "url": "https://csrc.nist.gov/pubs/fips/203/final"},
                              {"id": "FIPS 204", "name": "ML-DSA", "status": "Algorithm specification, not CR01 certification",
                               "url": "https://csrc.nist.gov/pubs/fips/204/final"}]}


def validate_demo_seed(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("seed must be an integer")
    if not 0 <= value <= 2_147_483_647:
        raise ValueError("seed must be between 0 and 2147483647")
    return value


def run_live_validation(seed: int = 9700, *, repo_root=None) -> dict[str, Any]:
    """Run native-only checks; the request id never seeds cryptographic keys."""
    from .native_demo import run_native_demo

    seed = validate_demo_seed(seed)
    started = time.perf_counter()
    handshake = run_native_demo(repo_root=repo_root, request_id=seed)
    attacks = handshake["attacks"]
    core_names = ("mutual_authentication", "key_confirmation", "context_match", "directional_keys", "payload_decrypts")
    checks = [{"id": name, "family": "native-handshake", "label": name.replace("_", " "),
               "passed": handshake["summary"].get(name) is True, "type": "native-integrated-demo"}
              for name in core_names]
    checks.extend({"id": name, "family": "native-attack-probe", "label": name.replace("_", " "),
                   "passed": passed is True, "type": "native-negative-probe"}
                  for name, passed in attacks.items())
    passed = sum(item["passed"] for item in checks)
    return {
        "schema": "CR01-LIVE-VALIDATION-v2", "generated_at": utc_now(),
        "summary": {"status": "pass" if passed == len(checks) else "partial",
                    "passed_checks": passed, "total_checks": len(checks),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "seed": seed, "writes_reports": False,
                    "claim_boundary": "Native C++ synthetic engineering checks through local binary pipes; not formal validation or certification."},
        "engine": handshake["engine"], "checks": checks,
        "handshake": {"summary": handshake["summary"], "transcript": handshake["transcript"],
                      "attacks": attacks, "trust_decisions": handshake["trust_decisions"]},
    }


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

