"""Execute native v2 endpoint regressions and write a source-bound public receipt."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.native import COMPILER
from cr01_sc.native import NativePeer, native_environment


class Results(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.cases.append({"test": test.id().split(".")[-1], "status": "pass"})
        if hasattr(test, "native_core_result"):
            self.cases[-1]["native_core_checks"] = test.native_core_result
        if hasattr(test, "native_hardening_result"):
            self.cases[-1]["native_hardening_checks"] = test.native_hardening_result

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        self.cases.append({"test": test.id().split(".")[-1], "subcase": str(subtest.params),
                           "status": "pass" if error is None else "fail"})


def input_hashes():
    paths = list((ROOT / "src/cpp").glob("*v2*.hpp"))
    paths += [ROOT / name for name in ("src/cpp/channel_binary.hpp", "src/cpp/main.cpp", "src/cpp/crypto.hpp",
        "src/cpp/json.hpp", "tests/native/cpp/endpoint_tests.cpp", "tools/build_native.ps1",
        "tools/build_native.sh", "tools/check_openssl.cpp",
        "tools/native.py", "src/python/cr01_sc/native.py", "src/python/cr01_sc/binary.py", "tools/interop.py", "tests/native/test_endpoint.py", "tests/native/test_binary.py",
        "src/python/cr01_sc/channel.py", "src/python/cr01_sc/handshake.py")]
    paths += [ROOT / "tests/native/test_hardening.py", ROOT / "tests/native/cpp/hardening_tests.cpp"]
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    before = input_hashes()
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/native"), pattern="test_*.py", top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Results).run(suite)
    drift = [path for path, digest in input_hashes().items() if before.get(path) != digest]
    ready = result.wasSuccessful() and not result.skipped and result.testsRun > 0 and COMPILER.is_file() and not drift
    compiler_version = None
    if COMPILER.is_file():
        compiler_version = subprocess.run([str(COMPILER), "--version"], capture_output=True, text=True,
                                          timeout=10, env=native_environment()).stdout.splitlines()[0]
    report = {"schema": "CR01-NATIVE-V2-INTEROP-v1", "status": "pass" if ready else "fail",
              "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
              "environment": {"system": platform.system(), "python": platform.python_version(),
                              "compiler": compiler_version, "native_openssl": sorted(NativePeer.backend_versions)},
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
              "source_sha256": before, "source_drift": drift, "cases": result.cases,
              "claim_boundary": "Local full v2 handshake, record and fresh-process restart interoperability; not independent cryptanalysis, quantum-security proof, production approval or VM rollback detection."}
    (args.out / "interop.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.out / "unittest.log").write_text(stream.getvalue(), encoding="utf-8")
    print(f"Native v2 endpoint checks: {report['status']}; tests={result.testsRun}; failures={len(result.failures)}; errors={len(result.errors)}; skipped={len(result.skipped)}")
    if not ready:
        print(stream.getvalue())
        raise SystemExit(1)


if __name__ == "__main__":
    main()
