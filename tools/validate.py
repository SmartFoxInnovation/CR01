"""Run the portable CR01-SC public validation suite and write a receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import platform
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_release import validation_input_hashes


def project_version(root: Path = ROOT) -> str:
    with (root / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def portable_command(arguments: list[str]) -> list[str]:
    return ["{python}" if item == sys.executable else item.replace("\\", "/") for item in arguments]


def validation_steps(out_dir: Path, include_native: bool = False) -> list[tuple[str, list[str]]]:
    steps = [
        ("unit_and_integration_tests",
         [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-q"]),
        ("primitive_checks",
         [sys.executable, "-m", "cr01_sc.primitives", "--out", str(out_dir / "primitives.json")]),
        ("public_record_vectors",
         [sys.executable, "tools/vectors.py", "--verify", "reports/vectors.json",
          "--out", str(out_dir / "vectors_checked.json")]),
        ("handshake_demo",
         [sys.executable, "-m", "cr01_sc.native_demo", "--out", str(out_dir / "demo.json"),
          "--request-id", "9700"] if include_native else
         [sys.executable, "-m", "cr01_sc.demo", "--out", str(out_dir / "reference_demo.json"),
          "--fixture-seed", "9700"]),
    ]
    if include_native:
        steps.append(("native_v2_endpoints",
                      [sys.executable, "tools/interop.py", "--out", str(out_dir / "native")]))
    return steps


def _output_tail(output: str, limit: int = 4000) -> str:
    cleaned = output.replace(str(ROOT), "{release-root}").replace(str(ROOT).replace("\\", "/"), "{release-root}")
    return cleaned[-limit:]


def run_validation(out_dir: Path, include_native: bool = False, *, progress: bool = False) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc).isoformat()
    source_hashes = validation_input_hashes()
    results: list[dict[str, Any]] = []
    for name, command in validation_steps(out_dir, include_native=include_native):
        if progress:
            print(f"Running {name}...", flush=True)
        started = time.perf_counter()
        try:
            completed = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, check=False, timeout=600)
        except subprocess.TimeoutExpired:
            completed = subprocess.CompletedProcess(command, 124, "Validation step exceeded its 600-second limit.")
        except OSError:
            completed = subprocess.CompletedProcess(command, 127, "Validation step could not be started.")
        results.append(
            {
                "name": name,
                "status": "pass" if completed.returncode == 0 else "fail",
                "exit_code": completed.returncode,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "command": portable_command(command),
                "output_tail": _output_tail(completed.stdout),
            }
        )
        (out_dir / f"{name}.log").write_text(_output_tail(completed.stdout, limit=1_000_000), encoding="utf-8")
        if progress:
            print(f"{name}: {results[-1]['status']}", flush=True)
        if completed.returncode != 0:
            break

    passed = sum(item["status"] == "pass" for item in results)
    current_hashes = validation_input_hashes()
    source_drift = sorted(path for path in source_hashes.keys() | current_hashes.keys()
                          if source_hashes.get(path) != current_hashes.get(path))
    receipt = {
        "schema": "CR01-SC-VALIDATION-v2",
        "product": "CR01-SC",
        "version": project_version(),
        "license": "PolyForm-Noncommercial-1.0.0",
        "status": "pass" if not source_drift and passed == len(results) and len(results) == len(validation_steps(out_dir, include_native)) else "fail",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "validation_input_sha256": source_hashes,
        "source_drift": source_drift,
        "summary": {
            "passed_steps": passed,
            "executed_steps": len(results),
            "expected_steps": len(validation_steps(out_dir, include_native)),
            "native_second_implementation_requested": include_native,
            "claim_boundary": "Portable engineering validation only; not formal proof, independent audit, FIPS validation, or production approval.",
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "unit_test_count": next((int(match.group(1)) for step in results
                                 if step["name"] == "unit_and_integration_tests"
                                 if (match := re.search(r"Ran (\d+) tests?", step["output_tail"]))), 0),
        "steps": results,
    }
    receipt_path = out_dir / "validation.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CR01-SC public validation suite.")
    parser.add_argument("--out", type=Path, default=Path("validation-output"))
    parser.add_argument(
        "--include-native",
        action="store_true",
        help="Build and run C++ checks (Windows MSYS2, or Linux CXX with explicit OPENSSL_ROOT).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    receipt = run_validation(args.out, include_native=args.include_native, progress=True)
    summary = receipt["summary"]
    print(
        f"CR01 public validation: {receipt['status']}; "
        f"steps={summary['passed_steps']}/{summary['expected_steps']}; "
        f"receipt={args.out / 'validation.json'}"
    )
    if receipt["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
