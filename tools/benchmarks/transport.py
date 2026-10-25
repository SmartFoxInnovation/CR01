"""Bounded matched JSON/binary app timings, with separate in-process baselines."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric import mldsa
from cr01_sc.handshake import HandshakeEndpoint
from tools.native import COMPILER, compile_native, openssl_flags
from cr01_sc.native import NativePeer, complete, generate_native_identity, native_environment, write_native_pin
from tools.interop import input_hashes

APP = b"bounded-v2-benchmark"
AAD = b"v2-bench"
SIZES = ((64, 10000), (1024, 10000), (65536, 1000), (1048576, 100))
PIPE_SIZES = ((64, 500), (1024, 500), (65536, 100), (1048576, 20))


def stats(samples):
    ordered = sorted(samples)
    return {"samples": len(samples), "mean_ms": statistics.mean(samples),
            "p50_ms": ordered[(len(ordered)-1)//2], "p95_ms": ordered[math.ceil(len(ordered)*.95)-1]}


def elapsed(start):
    return (time.perf_counter_ns() - start) / 1e6


def measure_records(initiator, responder, sizes):
    results = []
    for size, count in sizes:
        data = b"Z" * size
        for _ in range(5):
            if responder.receive(initiator.send(data, AAD), expected_aad=AAD) != data:
                raise AssertionError("warmup roundtrip failed")
        samples = []
        for index in range(count):
            sender, receiver = (initiator, responder) if index % 2 == 0 else (responder, initiator)
            start = time.perf_counter_ns()
            frame = sender.send(data, AAD)
            plaintext = receiver.receive(frame, expected_aad=AAD)
            samples.append(elapsed(start))
            if plaintext != data: raise AssertionError("measured roundtrip failed")
        results.append({"payload_bytes": size, "encoded_bytes": len(frame), **stats(samples)})
    return results


def python_worker():
    a, b = mldsa.MLDSA65PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
    def pair():
        return (HandshakeEndpoint("initiator", a, b.public_key().public_bytes_raw(), application=APP, epoch=1),
                HandshakeEndpoint("responder", b, a.public_key().public_bytes_raw(), application=APP, epoch=1))
    samples, keygen = [], []
    for _ in range(10):
        start = time.perf_counter_ns(); mldsa.MLDSA65PrivateKey.generate(); keygen.append(elapsed(start))
    for index in range(-3, 30):
        start = time.perf_counter_ns(); i, r = pair(); flights = complete(i, r); duration = elapsed(start)
        if i.channel.session_id != r.channel.session_id: raise AssertionError("session mismatch")
        if index >= 0: samples.append(duration)
        i.close(); r.close()
    i, r = pair(); complete(i, r)
    try: records = measure_records(i.channel, r.channel, SIZES)
    finally: i.close(); r.close()
    return {"kind": "python-in-process", "identity_keygen": stats(keygen),
            "handshake": {**stats(samples), "wire_bytes": sum(map(len, flights))}, "records": records}


def app_worker(executable, transport):
    with tempfile.TemporaryDirectory(prefix="cr01-transport-bench-") as folder:
        work = Path(folder)
        for own in ("i", "r"):
            public = generate_native_identity(executable, work / (own + ".pem"))
            write_native_pin(executable,work/(own+".pub"),public)
        def pair():
            i = NativePeer(executable, "initiator", work / "i.pem", work / "r.pub", application=APP, transport=transport)
            try:
                r = NativePeer(executable, "responder", work / "r.pem", work / "i.pub", application=APP, transport=transport)
            except Exception:
                i.close(); raise
            return i, r
        samples = []
        for index in range(-1, 10):
            i, r = pair()
            try:
                start = time.perf_counter_ns(); flights = complete(i, r); duration = elapsed(start)
                if i.session_id != r.session_id: raise AssertionError("app session mismatch")
                if index >= 0: samples.append(duration)
            finally: i.close(); r.close()
        i, r = pair()
        try:
            complete(i, r)
            records = measure_records(i, r, PIPE_SIZES)
        finally: i.close(); r.close()
        return {"kind": "native-" + transport + "-pipes", "handshake": {**stats(samples),
                "wire_bytes": sum(map(len, flights))}, "records": records, "openssl": i.ready["openssl"]}


def benchmark_inputs():
    hashes = input_hashes()
    for name in ("tools/benchmarks/transport.py", "tests/benchmarks/cpp/transport.cpp", "pyproject.toml"):
        hashes[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return hashes


def comparison(runs):
    rows = []
    for size, _ in PIPE_SIZES:
        means = {kind: statistics.median(next(row["mean_ms"] for row in run["records"] if row["payload_bytes"] == size)
                    for run in runs if run["kind"] == kind)
                 for kind in ("native-json-pipes", "native-binary-pipes")}
        binary_ms = means["native-binary-pipes"]
        rows.append({"payload_bytes": size, "json_ms": means["native-json-pipes"], "binary_ms": binary_ms,
                     "json_over_binary_elapsed_ratio": means["native-json-pipes"] / binary_ms,
                     "binary_payload_mib_per_second": size / 1048576 * 1000 / binary_ms})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--repeats", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--worker", choices=("python", "json", "binary"))
    parser.add_argument("--executable", type=Path)
    args = parser.parse_args()
    if args.worker:
        row = python_worker() if args.worker == "python" else app_worker(args.executable, args.worker)
        print(json.dumps(row)); return
    if args.out is None: parser.error("--out required")
    args.out.mkdir(parents=True, exist_ok=False)
    before = benchmark_inputs(); started = datetime.now(timezone.utc).isoformat()
    runs = []
    with tempfile.TemporaryDirectory(prefix="cr01-transport-build-") as folder:
        build = Path(folder)
        app = compile_native(build / "channel.exe")
        native = build / "benchmark.exe"
        command = [str(COMPILER), "-std=c++20", "-O3", "-DNDEBUG", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                   "-I", str(ROOT / "src/cpp"),
                   str(ROOT / "tests/benchmarks/cpp/transport.cpp"),
                   *openssl_flags(), "-o", str(native)]
        compiled = subprocess.run(command, env=native_environment(), capture_output=True, text=True, timeout=120)
        (args.out / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
        if compiled.returncode: raise RuntimeError(compiled.stdout + compiled.stderr)
        executable_hash = hashlib.sha256(app.read_bytes()).hexdigest()
        # Alternate transport order across repeats to expose, not conceal, order effects.
        for repeat in range(args.repeats):
            order = ["native", "python", *( ("json", "binary") if repeat % 2 == 0 else ("binary", "json") )]
            for kind in order:
                print(f"Fresh-process run {repeat+1}/{args.repeats}: {kind}", flush=True)
                cmd = [str(native)] if kind == "native" else [sys.executable, str(Path(__file__).resolve()),
                        "--worker", kind, "--executable", str(app)]
                completed = subprocess.run(cmd, env=native_environment(), capture_output=True, text=True, timeout=180)
                (args.out / f"run-{repeat+1}-{kind}.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
                if completed.returncode: raise RuntimeError("benchmark worker failed: " + completed.stderr)
                row = json.loads(completed.stdout); row["repeat"] = repeat + 1; runs.append(row)
                (args.out / "partial.json").write_text(json.dumps(runs, indent=2) + "\n", encoding="utf-8")
    drift = [name for name, value in benchmark_inputs().items() if before.get(name) != value]
    compiler = subprocess.run([str(COMPILER), "--version"], env=native_environment(), capture_output=True,
                              text=True, timeout=10).stdout.splitlines()[0]
    receipt = {"schema": "CR01-V2-TRANSPORT-BENCH-v1", "status": "pass" if not drift else "fail",
               "product_version": tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"],
               "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
               "environment": {"system": platform.platform(), "processor": platform.processor(),
                               "python": platform.python_version(), "cryptography": cryptography.__version__,
                               "python_openssl": backend.openssl_version_text(), "compiler": compiler,
                               "native_openssl": sorted({run["openssl"] for run in runs if "openssl" in run})},
               "source_sha256": before, "source_drift": drift, "app_executable_sha256": executable_hash,
               "repeats": args.repeats, "runs": runs, "comparison": comparison(runs),
               "aggregation": "Median of per-run means, not pooled latency percentiles; individual run p50/p95 retained.",
               "claim_boundary": "Local synthetic single-thread Windows timing; no CPU isolation, fixed-clock/thermal/idle gate, network, server-capacity, constant-time or TLS/security-equivalence claim. One record operation is seal plus authenticated receive; Python orchestration and copies included in app timings. Identity provisioning/process startup excluded from handshakes. Different OpenSSL backends for Python/native; not a pure language comparison. All payloads checked; no private keys retained."}
    (args.out / "transport_benchmark.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt["comparison"], indent=2), flush=True)
    if drift: raise SystemExit("source changed during benchmark")


if __name__ == "__main__": main()
