# Repeat the checks

Run from the bundle root with the Python environment in [Guide](GUIDE.md).
Use a fresh output folder; keep the supplied results intact.

## Validate behavior

```powershell
python tools/validate.py --out validation-output --include-native
```

Five stages run: the current regression suite, eleven primitive/backend checks,
the eight public record fixtures through a separate code path, the native visual
demo (13 checks) and
the full native endpoint gate. The native gate rejects skipped tests.
The receipt records commands, counts, failures, platform and source hashes.

Without a configured native test toolchain, omit `--include-native` for four stages.
That portable path runs the Python reference handshake, not the native demo.
Native tests may skip in the general suite; that does not validate C++. Build
`bin/cr01sc.exe` on Windows or `bin/cr01sc` on Linux before full visual checks.
Windows tests use MSYS2 GCC; `OPENSSL_ROOT` selects a separate OpenSSL prefix.
Linux native tests require explicit `OPENSSL_ROOT` plus `CXX` (default `g++`).
Use the same prefix for build, tests and benchmarks; see the guide. The native
gate rejects skips. The general Linux suite may skip the Windows-only PowerShell
script check; that is separate from the native endpoint tests.

Individual checks:

```powershell
python tools/interop.py --out validation-output/native
python tools/vectors.py --verify reports/vectors.json --out validation-output/vectors.json
python -m cr01_sc.native_demo --out validation-output/demo.json
```

The vector verifier does not import CR01-SC, but uses the same Python crypto
backend.

## Measure performance

```powershell
python tools/benchmarks/tls.py --out validation-output/comparison --repeats 5
python tools/benchmarks/transport.py --out validation-output/transport --repeats 3
python tools/benchmarks/lifecycle.py --out validation-output/lifecycle --repeats 5
```

Benchmark folders must not already exist. TLS output includes raw samples and
`tls_aes.json`, a compact receipt retaining every run's summary. Transport output
is `transport_benchmark.json`. No slow runs are discarded. Setup, engine,
local-pipe and network costs are different; [Results](RESULTS.md) explains the
comparison boundaries.

Lifecycle output is `lifecycle.json`. It retains plain timing controls and a
separate instrumented profile for identity loading, first-use warm-up, 200 fresh
warm handshakes per run and established 1 KiB/1 MiB records. Real CLI process-pair
launch-to-ready and ready-to-handshake costs are measured separately. Two further
conditioning handshakes follow the first-use sample; record timing uses five
warm-ups per payload size. These stages are different workloads, not an additive
startup total. Fresh processes do not flush OS/file caches.

`--baseline path/to/extracted-source-root` runs the same diagnostic harness against
an untouched prior C++ source tree, alternating candidate/baseline order each run.
The receipt records both source sets. Profiling copies are generated under the
output folder; production sources contain no profiler. Inclusive profile times
nest and must not be added together. `--quick` is a smoke check only and is not
accepted as current lifecycle evidence by the demo.

## Build or verify an archive

After a code change, refresh the relevant canonical reports first. Rerun the
full gate into a fresh folder, then copy only its validation receipt:

```powershell
python tools/validate.py --out fresh-validation --include-native
Copy-Item fresh-validation/validation.json reports/validation.json
python tools/build_release.py --out dist
python tools/build_release.py --verify dist/0.15.2-cr01-sc-technical-preview.zip
```

Do not write step outputs over canonical reports during the gate: they are
hashed inputs. The builder rejects failed, incomplete or stale validation.
Benchmark execution is separate from packaging.

The ZIP's `VALIDATION_MANIFEST.json` lists every file's size and SHA-256;
the ZIP checksum is beside it. Identical inputs produce an identical archive
with the same Python/compression runtime. Different zlib implementations can
produce different ZIP bytes from identical contents; compare manifest hashes
when checking across platforms.
Checksums detect changes; they do not authenticate the author. Test a clean
extraction before sharing. Keep earlier candidates separately.

## Share a finding

Include the archive checksum, command, platform, expected/observed behavior and
a small synthetic reproduction. Send sensitive findings privately to the address
in [SECURITY.md](../SECURITY.md). Do not submit confidential material or material
you lack permission to share.

Use is governed by [LICENSE](../LICENSE).
