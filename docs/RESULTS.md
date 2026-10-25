# Results

CR01-SC 0.15.2 is a v2 research preview. Passing these checks does not establish
production suitability or quantum resistance.

## Validation

| Check | Result |
| --- | --- |
| Windows regression suite | 160 tests passed; no skips |
| Linux aarch64 regression suite | 160 tests; Windows PowerShell test skipped |
| Validation stages | 5 passed on each platform |
| Native endpoint tests | 60 passed on each platform; no skips |
| Native visual demo | 13 checks passed |
| Public record vectors | 8 matched Python and C++ |
| Python primitive/backend checks | 11 passed |

The [validation receipt](../reports/validation.json) lists commands, counts and
source hashes. The [native receipt](../reports/interop.json) covers Python/C++
handshakes in both roles, binary/JSON transports, fresh-process restarts, replay,
tampering, expiry, parser limits and maximum-size records.

Memory and identity tests cover protected allocation failures, cleansing, KDF
slots, identity permissions and synthetic RNG/backend failures. A Linux
ASan/UBSan hardening harness passed. OpenSSL was not sanitizer-built, leak
checking was disabled, and intercepted memory locks are not OS-locking evidence.

Test vectors use deliberately public keys. They cover record encoding and
authentication, not the complete handshake. Test counts overlap and are not
security ratings or certification.

## Record and handshake performance

Measured on 2026-10-25: Intel i7-8700K, Windows, GCC 15.2.0, OpenSSL 3.6.5.
Figures are medians of five run means from the
[TLS/AES comparison](../reports/benchmarks/tls_aes.json).

| Profile | Engine handshake (ms) | Engine 1 KiB (µs) | Engine 1 MiB (ms) | App 1 MiB (ms) |
| --- | ---: | ---: | ---: | ---: |
| CR01 v2 | 5.848 | 3.158 | 0.724 | 3.070 |
| TLS 1.3, classical | 1.274 | 3.871 | 1.775 | 4.203 |
| TLS 1.3, hybrid | 1.761 | 3.362 | 1.910 | 4.206 |
| TLS 1.3, hybrid + ML-DSA | 5.188 | 3.433 | 1.877 | 4.294 |
| Preallocated AES-GCM | No handshake | 0.919 | 0.585 | Not measured |

One record operation includes seal, authenticated receive, payload checking and
cleanup. Engine timing is in-process; app timing includes local pipes.
Handshake timing excludes process launch, credential provisioning and context
configuration, but includes endpoint creation and handshake-time secret allocations.

The CR01 handshake run means ranged from 5.293 to 6.728 ms; hybrid + ML-DSA ranged
from 5.078 to 5.657 ms. Their overlapping ranges do not establish a reliable ranking.

TLS verifies mutual certificate chains, exact leaf pins and the client hostname,
uses ordered streams and splits records at 16 KiB. Its hybrid profiles use
X25519MLKEM768; the ML-DSA profile also uses ML-DSA authentication. CR01 uses
exact public-key pins and larger independent records with a replay window.
AES-only uses provisioned keys without peer authentication or a session protocol.

The separate [transport comparison](../reports/benchmarks/transport.json) measured
6.448 ms for binary and 309.480 ms for JSON at 1 MiB, across three repeats.

These are local synthetic workloads with different trust, record and buffer/API
contracts. They are not network-capacity measurements. CPU isolation, fixed clocks
and thermal/idle controls were not used.

## Startup and session timings

The [lifecycle measurement](../reports/benchmarks/lifecycle.json) uses five runs.
Plain builds supply timings; instrumented builds supply profiles.

| Measurement | Median (ms) | Work measured |
| --- | ---: | --- |
| Cold start | 38.637 | Launch two CLI processes sequentially until both are ready |
| Identity load | 4.999 | Load both protected private files in the in-process harness |
| Warm-up | 8.568 | First disposable full handshake after identity loading, including endpoint creation and cleanup |
| Fresh warm handshake | 6.168 | New endpoints and fresh v2 material; 200 samples per run after three conditioning handshakes |
| First ready-process handshake | 14.486 | Full v2 through Python/binary pipes, excluding process launch |
| Running session, 1 KiB | 0.00253 | Established engine: seal, authenticated receive, payload check and cleanup |
| Running session, 1 MiB | 0.765 | Same operation, established engine |

The rows are separate workloads, not an additive startup total. OS/file caches
were not flushed. Warm-up is a disposable diagnostic session. The CLI endpoint
is single-use and requires a fresh full handshake after restart.

The TLS/AES comparison uses 30 handshakes per run; lifecycle measurement uses 200.
Their record-conditioning workloads also differ.

## Handshake profile

Median exclusive diagnostic time per warm handshake:

| Work | Time (ms) |
| --- | ---: |
| Protected allocation/lock and cleanse/release | 0.130 |
| Provider signing | 3.877 |
| Provider verification | 0.804 |
| Signing initialization | 0.015 |
| Verification initialization | 0.022 |

The handshake uses eight protected allocations. KDF intermediates occupy disjoint
slots in operation-owned locked memory, cleansed on success and failure.
Instrumented timings include profiling overhead; nested inclusive times cannot
be summed. Timing measurements do not establish constant-time behavior.

## Environment and limits

Windows checks used GCC 15.2.0. Linux aarch64 checks used GCC 13.3.0 and Python
3.12.3. Both native builds used OpenSSL 3.6.5. Python locks select cryptography
50.0.2, cffi 2.1.1 and pycparser 3.12; the checked Python wheel uses OpenSSL 4.0.3.

There is no independent cryptanalysis, formal composition proof, quantum-security
proof, side-channel assurance, process-wide secure-memory guarantee or production
approval. Tests do not validate physical entropy quality or arbitrary memory-read
resistance. Linux performance/browser behavior, macOS, GitHub CI, full-app/provider
sanitizers, real POSIX fork behavior, actual VM/process restores, network capacity
and the upstream OpenSSL test suite are not covered by these checks.

Live memory restoration remains unsupported. The restart policy is not a rollback
detector or automatic compromise recovery. Read [Protocol](PROTOCOL.md#limits)
for the full assumptions and security limits.
