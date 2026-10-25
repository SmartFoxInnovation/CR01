# Evidence files

[Results](../docs/RESULTS.md) summarizes these machine-readable test results,
measurement samples and source hashes.

| File | Contents |
| --- | --- |
| `validation.json` | Validation commands, counts, platform and input hashes |
| `primitives.json` | Eleven Python primitive/backend checks |
| `demo.json` | Native handshake, records and eight rejection probes |
| `interop.json` | Python/C++ endpoint and binary/JSON transport tests |
| `vectors.json` | Eight public record fixtures with synthetic keys |
| `benchmarks/tls_aes.json` | Same-machine TLS 1.3 and AES-GCM comparison |
| `benchmarks/transport.json` | Binary and JSON pipe costs |
| `benchmarks/lifecycle.json` | Startup, warm-up, handshake and session timings, with diagnostic profiles |

Each measurement report includes its platform, date, source hashes and run data.
Public fixture keys are for testing only; do not use them for traffic. Record
vectors cover encoding and authentication, not the complete handshake.
