# Native CR01-SC v2

This is the full v2 endpoint. It uses
OpenSSL for ML-KEM-768, ML-DSA-65 and AES-256-GCM. It requires an OpenSSL build
with those algorithms (the tested version is pinned in the lock files).

From the repository root on Windows, with MSYS2 UCRT64 installed:

```powershell
powershell -ExecutionPolicy Bypass -File tools/build_native.ps1
python tools/interop.py --out validation-output/native
```

This produces `bin/cr01sc.exe` and copies its runtime DLLs next to it.

On Linux, with a C++20 compiler and patched OpenSSL development files:

```bash
bash tools/build_native.sh
```

This produces `bin/cr01sc`. `make` invokes the same Linux script. Both scripts
probe required OpenSSL algorithms before compiling the endpoint. Neither installs
dependencies or changes protocol options. See [the guide](../../docs/GUIDE.md)
for custom toolchain locations, the Python adapter and identity handling.
Included performance measurements are Windows-only.

This folder contains the endpoint, strict flight/pipe parsers, record state and
authenticated plaintext ownership. `tests/native/cpp/` at the project root
contains C++ core and public-vector checks; Python interoperability tests live
in `tests/native/` at the project root.

`channel_v2_secret.hpp` owns bounded locked secret intermediates;
`channel_v2_identity.hpp` handles checked identity/pin files. Lock/permission
failures reject. Use `--memory-status` to exercise a small allocation probe;
provider-owned key memory is not covered. The guide describes required host
permissions and the unsupported live-snapshot/rollback boundary.

Research preview only. No production or side-channel assurance.
