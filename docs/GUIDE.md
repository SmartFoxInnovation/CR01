# Run CR01-SC

Use synthetic data. The preview is for evaluation, not real secrets.
Run commands from the extracted bundle's root folder. Build scripts are included
under `tools/`: `build_native.ps1` for Windows and `build_native.sh` for Linux.

## Native visual demo

Follow [README.md](../README.md) to create the virtual environment and install
the locked dependencies. For the shorter commands below, activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

On Linux, activate with `source .venv/bin/activate`. If Windows execution policy
prevents activation, replace `python` with `.\.venv\Scripts\python.exe`;
no policy change is needed. Linux can use `.venv/bin/python` directly.

The editable install in README makes `cr01_sc` available from `src/python/`.
`cr01_sc.native` wraps the C++ pipe interface; the Python protocol modules are
kept for reference tests and interoperability only. The visual live action
uses C++ for both peers and all protocol cryptography; it does not import
the Python protocol or primitive-check implementation. The wrapper does not
compile the engine or import development tools.

The browser console shows supplied evidence and runs bounded live checks.
It binds to localhost by default. Reports are recorded observations, not live
performance measurements. To run a fresh-key handshake without the browser:

```powershell
python -m cr01_sc.native_demo --out validation-output/demo.json --request-id 9700
```

If port 8765 is already in use, add `--port 8766 --open` when starting the console
and use `http://127.0.0.1:8766/`. Keep the server running while using the browser;
Ctrl+C stops it.

The request id is metadata, never a cryptographic seed. Live checks create fresh
native identities each time, send public flights over CRB1 local pipes, and show
the executable SHA-256 and native OpenSSL version. A file hash identifies the
local executable; it does not authenticate its author or prove its security.

The demo creates unencrypted private identity files in a temporary directory.
Peers are closed and the directory removed on normal completion and handled
failure. There is no secure-erasure or crash-cleanup guarantee. Use only synthetic
data and a suitably protected OS temporary directory. The cooperative 30-second
budget and response timeouts do not supervise every blocking OS pipe or cleanup
operation; the host remains responsible for process supervision.

For the Python reference test path, use
`python -m cr01_sc.demo --out validation-output/reference-demo.json`.
Its optional `--fixture-seed 9700` selects deliberately public test identities,
not repeatable session randomness. It is not the visual demo backend.

## Build and test C++

### Memory and identity prerequisites

The native engine requires locked allocations for its explicitly owned secret
buffers. Lock/protection failures stop the operation; it does not silently fall
back to ordinary memory. Linux needs a sufficient `RLIMIT_MEMLOCK` and permits
`mlock`, `madvise(MADV_DONTDUMP)` and process dump restrictions. Windows needs
`VirtualLock` capacity and a filesystem supporting ownership/DACL checks.
Do not solve a failed probe by running the demo as administrator or disabling the
checks. Use an appropriate host policy or leave that environment unsupported.

After building, inspect the bounded allocation probe:

```powershell
.\bin\cr01sc.exe --memory-status
```

Linux: `./bin/cr01sc --memory-status`. Success covers that probe, not all future
allocations or provider-owned key storage. Windows dump configuration remains
external. See [the exact memory scope](PROTOCOL.md#native-secret-memory).

Use `--generate-identity` in a protected directory. On Linux an existing private
identity must be owned by the process user, owner-readable, single-link and have
no group/other permissions (normally0600). On Windows its owner must be the current
user; broad allow ACLs reject. The native generator creates restrictive ACLs rather
than inheriting broad access. Do not loosen private-file permissions to make a
test pass. Public pin files may be readable by others but not writable by them.
HSM, encrypted-key/password integration and secure disk erasure are not provided.

Never resume live CR01 processes from VM snapshots or process checkpoints.
Use a trusted stop/discard/restart and a new full handshake. This is a restriction,
not a rollback detector. Read [the rollback policy](PROTOCOL.md#rollback-policy).

Both scripts require a C++20 compiler and patched OpenSSL development headers
and libraries providing ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF and SHA-256.
This preview uses OpenSSL 3.6.5. The build probe checks headers, the loaded runtime
and algorithm availability against snapshot floors: 3.5.9+, 3.6.5+ or 4.0.3+.
It is not an ongoing advisory scan or a guarantee that a version is safe.
Scripts install nothing and generate no identity keys. A failed prerequisite
check does not replace an existing engine.

### Windows

Install MSYS2 UCRT64 GCC and OpenSSL. The checked package versions are listed
in [native-packages.lock](../config/native-packages.lock). The default toolchain
is `C:\msys64\ucrt64`; use `-ToolchainRoot D:\msys64\ucrt64` for another location.

```powershell
powershell -ExecutionPolicy Bypass -File tools/build_native.ps1
python tools/interop.py --out validation-output/native-v2
```

This produces `bin/cr01sc.exe` plus four runtime DLLs. Run from another working
directory by supplying the script's full path; outputs still go to its own `bin/`.
The Windows interoperability runner builds its own test programs
and connects Python and native peers in both roles. Missing native tooling
fails this dedicated gate; it is not counted as a successful native test.
The test compiler uses MSYS2 at its default location. Set the OpenSSL prefix in
the current PowerShell session so app builds, tests and benchmarks agree:

```powershell
$env:OPENSSL_ROOT = "D:\OpenSSL\ucrt64"
powershell -ExecutionPolicy Bypass -File tools/build_native.ps1
python tools/interop.py --out validation-output/native-isolated
```

That prefix needs `bin/libcrypto-3-x64.dll`, `include/openssl` and `lib/`.
`-OpenSSLRoot` sets it for the build script only; the environment variable also
selects it for Python test/benchmark helpers. An invalid prefix fails explicitly.

### Linux

Install Bash, a C++20-capable `g++` and patched OpenSSL development files using your
system's normal package process. Many distributions ship older OpenSSL: installing
a package named `libssl-dev` alone does not establish the required version.

```bash
bash tools/build_native.sh
.venv/bin/python -m cr01_sc.native_demo --out validation-output/demo-linux.json
```

Output is `bin/cr01sc`; it dynamically links to the installed OpenSSL library.
For an OpenSSL installation outside the system paths:

```bash
export OPENSSL_ROOT=/opt/openssl
export CXX=g++
bash tools/build_native.sh
.venv/bin/python tools/interop.py --out validation-output/native-linux
```

The prefix must contain `include/openssl` and `lib/libcrypto.so` or
`lib64/libcrypto.so`. Static-only installations may need additional platform link
dependencies and were not checked. The selected library directory is embedded as a runtime search path;
keep that installation available and protected. `CXX` is one compiler executable,
not a command with flags. `make` delegates to this same script.
Use `--help` on Bash or `-Help` on PowerShell for usage. On Linux, an explicit
`OPENSSL_ROOT` enables the native test compiler and its runtime library path.
Without that test prefix, native tests may skip; that is not native validation.

## Connect two native peers

Generate a separate identity for each peer. These commands refuse to overwrite
an existing private file:

```powershell
$alice = .\bin\cr01sc.exe --generate-identity alice_private.pem | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $alice.status -ne 'identity-created') { throw 'Alice identity failed' }
.\bin\cr01sc.exe --write-peer-pin alice.pub $alice.public_key
if ($LASTEXITCODE -ne 0) { throw 'Alice pin failed' }
$bob = .\bin\cr01sc.exe --generate-identity bob_private.pem | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $bob.status -ne 'identity-created') { throw 'Bob identity failed' }
.\bin\cr01sc.exe --write-peer-pin bob.pub $bob.public_key
if ($LASTEXITCODE -ne 0) { throw 'Bob pin failed' }
```

The PEM files are unencrypted. Protect their directory and Windows ACLs; do not
commit or share them. Authenticate public pins out of band before use. This local
example is not a production provisioning procedure. Native private PEM files
are not claimed to be portable to the Python backend.
`--write-peer-pin FILE HEX` writes a new raw public pin with restrictive access;
it does not authenticate where those public bytes came from. Existing pin files
are never overwritten. On Linux the same commands use `./bin/cr01sc`; Python
can use `generate_native_identity` and `write_native_pin` from `cr01_sc.native`.

Save this as `two_peers.py` in the bundle root. It connects two native processes
over binary local pipes and checks that the decrypted message is correct:

```python
from pathlib import Path
import os
from cr01_sc.native import NativePeer, complete

exe = Path("bin") / ("cr01sc.exe" if os.name == "nt" else "cr01sc")
alice = NativePeer(exe, "initiator", Path("alice_private.pem"), Path("bob.pub"),
                   application=b"example", epoch=1, transport="binary")
try:
    bob = NativePeer(exe, "responder", Path("bob_private.pem"), Path("alice.pub"),
                     application=b"example", epoch=1, transport="binary")
    try:
        complete(alice, bob)
        record = alice.send(b"hello", b"request-1")
        assert bob.receive(record, expected_aad=b"request-1") == b"hello"
        print("Authenticated message received: hello")
    finally:
        bob.close()
finally:
    alice.close()
```

Run `python two_peers.py`. On success it prints
`Authenticated message received: hello` and closes both peers.

Use `transport="json"` for the text interface. Both adapters call the same
endpoint checks. Binary data requires binary-aware pipes, not a text-mode
PowerShell pipeline. Local pipes carry control messages and plaintext: protect
process access and do not log their contents.

Restart either process by provisioning its identity and pin again, then doing
a fresh handshake. Traffic keys, counters and old sessions cannot be restored.
For field layouts, limits and the command sequence, read [Protocol](PROTOCOL.md).
For complete checks and measurements, read [Validation](VALIDATION.md).
