# Generated binaries

From the project root, choose the script for your platform:

```powershell
powershell -ExecutionPolicy Bypass -File tools/build_native.ps1
```

```bash
bash tools/build_native.sh
```

Windows produces `cr01sc.exe` and its runtime DLLs. Linux produces `cr01sc`,
linked to the installed OpenSSL library. Both scripts check required algorithms
before building. These are local build outputs, not included in the source ZIP.
See [build prerequisites](../docs/GUIDE.md#build-and-test-c). The Python wrapper is
`cr01_sc.native`; its example is in [the guide](../docs/GUIDE.md).
