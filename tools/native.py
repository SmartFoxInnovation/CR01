"""Compile development/test endpoints. Runtime pipe API lives in cr01_sc.native."""
from pathlib import Path
import os
import shutil
import subprocess

from cr01_sc.native import native_environment

ROOT = Path(__file__).resolve().parents[1]
COMPILER = (Path(r"C:\msys64\ucrt64\bin\g++.exe") if os.name == "nt" else
            Path(shutil.which(os.environ.get("CXX", "g++")) or "/cr01-compiler-unavailable")
            if os.environ.get("OPENSSL_ROOT") else Path("/cr01-native-test-prefix-not-configured"))


def openssl_flags(*, tls=False):
    """One configured prefix for headers, link libraries and POSIX runtime lookup."""
    root = Path(os.environ.get("OPENSSL_ROOT", str(COMPILER.parent.parent))).resolve()
    library = root / "lib"
    if os.name != "nt" and not (library / "libcrypto.so").is_file() and (root / "lib64").is_dir():
        library = root / "lib64"
    if os.environ.get("OPENSSL_ROOT"):
        required = ("crypto", "ssl") if tls else ("crypto",)
        if not (root / "include/openssl/opensslv.h").is_file() or any(
                not any((library / f"lib{name}{suffix}").is_file()
                        for suffix in (".dll.a", ".so", ".a")) for name in required):
            raise ValueError("OPENSSL_ROOT has no required development headers/libraries")
    flags = ["-I", str(root / "include"), "-L", str(library)]
    if os.name != "nt":
        flags += ["-Xlinker", "-rpath", "-Xlinker", str(library)]
    return flags + (["-lssl"] if tls else []) + ["-lcrypto"]

def compile_native(output: Path, *, unit=False):
    if not COMPILER.is_file():
        raise RuntimeError("Native compiler/OpenSSL test environment unavailable")
    source = ROOT / ("tests/native/cpp/endpoint_tests.cpp" if unit else "src/cpp/main.cpp")
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [str(COMPILER), "-std=c++20", "-O3", "-DNDEBUG", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
               str(source), *openssl_flags(), "-o", str(output)]
    completed = subprocess.run(command, capture_output=True, text=True, env=native_environment(), timeout=120)
    if completed.returncode:
        raise RuntimeError("native compilation failed:\n" + completed.stdout + completed.stderr)
    return output
