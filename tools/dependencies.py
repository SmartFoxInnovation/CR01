"""Generate exact local third-party dependency/license output.

The output is intentionally evidence-oriented: it records exact installed
Python runtime packages, local MSYS2 native packages used by the C++ backend,
license expressions, installed license-file paths, and license-file hashes.

This is not legal advice and it does not replace review of the final artifact
being distributed. It gives reviewers a reproducible snapshot for this repo's
current technical-preview build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from importlib import metadata
from pathlib import Path

try:
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal Python installs.
    Requirement = None  # type: ignore[assignment]
    default_environment = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
MSYS_ROOT = Path(r"C:\msys64")
UCRT64 = MSYS_ROOT / "ucrt64"
PACMAN = MSYS_ROOT / "usr" / "bin" / "pacman.exe"
OPENSSL_EXE = UCRT64 / "bin" / "openssl.exe"
GXX_EXE = UCRT64 / "bin" / "g++.exe"

PYTHON_RUNTIME_ROOTS = ("cryptography",)
NATIVE_PACKAGES = (
    "mingw-w64-ucrt-x86_64-openssl",
    "mingw-w64-ucrt-x86_64-gcc",
    "mingw-w64-ucrt-x86_64-gcc-libs",
    "mingw-w64-ucrt-x86_64-libwinpthread",
)
NATIVE_LICENSE_DIRS = {
    "mingw-w64-ucrt-x86_64-openssl": UCRT64 / "share" / "licenses" / "openssl",
    "mingw-w64-ucrt-x86_64-gcc": UCRT64 / "share" / "licenses" / "gcc-libs",
    "mingw-w64-ucrt-x86_64-gcc-libs": UCRT64 / "share" / "licenses" / "gcc-libs",
    "mingw-w64-ucrt-x86_64-libwinpthread": UCRT64 / "share" / "licenses" / "libwinpthread",
}
RUNTIME_DLLS = (
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll",
)


@dataclass(frozen=True)
class LicenseFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class PythonPackageNotice:
    name: str
    version: str
    license_expression: str | None
    license_text: str | None
    license_classifiers: tuple[str, ...]
    requires_dist: tuple[str, ...]
    license_files: tuple[LicenseFile, ...]


@dataclass(frozen=True)
class NativePackageNotice:
    name: str
    version: str | None
    tool_version: str | None
    license_files: tuple[LicenseFile, ...]
    runtime_artifacts: tuple[str, ...]
    package_source: str
    package_sha256: str | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def license_file_record(path: Path) -> LicenseFile:
    return LicenseFile(path=str(path), sha256=sha256_file(path))


def installed_license_files(dist: metadata.Distribution) -> tuple[LicenseFile, ...]:
    files = dist.files or ()
    records: list[LicenseFile] = []
    for file in files:
        text = str(file).upper()
        if not any(marker in text for marker in ("LICENSE", "NOTICE", "COPYING", "AUTHORS")):
            continue
        try:
            located = Path(dist.locate_file(file))
        except FileNotFoundError:
            continue
        if located.is_file():
            records.append(license_file_record(located))
    return tuple(records)


def requirement_name(requirement: str) -> str | None:
    if Requirement is not None and default_environment is not None:
        parsed = Requirement(requirement)
        if parsed.marker is not None and not parsed.marker.evaluate(default_environment()):
            return None
        return parsed.name
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    return None if match is None else match.group(1)


def python_runtime_closure(roots: tuple[str, ...] = PYTHON_RUNTIME_ROOTS) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    queue = list(roots)
    while queue:
        name = queue.pop(0)
        normalized = name.lower().replace("_", "-")
        if normalized in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        seen.add(normalized)
        ordered.append(dist.metadata.get("Name", name))
        for requirement in dist.metadata.get_all("Requires-Dist") or ():
            child = requirement_name(requirement)
            if child is not None:
                queue.append(child)
    return tuple(ordered)


def collect_python_notices() -> tuple[PythonPackageNotice, ...]:
    notices: list[PythonPackageNotice] = []
    for name in python_runtime_closure():
        dist = metadata.distribution(name)
        meta = dist.metadata
        notices.append(
            PythonPackageNotice(
                name=meta.get("Name", name),
                version=dist.version,
                license_expression=meta.get("License-Expression"),
                license_text=meta.get("License"),
                license_classifiers=tuple(
                    classifier
                    for classifier in (meta.get_all("Classifier") or ())
                    if classifier.startswith("License")
                ),
                requires_dist=tuple(meta.get_all("Requires-Dist") or ()),
                license_files=installed_license_files(dist),
            )
        )
    return tuple(notices)


def run_command(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip()


def pacman_version(package: str) -> str | None:
    if not PACMAN.is_file():
        return None
    output = run_command([str(PACMAN), "-Q", package])
    if not output:
        return None
    parts = output.split()
    return parts[1] if len(parts) >= 2 else None


def collect_native_notices() -> tuple[NativePackageNotice, ...]:
    openssl_root = Path(os.environ.get("OPENSSL_ROOT", str(UCRT64))).resolve()
    openssl_exe = openssl_root / "bin" / ("openssl.exe" if os.name == "nt" else "openssl")
    openssl_version = run_command([str(openssl_exe), "version"]) if openssl_exe.is_file() else None
    gxx_version = None
    if GXX_EXE.is_file():
        output = run_command([str(GXX_EXE), "--version"])
        if output:
            gxx_version = output.splitlines()[0]

    notices: list[NativePackageNotice] = []
    for package in NATIVE_PACKAGES:
        isolated = package.endswith("openssl") and openssl_root != UCRT64.resolve()
        package_version = None if isolated else pacman_version(package)
        package_source = "custom prefix; package metadata unavailable" if isolated else "pacman local database"
        package_sha = None
        if isolated:
            metadata_file = openssl_root.parent / ".PKGINFO"
            if metadata_file.is_file():
                fields = dict(line.split(" = ", 1) for line in metadata_file.read_text(encoding="utf-8").splitlines()
                              if line.startswith(("pkgname = ", "pkgver = ")))
                if fields.get("pkgname") != package or not fields.get("pkgver"):
                    raise ValueError("OpenSSL package metadata does not identify the selected package")
                package_version = fields["pkgver"]
                if not openssl_version or f"OpenSSL {package_version.rsplit('-', 1)[0]} " not in openssl_version:
                    raise ValueError("OpenSSL package and runtime versions disagree")
                package_source = "extracted MSYS2 package (.PKGINFO)"
                receipt_file = metadata_file.with_name(".cr01-package.json")
                if receipt_file.is_file():
                    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
                    if (receipt.get("pkginfo_sha256") != sha256_file(metadata_file) or
                            receipt.get("package") != package or receipt.get("version") != package_version):
                        raise ValueError("OpenSSL acquisition receipt does not match package metadata")
                    package_sha = receipt.get("sha256")
                    package_source = receipt.get("url", package_source)
        license_root = openssl_root if package.endswith("openssl") else UCRT64
        license_dir = openssl_root / "share/licenses/openssl" if package.endswith("openssl") else NATIVE_LICENSE_DIRS[package]
        license_files = tuple(
            LicenseFile(path="ucrt64/" + path.relative_to(license_root).as_posix(), sha256=sha256_file(path))
            for path in sorted(license_dir.rglob("*"))
            if path.is_file()
        ) if license_dir.is_dir() else ()
        if package.endswith("openssl"):
            tool_version = openssl_version
            artifacts = tuple(name for name in RUNTIME_DLLS if name.startswith(("libcrypto", "libssl")))
        elif package.endswith("gcc"):
            tool_version = gxx_version
            artifacts = ()
        elif package.endswith("gcc-libs"):
            tool_version = gxx_version
            artifacts = tuple(name for name in RUNTIME_DLLS if name.startswith(("libgcc", "libstdc++")))
        else:
            tool_version = None
            artifacts = tuple(name for name in RUNTIME_DLLS if name.startswith("libwinpthread"))
        notices.append(
            NativePackageNotice(
                name=package,
                version=package_version,
                tool_version=tool_version,
                license_files=license_files,
                runtime_artifacts=artifacts,
                package_source=package_source,
                package_sha256=package_sha,
            )
        )
    return tuple(notices)


def render_markdown(result: dict[str, object]) -> str:
    lines = [
        "# Third-Party Dependency License Output",
        "",
        "## Summary",
        "",
    ]
    summary = result["summary"]
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")

    lines.extend(
        [
            "",
            "## Python Runtime Packages",
            "",
            "| Package | Version | License expression | License files |",
            "| --- | ---: | --- | ---: |",
        ]
    )
    for package in result["python_runtime_packages"]:
        lines.append(
            f"| {package['name']} | {package['version']} | "
            f"{package['license_expression'] or package['license_text'] or 'not declared'} | "
            f"{len(package['license_files'])} |"
        )

    lines.extend(["", "## Native Toolchain / Runtime Components", ""])
    lines.extend(
        [
            "| Package | Version | Tool version | Runtime artifacts | License files |",
            "| --- | ---: | --- | --- | ---: |",
        ]
    )
    for package in result["native_packages"]:
        artifacts = ", ".join(package["runtime_artifacts"]) if package["runtime_artifacts"] else "n/a"
        lines.append(
            f"| {package['name']} | {package['version']} | "
            f"{package['tool_version'] or 'n/a'} | {artifacts} | {len(package['license_files'])} |"
        )

    lines.extend(["", "## License File Hashes", ""])
    for section_name in ("python_runtime_packages", "native_packages"):
        lines.append(f"### {section_name}")
        for package in result[section_name]:
            lines.append(f"#### {package['name']} {package.get('version') or ''}".rstrip())
            if not package["license_files"]:
                lines.append("- No installed license files found by the generator.")
            for item in package["license_files"]:
                lines.append(f"- `{item['path']}` sha256 `{item['sha256']}`")
            lines.append("")

    lines.extend(
        [
            "## Boundary",
            "",
            "- This report is generated from the exact packages available in the local build environment.",
            "- The repository does not vendor these dependencies in source form.",
            "- If distributing wheels, containers, installers, or native binaries, preserve upstream license texts and notices for the exact artifacts shipped.",
            "- This report is not legal advice and does not create a FIPS/ACVP/CMVP validation claim.",
        ]
    )
    return "\n".join(lines)


def generate_third_party_license_report() -> dict[str, object]:
    python_notices = collect_python_notices()
    native_notices = collect_native_notices()
    return {
        "summary": {
            "python_executable": sys.executable,
            "python_runtime_package_count": len(python_notices),
            "native_package_count": len(native_notices),
            "generator": "tools/dependencies.py",
            "claim_boundary": "Dependency/license evidence only; not legal advice or compliance certification.",
        },
        "python_runtime_packages": [asdict(item) for item in python_notices],
        "native_packages": [asdict(item) for item in native_notices],
    }


def write_third_party_license_report(out_dir: Path) -> dict[str, object]:
    result = generate_third_party_license_report()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "third_party_licenses.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "third_party_licenses.md").write_text(render_markdown(result), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate exact local third-party dependency license output.")
    parser.add_argument("--out", type=Path, default=Path("reports") / "third_party_licenses")
    args = parser.parse_args()
    result = write_third_party_license_report(args.out)
    print(
        "Third-party license report complete: "
        f"python_packages={result['summary']['python_runtime_package_count']}; "
        f"native_packages={result['summary']['native_package_count']}; "
        f"out={args.out}"
    )


if __name__ == "__main__":
    main()
