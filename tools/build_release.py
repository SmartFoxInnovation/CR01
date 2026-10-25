"""Build and verify the deterministic CR01-SC public validation edition."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_TIMESTAMP = (2026, 10, 17, 0, 0, 0)
MANIFEST_NAME = "VALIDATION_MANIFEST.json"
LICENSE_ID = "PolyForm-Noncommercial-1.0.0"

TOP_LEVEL_FILES = {
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
    "requirements.lock",
    "requirements.txt",
}

DOCUMENTATION_FILES = {
    "docs/GUIDE.md",
    "docs/RESULTS.md",
    "docs/PROTOCOL.md",
    "docs/VALIDATION.md",
    "docs/HANDSHAKE.pdf",
}

GITHUB_FILES = {
    ".github/ISSUE_TEMPLATE/research-finding.yml",
    ".github/ISSUE_TEMPLATE/validation-failure.yml",
    ".github/pull_request_template.md",
    ".github/workflows/validation.yml",
}

TOOL_FILES = {
    "tools/__init__.py", "tools/build_release.py", "tools/validate.py",
    "tools/vectors.py", "tools/native.py",
    "tools/interop.py", "tools/locks.py", "tools/dependencies.py",
    "tools/benchmarks/__init__.py", "tools/benchmarks/transport.py",
    "tests/benchmarks/cpp/transport.cpp", "tools/benchmarks/tls.py",
    "tests/benchmarks/cpp/tls_main.cpp", "tests/benchmarks/cpp/tls_support.hpp",
    "tools/benchmarks/lifecycle.py", "tests/benchmarks/cpp/lifecycle.cpp",
    "tests/benchmarks/cpp/lifecycle_profile.hpp",
}

NATIVE_FILES = {
    "Makefile", "src/cpp/README.md", "tools/build_native.ps1", "tools/build_native.sh",
    "tools/check_openssl.cpp", "bin/README.md",
    "config/native-packages.lock", "config/native-packages.lock.json",
    "src/cpp/main.cpp", "src/cpp/crypto.hpp",
    "src/cpp/json.hpp", "src/cpp/channel_binary.hpp",
    "src/cpp/channel_v2_core.hpp", "src/cpp/channel_v2_gcm.hpp",
    "src/cpp/channel_v2_plaintext.hpp", "src/cpp/channel_v2_flight.hpp",
    "src/cpp/channel_v2_crypto.hpp", "src/cpp/channel_v2_endpoint.hpp",
    "src/cpp/channel_v2_secret.hpp", "src/cpp/channel_v2_identity.hpp",
    "tests/native/cpp/vector_tests.cpp", "tests/native/cpp/endpoint_tests.cpp",
}

VALIDATION_RECEIPT = "reports/validation.json"

REPORT_FILES = {
    "reports/README.md", "reports/vectors.json", "reports/primitives.json",
    "reports/demo.json", "reports/interop.json", VALIDATION_RECEIPT,
    "reports/benchmarks/tls_aes.json", "reports/benchmarks/transport.json",
    "reports/benchmarks/lifecycle.json",
}

TEXT_SUFFIXES = {
    "",
    ".cff",
    ".css",
    ".cpp",
    ".hpp",
    ".html",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".svg",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

FORBIDDEN_SUFFIXES = {".env", ".key", ".p12", ".pem", ".pfx", ".secret"}
LOCAL_PATH_PATTERN = re.compile(
    rb"(?i)(?:[A-Z]:\\" + b"Users" + rb"\\[^\\\r\n\t ]+|/" + b"home" + rb"/[^/\r\n\t ]+)"
)
PRIVATE_KEY_PATTERN = re.compile(
    rb"(?m)^-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?$"
)


class ReleaseError(RuntimeError):
    """Raised when a validation artifact violates the release contract."""


def project_version(root: Path = ROOT) -> str:
    with (root / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _relative_files(directory: Path, root: Path) -> Iterable[str]:
    if _is_reparse_point(directory):
        raise ReleaseError("release source directory must not be a link/reparse point")
    for path in sorted(directory.rglob("*")):
        if "__pycache__" in path.parts or path.suffix.lower() in {".pyc", ".pyo"}:
            continue
        if _is_reparse_point(path):
            raise ReleaseError("release source tree contains a link/reparse point")
        if path.is_file():
            yield path.relative_to(root).as_posix()


def collect_release_paths(root: Path = ROOT) -> list[str]:
    paths = set(
        TOP_LEVEL_FILES
        | DOCUMENTATION_FILES
        | GITHUB_FILES
        | TOOL_FILES
        | NATIVE_FILES
        | REPORT_FILES
    )

    for directory_name in ("src/python/cr01_sc", "tests"):
        directory = root / directory_name
        if not directory.is_dir():
            raise ReleaseError(f"required directory missing: {directory_name}")
        paths.update(_relative_files(directory, root))

    missing = [relative for relative in sorted(paths) if not (root / relative).is_file()]
    if missing:
        raise ReleaseError(f"required validation files missing: {', '.join(missing)}")
    return sorted(paths)


def validation_input_hashes(root: Path = ROOT) -> dict[str, str]:
    """Bind source, reader documents, tests and fixed reports, not the receipt."""
    paths = TOOL_FILES | NATIVE_FILES | DOCUMENTATION_FILES | {
        "README.md", "SECURITY.md",
        "pyproject.toml", "requirements.txt", "requirements.lock", "LICENSE", "NOTICE",
    } | {path for path in REPORT_FILES if path.endswith(".json") and path != VALIDATION_RECEIPT}
    for directory_name in ("src/python/cr01_sc", "tests"):
        paths = paths | set(_relative_files(root / directory_name, root))
    return {path: hashlib.sha256(inspect_source_file(root / path, path)).hexdigest()
            for path in sorted(paths)}


def validate_receipt(receipt: dict[str, Any], expected: dict[str, str]) -> None:
    """Reject failed, incomplete or source-stale evidence before a CLI build."""
    if receipt.get("schema") != "CR01-SC-VALIDATION-v2" or receipt.get("status") != "pass":
        raise ReleaseError("a passing public validation receipt is required")
    steps = receipt.get("steps", [])
    required = {"unit_and_integration_tests", "primitive_checks", "public_record_vectors", "handshake_demo"}
    names = [step.get("name") for step in steps]
    if not required.issubset(names) or len(names) != len(set(names)) or any(
        step.get("status") != "pass" or step.get("exit_code") != 0 for step in steps
    ):
        raise ReleaseError("validation receipt has missing, duplicate or failing steps")
    summary = receipt.get("summary", {})
    expected_steps = 5 if summary.get("native_second_implementation_requested") else 4
    if (len(steps) != expected_steps or any(summary.get(key) != expected_steps for key in
            ("passed_steps", "executed_steps", "expected_steps")) or
            (expected_steps == 5 and "native_v2_endpoints" not in names)):
        raise ReleaseError("validation receipt summary is inconsistent")
    if receipt.get("validation_input_sha256") != expected or receipt.get("source_drift") != []:
        raise ReleaseError("validation evidence is stale; rerun public validation for these source bytes")


def inspect_source_file(path: Path, relative: str) -> bytes:
    _safe_member_name(relative)
    for parent in list(path.parents)[:len(PurePosixPath(relative).parts) - 1]:
        if _is_reparse_point(parent):
            raise ReleaseError("release source parent must not be a link/reparse point")
    if _is_reparse_point(path):
        raise ReleaseError(f"links/reparse points are not allowed: {relative}")
    suffix = path.suffix.lower()
    if suffix in FORBIDDEN_SUFFIXES or path.name.lower() in {".env", "id_rsa", "id_ed25519"}:
        raise ReleaseError(f"private-material filename is not publishable: {relative}")
    data = path.read_bytes()
    if len(data) > 10 * 1024 * 1024:
        raise ReleaseError(f"validation file exceeds 10 MiB limit: {relative}")
    if suffix in TEXT_SUFFIXES:
        if LOCAL_PATH_PATTERN.search(data):
            raise ReleaseError(f"workstation-local user path found: {relative}")
        if PRIVATE_KEY_PATTERN.search(data):
            raise ReleaseError(f"private key material found: {relative}")
    return data


def build_manifest(root: Path, relative_paths: list[str]) -> tuple[dict[str, Any], dict[str, bytes]]:
    files: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    for relative in relative_paths:
        data = inspect_source_file(root / relative, relative)
        payloads[relative] = data
        files.append(
            {
                "path": relative,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    version = project_version(root)
    manifest = {
        "schema": "CR01-GITHUB-VALIDATION-RELEASE-v2",
        "product": "CR01-SC",
        "edition": "github-noncommercial-validation",
        "version": version,
        "license": {
            "spdx": LICENSE_ID,
            "commercial_use": False,
            "notice": "Source-available under PolyForm Noncommercial 1.0.0; not OSI open source.",
        },
        "security_status": {"production_ready": False, "quantum_security_proven": False},
        "purpose": "Independent noncommercial study, reproduction, benchmarking, interoperability testing, confirmation, and falsification.",
        "file_count": len(files),
        "total_bytes": sum(item["bytes"] for item in files),
        "files": files,
    }
    return manifest, payloads


def _zip_entry(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, ARCHIVE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info, data


def build_release(out_dir: Path, root: Path = ROOT) -> tuple[Path, Path, dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    version = project_version(root)
    release_root = f"{version}-cr01-sc-technical-preview"
    archive = out_dir / f"{release_root}.zip"
    checksum_path = out_dir / f"{archive.name}.sha256"
    manifest, payloads = build_manifest(root, collect_release_paths(root))
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for relative in sorted(payloads):
            info, data = _zip_entry(f"{release_root}/{relative}", payloads[relative])
            bundle.writestr(info, data)
        info, data = _zip_entry(f"{release_root}/{MANIFEST_NAME}", manifest_bytes)
        bundle.writestr(info, data)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    verify_release(archive)
    return archive, checksum_path, manifest


def _safe_member_name(name: str) -> PurePosixPath:
    parsed = PurePosixPath(name)
    if (not isinstance(name, str) or "\\" in name or ":" in name or parsed.as_posix() != name
            or parsed.is_absolute() or ".." in parsed.parts or not parsed.parts):
        raise ReleaseError(f"unsafe archive member: {name}")
    return parsed


def verify_release(archive: Path) -> dict[str, Any]:
    if not archive.is_file():
        raise ReleaseError(f"archive not found: {archive}")
    with zipfile.ZipFile(archive, "r") as bundle:
        names = bundle.namelist()
        if len(names) != len({name.casefold() for name in names}):
            raise ReleaseError("archive contains duplicate members")
        if sum(info.file_size for info in bundle.infolist()) > 16 * 1024 * 1024:
            raise ReleaseError("archive uncompressed size exceeds limit")
        for info in bundle.infolist():
            if info.file_size > 10 * 1024 * 1024 or stat.S_ISLNK(info.external_attr >> 16):
                raise ReleaseError("archive contains oversized file or symlink")
        parsed_names = [_safe_member_name(name) for name in names]
        roots = {path.parts[0] for path in parsed_names}
        if len(roots) != 1:
            raise ReleaseError("archive must contain exactly one release root")
        release_root = next(iter(roots))
        manifest_member = f"{release_root}/{MANIFEST_NAME}"
        if manifest_member not in names:
            raise ReleaseError("validation manifest missing from archive")
        manifest = json.loads(bundle.read(manifest_member).decode("utf-8"))
        if manifest.get("schema") not in {"CR01-GITHUB-VALIDATION-RELEASE-v1", "CR01-GITHUB-VALIDATION-RELEASE-v2"}:
            raise ReleaseError("unexpected validation manifest schema")
        if manifest.get("license", {}).get("spdx") != LICENSE_ID:
            raise ReleaseError("validation manifest license mismatch")
        if manifest.get("license", {}).get("commercial_use") is not False:
            raise ReleaseError("validation artifact must deny commercial use")
        if manifest["schema"].endswith("v2") and manifest.get("security_status", {}).get("production_ready") is not False:
            raise ReleaseError("validation artifact must state its non-production security posture")

        expected = {manifest_member}
        for entry in manifest.get("files", []):
            relative = str(entry["path"])
            _safe_member_name(relative)
            member = f"{release_root}/{relative}"
            if member in expected:
                raise ReleaseError("manifest contains duplicate entries")
            expected.add(member)
            if member not in names:
                raise ReleaseError(f"manifest file missing from archive: {relative}")
            data = bundle.read(member)
            if len(data) != int(entry["bytes"]):
                raise ReleaseError(f"size mismatch: {relative}")
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ReleaseError(f"hash mismatch: {relative}")
            if Path(relative).suffix.lower() in FORBIDDEN_SUFFIXES:
                raise ReleaseError(f"private-material filename in archive: {relative}")
            if LOCAL_PATH_PATTERN.search(data) or PRIVATE_KEY_PATTERN.search(data):
                raise ReleaseError(f"private/local material in archive: {relative}")
        if set(names) != expected:
            extras = sorted(set(names) - expected)
            missing = sorted(expected - set(names))
            raise ReleaseError(f"archive inventory mismatch; extras={extras}; missing={missing}")
        if manifest.get("file_count") != len(manifest["files"]) or manifest.get("total_bytes") != sum(entry["bytes"] for entry in manifest["files"]):
            raise ReleaseError("manifest totals mismatch")
        return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify the CR01-SC GitHub noncommercial validation edition.")
    parser.add_argument("--out", type=Path, default=Path("dist"), help="Output directory for a new release.")
    parser.add_argument("--verify", type=Path, help="Verify an existing validation ZIP instead of building.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.verify:
            manifest = verify_release(args.verify)
            print(
                f"Validation artifact verified: {args.verify}; "
                f"version={manifest['version']}; files={manifest['file_count']}; license={LICENSE_ID}"
            )
            return
        receipt = json.loads((ROOT / VALIDATION_RECEIPT).read_text(encoding="utf-8"))
        validate_receipt(receipt, validation_input_hashes())
        archive, checksum, manifest = build_release(args.out)
        print(
            f"Validation artifact built: {archive}; files={manifest['file_count']}; "
            f"bytes={manifest['total_bytes']}; checksum={checksum}"
        )
    except (OSError, ValueError, zipfile.BadZipFile, ReleaseError) as exc:
        raise SystemExit(f"validation release failed: {exc}") from exc


if __name__ == "__main__":
    main()
