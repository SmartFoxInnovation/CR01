"""Build entry points, early failures and packaged command references."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from tools.build_release import collect_release_paths, validation_input_hashes

ROOT = Path(__file__).resolve().parents[2]


def bash_path():
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (Path("C:/Program Files/Git/bin/bash.exe"), Path("C:/msys64/usr/bin/bash.exe")):
        if candidate.is_file():
            return str(candidate)
    raise unittest.SkipTest("Bash is required to check the Linux build script")


class BuildScriptTests(unittest.TestCase):
    def bash(self, *arguments):
        return subprocess.run([bash_path(), *arguments], capture_output=True, text=True,
                              cwd=ROOT, timeout=30)

    def test_both_scripts_and_probe_are_shipped_and_source_bound(self):
        inventory = collect_release_paths()
        hashes = validation_input_hashes()
        for name in ("tools/build_native.ps1", "tools/build_native.sh", "tools/check_openssl.cpp"):
            self.assertIn(name, inventory)
            self.assertEqual(hashes[name], hashlib.sha256((ROOT / name).read_bytes()).hexdigest())
        self.assertNotIn(b"\r", (ROOT / "tools/build_native.sh").read_bytes())

    def test_packaged_document_commands_do_not_reference_removed_helpers(self):
        inventory = set(collect_release_paths())
        for name in sorted(path for path in inventory if path.endswith(".md")):
            for target in re.findall(r"tools/[\w./-]+\.(?:py|ps1|sh)", (ROOT / name).read_text()):
                self.assertIn(target, inventory, (name, target))

    def test_linux_syntax_help_and_invalid_arguments(self):
        self.assertEqual(self.bash("-n", "tools/build_native.sh").returncode, 0)
        help_result = self.bash("tools/build_native.sh", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("OPENSSL_ROOT", help_result.stdout)
        invalid = self.bash("tools/build_native.sh", "--unknown")
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("Unknown argument", invalid.stderr)

    def test_missing_compiler_does_not_replace_existing_output(self):
        # Bash function only routes the early branch on Windows; not a Linux-build claim.
        with tempfile.TemporaryDirectory(prefix="cr01 build missing compiler ") as temporary:
            root = Path(temporary)
            (root / "tools").mkdir()
            (root / "bin").mkdir()
            engine = root / "bin/cr01sc"
            engine.write_bytes(b"existing-engine")
            script = root / "tools/build_native.sh"
            shutil.copyfile(ROOT / "tools/build_native.sh", script)
            result = self.bash("-c", 'uname() { printf "Linux\\n"; }; export -f uname; '
                               'CXX=cr01-compiler-not-installed bash "$1"', "test", script.as_posix())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("C++20 compiler missing", result.stderr)
            self.assertEqual(engine.read_bytes(), b"existing-engine")
            self.assertEqual(set(path.name for path in (root / "bin").iterdir()), {"cr01sc"})

    def test_missing_openssl_prefix_is_a_clear_failure(self):
        with tempfile.TemporaryDirectory(prefix="cr01 missing openssl ") as temporary:
            root = Path(temporary)
            result = self.bash("-c", 'uname() { printf "Linux\\n"; }; export -f uname; '
                               'CXX=bash OPENSSL_ROOT="$1" bash tools/build_native.sh', "test", root.as_posix())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("OPENSSL_ROOT must contain", result.stderr)

    def test_windows_script_syntax_help_and_missing_toolchain(self):
        if os.name != "nt":
            self.skipTest("PowerShell Windows build checks run on Windows")
        script = ROOT / "tools/build_native.ps1"
        # PowerShell's own parser checks every branch without executing it.
        parse = subprocess.run(["powershell", "-NoProfile", "-Command",
            "$tokens=$null;$errors=$null;"
            f"[void][Management.Automation.Language.Parser]::ParseFile('{script.as_posix()}',[ref]$tokens,[ref]$errors);"
            "if($errors.Count){$errors|ForEach-Object{$_.Message};exit 1}"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(parse.returncode, 0, parse.stdout + parse.stderr)
        help_result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                                     "-File", str(script), "-Help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("ToolchainRoot", help_result.stdout)
        with tempfile.TemporaryDirectory(prefix="cr01 missing toolchain ") as temporary:
            result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-ToolchainRoot", temporary], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("MSYS2 UCRT64 GCC is required", result.stderr)


if __name__ == "__main__":
    unittest.main()
