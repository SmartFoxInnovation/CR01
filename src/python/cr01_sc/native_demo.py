"""Native-only synthetic walkthrough. Python routes public flights, not crypto."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from ._paths import default_project_root
from .native import NativePeer, generate_native_identity, write_native_pin

UNAVAILABLE = "Native demo unavailable. See docs/GUIDE.md: tools/build_native.ps1 (Windows) or tools/build_native.sh (Linux)."


class NativeDemoUnavailable(RuntimeError):
    """A sanitized operational failure; never a successful negative probe."""


def engine_path(repo_root=None):
    root = Path(repo_root).resolve() if repo_root is not None else default_project_root()
    return root / "bin" / ("cr01sc.exe" if os.name == "nt" else "cr01sc")


def source_paths(root):
    paths = [path.relative_to(root).as_posix() for path in (root / "src/cpp").glob("*")
             if path.suffix in {".cpp", ".hpp"}]
    return paths + ["src/python/cr01_sc/native_demo.py", "src/python/cr01_sc/native.py",
                    "src/python/cr01_sc/binary.py", "src/python/cr01_sc/_paths.py",
                    "src/python/cr01_sc/__init__.py", "src/python/cr01_sc/reporting.py",
                    "tools/build_native.ps1", "tools/build_native.sh", "tools/check_openssl.cpp",
                    "config/native-packages.lock", "config/native-packages.lock.json"]


def run_native_demo(*, repo_root=None, executable=None, request_id=None):
    if request_id is not None and (type(request_id) is not int or not 0 <= request_id <= 2_147_483_647):
        raise ValueError("invalid validation request id")
    executable = Path(executable) if executable is not None else engine_path(repo_root)
    started = time.monotonic()
    # Cooperative budget between calls; not a supervisor for blocked OS pipe writes.
    def remaining(limit=3):
        value = min(limit, 30 - (time.monotonic() - started))
        if value <= 0:
            raise TimeoutError("native demo budget exhausted")
        return value

    def rejected(operation):
        try:
            operation()
        except ValueError as exc:
            # Local codec/argument errors must not masquerade as engine rejections.
            if str(exc) != "native request rejected":
                raise
            return True
        return False

    peers = []
    try:
        executable = executable.resolve(strict=True)
        if not executable.is_file() or not 0 < executable.stat().st_size <= 16 * 1024 * 1024:
            raise OSError("invalid engine")
        executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="cr01-native-demo-") as directory, ExitStack() as resources:
            work = Path(directory)
            public = {}
            for name in ("i", "r", "unknown"):
                public[name] = generate_native_identity(executable, work / (name + ".pem"), timeout=remaining(5))
                if len(public[name]) != 1952:
                    raise ValueError("unexpected identity size")
                write_native_pin(executable, work / (name + ".pub"), public[name], timeout=remaining(5))

            def peer(role, own=None):
                name, other = ("i", "r") if role == "initiator" else ("r", "i")
                name = own or name
                endpoint = NativePeer(executable, role, work / (name + ".pem"), work / (other + ".pub"),
                                      application=b"CR01-v2-native-demo", epoch=1, transport="binary",
                                      response_timeout=remaining())
                resources.callback(endpoint.close)
                peers.append(endpoint)
                if endpoint.ready.get("version") != 2 or endpoint.ready.get("public_key") != public[name].hex():
                    raise ValueError("unexpected native identity")
                return endpoint

            def call(endpoint, method, *args, **kwargs):
                endpoint.response_timeout = remaining()
                return getattr(endpoint, method)(*args, **kwargs)

            def complete(first, second):
                hello = call(first, "start")
                reply = call(second, "respond", hello)
                finish = call(first, "finish", reply)
                ack = call(second, "accept", finish)
                call(first, "confirm", ack)
                return hello, reply, finish, ack

            first, second = peer("initiator"), peer("responder")
            flights = complete(first, second)
            state_i, state_r = call(first, "command", "status"), call(second, "command", "status")
            established = state_i.get("phase") == state_r.get("phase") == "established"
            sid = state_i.get("session_id")
            matches = isinstance(sid, bytes) and len(sid) == 16 and sid == state_r.get("session_id")
            message = call(first, "send", b"native demo message", b"demo")
            payload_ok = call(second, "receive", message, expected_aad=b"demo") == b"native demo message"
            response = call(second, "send", b"native responder", b"reply")
            bidirectional = call(first, "receive", response, expected_aad=b"reply") == b"native responder"
            attacks = {
                "record_replay_rejected": rejected(lambda: call(second, "receive", message)),
                "record_reflection_rejected": rejected(lambda: call(first, "receive", message)),
            }
            unseen = call(first, "send", b"fresh tag probe")
            attacks["record_tamper_rejected"] = rejected(
                lambda: call(second, "receive", unseen[:-1] + bytes([unseen[-1] ^ 1])))
            payload_ok = payload_ok and call(second, "receive", unseen) == b"fresh tag probe"
            first.close()
            second.close()

            cold = peer("responder")
            attacks["old_record_after_restart_rejected"] = rejected(lambda: call(cold, "receive", message))
            cold.close()
            stale = peer("responder")
            call(stale, "respond", flights[0])
            attacks["old_finish_after_restart_rejected"] = rejected(lambda: call(stale, "accept", flights[2]))
            stale.close()
            new_i, new_r = peer("initiator"), peer("responder")
            complete(new_i, new_r)
            new_sid = call(new_r, "command", "status").get("session_id")
            attacks["cross_session_record_rejected"] = new_sid != sid and rejected(
                lambda: call(new_r, "receive", message))
            new_i.close()
            new_r.close()
            downgraded = json.loads(flights[0])
            downgraded["payload"]["version"] = 1
            encoded = json.dumps(downgraded, sort_keys=True, separators=(",", ":")).encode("ascii")
            bad_r = peer("responder")
            attacks["downgrade_rejected"] = rejected(lambda: call(bad_r, "respond", encoded))
            bad_r.close()
            unknown, pinned = peer("initiator", "unknown"), peer("responder")
            untrusted_hello = call(unknown, "start")
            attacks["untrusted_identity_rejected"] = rejected(lambda: call(pinned, "respond", untrusted_hello))
            if hashlib.sha256(executable.read_bytes()).hexdigest() != executable_hash:
                raise OSError("engine file changed during demo")
            flags = {"mutual_authentication": established, "key_confirmation": established,
                     "context_match": matches, "directional_keys": bidirectional and attacks["record_reflection_rejected"],
                     "payload_decrypts": payload_ok and bidirectional}
            return {
                "schema": "CR01-NATIVE-DEMO-v1",
                "summary": {"version": 2, "status": "ready" if all(flags.values()) and all(attacks.values()) else "failed",
                            **flags, "request_id": request_id, "key_mode": "fresh-native-os-keys",
                            "toy_core_used": False, "restart_policy": "fresh-full-handshake-no-resumption",
                            "all_attack_checks_pass": all(attacks.values())},
                "engine": {"implementation": "C++", "transport": "CRB1 binary via cr01_sc.native",
                           "executable_sha256": executable_hash, "openssl": sorted({p.ready["openssl"] for p in peers}),
                           "native_peer_processes": len(peers), "python_reference_used": False,
                           "boundary": "Executable hash identifies the local file; not author authentication or independent assurance."},
                "transcript": {
                    "identity_pins": {"initiator_sha256": hashlib.sha256(public["i"]).hexdigest(),
                                      "responder_sha256": hashlib.sha256(public["r"]).hexdigest()},
                    "flights": {name: {"bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()}
                                for name, frame in zip(("initiator_hello", "responder_hello", "initiator_finish", "responder_finished"), flights)},
                    "records": {"session_id": sid.hex() if isinstance(sid, bytes) else None,
                                "sent_bytes": len(message), "reply_bytes": len(response)}},
                "attacks": attacks,
                "trust_decisions": {"initiator_pin": {"trusted": established}, "responder_pin": {"trusted": established}},
            }
    except Exception:
        # No private paths, generated key contents, subprocess output or backend reasons.
        raise NativeDemoUnavailable(UNAVAILABLE) from None


def main():
    import argparse
    from .reporting import write_report
    parser = argparse.ArgumentParser(description="Run the C++ v2 demo through the Python binary wrapper.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=default_project_root())
    parser.add_argument("--request-id", type=int)
    args = parser.parse_args()
    try:
        report = run_native_demo(repo_root=args.repo_root, request_id=args.request_id)
    except NativeDemoUnavailable as exc:
        raise SystemExit(str(exc)) from None
    write_report(args.out, report, source_paths(args.repo_root.resolve()))
    passed = report["summary"]["status"] == "ready"
    print(f"Native C++ v2 demo: {'pass' if passed else 'fail'}; {sum(report['attacks'].values())}/8 probes")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
