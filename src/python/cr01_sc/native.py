"""Bounded native process driver for v2 demonstrations and regression tests.

Only public flights, records and synthetic test payloads pass through this driver.
No keys or counters are exported from the native endpoint.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import queue
import subprocess
import threading
from . import binary as binary_transport

_TOOLCHAIN_BIN = Path(r"C:\msys64\ucrt64\bin")
MAX_LINE = 2 * (8 * 1024 * 1024 + 64 * 1024 + 128) + 128


def native_environment():
    env = dict(os.environ)
    if os.name == "nt":
        bins = [str(_TOOLCHAIN_BIN)]
        prefix = env.get("OPENSSL_ROOT")
        if prefix:
            selected = Path(prefix) / "bin"
            if not (selected / "libcrypto-3-x64.dll").is_file():
                raise ValueError("OPENSSL_ROOT has no Windows libcrypto runtime")
            bins.insert(0, str(selected))
        env["PATH"] = os.pathsep.join(bins + [env.get("PATH", "")])
    return env


def _checked_timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 20:
        raise ValueError("native timeout must be positive and at most 20 seconds")
    return value


def generate_native_identity(executable: Path, path: Path, *, timeout=20):
    timeout = _checked_timeout(timeout)
    done = subprocess.run([str(executable), "--generate-identity", str(path)], capture_output=True,
                          text=True, env=native_environment(), timeout=timeout)
    if done.returncode:
        raise ValueError("native identity creation rejected")
    result = json.loads(done.stdout)
    return bytes.fromhex(result["public_key"])


def write_native_pin(executable: Path, path: Path, public: bytes, *, timeout=20):
    """Write an already authenticated public pin with restrictive file access."""
    timeout = _checked_timeout(timeout)
    if not isinstance(public, bytes) or len(public) != 1952:
        raise ValueError("native pin must contain 1952 public bytes")
    done = subprocess.run([str(executable), "--write-peer-pin", str(path), public.hex()],
                          capture_output=True, text=True, env=native_environment(), timeout=timeout)
    if done.returncode or json.loads(done.stdout) != {"status": "pin-written"}:
        raise ValueError("native pin creation rejected")


class NativePeer:
    backend_versions = set()
    def __init__(self, executable: Path, role: str, identity_path: Path, pin_path: Path,
                 *, application=b"native-v2-test", epoch=1, transport="json", response_timeout=20):
        if transport not in ("json", "binary"): raise ValueError("invalid transport")
        self.transport = transport
        self.response_timeout = _checked_timeout(response_timeout)
        self._command_lock = threading.Lock()
        options = {"text": True, "encoding": "ascii", "bufsize": 1} if transport == "json" else {"bufsize": 0}
        args = [str(executable), "--role", role, "--identity", str(identity_path),
            "--peer-public", str(pin_path), "--application", application.hex(), "--epoch", str(epoch)]
        if transport == "binary": args += ["--transport", "binary"]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=native_environment(), **options)
        self._responses = queue.Queue(maxsize=4)
        def read():
            try:
                while True:
                    if transport == "binary":
                        response = binary_transport.read_response(self.process.stdout)
                        if response is None: break
                    else:
                        line = self.process.stdout.readline(MAX_LINE + 1)
                        if not line: break
                        if len(line) > MAX_LINE: raise ValueError("native output exceeded limit")
                        response = json.loads(line)
                    self._responses.put(response, timeout=5)
            except (ValueError, OSError, queue.Full):
                pass
            finally:
                try:
                    self._responses.put(None, timeout=1)
                except queue.Full:
                    pass
        self._reader = threading.Thread(target=read, daemon=True)
        self._reader.start()
        try:
            self.ready = self._read()
            if self.ready.get("status") != "endpoint-ready":
                raise ValueError("native endpoint initialization rejected")
            self.backend_versions.add(self.ready["openssl"])
        except Exception:
            self.close()
            raise

    def _read(self):
        try:
            value = self._responses.get(timeout=self.response_timeout)
        except queue.Empty:
            self.close()
            raise RuntimeError("native response timed out") from None
        if value is None:
            self.close()
            raise RuntimeError("native endpoint exited without a response")
        return value

    def raw(self, line):
        with self._command_lock:
            if self.transport == "binary": binary_transport.write_all(self.process.stdin, (line,))
            else:
                self.process.stdin.write(line + "\n")
                self.process.stdin.flush()
            return self._read()

    def command(self, op, data=None, **fields):
        if self.transport == "binary":
            allowed = {"aad"} if op == "send" else {"expected_aad"} if op == "receive" else set()
            if set(fields) - allowed: raise ValueError("invalid command fields")
            auxiliary = fields.get("aad", fields.get("expected_aad", b""))
            if isinstance(auxiliary, str): auxiliary = bytes.fromhex(auxiliary)
            parts = binary_transport.request(op, b"" if data is None else data, auxiliary,
                                               expected_aad="expected_aad" in fields)
            with self._command_lock:
                binary_transport.write_all(self.process.stdin, parts)
                response = self._read()
            if response.get("status") != "ok": raise ValueError("native request rejected")
            if response.pop("_opcode", None) != binary_transport.OPERATIONS[op]:
                self.close()
                raise ValueError("binary response operation mismatch")
            return response
        request = {"op": op, **fields}
        if data is not None:
            request["data"] = data.hex()
        response = self.raw(json.dumps(request))
        if response.get("status") != "ok":
            raise ValueError("native request rejected")
        return response

    @staticmethod
    def _bytes(value): return value if isinstance(value, bytes) else bytes.fromhex(value)
    def start(self): return self._bytes(self.command("start")["data"])
    def respond(self, frame): return self._bytes(self.command("respond", frame)["data"])
    def finish(self, frame): return self._bytes(self.command("finish", frame)["data"])
    def accept(self, frame): return self._bytes(self.command("accept", frame)["data"])
    def confirm(self, frame): self.command("confirm", frame)
    @property
    def channel(self):
        state = self.command("status")
        if state["phase"] != "established":
            raise ValueError("completed handshake required")
        return self
    @property
    def session_id(self): return self._bytes(self.command("status")["session_id"])
    def send(self, data, aad=b""):
        return self._bytes(self.command("send", data, aad=aad if self.transport == "binary" else aad.hex())["data"])
    def receive(self, frame, *, expected_aad=None):
        fields = {} if expected_aad is None else {"expected_aad": expected_aad if self.transport == "binary" else expected_aad.hex()}
        return self._bytes(self.command("receive", frame, **fields)["data"])
    def stop(self): self.command("close")
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=10)
        for handle in (self.process.stdin, self.process.stdout, self.process.stderr):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
        self._reader.join(timeout=2)


def complete(initiator, responder):
    hello = initiator.start()
    reply = responder.respond(hello)
    finish = initiator.finish(reply)
    ack = responder.accept(finish)
    initiator.confirm(ack)
    return hello, reply, finish, ack
