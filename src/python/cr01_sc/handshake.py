"""Four-flight mutually pinned ML-KEM/ML-DSA research handshake.

No toy composite key; no session restore. Caller provisions a distinct ML-DSA
identity and exact peer public pin out-of-band. Messages are canonical bounded
JSON bytes, not shared private state. No TLS/HPKE interoperability or proof.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from functools import wraps

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .channel import _new_channel


DOMAIN = b"CR01-SC-HANDSHAKE-v2\x00"
SUITE = "ML-KEM-768/ML-DSA-65/HKDF-SHA256/AES-256-GCM"
MAX_FLIGHT = 32 * 1024
HANDSHAKE_SECONDS = 120


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(value).digest()


def packed(*values):
    return b"".join(len(value).to_bytes(4, "big") + value for value in values)


def derive(secret, transcript, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript,
                info=DOMAIN + label).derive(secret)


def hex_field(payload, name, size):
    value = payload[name]
    if not isinstance(value, str) or len(value) != 2 * size:
        raise ValueError("handshake rejected")
    result = bytes.fromhex(value)
    if result.hex() != value:
        raise ValueError("handshake rejected")
    return result


def step(phase):
    def decorate(method):
        @wraps(method)
        def call(self, *args, **kwargs):
            with self._lock:
                try:
                    self._check(phase)
                    return method(self, *args, **kwargs)
                except (ValueError, InvalidSignature, KeyError, TypeError, OverflowError, RecursionError):
                    self.close()
                    raise ValueError("handshake rejected") from None
        return call
    return decorate


class HandshakeEndpoint:
    """Single-use, per-peer endpoint. A new endpoint means a fresh handshake.

    Pin/epoch updates are caller policy, not an automatic PKI. No shared root
    signing key or received self-asserted identity is trusted by this API.
    """

    def __init__(self, role, identity, peer_public: bytes, *, application: bytes, epoch: int):
        if role not in ("initiator", "responder") or not isinstance(identity, mldsa.MLDSA65PrivateKey):
            raise ValueError("distinct ML-DSA-65 identity and role required")
        if not isinstance(peer_public, bytes) or len(peer_public) != 1952:
            raise ValueError("exact ML-DSA-65 peer public pin required")
        if not isinstance(application, bytes) or not 1 <= len(application) <= 1024:
            raise ValueError("application binding required")
        if type(epoch) is not int or not 0 < epoch < (1 << 64):
            raise ValueError("positive policy epoch required")
        own_public = identity.public_key().public_bytes_raw()
        if own_public == peer_public:
            raise ValueError("peer identities must be distinct")
        self.role = role
        self._identity = identity
        self._peer = mldsa.MLDSA65PublicKey.from_public_bytes(peer_public)
        own, peer = digest(own_public).hex(), digest(peer_public).hex()
        initiator, responder = (own, peer) if role == "initiator" else (peer, own)
        self._base = {"version": 2, "suite": SUITE, "application": application.hex(),
                      "epoch": epoch, "initiator": initiator, "responder": responder}
        self._phase = "new_i" if role == "initiator" else "new_r"
        self._pid = os.getpid()
        self._born = self._last_clock = time.monotonic()
        self._lock = threading.RLock()
        self._channel = None
        self._ephemeral = self._secret = self._hello = self._reply = self._finish = None

    def __reduce_ex__(self, protocol):
        raise TypeError("handshakes cannot be serialized or copied")

    def __repr__(self):
        return f"HandshakeEndpoint(version=2, role={self.role!r}, phase={self._phase!r})"

    def _check(self, phase):
        now = time.monotonic()
        if (self._phase != phase or self._pid != os.getpid() or not self._last_clock <= now
                or now >= self._born + HANDSHAKE_SECONDS):
            raise ValueError("handshake unavailable")
        self._last_clock = now

    def close(self):
        with self._lock:
            if self._channel is not None:
                self._channel.close()
            self._channel = None
            self._identity = None
            self._ephemeral = self._secret = self._hello = self._reply = self._finish = None
            self._phase = "closed"

    @property
    def channel(self):
        with self._lock:
            if self._pid != os.getpid() or self._phase != "established" or self._channel is None:
                raise ValueError("completed handshake required")
            with self._channel._lock:
                self._channel._check()
            return self._channel

    def _sign(self, kind, fields):
        payload = {**self._base, "kind": kind, **fields}
        signature = self._identity.sign(DOMAIN + packed(canonical(payload)))
        return canonical({"payload": payload, "signature": signature.hex()})

    def _verify(self, frame, kind, fields):
        if not isinstance(frame, bytes) or not 0 < len(frame) <= MAX_FLIGHT:
            raise ValueError("handshake rejected")
        envelope = json.loads(frame)
        if (not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}
                or canonical(envelope) != frame):
            raise ValueError("handshake rejected")
        payload = envelope["payload"]
        if (not isinstance(payload, dict) or set(payload) != set(self._base) | {"kind"} | set(fields)
                or type(payload["version"]) is not int or type(payload["epoch"]) is not int
                or any(payload.get(key) != value for key, value in self._base.items())
                or payload["kind"] != kind):
            raise ValueError("handshake rejected")
        signature = hex_field(envelope, "signature", 3309)
        self._peer.verify(signature, DOMAIN + packed(canonical(payload)))
        return payload

    @step("new_i")
    def start(self):
        self._hello = self._sign("initiator_hello", {"nonce": os.urandom(32).hex()})
        self._phase = "await_reply"
        return self._hello

    @step("new_r")
    def respond(self, hello: bytes):
        payload = self._verify(hello, "initiator_hello", {"nonce"})
        hex_field(payload, "nonce", 32)
        self._hello = hello
        self._ephemeral = mlkem.MLKEM768PrivateKey.generate()
        self._reply = self._sign("responder_hello", {"hello_hash": digest(hello).hex(),
            "nonce": os.urandom(32).hex(), "kem_public": self._ephemeral.public_key().public_bytes_raw().hex()})
        self._phase = "await_finish"
        return self._reply

    def _transcript(self, ciphertext):
        return digest(DOMAIN + packed(self._hello, self._reply, ciphertext))

    @step("await_reply")
    def finish(self, reply: bytes):
        payload = self._verify(reply, "responder_hello", {"hello_hash", "nonce", "kem_public"})
        if hex_field(payload, "hello_hash", 32) != digest(self._hello):
            raise ValueError("handshake rejected")
        hex_field(payload, "nonce", 32)
        public = mlkem.MLKEM768PublicKey.from_public_bytes(hex_field(payload, "kem_public", 1184))
        secret, ciphertext = public.encapsulate()
        self._reply = reply
        transcript = self._transcript(ciphertext)
        self._secret = secret
        self._transcript_hash = transcript
        finished = hmac.digest(derive(secret, transcript, b"initiator-finished"), transcript, "sha256")
        self._finish = self._sign("initiator_finish", {"hello_hash": digest(self._hello).hex(),
            "reply_hash": digest(reply).hex(), "kem_ciphertext": ciphertext.hex(), "finished": finished.hex()})
        self._phase = "await_confirm"
        return self._finish

    def _ack(self):
        transcript = digest(DOMAIN + packed(self._transcript_hash, self._finish))
        mac = hmac.digest(derive(self._secret, self._transcript_hash, b"responder-finished"), transcript, "sha256")
        return canonical({"version": 2, "kind": "responder_finished", "transcript": transcript.hex(), "finished": mac.hex()})

    def _establish(self, ack):
        final = digest(DOMAIN + packed(self._transcript_hash, self._finish, ack))
        self._channel = _new_channel(final[:16], derive(self._secret, final, b"initiator-traffic"),
                                     derive(self._secret, final, b"responder-traffic"), self.role)
        self._secret = self._ephemeral = self._hello = self._reply = self._finish = None
        self._phase = "established"

    @step("await_finish")
    def accept(self, finish: bytes):
        payload = self._verify(finish, "initiator_finish", {"hello_hash", "reply_hash", "kem_ciphertext", "finished"})
        if (hex_field(payload, "hello_hash", 32) != digest(self._hello)
                or hex_field(payload, "reply_hash", 32) != digest(self._reply)):
            raise ValueError("handshake rejected")
        ciphertext = hex_field(payload, "kem_ciphertext", 1088)
        self._secret = self._ephemeral.decapsulate(ciphertext)
        self._transcript_hash = self._transcript(ciphertext)
        expected = hmac.digest(derive(self._secret, self._transcript_hash, b"initiator-finished"),
                               self._transcript_hash, "sha256")
        if not hmac.compare_digest(hex_field(payload, "finished", 32), expected):
            raise ValueError("handshake rejected")
        self._finish = finish
        ack = self._ack()
        self._establish(ack)
        return ack

    @step("await_confirm")
    def confirm(self, ack: bytes):
        if not isinstance(ack, bytes) or len(ack) > MAX_FLIGHT or not hmac.compare_digest(ack, self._ack()):
            raise ValueError("handshake rejected")
        self._establish(ack)
