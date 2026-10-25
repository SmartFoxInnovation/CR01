"""Handshake-owned v2 records. No key export, checkpoint or resumption API.

This is a research channel, not a validated transport. Fresh handshake keys are
required after process restart/fork. Python object privacy is not a key vault.
"""
from __future__ import annotations

import os
import struct
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DOMAIN = b"CR01-SC-CHANNEL-v2\x00"
HEADER = struct.Struct("!4sB16sQII")
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_AAD = 64 * 1024
MAX_MESSAGES = 1_000_000
MAX_AGE = 3600
WINDOW = 64
_CONSTRUCTION_TOKEN = object()


class RecordChannel:
    """Created only by a completed v2 handshake; methods exchange bytes."""

    def __init__(self, token, session_id: bytes, send_key: bytes, receive_key: bytes, direction: int):
        if token is not _CONSTRUCTION_TOKEN:
            raise ValueError("a completed v2 handshake is required")
        self.session_id = session_id
        self._send_key, self._receive_key = send_key, receive_key
        self._direction = direction
        self._next = 1
        self._highest = 0
        self._seen = 0
        self._received = 0
        self._pid = os.getpid()
        self._born = self._last_clock = time.monotonic()
        self._closed = False
        self._lock = threading.RLock()

    def __reduce_ex__(self, protocol):
        raise TypeError("v2 channels cannot be serialized or copied; perform a fresh handshake")

    def __repr__(self):
        return f"RecordChannel(version=2, session_id={self.session_id.hex()!r}, closed={self._closed})"

    def _check(self):
        now = time.monotonic()
        if (self._closed or self._pid != os.getpid() or not self._last_clock <= now
                or now >= self._born + MAX_AGE):
            self.close()
            raise ValueError("channel unavailable; fresh handshake required")
        self._last_clock = now

    def close(self):
        with self._lock:
            self._closed = True
            self._send_key = self._receive_key = b""
            # Dropping references is not a Python secure-erasure guarantee.

    def send(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PAYLOAD:
            raise ValueError("invalid payload")
        if not isinstance(aad, bytes) or len(aad) > MAX_AAD:
            raise ValueError("invalid associated data")
        with self._lock:
            self._check()
            sequence = self._next
            if sequence > MAX_MESSAGES:
                self.close()
                raise ValueError("channel exhausted; fresh handshake required")
            # Reserve BEFORE encryption: an encryption failure burns, never reuses, a nonce.
            self._next += 1
            header = HEADER.pack(b"CR02", self._direction, self.session_id, sequence,
                                 len(aad), len(plaintext) + 16)
            sealed = AESGCM(self._send_key).encrypt(sequence.to_bytes(12, "big"), plaintext,
                                                   DOMAIN + header + aad)
            return header + aad + sealed

    def receive(self, frame: bytes, *, expected_aad: bytes | None = None) -> bytes:
        if (not isinstance(frame, bytes) or len(frame) < HEADER.size + 16
                or len(frame) > HEADER.size + MAX_AAD + MAX_PAYLOAD + 16):
            raise ValueError("record rejected")
        if expected_aad is not None and (not isinstance(expected_aad, bytes) or len(expected_aad) > MAX_AAD):
            raise ValueError("record rejected")
        with self._lock:
            self._check()
            magic, direction, sid, sequence, aad_size, sealed_size = HEADER.unpack_from(frame)
            if (magic != b"CR02" or direction != 1 - self._direction or sid != self.session_id
                    or not 0 < sequence <= MAX_MESSAGES or aad_size > MAX_AAD
                    or not 16 <= sealed_size <= MAX_PAYLOAD + 16
                    or len(frame) != HEADER.size + aad_size + sealed_size
                    or self._received >= MAX_MESSAGES):
                raise ValueError("record rejected")
            distance = self._highest - sequence
            if distance >= WINDOW or (distance >= 0 and self._seen & (1 << distance)):
                raise ValueError("record rejected")
            aad = frame[HEADER.size:HEADER.size + aad_size]
            if expected_aad is not None and aad != expected_aad:
                raise ValueError("record rejected")
            try:
                plaintext = AESGCM(self._receive_key).decrypt(sequence.to_bytes(12, "big"),
                    frame[HEADER.size + aad_size:], DOMAIN + frame[:HEADER.size] + aad)
            except InvalidTag:
                raise ValueError("record rejected") from None
            # Only authenticated records move the bounded sliding window.
            if sequence > self._highest:
                shift = sequence - self._highest
                self._seen = 0 if shift >= WINDOW else (self._seen << shift) & ((1 << WINDOW) - 1)
                self._highest = sequence
                distance = 0
            self._seen |= 1 << distance
            self._received += 1
            return plaintext


def _new_channel(session_id, initiator_key, responder_key, role):
    send, receive = (initiator_key, responder_key) if role == "initiator" else (responder_key, initiator_key)
    return RecordChannel(_CONSTRUCTION_TOKEN, session_id, send, receive, 0 if role == "initiator" else 1)
