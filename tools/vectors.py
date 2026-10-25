"""Generate original public synthetic v2 AES-GCM record fixtures, not live keys."""
import argparse
import json
from pathlib import Path
import struct
import hashlib
from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def vectors():
    results = []
    for direction in (0, 1):
        for index, size in enumerate((0, 1, 32, 255)):
            key = bytes((n + direction * 32) % 256 for n in range(32))
            sid = bytes(range(16))
            sequence = index + 1
            plaintext = bytes(n % 256 for n in range(size))
            aad = b"public-v2-fixture" if index else b""
            header = struct.pack("!4sB16sQII", b"CR02", direction, sid, sequence, len(aad), size + 16)
            nonce = sequence.to_bytes(12, "big")
            sealed = AESGCM(key).encrypt(nonce, plaintext, b"CR01-SC-CHANNEL-v2\x00" + header + aad)
            results.append({"direction": direction, "sequence": sequence, "key": key.hex(),
                            "session_id": sid.hex(), "plaintext": plaintext.hex(), "aad": aad.hex(),
                            "frame": (header + aad + sealed).hex()})
    return {"schema": "CR01-V2-PUBLIC-RECORD-VECTORS-v1", "origin": "Original synthetic public fixtures; repository licence applies. Never use fixture keys for traffic.",
            "scope": "Record encoding and AES-GCM only, not handshake vectors or security proof.", "vectors": results}


def verify(document):
    """Check fixtures without importing the CR01-SC encoder or channel."""
    if document.get("schema") != "CR01-V2-PUBLIC-RECORD-VECTORS-v1":
        raise ValueError("unexpected fixture schema")
    entries = document.get("vectors", [])
    if len(entries) != 8 or entries != vectors()["vectors"]:
        raise ValueError("fixtures differ from the eight original public cases")
    rejected = 0
    for entry in entries:
        frame = bytes.fromhex(entry["frame"])
        key = bytes.fromhex(entry["key"])
        magic, direction, sid, sequence, aad_size, sealed_size = struct.unpack("!4sB16sQII", frame[:37])
        if (magic != b"CR02" or direction not in (0, 1) or len(key) != 32
                or len(frame) != 37 + aad_size + sealed_size or sealed_size < 16
                or sid.hex() != entry["session_id"] or sequence != entry["sequence"]):
            raise ValueError("invalid fixture header")
        nonce = sequence.to_bytes(12, "big")
        associated = b"CR01-SC-CHANNEL-v2\x00" + frame[:37 + aad_size]
        sealed = frame[37 + aad_size:]
        plaintext = AESGCM(key).decrypt(nonce, sealed, associated)
        if plaintext.hex() != entry["plaintext"]:
            raise ValueError("fixture plaintext mismatch")
        for changed_sealed, changed_aad in (
            (sealed[:-1] + bytes([sealed[-1] ^ 1]), associated),
            (sealed, associated + b"changed"),
        ):
            try:
                AESGCM(key).decrypt(nonce, changed_sealed, changed_aad)
            except InvalidTag:
                rejected += 1
            else:
                raise ValueError("fixture mutation was accepted")
    return {"schema": "CR01-V2-VECTOR-CHECK-v1", "status": "pass",
            "checked_vectors": len(entries), "authentication_mutations_rejected": rejected,
            "boundary": "Independent code path, same cryptography backend; not an independent audit."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verify", type=Path, help="Verify the original public fixtures.")
    args = parser.parse_args()
    report = verify(json.loads(args.verify.read_text(encoding="utf-8"))) if args.verify else vectors()
    if args.verify:
        report["fixture_sha256"] = hashlib.sha256(args.verify.read_bytes()).hexdigest()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Verified 8 public v2 vectors and rejected 16 authentication mutations" if args.verify
          else "Wrote 8 public synthetic v2 record vectors")


if __name__ == "__main__":
    main()
