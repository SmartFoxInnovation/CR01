"""CRB1 bounded local-control codec. Not encryption or a network trust boundary."""
import struct

HEADER = struct.Struct("!4sBBBBII")
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_AAD = 64 * 1024
MAX_RECORD = 37 + MAX_AAD + MAX_PAYLOAD + 16
OPERATIONS = {"start": 1, "respond": 2, "finish": 3, "accept": 4, "confirm": 5,
              "send": 6, "receive": 7, "status": 8, "close": 9}
PHASES = {1: "new_i", 2: "new_r", 3: "await_reply", 4: "await_finish",
          5: "await_confirm", 6: "established", 7: "closed"}
REJECTION = HEADER.pack(b"CRB1", 255, 1, 0, 0, 0, 0)


def request(op, data=b"", auxiliary=b"", *, expected_aad=False):
    if op not in OPERATIONS or not isinstance(data, bytes) or not isinstance(auxiliary, bytes):
        raise ValueError("invalid binary request")
    code = OPERATIONS[op]
    limit = MAX_PAYLOAD if op == "send" else MAX_RECORD if op == "receive" else 32768 if 2 <= code <= 5 else 0
    if (len(data) > limit or len(auxiliary) > (MAX_AAD if op in ("send", "receive") else 0)
            or (expected_aad and op != "receive") or (op == "receive" and auxiliary and not expected_aad)):
        raise ValueError("invalid binary request")
    return HEADER.pack(b"CRB1", code, int(expected_aad), 0, 0, len(data), len(auxiliary)), data, auxiliary


def write_all(stream, parts):
    for part in parts:
        remaining = memoryview(part)
        while remaining:
            written = stream.write(remaining)
            if not written: raise OSError("binary pipe write failed")
            remaining = remaining[written:]
    stream.flush()


def read_exact(stream, count, *, clean_eof=False):
    value = bytearray(count)
    view = memoryview(value)
    done = 0
    while done < count:
        received = stream.readinto(view[done:])
        if not received:
            if done == 0 and clean_eof: return None
            raise ValueError("truncated binary response")
        done += received
    return bytes(value)


def read_response(stream):
    header = read_exact(stream, HEADER.size, clean_eof=True)
    if header is None: return None
    magic, op, status, phase, reserved, size, aux_size = HEADER.unpack(header)
    if magic != b"CRB1" or reserved: raise ValueError("invalid binary response")
    if status == 1:
        if header != REJECTION: raise ValueError("invalid binary rejection")
        return {"status": "rejected"}
    if status == 2:
        if op or phase not in (1, 2) or size != 1952 or aux_size > 4096:
            raise ValueError("invalid binary ready")
        return {"status": "endpoint-ready", "version": 2, "public_key": read_exact(stream, size).hex(),
                "openssl": read_exact(stream, aux_size).decode("ascii")}
    if (status != 0 or op not in OPERATIONS.values() or phase not in PHASES or size > MAX_RECORD
            or aux_size != (16 if phase == 6 else 0)):
        raise ValueError("invalid binary response")
    result = {"status": "ok", "data": read_exact(stream, size), "phase": PHASES[phase], "_opcode": op}
    if aux_size: result["session_id"] = read_exact(stream, aux_size)
    return result
