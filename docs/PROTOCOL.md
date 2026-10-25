# CR01-SC v2 reference

V2 is the active custom research protocol. It uses backend ML-KEM-768,
ML-DSA-65, HKDF-SHA256 and AES-256-GCM. Python and the
C++ endpoint implement the same handshake and record format.

## Handshake

Each peer has its own private signing identity and an exact, authenticated
public-key pin for the other peer. Same-identity peers reject. Both peers must
agree on application bytes and a positive policy epoch. There is no trust on
first use, downgrade negotiation or fallback to v1.

1. Initiator signs a hello binding the suite/version, ordered identity hashes,
   application, epoch, message kind and fresh 32-byte nonce.
2. Responder checks those bindings and signs a reply with a fresh nonce and
   ephemeral ML-KEM public key, bound to the hello.
3. Initiator verifies the reply, encapsulates, and signs a finish binding both
   flights, the KEM ciphertext and the initiator Finished MAC.
4. Responder verifies the signed bindings before decapsulation, checks Finished
   and returns a separately keyed responder Finished. Initiator releases its
   channel only after checking that confirmation.

The responder cannot know that its last flight arrived. A lost last flight
requires a new handshake; there is no retransmission/resumption cache.

Flights are canonical ASCII JSON, at most 32 KiB. Duplicate/extra fields, wrong
types, alternate encodings, incorrect bindings and invalid signatures reject.
Pending endpoints are single-use, locked and expire after 120 seconds. Rejected
handshake flights close the pending endpoint; retry with a new one.

HKDF uses the KEM secret and transcript hashes with distinct labels for the two
Finished keys and directional traffic keys. Traffic keys bind the final
transcript, including the signed initiator finish and responder Finished.
The session ID is the first 16 bytes of the final transcript hash.

## Encrypted records

```text
CR02 | direction | session ID | sequence | AAD length | sealed length | AAD | ciphertext + tag
 4         1           16           8           4              4       variable   variable
```

Lengths above are bytes; integers are unsigned big-endian. The tag is 16 bytes.
The positive sequence is encoded into a 12-byte nonce. Authenticated data is
`CR01-SC-CHANNEL-v2`, a zero byte, the entire header and the external AAD.
The header binds direction, session, sequence and lengths.

| Limit | Value |
| --- | ---: |
| Plaintext per record | 8 MiB |
| External AAD | 64 KiB |
| Messages per direction | 1,000,000 |
| Session age | 3,600 seconds |
| Receive replay window | 64 records |

Send reserves the sequence before encryption; a backend failure burns that
nonce. Receive authenticates before committing replay state. Duplicates,
evicted records, reflected traffic and other sessions reject. Out-of-order
records within the window are allowed. Supply `expected_aad` when the caller
must enforce a particular AAD value, including an explicitly empty value.

## Native app interfaces

`cr01sc.exe` runs the full endpoint, including its handshake, replay and restart
policy.

Launch with `--role initiator` or `--role responder`, `--identity <private.pem>`,
`--peer-public <pin-file>`, `--application <hex>` and `--epoch <positive-integer>`.
Pins accept raw 1,952-byte keys or lowercase hex with optional final LF/CRLF.
The initial ready response is not an established channel.

JSON-lines is the default; `--transport json` selects it explicitly. Each
request is one complete newline-terminated object; byte fields use lowercase
hex. The handshake command order is:

```text
initiator: start -> responder: respond -> initiator: finish
          -> responder: accept -> initiator: confirm
```

Pass each response's `data` bytes unchanged to the next peer's `data` field.
`send` accepts plaintext `data` and `aad`; `receive` accepts record `data` and
optional `expected_aad`. `status` reports public phase/session information;
`close` terminates the endpoint. Rejections return `{"status":"rejected"}`
without plaintext or internal cryptographic reasons.

With `--transport binary`, the 16-byte local CRB1 header is:

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 4 | ASCII `CRB1` |
| 4 | 1 | Operation |
| 5 | 1 | Request flags / response status |
| 6 | 1 | Request zero / public response phase |
| 7 | 1 | Reserved zero |
| 8 | 4 | Data length, big-endian |
| 12 | 4 | Auxiliary length, big-endian |

Data bytes follow, then auxiliary bytes. Operations are start=1, respond=2,
finish=3, accept=4, confirm=5, send=6, receive=7, status=8 and close=9.
Send carries plaintext/AAD; receive carries record/optional expected AAD.
Only receive accepts flag 1, meaning the supplied expected AAD is required.
With flag 0, its auxiliary field must be empty. Other request flags are zero.
Handshake operations carry unchanged canonical flight bytes and empty auxiliary.
Start/status/close carry no request body.

Success echoes the operation with status 0; established responses carry the
16-byte session ID as auxiliary. Confirm/status/close return empty data. Initial
ready uses operation 0/status 2, its public key as data and OpenSSL version as
auxiliary. Phases are new initiator=1, new responder=2, await reply=3, await
finish=4, await confirm=5, established=6 and closed=7.

Binary rejection is exactly `43524231ff0100000000000000000000`, with no body.
Header/operation limits are checked before allocation: handshake 32 KiB;
send 8 MiB plus 64 KiB AAD; receive 8 MiB plus 64 KiB plus 53 framing/tag bytes,
and at most 64 KiB expected AAD. Invalid framing, unknown operations/flags,
impossible lengths and partial-frame EOF close the stream without fallback or
resynchronisation. Clean EOF between frames closes normally.

## Ownership and restart

Native `send_into` reuses caller-owned ciphertext storage. Output must not alias
either input or be shared unsafely across calls. Transmit it only after success.

`receive_owned(std::move(frame), expected_aad)` consumes exclusive ciphertext
ownership. It decrypts in place but exposes no plaintext result until tag and
length checks succeed and the endpoint commits replay state. Its move-only
`AuthenticatedRecord.view()` is read-only and lasts only while that owner is
unmoved and alive. Do not use borrowed frame aliases after transfer.

Failure, destruction or replacement cleanses the full used frame.
`take_cleansed_storage()` returns zeroed storage for reuse and invalidates the
view. The immutable-input `receive()` accepts ciphertext and allocates its
own result. Buffer cleansing does not cover every process/allocator/OS copy;
retained capacity is not a promise of lower memory use.

No v2 API saves or imports traffic keys/counters, copies endpoint state or resumes
a session. Restart requires fresh nonces, ephemeral KEM material and a full
handshake, even with the same long-lived identity. PID/clock guards reject
inherited or invalid live state. There is no durable VM/live-memory rollback
detector. Authenticated results may outlive an endpoint; close obsolete endpoints.

### Rollback policy

Supported restart means discarding the old process and all live session state,
then completing a fresh handshake on a trusted host with working OS randomness.
It does not mean restoring saved memory and resetting the counters.

- Live VM snapshots, RAM cloning and process checkpoints/restores are unsupported
  while an endpoint or its keys exist. Suspend/resume is not an approved recovery
  mechanism. A restore can duplicate keys and counters and reuse GCM nonces.
- PID and monotonic-clock checks do not detect every restored or cloned process.
  A file counter inside the same snapshot is not an anti-rollback mechanism.
- The host/orchestrator must prevent old live engines from resuming. If that
  cannot be guaranteed, the deployment is outside this preview's supported model.
  A future detector needs trusted freshness outside the rollback boundary.
- Disk/configuration restores can also restore obsolete identities, pins or
  policy epochs. Their currency must be established through a trusted external
  provisioning policy; this protocol does not distribute revocations.
- After endpoint compromise, remediate or rebuild the host, revoke/reprovision
  compromised identities and authenticated pins, then establish fresh sessions.
  A new handshake alone does not repair a still-compromised host or identity.

These are deployment restrictions, not implemented VM rollback detection or
automatic post-compromise recovery. Actual hypervisor restores were not tested.

### Native secret memory

KEM shared secrets, Finished/HKDF/traffic-key intermediates and encoded identity
input use bounded, move-only native buffers. They use dedicated OS pages,
require successful `VirtualLock` on Windows or `mlock` on Linux, and cleanse the
whole allocation before unlock/free, including failure paths. Linux also requires
`MADV_DONTDUMP`; the native CLI disables process core dumps and ordinary dumpability.
Protection/allocation failures reject; there is no ordinary-heap fallback.

This covers those allocations only. Long-lived signing/ephemeral private keys,
expanded traffic-key state and intermediate computations inside OpenSSL providers
are not claimed to use these buffers. Neither are Python objects, plaintext pipe
copies, registers, other allocator/OS copies, Windows crash dumps or hypervisor
memory. Locked pages are still readable by the process. This is not process-wide
secure memory, protection from arbitrary memory reads or a side-channel assurance.
Windows crash-dump policy and privileged access remain host responsibilities.

Randomness still comes from OpenSSL's OS-seeded CSPRNG. Failure returns reject;
there is no custom entropy pool, deterministic seed or weaker random fallback.
Synthetic failure tests exercise cleanup and closed-endpoint behavior, not the
quality of a physical entropy source or an actually unseeded kernel.

## Limits

Correct pins, protected identity custody, trustworthy OS randomness and protected
endpoint memory are assumptions. Identity storage uses unencrypted research PEM
files. Native identity reads bind checks and IO to one opened regular file,
reject leaf links and require a single link. Linux requires the process owner,
owner-read permission and no group/other permissions. Windows requires the current
user as owner and a DACL granting access only to that user, SYSTEM or local
Administrators. New native files are exclusive-create: mode0600 on Linux; a
protected current-user/SYSTEM DACL on Windows. Existing files are never overwritten.
Failed writes can leave a restricted partial file; it is not a usable identity.

Pins are public, not secret: reads may be shared, but untrusted write access is
rejected. Linux pin owners must be the process user or root, without group/other
write bits; Windows rejects write/control grants outside the trusted principals.
These conservative checks do not validate every ancestor directory/junction,
all filesystem semantics or administrator/kernel behavior. Parent-directory
protection and trustworthy provisioning remain operator responsibilities.
Private-file interchange between native/Python backends is not claimed.

Identity hashes, application, epoch and other handshake metadata are public.
The protocol does not hide identities. Local app pipes carry plaintext/control
data; they are not an authenticated Internet service. The Python driver has a
20-second default response deadline; native blocking stdin needs host supervision.
The visual demo selects shorter response timeouts and a cooperative budget, not
a hard wall-clock guarantee. It creates temporary unencrypted native identities
and cleans them on normal/error exit, not necessarily after a process/OS crash.

Revocation distribution, external trust-policy rollback, network transport,
rate limiting and application delivery semantics remain deployment work.
Fresh handshakes do not repair compromised identities or automatically recover
after full endpoint compromise. Context length alone is not evidence of entropy.

There is no independent cryptanalysis, formal composition/combiner theorem,
quantum-security proof, side-channel/constant-time assurance, certification or
production approval. Using standardized primitives does not prove this custom
composition secure. No new cryptographic primitive or proven novelty is claimed.

Related specifications:
[TLS 1.3 authentication](https://www.rfc-editor.org/rfc/rfc8446#section-4.4),
[TLS key scheduling](https://www.rfc-editor.org/rfc/rfc8446#section-7.1) and
[HPKE security considerations](https://www.rfc-editor.org/rfc/rfc9180#section-9).
Those specifications' proofs and deployment experience do not transfer to CR01.
