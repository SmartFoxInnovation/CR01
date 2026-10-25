"""Public-only report for the active v2 channel; no private state in reports."""
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import mldsa

from .handshake import HandshakeEndpoint, canonical


def rejected(operation):
    try:
        operation()
    except ValueError:
        return True
    return False


def identity(seed, role):
    if seed is None:
        return mldsa.MLDSA65PrivateKey.generate()
    # Deliberately public fixture identities, NOT a deployable key generator.
    fixture = hashlib.sha256(b"CR01-v2-public-fixture" + seed.to_bytes(8, "big") + role).digest()
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(fixture)


def run_channel_demo(seed=None):
    if seed is not None and (type(seed) is not int or not 0 <= seed <= 2_147_483_647):
        raise ValueError("invalid public-fixture seed")
    initiator_key, responder_key = identity(seed, b"initiator"), identity(seed, b"responder")
    initiator_public = initiator_key.public_key().public_bytes_raw()
    responder_public = responder_key.public_key().public_bytes_raw()

    def pair():
        args = {"application": b"CR01-v2-demo", "epoch": 1}
        return (HandshakeEndpoint("initiator", initiator_key, responder_public, **args),
                HandshakeEndpoint("responder", responder_key, initiator_public, **args))

    def complete(first, second):
        hello = first.start()
        reply = second.respond(hello)
        finish = first.finish(reply)
        ack = second.accept(finish)
        first.confirm(ack)
        return (hello, reply, finish, ack)

    first, second = pair()
    flights = complete(first, second)
    message = first.channel.send(b"CR01 v2: no composite core", b"demo")
    payload_ok = second.channel.receive(message, expected_aad=b"demo") == b"CR01 v2: no composite core"
    response = second.channel.send(b"independent responder", b"demo-reply")
    bidirectional = first.channel.receive(response, expected_aad=b"demo-reply") == b"independent responder"
    attacks = {
        "record_replay_rejected": rejected(lambda: second.channel.receive(message)),
        "record_tamper_rejected": rejected(lambda: first.channel.receive(response[:-1] + bytes([response[-1] ^ 1]))),
        "record_reflection_rejected": rejected(lambda: first.channel.receive(message)),
    }
    # Exercise invalid authentication on an unseen sequence, not just an already-replayed record.
    unseen = first.channel.send(b"fresh tag probe")
    attacks["record_tamper_rejected"] = attacks["record_tamper_rejected"] and rejected(
        lambda: second.channel.receive(unseen[:-1] + bytes([unseen[-1] ^ 1])))
    payload_ok = payload_ok and second.channel.receive(unseen) == b"fresh tag probe"
    restart_i, restart_r = pair()
    attacks["old_record_after_restart_rejected"] = rejected(lambda: restart_r.channel.receive(message))
    # Replaying an old hello only obtains a new challenge/KEM key, never an old channel.
    restart_r.respond(flights[0])
    attacks["old_finish_after_restart_rejected"] = rejected(lambda: restart_r.accept(flights[2]))
    restart_i.close()
    new_i, new_r = pair()
    complete(new_i, new_r)
    attacks["cross_session_record_rejected"] = rejected(lambda: new_r.channel.receive(message))
    bad_i, bad_r = pair()
    downgraded = json.loads(bad_i.start())
    downgraded["payload"]["version"] = 1
    attacks["downgrade_rejected"] = rejected(lambda: bad_r.respond(canonical(downgraded)))
    wrong = mldsa.MLDSA65PrivateKey.generate()
    unknown = HandshakeEndpoint("initiator", wrong, responder_public, application=b"CR01-v2-demo", epoch=1)
    _, pinned = pair()
    attacks["untrusted_identity_rejected"] = rejected(lambda: pinned.respond(unknown.start()))
    matches = first.channel.session_id == second.channel.session_id
    result = {"schema": "CR01-CHANNEL-V2-ASSESSMENT-v1", "summary": {
        "version": 2, "status": "ready" if matches and payload_ok and bidirectional and all(attacks.values()) else "failed",
        "seed": seed, "key_mode": "fresh-os-keys" if seed is None else "public-fixture-identities-fresh-session",
        "context_match": matches, "mutual_authentication": True, "key_confirmation": True,
        "directional_keys": attacks["record_reflection_rejected"] and bidirectional,
        "toy_core_used": False, "restart_policy": "fresh-full-handshake-no-resumption",
        "payload_decrypts": payload_ok and bidirectional, "all_attack_checks_pass": all(attacks.values()),
        "notes": [
            "Distinct locally pinned ML-DSA identities; fresh ephemeral ML-KEM-768 for each handshake.",
            "Fresh OS nonces and KEM randomness even in explicit public-fixture identity mode; never use fixture identities for real traffic.",
            "No toy composite core or shared peer private identity; directional HKDF/AES-256-GCM traffic keys.",
            "Restart/fork requires a fresh full handshake; traffic keys are not saved or restored.",
            "Custom research composition, not TLS/HPKE, independent audit, quantum-security proof or production approval.",
        ]},
        "transcript": {
            "identity_pins": {"initiator_sha256": hashlib.sha256(initiator_public).hexdigest(),
                              "responder_sha256": hashlib.sha256(responder_public).hexdigest()},
            "flights": {name: {"bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()}
                        for name, frame in zip(("initiator_hello", "responder_hello", "initiator_finish", "responder_finished"), flights)},
            "records": {"session_id": first.channel.session_id.hex(), "sent_bytes": len(message), "reply_bytes": len(response)}},
        "attacks": attacks,
        "trust_decisions": {"initiator_pin": {"trusted": True}, "responder_pin": {"trusted": True}},
    }
    for endpoint in (first, second, restart_r, new_i, new_r, bad_i, bad_r, unknown, pinned):
        endpoint.close()
    return result


def main():
    import argparse
    from .reporting import write_report
    parser = argparse.ArgumentParser(description="Run a fresh v2 handshake and bounded negative probes.")
    parser.add_argument("--out", required=True, help="Public JSON receipt file.")
    parser.add_argument("--fixture-seed", type=int, help="Known public test identities; never traffic keys.")
    args = parser.parse_args()
    report = run_channel_demo(args.fixture_seed)
    write_report(args.out, report, ["src/python/cr01_sc/channel.py", "src/python/cr01_sc/handshake.py", "src/python/cr01_sc/demo.py"])
    passed = report["summary"]["status"] == "ready"
    print(f"CR01-SC v2 demo: {'pass' if passed else 'fail'}; {sum(report['attacks'].values())}/{len(report['attacks'])} probes")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
