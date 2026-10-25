"""Local ACVP-readiness checks for CR01-SC standard primitives.

This module runs public known-answer tests and backend self-consistency checks.
It is not ACVP, CAVP, CMVP, or FIPS validation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
except ModuleNotFoundError:  # pragma: no cover - depends on installed cryptography version.
    mlkem = None  # type: ignore[assignment]

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ModuleNotFoundError:  # pragma: no cover - depends on installed cryptography version.
    mldsa = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ReadinessVectorResult:
    name: str
    algorithm: str
    source: str
    test_type: str
    passed: bool
    details: str


def hx(value: str) -> bytes:
    return bytes.fromhex("".join(value.split()))


def check_sha256_empty() -> ReadinessVectorResult:
    digest = hashlib.sha256(b"").hexdigest()
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    return ReadinessVectorResult(
        name="sha256_empty",
        algorithm="SHA2-256",
        source="NIST/FIPS-style public SHA-256 known answer",
        test_type="known-answer",
        passed=digest == expected,
        details=f"expected={expected}; actual={digest}",
    )


def check_sha256_abc() -> ReadinessVectorResult:
    digest = hashlib.sha256(b"abc").hexdigest()
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    return ReadinessVectorResult(
        name="sha256_abc",
        algorithm="SHA2-256",
        source="NIST/FIPS-style public SHA-256 known answer",
        test_type="known-answer",
        passed=digest == expected,
        details=f"expected={expected}; actual={digest}",
    )


def run_hmac_sha256(key: bytes, data: bytes) -> str:
    signer = hmac.HMAC(key, hashes.SHA256())
    signer.update(data)
    return signer.finalize().hex()


def check_hmac_sha256_rfc4231_case_1() -> ReadinessVectorResult:
    actual = run_hmac_sha256(b"\x0b" * 20, b"Hi There")
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    return ReadinessVectorResult(
        name="hmac_sha256_rfc4231_case_1",
        algorithm="HMAC-SHA2-256",
        source="RFC 4231 test case 1",
        test_type="known-answer",
        passed=actual == expected,
        details=f"expected={expected}; actual={actual}",
    )


def check_hmac_sha256_rfc4231_case_2() -> ReadinessVectorResult:
    actual = run_hmac_sha256(b"Jefe", b"what do ya want for nothing?")
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    return ReadinessVectorResult(
        name="hmac_sha256_rfc4231_case_2",
        algorithm="HMAC-SHA2-256",
        source="RFC 4231 test case 2",
        test_type="known-answer",
        passed=actual == expected,
        details=f"expected={expected}; actual={actual}",
    )


def check_hkdf_sha256_rfc5869_case_1() -> ReadinessVectorResult:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=42,
        salt=hx("000102030405060708090a0b0c"),
        info=hx("f0f1f2f3f4f5f6f7f8f9"),
    ).derive(b"\x0b" * 22)
    expected = hx(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    return ReadinessVectorResult(
        name="hkdf_sha256_rfc5869_case_1",
        algorithm="HKDF-SHA2-256",
        source="RFC 5869 test case 1",
        test_type="known-answer",
        passed=okm == expected,
        details=f"expected={expected.hex()}; actual={okm.hex()}",
    )


def aes_gcm_result(
    name: str,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes | None,
    expected_ciphertext: bytes,
    expected_tag: bytes,
    source: str,
) -> ReadinessVectorResult:
    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    decrypts = AESGCM(key).decrypt(nonce, ciphertext + tag, aad) == plaintext
    passed = ciphertext == expected_ciphertext and tag == expected_tag and decrypts
    return ReadinessVectorResult(
        name=name,
        algorithm="AES-256-GCM",
        source=source,
        test_type="known-answer",
        passed=passed,
        details=(
            f"expected_ciphertext={expected_ciphertext.hex()}; actual_ciphertext={ciphertext.hex()}; "
            f"expected_tag={expected_tag.hex()}; actual_tag={tag.hex()}; decrypts={decrypts}"
        ),
    )


def check_aes256_gcm_nist_case_13() -> ReadinessVectorResult:
    return aes_gcm_result(
        name="aes256_gcm_nist_case_13_empty",
        key=b"\x00" * 32,
        nonce=b"\x00" * 12,
        plaintext=b"",
        aad=None,
        expected_ciphertext=b"",
        expected_tag=hx("530f8afbc74536b9a963b4f1c4cb738b"),
        source="McGrew/Viega GCM revised proposal Appendix B test case 13 (public NIST-hosted proposal, not SP 800-38D Appendix B)",
    )


def check_aes256_gcm_nist_case_14() -> ReadinessVectorResult:
    return aes_gcm_result(
        name="aes256_gcm_nist_case_14_one_block",
        key=b"\x00" * 32,
        nonce=b"\x00" * 12,
        plaintext=b"\x00" * 16,
        aad=None,
        expected_ciphertext=hx("cea7403d4d606b6e074ec5d3baf39d18"),
        expected_tag=hx("d0d1c8a799996bf0265b98b5d48ab919"),
        source="McGrew/Viega GCM revised proposal Appendix B test case 14 (public NIST-hosted proposal, not SP 800-38D Appendix B)",
    )


def check_aes256_gcm_tamper_rejects() -> ReadinessVectorResult:
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"CR01 ACVP readiness AES-GCM tamper check"
    aad = b"cr01-readiness"
    encrypted = bytearray(AESGCM(key).encrypt(nonce, plaintext, aad))
    encrypted[-1] ^= 1
    rejected = False
    try:
        AESGCM(key).decrypt(nonce, bytes(encrypted), aad)
    except InvalidTag:
        rejected = True
    return ReadinessVectorResult(
        name="aes256_gcm_tamper_rejects",
        algorithm="AES-256-GCM",
        source="local negative authentication check",
        test_type="negative-authentication",
        passed=rejected,
        details=f"tampered_tag_rejected={rejected}",
    )


def check_x25519_rfc7748() -> ReadinessVectorResult:
    alice_private = x25519.X25519PrivateKey.from_private_bytes(
        hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    )
    bob_private = x25519.X25519PrivateKey.from_private_bytes(
        hx("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    )
    alice_public = alice_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    bob_public = bob_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    expected_alice_public = hx("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    expected_bob_public = hx("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected_shared = hx("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    shared_left = alice_private.exchange(bob_private.public_key())
    shared_right = bob_private.exchange(alice_private.public_key())
    passed = (
        alice_public == expected_alice_public
        and bob_public == expected_bob_public
        and shared_left == expected_shared
        and shared_right == expected_shared
    )
    return ReadinessVectorResult(
        name="x25519_rfc7748",
        algorithm="X25519",
        source="RFC 7748 section 6.1",
        test_type="known-answer",
        passed=passed,
        details=(
            f"alice_public={alice_public.hex()}; bob_public={bob_public.hex()}; "
            f"shared_left={shared_left.hex()}; shared_right={shared_right.hex()}"
        ),
    )


def check_mlkem768_self_consistency() -> ReadinessVectorResult:
    if mlkem is None:
        return ReadinessVectorResult(
            name="mlkem768_self_consistency",
            algorithm="ML-KEM-768",
            source="local backend self-consistency",
            test_type="backend-self-consistency",
            passed=False,
            details="ML-KEM backend unavailable in installed cryptography package",
        )
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()
    shared_secret, ciphertext = public_key.encapsulate()
    decapsulated = private_key.decapsulate(ciphertext)
    passed = shared_secret == decapsulated and len(ciphertext) > 0 and len(shared_secret) > 0
    return ReadinessVectorResult(
        name="mlkem768_self_consistency",
        algorithm="ML-KEM-768",
        source="local backend self-consistency",
        test_type="backend-self-consistency",
        passed=passed,
        details=f"ciphertext_bytes={len(ciphertext)}; shared_secret_bytes={len(shared_secret)}",
    )


def check_mldsa65_self_consistency() -> ReadinessVectorResult:
    if mldsa is None:
        return ReadinessVectorResult(
            name="mldsa65_self_consistency",
            algorithm="ML-DSA-65",
            source="local backend self-consistency",
            test_type="backend-self-consistency",
            passed=False,
            details="ML-DSA backend unavailable in installed cryptography package",
        )
    private_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(range(32)))
    public_key = private_key.public_key()
    message = b"CR01 ACVP readiness ML-DSA self-consistency"
    signature = private_key.sign(message)
    verified = True
    tamper_rejected = False
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        verified = False
    try:
        public_key.verify(signature, message + b"!")
    except InvalidSignature:
        tamper_rejected = True
    public_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    passed = verified and tamper_rejected and len(signature) > 0 and len(public_bytes) > 0
    return ReadinessVectorResult(
        name="mldsa65_self_consistency",
        algorithm="ML-DSA-65",
        source="local backend self-consistency",
        test_type="backend-self-consistency",
        passed=passed,
        details=(
            f"public_key_bytes={len(public_bytes)}; signature_bytes={len(signature)}; "
            f"verified={verified}; tamper_rejected={tamper_rejected}"
        ),
    )


CHECKS: tuple[Callable[[], ReadinessVectorResult], ...] = (
    check_sha256_empty,
    check_sha256_abc,
    check_hmac_sha256_rfc4231_case_1,
    check_hmac_sha256_rfc4231_case_2,
    check_hkdf_sha256_rfc5869_case_1,
    check_aes256_gcm_nist_case_13,
    check_aes256_gcm_nist_case_14,
    check_aes256_gcm_tamper_rejects,
    check_x25519_rfc7748,
    check_mlkem768_self_consistency,
    check_mldsa65_self_consistency,
)


def run_acvp_readiness() -> dict[str, object]:
    results = [check() for check in CHECKS]
    known_answer = [item for item in results if item.test_type == "known-answer"]
    self_consistency = [item for item in results if item.test_type == "backend-self-consistency"]
    negative = [item for item in results if item.test_type == "negative-authentication"]
    summary = {
        "status": "ready" if all(item.passed for item in results) else "partial",
        "official_acvp_run": False,
        "official_fips_validation": False,
        "total_checks": len(results),
        "passed_checks": sum(1 for item in results if item.passed),
        "known_answer_checks": len(known_answer),
        "known_answer_passed": sum(1 for item in known_answer if item.passed),
        "self_consistency_checks": len(self_consistency),
        "self_consistency_passed": sum(1 for item in self_consistency if item.passed),
        "negative_checks": len(negative),
        "negative_passed": sum(1 for item in negative if item.passed),
        "claim_boundary": (
            "Local known-answer and backend self-consistency checks only; "
            "not ACVP/CAVP/CMVP/FIPS validation."
        ),
    }
    return {
        "summary": summary,
        "results": [asdict(item) for item in results],
        "notes": [
            "Known-answer checks increase confidence that standard primitive APIs are wired correctly.",
            "ML-KEM and ML-DSA checks are backend self-consistency checks, not official ACVP vectors.",
            "Official ACVP requires ACVTS workflow; production certificates require accredited lab/module validation.",
        ],
    }



def main():
    import argparse
    from .reporting import write_report
    parser = argparse.ArgumentParser(description="Check backend primitives against public inputs; not certification.")
    parser.add_argument("--out", required=True, help="Public JSON receipt file.")
    args = parser.parse_args()
    report = run_acvp_readiness()
    report["schema"] = "CR01-PRIMITIVE-CHECKS-v1"
    write_report(args.out, report, ["src/python/cr01_sc/primitives.py"])
    summary = report["summary"]
    print(f"Primitive checks: {summary['passed_checks']}/{summary['total_checks']}")
    if summary["status"] != "ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
