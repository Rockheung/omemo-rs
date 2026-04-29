#!/usr/bin/env python3
"""
Generate AEAD (AES-256-CBC + HMAC) fixtures from python-doubleratchet's
`recommended.aead_aes_hmac.AEAD`. Output JSON consumed by Rust replay tests.

This is the *base* recommended AEAD: the output is `ciphertext || full_HMAC`.
The 16-byte HMAC truncation used by OMEMO 2 is a twomemo-layer override
(`twomemo.AEADImpl`) and is *not* covered here — it lives with omemo-twomemo.

Determinism: encryption is fully deterministic given (key, AD, plaintext, info,
hash) because the IV is derived via HKDF from the key. So fixtures regenerate
stable.
"""
import asyncio
import hashlib
import json
from pathlib import Path

from doubleratchet.recommended import HashFunction, aead_aes_hmac

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "aead_aes_hmac.json"


def det(seed: bytes, label: str, length: int) -> bytes:
    """Deterministic key material derived from seed+label via SHA-512."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def make_aead(hash_fn: HashFunction, info: bytes):
    class A(aead_aes_hmac.AEAD):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return hash_fn

        @staticmethod
        def _get_info() -> bytes:
            return info

    return A


HASH_NAMES = {
    HashFunction.SHA_256: "sha256",
    HashFunction.SHA_512: "sha512",
}


async def gen_case(seed_label: str, hash_fn: HashFunction, info: bytes,
                   plaintext_len: int, ad_len: int) -> dict:
    seed = det(b"aead-aes-hmac-fixture", seed_label, 32)
    key = det(seed, "key", 32)
    plaintext = det(seed, "plaintext", plaintext_len)
    ad = det(seed, "ad", ad_len)
    A = make_aead(hash_fn, info)
    ciphertext = await A.encrypt(plaintext, key, ad)
    return {
        "label": seed_label,
        "hash": HASH_NAMES[hash_fn],
        "info_hex": info.hex(),
        "key_hex": key.hex(),
        "ad_hex": ad.hex(),
        "plaintext_hex": plaintext.hex(),
        "ciphertext_hex": ciphertext.hex(),
    }


async def main():
    cases = []

    # Canonical OMEMO 2 message-key derivation: SHA-256, "OMEMO Message Key Material" info.
    omemo_info = b"OMEMO Message Key Material"
    # Vary plaintext length around the AES block boundary to exercise PKCS#7 padding.
    plaintext_lens = [0, 1, 15, 16, 17, 31, 32, 33, 64, 128, 257]
    for n, plen in enumerate(plaintext_lens):
        cases.append(await gen_case(
            f"omemo-{n:02d}-plen{plen}", HashFunction.SHA_256, omemo_info,
            plaintext_len=plen, ad_len=64,
        ))

    # Vary associated_data length (incl. empty AD).
    for n, alen in enumerate([0, 1, 32, 96]):
        cases.append(await gen_case(
            f"omemo-ad{n:02d}-alen{alen}", HashFunction.SHA_256, omemo_info,
            plaintext_len=42, ad_len=alen,
        ))

    # Different info string.
    for n in range(2):
        cases.append(await gen_case(
            f"alt-info-{n}", HashFunction.SHA_256, b"alt info string",
            plaintext_len=80, ad_len=32,
        ))

    # SHA-512 variant — exercises 64-byte HMAC tail and IV derived from a longer
    # HKDF run. (OMEMO 2 itself uses SHA-256, but the base AEAD class supports
    # both, and the python-doubleratchet test suite exercises both.)
    for n in range(3):
        cases.append(await gen_case(
            f"sha512-{n}", HashFunction.SHA_512, b"OMEMO Message Key Material",
            plaintext_len=50 + n * 20, ad_len=64,
        ))

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.recommended.aead_aes_hmac",
        "algorithm": "AES-256-CBC + HMAC (recommended AEAD)",
        "note": "ciphertext field = AES-CBC(PKCS7) || full HMAC; key/IV/auth_key all from HKDF(salt=zeros, ikm=key, info=info, len=80) split 32/32/16",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
