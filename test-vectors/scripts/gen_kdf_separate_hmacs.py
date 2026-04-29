#!/usr/bin/env python3
"""
Generate "separate HMACs" KDF fixtures from python-doubleratchet's
`recommended.kdf_separate_hmacs.KDF`. Output JSON consumed by Rust replay tests.

Mechanism: for each byte b[i] of the KDF data, compute HMAC-<hash>(key, b[i]),
and concatenate. Output length must be `len(data) * hash_size`.

OMEMO 2 / twomemo uses this as the message-chain KDF with
`data = b"\\x02\\x01"` and SHA-256, splitting the 64-byte output into
(new_chain_key, message_key).
"""
import asyncio
import hashlib
import json
from pathlib import Path

from doubleratchet.recommended import HashFunction, kdf_separate_hmacs

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "kdf_separate_hmacs.json"


def det(seed: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def make_kdf(hash_fn: HashFunction):
    class K(kdf_separate_hmacs.KDF):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return hash_fn

    return K


HASH_NAMES = {
    HashFunction.SHA_256: "sha256",
    HashFunction.SHA_512: "sha512",
}


async def gen_case(label: str, hash_fn: HashFunction, key: bytes, data: bytes) -> dict:
    K = make_kdf(hash_fn)
    out_len = len(data) * (32 if hash_fn is HashFunction.SHA_256 else 64)
    out = await K.derive(key, data, out_len)
    return {
        "label": label,
        "hash": HASH_NAMES[hash_fn],
        "key_hex": key.hex(),
        "data_hex": data.hex(),
        "out_len": out_len,
        "expected_hex": out.hex(),
    }


async def main():
    cases = []

    # Canonical OMEMO 2 message chain: SHA-256, data = b"\x02\x01" (twomemo
    # MESSAGE_CHAIN_CONSTANT, applied per chain step).
    for n in range(8):
        seed = det(b"kdf-sep-hmac-fixture", f"omemo-{n}", 32)
        key = det(seed, "key", 32)
        cases.append(await gen_case(f"omemo-{n}", HashFunction.SHA_256, key, b"\x02\x01"))

    # 1-byte data (only message_key derive, or only chain_key derive).
    for n, b in enumerate([b"\x01", b"\x02", b"\xff"]):
        seed = det(b"kdf-sep-hmac-fixture", f"single-{n}", 32)
        key = det(seed, "key", 32)
        cases.append(await gen_case(f"single-{b.hex()}-{n}", HashFunction.SHA_256, key, b))

    # Longer data — exercises the loop.
    for n in range(3):
        seed = det(b"kdf-sep-hmac-fixture", f"long-{n}", 32)
        key = det(seed, "key", 32)
        data = bytes(range(1, 1 + 5 + n))  # 5..7 bytes
        cases.append(await gen_case(f"long-{n}", HashFunction.SHA_256, key, data))

    # SHA-512 variant.
    for n in range(3):
        seed = det(b"kdf-sep-hmac-fixture", f"sha512-{n}", 32)
        key = det(seed, "key", 64)
        cases.append(await gen_case(f"sha512-{n}", HashFunction.SHA_512, key, b"\x02\x01"))

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.recommended.kdf_separate_hmacs",
        "algorithm": "separate-HMACs KDF (per-byte HMAC concat)",
        "note": "for each byte b in data: out += HMAC(key, b); twomemo uses data=b'\\x02\\x01' for the message chain",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
