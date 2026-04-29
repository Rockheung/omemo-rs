#!/usr/bin/env python3
"""
Generate deterministic HKDF test fixtures from python-doubleratchet's
recommended kdf_hkdf implementation. Output JSON consumed by Rust replay tests.

OMEMO 2 (twomemo) uses HKDF-SHA256 for the root chain with info "OMEMO Root Chain".
We exercise that exact configuration plus a few control cases.
"""
import asyncio
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from doubleratchet.recommended import HashFunction, kdf_hkdf

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "kdf_hkdf.json"


def make_kdf(hash_fn: HashFunction, info: bytes):
    class KDF(kdf_hkdf.KDF):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return hash_fn

        @staticmethod
        def _get_info() -> bytes:
            return info

    return KDF


HASH_NAMES = {
    HashFunction.SHA_256: "sha256",
    HashFunction.SHA_512: "sha512",
}


async def gen_case(seed: int, hash_fn: HashFunction, info: bytes,
                   key_len: int, data_len: int, out_len: int) -> dict:
    rng = secrets.SystemRandom(seed) if False else None  # secrets is non-seedable; use os.urandom + record
    key = os.urandom(key_len)
    data = os.urandom(data_len)
    KDF = make_kdf(hash_fn, info)
    out = await KDF.derive(key, data, out_len)
    return {
        "hash": HASH_NAMES[hash_fn],
        "info_hex": info.hex(),
        "key_hex": key.hex(),
        "data_hex": data.hex(),
        "out_len": out_len,
        "expected_hex": out.hex(),
    }


async def main():
    cases = []
    # Canonical OMEMO 2 root chain config
    omemo_info = b"OMEMO Root Chain"
    for n in range(8):
        cases.append(await gen_case(n, HashFunction.SHA_256, omemo_info,
                                    key_len=32, data_len=32, out_len=64))
    # Variants: longer outputs, shorter inputs, sha512
    for n in range(4):
        cases.append(await gen_case(100 + n, HashFunction.SHA_256, b"alt-info",
                                    key_len=32, data_len=64, out_len=32))
    for n in range(4):
        cases.append(await gen_case(200 + n, HashFunction.SHA_512, b"alt-info-512",
                                    key_len=64, data_len=32, out_len=128))

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.recommended.kdf_hkdf",
        "algorithm": "HKDF",
        "note": "info parameter is fixed per-KDF-instance; data is HKDF salt+ikm split per impl",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases → {OUT.relative_to(Path.cwd().parent)}")


if __name__ == "__main__":
    asyncio.run(main())
