#!/usr/bin/env python3
"""
Generate KDFChain fixtures from python-doubleratchet's `kdf_chain.KDFChain`.

Each fixture case is a sequence of `step(data, length)` invocations on a
single chain, recording the per-step output and the post-step chain key.
We exercise two configurations to catch regressions in either the HKDF wrapper
or the separate-HMACs wrapper underlying the chain:

* `root` — root chain: HKDF-SHA-256 wrapper with info "OMEMO Root Chain",
  data = a 32-byte DH output per step, length=32. Models the OMEMO 2 root
  chain (each step replaces the 32-byte root key and yields a 32-byte chain
  key for a new message chain).
* `msg` — message chain: separate-HMACs SHA-256, data = b"\\x02\\x01"
  (twomemo MESSAGE_CHAIN_CONSTANT), length=32. Models the per-message
  symmetric ratchet step (32-byte chain key in, 32-byte message key out).
"""
import asyncio
import hashlib
import json
from pathlib import Path

from doubleratchet import kdf_chain
from doubleratchet.recommended import HashFunction, kdf_hkdf, kdf_separate_hmacs

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "kdf_chain.json"


def det(seed: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def make_root_kdf():
    class K(kdf_hkdf.KDF):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return HashFunction.SHA_256

        @staticmethod
        def _get_info() -> bytes:
            return b"OMEMO Root Chain"

    return K


def make_msg_kdf():
    class K(kdf_separate_hmacs.KDF):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return HashFunction.SHA_256

    return K


async def gen_root_case(seed: bytes) -> dict:
    K = make_root_kdf()
    initial_key = det(seed, "root-init", 32)
    chain = kdf_chain.KDFChain.create(K, initial_key)
    steps = []
    for i in range(5):
        data = det(seed, f"root-data-{i}", 32)
        out = await chain.step(data, 32)
        steps.append({
            "data_hex": data.hex(),
            "length": 32,
            "out_hex": out.hex(),
            "key_after_hex": chain.model.key.hex(),
            "length_after": chain.model.length,
        })
    return {
        "label": f"root-{seed.hex()[:8]}",
        "kind": "hkdf-root",
        "info_hex": b"OMEMO Root Chain".hex(),
        "hash": "sha256",
        "key_hex": initial_key.hex(),
        "steps": steps,
    }


async def gen_msg_case(seed: bytes) -> dict:
    K = make_msg_kdf()
    initial_key = det(seed, "msg-init", 32)
    chain = kdf_chain.KDFChain.create(K, initial_key)
    steps = []
    for _ in range(6):
        out = await chain.step(b"\x02\x01", 32)
        steps.append({
            "data_hex": "0201",
            "length": 32,
            "out_hex": out.hex(),
            "key_after_hex": chain.model.key.hex(),
            "length_after": chain.model.length,
        })
    return {
        "label": f"msg-{seed.hex()[:8]}",
        "kind": "separate-hmacs-msg",
        "hash": "sha256",
        "key_hex": initial_key.hex(),
        "steps": steps,
    }


async def main():
    cases = []
    for n in range(3):
        cases.append(await gen_root_case(det(b"kdf-chain-fixture", f"root-{n}", 32)))
    for n in range(3):
        cases.append(await gen_msg_case(det(b"kdf-chain-fixture", f"msg-{n}", 32)))

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.kdf_chain",
        "algorithm": "KDFChain",
        "note": "step(data, length) → derive(key.len()+length) → first key.len() bytes replace the key, last length bytes are returned",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
