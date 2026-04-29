#!/usr/bin/env python3
"""
Generate symmetric-key ratchet fixtures from python-doubleratchet's
`symmetric_key_ratchet.SymmetricKeyRatchet`.

Each case scripts a sequence of operations:
* `replace_sending(key)` / `replace_receiving(key)`
* `enc()` — calls next_encryption_key, records the 32-byte output and
  ratchet state.
* `dec()` — calls next_decryption_key, records similarly.

We exercise interleavings + a sending-chain rotation to verify the
`previous_sending_chain_length` capture.
"""
import asyncio
import hashlib
import json
from pathlib import Path

from doubleratchet import symmetric_key_ratchet
from doubleratchet.recommended import HashFunction, kdf_separate_hmacs

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "symmetric_key_ratchet.json"
TWOMEMO_CONST = b"\x02\x01"


def det(seed: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def make_kdf():
    class K(kdf_separate_hmacs.KDF):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return HashFunction.SHA_256

    return K


async def gen_case(seed: bytes, ops: list[tuple[str, bytes | None]]) -> dict:
    K = make_kdf()
    skr = symmetric_key_ratchet.SymmetricKeyRatchet.create(K, TWOMEMO_CONST)
    log = []
    for kind, payload in ops:
        if kind == "replace_send":
            skr.replace_chain(symmetric_key_ratchet.Chain.SENDING, payload)
            log.append({
                "op": "replace_send",
                "key_hex": payload.hex(),
                "send_len_after": skr.sending_chain_length,
                "recv_len_after": skr.receiving_chain_length,
                "prev_send_len_after": skr.previous_sending_chain_length,
            })
        elif kind == "replace_recv":
            skr.replace_chain(symmetric_key_ratchet.Chain.RECEIVING, payload)
            log.append({
                "op": "replace_recv",
                "key_hex": payload.hex(),
                "send_len_after": skr.sending_chain_length,
                "recv_len_after": skr.receiving_chain_length,
                "prev_send_len_after": skr.previous_sending_chain_length,
            })
        elif kind == "enc":
            mk = await skr.next_encryption_key()
            log.append({
                "op": "enc",
                "out_hex": mk.hex(),
                "send_len_after": skr.sending_chain_length,
                "recv_len_after": skr.receiving_chain_length,
                "prev_send_len_after": skr.previous_sending_chain_length,
            })
        elif kind == "dec":
            mk = await skr.next_decryption_key()
            log.append({
                "op": "dec",
                "out_hex": mk.hex(),
                "send_len_after": skr.sending_chain_length,
                "recv_len_after": skr.receiving_chain_length,
                "prev_send_len_after": skr.previous_sending_chain_length,
            })
        else:
            raise ValueError(kind)
    return {
        "label": seed.hex()[:8],
        "constant_hex": TWOMEMO_CONST.hex(),
        "ops": log,
    }


async def main():
    cases = []

    # Case A: full bidirectional flow with rotation.
    seed_a = det(b"skr-fixture", "alice", 32)
    ck1 = det(seed_a, "ck-1", 32)
    ck2 = det(seed_a, "ck-2", 32)
    ck3 = det(seed_a, "ck-3", 32)
    ops_a = [
        ("replace_send", ck1),
        ("enc", None), ("enc", None), ("enc", None),
        ("replace_recv", ck2),
        ("dec", None), ("dec", None),
        ("replace_send", ck3),  # should set previous_sending_chain_length=3
        ("enc", None),
        ("dec", None),
    ]
    cases.append(await gen_case(seed_a, ops_a))

    # Case B: receive-only chain (no sending chain ever set).
    seed_b = det(b"skr-fixture", "bob-recv", 32)
    cases.append(await gen_case(seed_b, [
        ("replace_recv", det(seed_b, "ck", 32)),
        ("dec", None), ("dec", None), ("dec", None), ("dec", None),
    ]))

    # Case C: send-only.
    seed_c = det(b"skr-fixture", "charlie-send", 32)
    cases.append(await gen_case(seed_c, [
        ("replace_send", det(seed_c, "ck", 32)),
        ("enc", None), ("enc", None), ("enc", None),
    ]))

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.symmetric_key_ratchet",
        "algorithm": "SymmetricKeyRatchet",
        "note": "constant b'\\x02\\x01' = twomemo MESSAGE_CHAIN_CONSTANT",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases ({sum(len(c['ops']) for c in cases)} ops) → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
