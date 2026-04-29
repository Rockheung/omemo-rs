#!/usr/bin/env python3
"""
Generate Diffie-Hellman ratchet fixtures.

Approach: subclass python-doubleratchet's `DiffieHellmanRatchet` (Curve25519
backend) so that `_generate_priv` pulls from a class-level deterministic queue.
Pre-stage the queue, then run a scripted Alice ↔ Bob conversation with one
mid-stream DH ratchet step and record:

* The injected priv keys (Alice's two ratchet privs, Bob's two ratchet privs).
* The shared root key (32 bytes).
* For each `enc()` / `dec(header)` call: the message-key bytes and (for dec)
  the skipped-keys list.

The Rust replay test loads the same priv queue and compares per-step bytes.
"""
import asyncio
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from doubleratchet.recommended import (
    HashFunction,
    diffie_hellman_ratchet_curve25519,
    kdf_hkdf,
    kdf_separate_hmacs,
)

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "dh_ratchet.json"
TWOMEMO_CONST = b"\x02\x01"
DOS_THRESHOLD = 1000


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


def x25519_pub(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# Class-level deterministic priv queue. We bind a fresh queue per scenario
# by subclassing inside the scenario function.
def make_dr_class(priv_queue: list[bytes]):
    queue = list(priv_queue)

    class DR(diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet):
        @staticmethod
        def _generate_priv() -> bytes:
            return queue.pop(0)

    return DR


async def gen_scenario(seed: bytes) -> dict:
    """4-message Alice→Bob, Bob→Alice, Alice→Bob, with one mid-stream DH step."""
    root_key = det(seed, "root", 32)

    # Pre-stage priv keys.
    bob_spk_priv = det(seed, "bob-spk", 32)  # passive init "given" priv
    bob_fresh1 = det(seed, "bob-fresh-1", 32)
    bob_fresh2 = det(seed, "bob-fresh-2", 32)

    alice_fresh1 = det(seed, "alice-fresh-1", 32)
    alice_fresh2 = det(seed, "alice-fresh-2", 32)

    bob_spk_pub = x25519_pub(bob_spk_priv)
    alice_pub1 = x25519_pub(alice_fresh1)

    # Alice (active): generates alice_fresh1 in __init__.
    Alice = make_dr_class([alice_fresh1, alice_fresh2])
    alice = await Alice.create(
        own_ratchet_priv=None,
        other_ratchet_pub=bob_spk_pub,
        root_chain_kdf=make_root_kdf(),
        root_chain_key=root_key,
        message_chain_kdf=make_msg_kdf(),
        message_chain_constant=TWOMEMO_CONST,
        dos_protection_threshold=DOS_THRESHOLD,
    )

    log = []

    # M0, M1: Alice → Bob.
    mk_a0, h_a0 = await alice.next_encryption_key()
    log.append(("alice_enc", mk_a0, h_a0, []))
    mk_a1, h_a1 = await alice.next_encryption_key()
    log.append(("alice_enc", mk_a1, h_a1, []))

    # Bob (passive): given bob_spk_priv, generates bob_fresh1 in __init__.
    Bob = make_dr_class([bob_fresh1, bob_fresh2])
    bob = await Bob.create(
        own_ratchet_priv=bob_spk_priv,
        other_ratchet_pub=alice_pub1,
        root_chain_kdf=make_root_kdf(),
        root_chain_key=root_key,
        message_chain_kdf=make_msg_kdf(),
        message_chain_constant=TWOMEMO_CONST,
        dos_protection_threshold=DOS_THRESHOLD,
    )

    mk_b0_recv, sk = await bob.next_decryption_key(h_a0)
    assert mk_b0_recv == mk_a0
    log.append(("bob_dec", mk_b0_recv, h_a0, sk))
    mk_b1_recv, sk = await bob.next_decryption_key(h_a1)
    assert mk_b1_recv == mk_a1
    log.append(("bob_dec", mk_b1_recv, h_a1, sk))

    # M2, M3: Bob → Alice (after Bob's __init__ already produced bob_fresh1
    # and replaced sending chain).
    mk_b0, h_b0 = await bob.next_encryption_key()
    log.append(("bob_enc", mk_b0, h_b0, []))
    mk_b1, h_b1 = await bob.next_encryption_key()
    log.append(("bob_enc", mk_b1, h_b1, []))

    # Alice receives Bob's first message — triggers DH ratchet step (Alice's
    # generate fresh priv pulls alice_fresh2). Then she gets the second one
    # in-order (no skip, no second step).
    mk_a_rcv0, sk = await alice.next_decryption_key(h_b0)
    assert mk_a_rcv0 == mk_b0
    log.append(("alice_dec", mk_a_rcv0, h_b0, sk))
    mk_a_rcv1, sk = await alice.next_decryption_key(h_b1)
    assert mk_a_rcv1 == mk_b1
    log.append(("alice_dec", mk_a_rcv1, h_b1, sk))

    # M4: Alice → Bob, after the ratchet step. Bob will trigger his own
    # ratchet step on receive (header pub is alice_fresh2's pub, ≠ alice_pub1).
    mk_a2, h_a2 = await alice.next_encryption_key()
    log.append(("alice_enc", mk_a2, h_a2, []))

    mk_b2_rcv, sk = await bob.next_decryption_key(h_a2)
    assert mk_b2_rcv == mk_a2
    log.append(("bob_dec", mk_b2_rcv, h_a2, sk))

    # Build serialisable form.
    def header_dict(h):
        return {
            "ratchet_pub_hex": h.ratchet_pub.hex(),
            "pn": h.previous_sending_chain_length,
            "n": h.sending_chain_length,
        }

    def skipped_list(sk):
        # `sk` is OrderedDict[(pub, n) -> msg_key] for dec ops, [] for enc ops.
        if isinstance(sk, list):
            return []
        out = []
        for (pub, n), mk in sk.items():
            out.append({"pub_hex": pub.hex(), "n": n, "mk_hex": mk.hex()})
        return out

    ops = []
    for kind, mk, h, sk in log:
        ops.append({
            "op": kind,
            "mk_hex": mk.hex(),
            "header": header_dict(h),
            "skipped": skipped_list(sk),
        })

    return {
        "label": seed.hex()[:8],
        "constant_hex": TWOMEMO_CONST.hex(),
        "root_info_hex": b"OMEMO Root Chain".hex(),
        "root_chain_key_hex": root_key.hex(),
        "alice_priv_queue_hex": [alice_fresh1.hex(), alice_fresh2.hex()],
        "bob_init_priv_hex": bob_spk_priv.hex(),
        "bob_init_other_pub_hex": alice_pub1.hex(),
        "bob_priv_queue_hex": [bob_fresh1.hex(), bob_fresh2.hex()],
        "bob_initial_other_pub_for_alice_hex": bob_spk_pub.hex(),
        "ops": ops,
    }


async def main():
    cases = [await gen_scenario(det(b"dhr-fixture", "scenario-1", 32))]

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.diffie_hellman_ratchet (Curve25519 subclass with deterministic _generate_priv)",
        "algorithm": "DiffieHellmanRatchet",
        "note": "Alice active + Bob passive; mid-stream DH ratchet step on Alice's first dec; ops are interleaved per-actor.",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases ({sum(len(c['ops']) for c in cases)} ops) → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
