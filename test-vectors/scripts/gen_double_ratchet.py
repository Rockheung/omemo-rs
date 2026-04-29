#!/usr/bin/env python3
"""
Generate top-level DoubleRatchet fixtures for the Stage 1.2 gate test.

Scenario (matches `docs/stages.md` Stage 1.2 gate):
  1. Alice → Bob:  M0  (initial; bootstraps Bob's DR via decrypt_initial_message)
  2. Bob → Alice:  M1  (triggers Alice's DH ratchet step on receive)
  3. Alice → Bob:  M2, M3   (Alice uses her new sending chain; M2 is "skipped"
                              by being delivered AFTER M3, exercising
                              out-of-order delivery and the skipped-keys cache)

Implementation notes:
* Custom DR class with deterministic `_generate_priv` (queue) and a
  deterministic `_build_associated_data`: ad || ratchet_pub(32) || pn(8 LE) ||
  n(8 LE).  The Rust port uses the same encoding via
  `double_ratchet::build_ad_default`.
* AEAD: twomemo's recommended AES-CBC + HMAC-SHA-256, info = "OMEMO Message
  Key Material" (full HMAC tail; the 16-byte truncation lives in
  omemo-twomemo, not in omemo-doubleratchet).
"""
import asyncio
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from doubleratchet import double_ratchet
from doubleratchet.recommended import (
    HashFunction,
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519,
    kdf_hkdf,
    kdf_separate_hmacs,
)
from doubleratchet.types import EncryptedMessage, Header

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "double_ratchet.json"
TWOMEMO_CONST = b"\x02\x01"
DOS_THRESHOLD = 1000
MAX_SKIP = 1000


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


def make_aead():
    class A(aead_aes_hmac.AEAD):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return HashFunction.SHA_256

        @staticmethod
        def _get_info() -> bytes:
            return b"OMEMO Message Key Material"

    return A


def make_dr_classes(priv_queue: list[bytes]):
    queue = list(priv_queue)

    class DR(diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet):
        @staticmethod
        def _generate_priv() -> bytes:
            return queue.pop(0)

    class TopDR(double_ratchet.DoubleRatchet):
        @staticmethod
        def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
            return (
                associated_data
                + header.ratchet_pub
                + header.previous_sending_chain_length.to_bytes(8, "little")
                + header.sending_chain_length.to_bytes(8, "little")
            )

    return DR, TopDR


def x25519_pub(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def header_dict(h: Header) -> dict:
    return {
        "ratchet_pub_hex": h.ratchet_pub.hex(),
        "pn": h.previous_sending_chain_length,
        "n": h.sending_chain_length,
    }


def encrypted_dict(em: EncryptedMessage) -> dict:
    return {
        "header": header_dict(em.header),
        "ciphertext_hex": em.ciphertext.hex(),
    }


async def gen_scenario(seed: bytes) -> dict:
    shared = det(seed, "shared", 32)
    ad = det(seed, "ad", 64)

    bob_spk_priv = det(seed, "bob-spk", 32)
    bob_spk_pub = x25519_pub(bob_spk_priv)

    # Pre-stage Alice's and Bob's priv queues. Alice generates 2 (initial
    # active priv, then a fresh priv when she rachet-steps on Bob's reply).
    # Bob generates 2 (a fresh priv inside passive __init__, then a fresh
    # priv when he ratchet-steps on Alice's M2/M3).
    alice_p1 = det(seed, "alice-1", 32)
    alice_p2 = det(seed, "alice-2", 32)
    bob_p1 = det(seed, "bob-1", 32)
    bob_p2 = det(seed, "bob-2", 32)

    AliceDR, AliceTop = make_dr_classes([alice_p1, alice_p2])
    BobDR, BobTop = make_dr_classes([bob_p1, bob_p2])

    # M0: Alice sends initial message.
    alice, em0 = await AliceTop.encrypt_initial_message(
        diffie_hellman_ratchet_class=AliceDR,
        root_chain_kdf=make_root_kdf(),
        message_chain_kdf=make_msg_kdf(),
        message_chain_constant=TWOMEMO_CONST,
        dos_protection_threshold=DOS_THRESHOLD,
        max_num_skipped_message_keys=MAX_SKIP,
        aead=make_aead(),
        shared_secret=shared,
        recipient_ratchet_pub=bob_spk_pub,
        message=b"hello bob, this is the very first message",
        associated_data=ad,
    )

    # Bob receives M0, bootstraps his DR.
    bob, m0_pt = await BobTop.decrypt_initial_message(
        diffie_hellman_ratchet_class=BobDR,
        root_chain_kdf=make_root_kdf(),
        message_chain_kdf=make_msg_kdf(),
        message_chain_constant=TWOMEMO_CONST,
        dos_protection_threshold=DOS_THRESHOLD,
        max_num_skipped_message_keys=MAX_SKIP,
        aead=make_aead(),
        shared_secret=shared,
        own_ratchet_priv=bob_spk_priv,
        message=em0,
        associated_data=ad,
    )
    assert m0_pt == b"hello bob, this is the very first message"

    # M1: Bob → Alice (introduces Bob's new ratchet pub, will trigger Alice's
    # DH ratchet step on receipt).
    em1 = await bob.encrypt_message(b"hello alice, got your message", ad)
    m1_pt = await alice.decrypt_message(em1, ad)
    assert m1_pt == b"hello alice, got your message"

    # M2, M3: Alice → Bob, but delivered out-of-order (M3 arrives first; M2
    # is skipped, then later delivered from Alice's skipped-keys cache on
    # Bob's side).
    em2 = await alice.encrypt_message(b"second message from alice", ad)
    em3 = await alice.encrypt_message(b"third message from alice", ad)

    # Bob receives M3 first — this triggers his DH ratchet step (Alice's
    # ratchet pub changed to alice_p2's pub) AND skips m=0 on the new
    # receive chain (which is Alice's M2). The skipped key is buffered.
    m3_pt = await bob.decrypt_message(em3, ad)
    assert m3_pt == b"third message from alice"
    bob_skipped_after_m3 = len(bob._DoubleRatchet__skipped_message_keys)

    # Now Bob receives M2 — should resolve from the skipped-keys cache.
    m2_pt = await bob.decrypt_message(em2, ad)
    assert m2_pt == b"second message from alice"
    bob_skipped_after_m2 = len(bob._DoubleRatchet__skipped_message_keys)

    return {
        "label": seed.hex()[:8],
        "shared_secret_hex": shared.hex(),
        "associated_data_hex": ad.hex(),
        "constant_hex": TWOMEMO_CONST.hex(),
        "max_skip": MAX_SKIP,
        "dos_threshold": DOS_THRESHOLD,
        "alice_priv_queue_hex": [alice_p1.hex(), alice_p2.hex()],
        "bob_spk_priv_hex": bob_spk_priv.hex(),
        "bob_spk_pub_hex": bob_spk_pub.hex(),
        "bob_priv_queue_hex": [bob_p1.hex(), bob_p2.hex()],
        "messages": [
            {
                "label": "M0 alice→bob initial",
                "plaintext_hex": m0_pt.hex(),
                "encrypted": encrypted_dict(em0),
            },
            {
                "label": "M1 bob→alice (triggers Alice DH step)",
                "plaintext_hex": m1_pt.hex(),
                "encrypted": encrypted_dict(em1),
            },
            {
                "label": "M2 alice→bob (delivered second, recovered from skip)",
                "plaintext_hex": m2_pt.hex(),
                "encrypted": encrypted_dict(em2),
            },
            {
                "label": "M3 alice→bob (delivered first, triggers Bob DH step + skip)",
                "plaintext_hex": m3_pt.hex(),
                "encrypted": encrypted_dict(em3),
            },
        ],
        "delivery_order": [
            {"to": "bob", "msg": 0},
            {"to": "alice", "msg": 1},
            {"to": "bob", "msg": 3},  # out-of-order: M3 arrives first.
            {"to": "bob", "msg": 2},
        ],
        "expected_bob_skipped_after_m3": bob_skipped_after_m3,
        "expected_bob_skipped_after_m2": bob_skipped_after_m2,
    }


async def main():
    cases = [await gen_scenario(det(b"dr-fixture", "scenario-1", 32))]

    fixture = {
        "source": "python-doubleratchet 1.3.0 / doubleratchet.double_ratchet",
        "algorithm": "DoubleRatchet (4-message round-trip with DH step + skip + OOO delivery)",
        "note": "build_associated_data = ad || ratchet_pub(32) || pn(8 LE) || n(8 LE); AEAD info = 'OMEMO Message Key Material' (full HMAC tail)",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases ({sum(len(c['messages']) for c in cases)} messages) → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
