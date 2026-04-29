#!/usr/bin/env python3
"""
Stage 1.4 GATE TEST fixture: Alice initiates a session with Bob and sends
1 KEX + 3 follow-up messages. Output the wire bytes (serialized
OMEMOKeyExchange + 3 OMEMOAuthenticatedMessages) so the Rust side can
replay byte-equal.

This stitches python-x3dh (StateImpl) + python-doubleratchet
(DoubleRatchetImpl + AEADImpl) together exactly the way python-twomemo
does — but without bringing in python-omemo's session orchestration. We
just want the wire bytes.
"""
import asyncio
import hashlib
import json
import secrets as _secrets
from pathlib import Path

import xeddsa

from doubleratchet.recommended import (
    HashFunction,
    diffie_hellman_ratchet_curve25519,
    kdf_hkdf,
    kdf_separate_hmacs,
)
from doubleratchet import diffie_hellman_ratchet as dhr_mod, double_ratchet as dr_mod

from x3dh.base_state import BaseState
from x3dh.identity_key_pair import IdentityKeyPairSeed
from x3dh.signed_pre_key_pair import SignedPreKeyPair
from x3dh.pre_key_pair import PreKeyPair
from x3dh.types import IdentityKeyFormat, Header as X3dhHeader
from x3dh.crypto_provider import HashFunction as X3dhHash
from x3dh import base_state as base_state_module

from twomemo.twomemo import (
    AEADImpl,
    DoubleRatchetImpl,
    MessageChainKDFImpl,
    RootChainKDFImpl,
    OMEMOAuthenticatedMessage,
    OMEMOKeyExchange,
)

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "twomemo.json"


def det(seed: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


class TwomemoState(BaseState):
    @staticmethod
    def _encode_public_key(_, pub):
        return pub


def make_state(seed: bytes, num_opks: int) -> TwomemoState:
    ik_seed = det(seed, "ik-seed", 32)
    ik_priv = xeddsa.seed_to_priv(ik_seed)
    spk_priv = det(seed, "spk-priv", 32)
    spk_nonce = det(seed, "spk-nonce", 64)
    spk_pub = xeddsa.priv_to_curve25519_pub(spk_priv)
    spk_sig = xeddsa.ed25519_priv_sign(ik_priv, spk_pub, spk_nonce)
    spk = SignedPreKeyPair(priv=spk_priv, sig=spk_sig, timestamp=1234567890)

    state = TwomemoState()
    state._BaseState__identity_key_format = IdentityKeyFormat.ED_25519
    state._BaseState__hash_function = X3dhHash.SHA_256
    state._BaseState__info = b"OMEMO X3DH"
    state._BaseState__identity_key = IdentityKeyPairSeed(ik_seed)
    state._BaseState__signed_pre_key = spk
    state._BaseState__old_signed_pre_key = None
    state._BaseState__pre_keys = {
        PreKeyPair(priv=det(seed, f"opk-{i}", 32)) for i in range(num_opks)
    }
    state._BaseState__hidden_pre_keys = set()
    return state


def make_dr_class(priv_queue: list[bytes]):
    """Build a per-actor DR subclass with deterministic _generate_priv."""
    queue = list(priv_queue)

    class DR(diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet):
        @staticmethod
        def _generate_priv() -> bytes:
            return queue.pop(0)

    return DR


async def main():
    seed = det(b"twomemo-fixture", "scenario", 32)

    alice = make_state(det(seed, "alice", 32), num_opks=0)
    bob = make_state(det(seed, "bob", 32), num_opks=3)

    bob_bundle = bob.bundle
    chosen_opk = sorted(bob_bundle.pre_keys, key=lambda b: b.hex())[0]

    ek_priv = det(seed, "ek-priv", 32)
    ad_appendix = b""

    # Monkey-patch x3dh's secrets calls.
    old_token = base_state_module.secrets.token_bytes
    old_choice = base_state_module.secrets.choice
    base_state_module.secrets.token_bytes = lambda n: ek_priv if n == 32 else old_token(n)
    base_state_module.secrets.choice = lambda seq: chosen_opk if chosen_opk in seq else old_choice(seq)
    try:
        ss_a, ad_a, x3dh_header = await alice.get_shared_secret_active(bob_bundle, b"")
        ss_b, ad_b, used_spk = await bob.get_shared_secret_passive(x3dh_header, b"")
    finally:
        base_state_module.secrets.token_bytes = old_token
        base_state_module.secrets.choice = old_choice
    assert ss_a == ss_b
    assert ad_a == ad_b

    # IDs in the KEX. python-twomemo uses arbitrary IDs assigned by storage.
    # We pick fixed ones for the fixture.
    spk_id = 1
    pk_id = 100  # corresponds to chosen_opk

    # ---- Alice DR (active). _generate_priv yields 1 fresh priv (initial),
    # plus more if she ever receives a message that triggers a ratchet step
    # (not the case in this 1-direction scenario, but stage anyway).
    AliceDR = make_dr_class([
        det(seed, "alice-dr-1", 32),
        det(seed, "alice-dr-2", 32),
    ])

    # The DR's other_ratchet_pub is bob's SPK pub (Curve25519).
    alice_dr, em0 = await DoubleRatchetImpl.encrypt_initial_message(
        diffie_hellman_ratchet_class=AliceDR,
        root_chain_kdf=RootChainKDFImpl,
        message_chain_kdf=MessageChainKDFImpl,
        message_chain_constant=DoubleRatchetImpl.MESSAGE_CHAIN_CONSTANT,
        dos_protection_threshold=100,
        max_num_skipped_message_keys=1000,
        aead=AEADImpl,
        shared_secret=ss_a,
        recipient_ratchet_pub=bob_bundle.signed_pre_key,
        message=b"hello bob (M0 in KEX)",
        associated_data=ad_a,
    )
    # em0.ciphertext is the serialised OMEMOAuthenticatedMessage bytes
    # (twomemo's AEADImpl.encrypt return value).
    auth_m0_bytes = em0.ciphertext
    # Wrap as KEX.
    auth_m0_parsed = OMEMOAuthenticatedMessage.FromString(auth_m0_bytes)
    kex0_bytes = OMEMOKeyExchange(
        pk_id=pk_id,
        spk_id=spk_id,
        ik=alice.bundle.identity_key,
        ek=x3dh_header.ephemeral_key,
        message=auth_m0_parsed,
    ).SerializeToString()

    # ---- Alice sends 3 follow-up messages.
    msgs = []
    for i in range(1, 4):
        em = await alice_dr.encrypt_message(
            f"alice msg #{i}".encode("utf-8"),
            ad_a,
        )
        msgs.append(em)

    # ---- Bob bootstrap from KEX.
    BobDR = make_dr_class([
        det(seed, "bob-dr-1", 32),
        det(seed, "bob-dr-2", 32),
    ])
    bob_dr, m0_pt = await DoubleRatchetImpl.decrypt_initial_message(
        diffie_hellman_ratchet_class=BobDR,
        root_chain_kdf=RootChainKDFImpl,
        message_chain_kdf=MessageChainKDFImpl,
        message_chain_constant=DoubleRatchetImpl.MESSAGE_CHAIN_CONSTANT,
        dos_protection_threshold=100,
        max_num_skipped_message_keys=1000,
        aead=AEADImpl,
        shared_secret=ss_b,
        own_ratchet_priv=used_spk.priv,
        message=em0,
        associated_data=ad_b,
    )
    assert m0_pt == b"hello bob (M0 in KEX)"

    # Bob decrypts M1, M2, M3 in order.
    decrypted = []
    for em in msgs:
        decrypted.append(await bob_dr.decrypt_message(em, ad_b))
    for i, pt in enumerate(decrypted, 1):
        assert pt == f"alice msg #{i}".encode("utf-8")

    fixture = {
        "source": "python-twomemo 2.1 + python-doubleratchet 1.3.0 + python-x3dh 1.3.0",
        "algorithm": "OMEMO 2 (twomemo) wire format",
        "note": "alice initiates → 1 KEX wrapping M0 + 3 follow-up OMEMOAuthenticatedMessages",

        "shared_secret_hex": ss_a.hex(),
        "associated_data_hex": ad_a.hex(),
        "spk_id": spk_id,
        "pk_id": pk_id,

        "alice": {
            "ik_seed_hex": det(det(seed, "alice", 32), "ik-seed", 32).hex(),
            "ik_pub_ed_hex": alice.bundle.identity_key.hex(),
            "ek_priv_hex": ek_priv.hex(),
            "ek_pub_hex": x3dh_header.ephemeral_key.hex(),
            "dr_priv_queue_hex": [
                det(seed, "alice-dr-1", 32).hex(),
                det(seed, "alice-dr-2", 32).hex(),
            ],
        },
        "bob": {
            "spk_priv_hex": used_spk.priv.hex(),
            "spk_pub_hex": bob_bundle.signed_pre_key.hex(),
            "opk_priv_hex": next(
                pk.priv for pk in bob._BaseState__pre_keys if pk.pub == chosen_opk
            ).hex(),
            "opk_pub_hex": chosen_opk.hex(),
            "dr_priv_queue_hex": [
                det(seed, "bob-dr-1", 32).hex(),
                det(seed, "bob-dr-2", 32).hex(),
            ],
        },

        "wire": {
            "kex0_hex": kex0_bytes.hex(),
            "follow_up_hex": [em.ciphertext.hex() for em in msgs],
        },
        "plaintexts_hex": [
            b"hello bob (M0 in KEX)".hex(),
            b"alice msg #1".hex(),
            b"alice msg #2".hex(),
            b"alice msg #3".hex(),
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
