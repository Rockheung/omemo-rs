#!/usr/bin/env python3
"""
Generate X3DH key agreement fixtures for OMEMO 2 (twomemo configuration).

Approach:
* Build deterministic Bob (passive) state via `BaseState.from_model`:
  IK seed → priv via SHA-512+clamp; SPK is signed using a recorded XEdDSA
  nonce; OPKs come from a deterministic seed expansion.
* Build deterministic Alice (active) state similarly.
* Monkey-patch `secrets.token_bytes` to return a recorded ephemeral priv
  during the active call, and `secrets.choice` to deterministically return
  the chosen OPK.
* Run active+passive, assert SS_alice == SS_bob, then record everything.

The Rust port (`omemo-x3dh`) takes ephemeral_priv and chosen_opk_pub as
explicit arguments so it doesn't need monkey-patching to replay.
"""
import asyncio
import hashlib
import json
import secrets as _secrets
from pathlib import Path

import xeddsa
from x3dh.base_state import BaseState
from x3dh.identity_key_pair import IdentityKeyPairSeed
from x3dh.signed_pre_key_pair import SignedPreKeyPair
from x3dh.pre_key_pair import PreKeyPair
from x3dh.types import IdentityKeyFormat, Header
from x3dh.crypto_provider import HashFunction
from x3dh import base_state as base_state_module

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "x3dh.json"
OMEMO_INFO = b"OMEMO X3DH"


class TwomemoState(BaseState):
    """`twomemo.StateImpl` analogue: ED_25519 IK format, pass-through encode."""

    @staticmethod
    def _encode_public_key(key_format, pub):
        return pub


def det(seed: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def make_state(seed: bytes, num_opks: int) -> TwomemoState:
    """Build a TwomemoState entirely from deterministic material."""
    ik_seed = det(seed, "ik-seed", 32)
    ik_priv = xeddsa.seed_to_priv(ik_seed)

    # SPK — for ED_25519 IK format (twomemo), sign with the raw IK priv so
    # the signing key's derived Ed25519 pub equals bundle.identity_key (which
    # is priv_to_ed25519_pub(ik_priv), preserving the natural sign bit).
    spk_priv = det(seed, "spk-priv", 32)
    spk_nonce = det(seed, "spk-nonce", 64)
    spk_pub = xeddsa.priv_to_curve25519_pub(spk_priv)
    spk_sig = xeddsa.ed25519_priv_sign(ik_priv, spk_pub, spk_nonce)
    spk = SignedPreKeyPair(priv=spk_priv, sig=spk_sig, timestamp=1234567890)

    # Build state via low-level construction (skip __generate_spk)
    state = TwomemoState()
    # Bypass the abstract-class private-name-mangled fields
    state._BaseState__identity_key_format = IdentityKeyFormat.ED_25519
    state._BaseState__hash_function = HashFunction.SHA_256
    state._BaseState__info = OMEMO_INFO
    state._BaseState__identity_key = IdentityKeyPairSeed(ik_seed)
    state._BaseState__signed_pre_key = spk
    state._BaseState__old_signed_pre_key = None
    state._BaseState__pre_keys = {
        PreKeyPair(priv=det(seed, f"opk-{i}", 32)) for i in range(num_opks)
    }
    state._BaseState__hidden_pre_keys = set()
    return state


async def gen_case(label: str, alice_seed: bytes, bob_seed: bytes,
                   ad_appendix: bytes, ek_priv: bytes, num_bob_opks: int,
                   require_pre_key: bool, use_pre_key: bool) -> dict:
    alice = make_state(alice_seed, num_opks=0)
    bob = make_state(bob_seed, num_opks=num_bob_opks)

    bob_bundle = bob.bundle

    # Choose an OPK deterministically: sort bob's OPKs by hex and pick the first.
    opks_sorted = sorted(bob_bundle.pre_keys, key=lambda b: b.hex())
    chosen_opk = opks_sorted[0] if (use_pre_key and opks_sorted) else None

    # Monkey-patch secrets in the x3dh.base_state module for this call.
    old_token = base_state_module.secrets.token_bytes
    old_choice = base_state_module.secrets.choice

    def fake_token_bytes(n):
        if n == 32:
            return ek_priv
        return _secrets.token_bytes(n)

    def fake_choice(seq):
        # Always return the deterministically-chosen OPK if present.
        if chosen_opk is not None and chosen_opk in seq:
            return chosen_opk
        return _secrets.choice(seq)

    try:
        base_state_module.secrets.token_bytes = fake_token_bytes
        base_state_module.secrets.choice = fake_choice

        ss_a, ad_a, header = await alice.get_shared_secret_active(
            bob_bundle,
            associated_data_appendix=ad_appendix,
            require_pre_key=require_pre_key,
        )
        ss_b, ad_b, used_spk = await bob.get_shared_secret_passive(
            header,
            associated_data_appendix=ad_appendix,
            require_pre_key=require_pre_key,
        )
    finally:
        base_state_module.secrets.token_bytes = old_token
        base_state_module.secrets.choice = old_choice

    assert ss_a == ss_b, "active vs passive shared secret mismatch"
    assert ad_a == ad_b, "active vs passive associated data mismatch"

    return {
        "label": label,
        "associated_data_appendix_hex": ad_appendix.hex(),
        "ephemeral_priv_hex": ek_priv.hex(),
        "use_pre_key": use_pre_key,
        "require_pre_key": require_pre_key,
        "alice": {
            "ik_seed_hex": det(alice_seed, "ik-seed", 32).hex(),
            "spk_priv_hex": det(alice_seed, "spk-priv", 32).hex(),
            "spk_nonce_hex": det(alice_seed, "spk-nonce", 64).hex(),
            "ik_pub_ed_hex": alice.bundle.identity_key.hex(),
        },
        "bob": {
            "ik_seed_hex": det(bob_seed, "ik-seed", 32).hex(),
            "spk_priv_hex": det(bob_seed, "spk-priv", 32).hex(),
            "spk_nonce_hex": det(bob_seed, "spk-nonce", 64).hex(),
            "opk_privs_hex": [det(bob_seed, f"opk-{i}", 32).hex() for i in range(num_bob_opks)],
            "bundle": {
                "ik_pub_hex": bob_bundle.identity_key.hex(),
                "spk_pub_hex": bob_bundle.signed_pre_key.hex(),
                "spk_sig_hex": bob_bundle.signed_pre_key_sig.hex(),
                "opks_pub_hex": [pk.hex() for pk in opks_sorted],
            },
        },
        "header": {
            "ik_hex": header.identity_key.hex(),
            "ek_hex": header.ephemeral_key.hex(),
            "spk_hex": header.signed_pre_key.hex(),
            "opk_hex": header.pre_key.hex() if header.pre_key else None,
        },
        "shared_secret_hex": ss_a.hex(),
        "associated_data_hex": ad_a.hex(),
    }


async def main():
    cases = []
    for n in range(3):
        cases.append(await gen_case(
            f"with-opk-{n}",
            alice_seed=det(b"x3dh-fixture", f"alice-{n}", 32),
            bob_seed=det(b"x3dh-fixture", f"bob-{n}", 32),
            ad_appendix=det(b"x3dh-fixture", f"ad-{n}", 24),
            ek_priv=det(b"x3dh-fixture", f"ek-{n}", 32),
            num_bob_opks=3,
            require_pre_key=True,
            use_pre_key=True,
        ))

    # No-OPK case (require_pre_key=False).
    cases.append(await gen_case(
        "no-opk",
        alice_seed=det(b"x3dh-fixture", "alice-noopk", 32),
        bob_seed=det(b"x3dh-fixture", "bob-noopk", 32),
        ad_appendix=b"",
        ek_priv=det(b"x3dh-fixture", "ek-noopk", 32),
        num_bob_opks=0,
        require_pre_key=False,
        use_pre_key=False,
    ))

    fixture = {
        "source": "python-x3dh 1.3.0 (twomemo configuration: ED_25519 IK format, info=OMEMO X3DH)",
        "algorithm": "X3DH",
        "note": "ephemeral_priv injected via monkey-patched secrets.token_bytes; OPK choice forced by sort order",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
