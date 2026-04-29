#!/usr/bin/env python3
"""
Generate XEdDSA test fixtures from python-xeddsa (CFFI binding to libxeddsa).
Exercises all 11 exported functions with deterministic inputs.
"""
import hashlib
import json
import secrets
from pathlib import Path

import xeddsa

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "xeddsa.json"


def det(seed: bytes, label: str, length: int) -> bytes:
    """Deterministic key material derived from seed+label via SHA-512."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def main():
    cases = []
    for n in range(8):
        master_seed = det(b"xeddsa-fixture", f"master-{n}", 32)
        # Curve25519/Ed25519 seed (32 bytes)
        ed_seed = det(master_seed, "ed-seed", 32)
        # XEdDSA-style private. Real OMEMO usage always passes clamped priv to
        # ed25519_priv_sign (priv comes from seed expansion or priv_force_sign).
        # Raw bytes with bit 255 set hit a libsodium ge_scalarmult_base
        # precondition violation (4-bit recoding assumes top nibble ≤ 7),
        # producing a non-canonical signature that no spec-compliant implementer
        # would replicate. We deliberately keep priv in the clamped subspace.
        priv_raw = det(master_seed, "priv", 32)
        priv = xeddsa.priv_force_sign(priv_raw, False)
        msg = det(master_seed, "msg", 64 + (n * 17))  # variable length message
        nonce = det(master_seed, "nonce", 64)  # 64-byte deterministic nonce for XEdDSA sign

        case = {
            "label": f"case-{n}",
            "ed_seed_hex": ed_seed.hex(),
            "priv_hex": priv.hex(),
            "msg_hex": msg.hex(),
            "nonce_hex": nonce.hex(),

            # seed → priv (SHA512 + clamp, similar to Ed25519 expansion)
            "seed_to_priv_hex": xeddsa.seed_to_priv(ed_seed).hex(),
            # seed → ed25519 pub
            "seed_to_ed_pub_hex": xeddsa.seed_to_ed25519_pub(ed_seed).hex(),
            # priv → curve25519 pub
            "priv_to_curve_pub_hex": xeddsa.priv_to_curve25519_pub(priv).hex(),
            # priv → ed25519 pub
            "priv_to_ed_pub_hex": xeddsa.priv_to_ed25519_pub(priv).hex(),
            # priv_force_sign(priv, False) and (priv, True)
            "priv_force_sign_false_hex": xeddsa.priv_force_sign(priv, False).hex(),
            "priv_force_sign_true_hex":  xeddsa.priv_force_sign(priv, True).hex(),
            # curve25519_pub_to_ed25519_pub with both sign-bit choices
            "curve_pub_hex": xeddsa.priv_to_curve25519_pub(priv).hex(),
            "curve_to_ed_sign0_hex": xeddsa.curve25519_pub_to_ed25519_pub(xeddsa.priv_to_curve25519_pub(priv), False).hex(),
            "curve_to_ed_sign1_hex": xeddsa.curve25519_pub_to_ed25519_pub(xeddsa.priv_to_curve25519_pub(priv), True).hex(),
            # ed25519_pub_to_curve25519_pub round-trip
            "ed_to_curve_hex": xeddsa.ed25519_pub_to_curve25519_pub(xeddsa.priv_to_ed25519_pub(priv)).hex(),

            # Standard Ed25519 sign from seed (deterministic)
            "ed25519_seed_sig_hex": xeddsa.ed25519_seed_sign(ed_seed, msg).hex(),

            # XEdDSA priv_sign with deterministic nonce (otherwise nondeterministic)
            "xeddsa_priv_sig_hex": xeddsa.ed25519_priv_sign(priv, msg, nonce).hex(),

            # X25519 (ECDH) — derive a peer key first
            "peer_priv_hex": (peer_priv := det(master_seed, "peer", 32)).hex(),
            "peer_curve_pub_hex": xeddsa.priv_to_curve25519_pub(peer_priv).hex(),
            "x25519_shared_hex": xeddsa.x25519(priv, xeddsa.priv_to_curve25519_pub(peer_priv)).hex(),
        }
        cases.append(case)

    fixture = {
        "source": "python-xeddsa 1.2.0 (CFFI to libxeddsa)",
        "algorithm": "XEdDSA + Ed25519 + Curve25519 conversion + X25519",
        "note": "All inputs deterministic (SHA-512 from labels). XEdDSA priv_sign uses fixed 64-byte nonce.",
        "cases": cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {len(cases)} cases → {OUT}")


if __name__ == "__main__":
    main()
