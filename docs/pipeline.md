# Test-Vector Replay Pipeline

The single most important piece of infrastructure in this project. Every Rust
crypto primitive must produce **byte-identical** output to its Syndace Python
counterpart. This document describes the pipeline so that anyone (or a future
agent) can extend it for a new primitive.

## 1. Why fixture replay rather than property tests

Property-based tests (random inputs, structural assertions) are how
`python-doubleratchet` checks itself. They can detect *bugs in algorithm
structure* but cannot detect *byte-level disagreement* between two
implementations of the same algorithm — which is exactly what we care about
for cross-implementation interop.

Therefore: we use the Python implementation as a **deterministic oracle**,
serialise its outputs into JSON, and assert byte-equal in Rust.

## 2. One-time setup

```bash
cd test-vectors
git clone --depth 1 https://github.com/Syndace/python-doubleratchet.git reference/python-doubleratchet
git clone --depth 1 https://github.com/Syndace/python-x3dh.git           reference/python-x3dh
git clone --depth 1 https://github.com/Syndace/python-xeddsa.git         reference/python-xeddsa
git clone --depth 1 https://github.com/Syndace/python-twomemo.git        reference/python-twomemo
git clone --depth 1 https://github.com/Syndace/python-omemo.git          reference/python-omemo

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install doubleratchet x3dh xeddsa twomemo 'omemo>=1'
```

`reference/` and `.venv/` are both gitignored. The pinned upstream versions
that have been validated:

| Package | Version |
|---|---|
| `doubleratchet` | 1.3.0 |
| `x3dh` | 1.3.0 |
| `xeddsa` | 1.2.0 |
| `twomemo` | 2.1.0 |
| `omemo` | 2.1.0 |

## 3. Pipeline stages

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Python oracle   │ →  │ JSON fixture    │ →  │ Rust replay     │ →  │ assert byte-=== │
│  (Syndace impl) │    │  (gitignored?   │    │  (cargo test)   │    │  panic on diff  │
│                 │    │   no, COMMITTED)│    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

Fixtures **are committed** so contributors without Python can still run the
Rust tests. Regenerating fixtures requires the venv.

## 4. Fixture format

Every fixture file is `test-vectors/fixtures/<primitive>.json` and follows
this skeleton:

```json
{
  "source":    "python-<package> <version> / <module>",
  "algorithm": "<short name>",
  "note":      "implementation notes if any",
  "cases": [
    { "label": "case-0", "<input fields>": "...", "<output fields>": "..." }
  ]
}
```

Inputs and outputs are hex-encoded strings. Use `<name>_hex` suffix to make
this obvious to the reader.

Inputs **must be deterministic** (no `os.urandom` without recording it).
The standard pattern is `det(seed, label, length)` — see
`scripts/gen_xeddsa.py` for the canonical helper. This makes fixtures
regeneration-stable: re-running the generator produces an identical file
unless the algorithm or upstream package changes.

## 5. Generator script template

```python
#!/usr/bin/env python3
"""Generate <primitive> fixtures from python-<package>."""
import hashlib, json
from pathlib import Path

# import the upstream module(s) you are oracle-ing
import doubleratchet  # or x3dh / xeddsa / twomemo

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "<primitive>.json"

def det(seed: bytes, label: str, length: int) -> bytes:
    """Deterministic key material from seed+label via SHA-512 counter mode."""
    out = b""; counter = 0
    while len(out) < length:
        out += hashlib.sha512(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]

def main():
    cases = []
    for n in range(N_CASES):
        seed = det(b"<primitive>-fixture", f"master-{n}", 32)
        # <prepare deterministic inputs>
        # <call upstream oracle>
        # <append result to cases>
    OUT.write_text(json.dumps({
        "source":    f"python-<package> {<package>.__version__}",
        "algorithm": "<name>",
        "note":      "<optional>",
        "cases":     cases,
    }, indent=2))

if __name__ == "__main__":
    main()
```

## 6. Rust replay test template

In `crates/omemo-test-harness/tests/<primitive>.rs`:

```rust
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case { /* mirror the JSON shape */ }

#[test]
fn replay_<primitive>_fixtures() {
    let fixture = load_fixture::<Case>("<primitive>.json").expect("load");
    assert!(!fixture.cases.is_empty());
    for (i, c) in fixture.cases.iter().enumerate() {
        let got = <our Rust function>(...);
        let expected = hex_decode(&c.expected_hex).unwrap();
        assert_eq!(got, expected, "case {i}: mismatch");
    }
}
```

`omemo-test-harness::load_fixture` walks up from the crate manifest to find
the workspace's `test-vectors/fixtures/` directory, so the same harness
works from any crate without absolute paths.

## 7. Adding a new primitive — checklist

1. Identify the upstream Python module(s) you are oracle-ing.
2. Write `scripts/gen_<primitive>.py` based on §5.
3. Run it with the venv active. Verify the output file looks plausible.
4. Add `crates/omemo-test-harness/tests/<primitive>.rs` per §6.
5. Add the Rust crate dep to `omemo-test-harness/Cargo.toml` if not already
   present.
6. `cargo test -p omemo-test-harness --test <primitive>`.
7. Iterate until green. **Do not weaken assertions.** If Rust and Python
   genuinely disagree (e.g. on edge inputs), document the disagreement,
   change the fixture inputs to the realistic subspace, and write a unit
   test pinning the divergence (see XEdDSA's `priv[31] <= 0x7F` story in
   `docs/decisions.md` ADR-005).
8. Commit fixture, generator, replay test, and Rust impl together.

## 8. Debugging failed replay

When a fixture case mismatches, the standard playbook:

1. Add a `tests/<primitive>_debug.rs` that prints intermediate values for
   case-0 and run with `cargo test -- --nocapture`.
2. Recompute the same intermediates in pure Python (or via the upstream
   oracle directly) and diff.
3. Look for: scalar-vs-bytes confusion, big-endian vs little-endian, info
   string differences, off-by-one in HKDF length, libsodium-vs-pure-impl
   precondition violations.
4. If the mismatch is on a primitive used elsewhere too, fix the primitive
   and **all** affected fixtures will start passing. If only certain inputs
   fail, narrow the input domain in the generator (don't paper over with a
   bug-for-bug replica of an unsafe upstream behaviour — see ADR-003).
5. Delete the debug test once green.

## 9. CI (planned)

Not yet wired. When set up (probably GitHub Actions):
* job 1: `cargo test --workspace` against the committed fixtures (no Python
  required).
* job 2: regenerate all fixtures from a frozen `requirements.txt`, then
  `git diff --exit-code test-vectors/fixtures/` to catch upstream drift.

## 10. Fixture inventory (Stage 1 complete)

10 generators / 10 replay tests. All cases are byte-equal across the Rust
and Python paths; `cargo test --workspace` is green.

| Fixture | Generator | Replay test | Cases | Validates |
|---|---|---|---|---|
| `kdf_hkdf.json` | `gen_kdf_hkdf.py` | `tests/kdf_hkdf.rs` | 16 | HKDF-SHA-256/512 wrapper |
| `xeddsa.json` | `gen_xeddsa.py` | `tests/xeddsa.rs` | 8 × 13 | XEdDSA + Curve↔Ed conversions + X25519 (104 assertions) |
| `aead_aes_hmac.json` | `gen_aead_aes_hmac.py` | `tests/aead_aes_hmac.rs` | 20 | AES-256-CBC + HMAC AEAD (base, full HMAC) + 2 tamper tests |
| `kdf_separate_hmacs.json` | `gen_kdf_separate_hmacs.py` | `tests/kdf_separate_hmacs.rs` | 17 | per-byte HMAC concat KDF |
| `kdf_chain.json` | `gen_kdf_chain.py` | `tests/kdf_chain.rs` | 6 | KDF chain (HKDF root + msg chain), multi-step |
| `symmetric_key_ratchet.json` | `gen_symmetric_key_ratchet.py` | `tests/symmetric_key_ratchet.rs` | 3 / 19 ops | sending+receiving chains, send-chain rotation |
| `dh_ratchet.json` | `gen_dh_ratchet.py` | `tests/dh_ratchet.rs` | 1 / 10 ops | Alice ↔ Bob with mid-stream DH ratchet step |
| `double_ratchet.json` | `gen_double_ratchet.py` | `tests/double_ratchet.rs` | 1 / 4 messages | **Stage 1.2 gate** — 4-msg round-trip with DH step + skip + OOO |
| `x3dh.json` | `gen_x3dh.py` | `tests/x3dh.rs` | 4 | **Stage 1.3 gate** — bundle + active/passive SS byte-equal |
| `twomemo.json` | `gen_twomemo.py` | `tests/twomemo.rs` | 1 KEX + 3 msgs | **Stage 1.4 gate** — protobuf wire format byte-equal |

Determinism notes:
* `python-x3dh` uses `secrets.token_bytes` for the active ephemeral and
  `secrets.choice` for OPK selection. Generators monkey-patch both during
  the run; the Rust API takes those values as explicit arguments instead.
* `python-doubleratchet`'s `_generate_priv` is overridden in the gen
  scripts to pull from a per-actor deterministic queue. The Rust API
  exposes `DhPrivProvider` with a `FixedDhPrivProvider` test impl.
* `python-x3dh.__generate_spk` uses a random XEdDSA nonce; we record the
  nonce in the fixture and pass it to `SignedPreKeyPair::create` on the
  Rust side.
