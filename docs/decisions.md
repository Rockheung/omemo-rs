# Architectural Decisions Log

A short, dated log of decisions whose *rationale* is more important than
the implementation. Order: most recent first. Update this file when a
decision is made or revisited; do not delete superseded entries — mark
them and add the successor below.

---

## ADR-005 — Restrict XEdDSA fixtures to clamped priv

**Date**: 2026-04-29
**Status**: accepted
**Stage**: 1.1

### Context
`python-xeddsa.ed25519_priv_sign(priv, msg, nonce)` is a thin CFFI wrapper
around libxeddsa, which calls libsodium's `ge_scalarmult_base(priv)` to
compute the public point `A`. The libsodium ref10 implementation expects
the scalar's top nibble (`priv[31] >> 4`) to be at most 7 (i.e.
`priv[31] <= 0x7F`); if violated, the 4-bit recoding loop produces a
non-canonical output. This is a precondition violation, not a documented
behaviour.

Our pure-Rust impl uses `Scalar::from_bytes_mod_order(priv)` and
`EdwardsPoint::mul_base`, which is mathematically correct for any 32-byte
input (it reduces `priv` mod `q` first). Hence the two implementations
**legitimately** disagree when `priv[31] >= 0x80`.

### Decision
The fixture generator (`scripts/gen_xeddsa.py`) processes its random
`priv_raw` through `xeddsa.priv_force_sign(priv_raw, False)` before using
it. `priv_force_sign` clamps and then conditionally negates so the result
is always a valid clamped Curve25519 scalar with `priv[31] <= 0x7F`.

### Consequences
* All Stage 1.1 fixtures pass byte-equal.
* This matches real OMEMO usage: every priv passed to `ed25519_priv_sign`
  in production comes from seed expansion (already clamped) or
  `priv_force_sign` itself.
* If a future fixture deliberately wants to exercise the "raw priv"
  pathway (it shouldn't), this ADR must be revisited.

---

## ADR-004 — Test by replay rather than property-based testing

**Date**: 2026-04-29
**Status**: accepted
**Stage**: 0

### Context
`python-doubleratchet`, `python-x3dh`, `python-xeddsa` ship with
property-based test suites (random inputs, structural assertions). These
are great at finding bugs in algorithm structure but blind to byte-level
disagreement between two implementations of the same algorithm.

We need byte-level interop with libxeddsa / python-twomemo / Conversations
/ Dino.

### Decision
Use the Python implementations as **deterministic oracles**:
1. Generator scripts (`scripts/gen_*.py`) feed deterministic inputs into
   the Python oracle and serialise (input, expected output) pairs to
   `fixtures/<primitive>.json`.
2. Rust replay tests load the JSON, run our impl on the same inputs, and
   `assert_eq!` against the expected output.

### Consequences
* Fixtures must be regenerable: every input is derived deterministically
  from a seed, no `os.urandom` without recording it.
* Fixtures are **committed** so contributors without the Python venv can
  still run `cargo test`.
* Upstream version drift is detectable: a CI job (planned) regenerates
  fixtures and `git diff --exit-code` to spot changes.

---

## ADR-003 — Match libxeddsa's non-spec XEdDSA, not the Signal XEdDSA paper

**Date**: 2026-04-29
**Status**: accepted
**Stage**: 1.1

### Context
The Signal XEdDSA spec (Trevor Perrin, 2016) defines:
```
calculate_key_pair(k):
  E = kB
  A = (E.y, sign=0)            # zero the sign bit
  a = if E.s == 1 { -k } else { k }   # negate scalar if Edwards pub had sign=1
r = SHA-512(0xFE || 0xFF*31 || a || M || Z) (mod q)
R = rB
h = SHA-512(R || A || M) (mod q)
s = r + h*a (mod q)
```

`libxeddsa/src/ed25519.c` implements a **simplified variant** that skips
`calculate_key_pair`:
```
A = priv * B   (with its natural sign bit, no clearing)
r = SHA-512(0xFE || 0xFF*31 || priv || M || Z)
R = rB
h = SHA-512(R || A || M)
s = h*priv + r
```

`python-xeddsa` is a thin CFFI binding to `libxeddsa`. Therefore the
"reference" output for OMEMO interop is the libxeddsa variant, not the
spec.

### Decision
`omemo-xeddsa::ed25519_priv_sign` matches **libxeddsa**, not the Signal
XEdDSA paper. Documented inline in the function body.

### Consequences
* OMEMO 2 sessions produced by us will verify with libxeddsa's
  `ed25519_verify` (and hence with python-xeddsa, slixmpp-omemo,
  Conversations, Dino — all of which use libxeddsa or libomemo-c
  underneath for OMEMO 2 identity signatures).
* Sessions produced by a strict-spec XEdDSA implementation will NOT
  verify against ours and vice versa. This is a real interop hazard for
  any non-libxeddsa OMEMO client. We accept this because there is no such
  client in the wild as of 2026-04.

---

## ADR-002 — License chain: drop libsignal and OMEMO 0.3

**Date**: 2026-04-29
**Status**: accepted
**Stage**: pre-0

### Context
Initial plan was to use `signalapp/libsignal` (Rust) as the Double Ratchet
+ X3DH foundation. License check: **AGPL-3.0-only**.

OMEMO 0.3.0 (`eu.siacs.conversations.axolotl`) reference implementation is
`python-oldmemo`, which is also **AGPL-3.0** because it inherits from the
libsignal-protocol-c codebase.

The downstream consumer of `omemo-rs` is the Rust rewrite of
`nan-curunir`, which is currently MIT. AGPL transitive deps are
incompatible with that licence.

### Decision
* Do not depend on `libsignal` (Rust).
* Do not implement OMEMO 0.3.0.
* Implement OMEMO 2 only, on top of MIT-licensed Syndace Python packages
  ported to Rust crypto primitives from RustCrypto.

### Alternatives considered
* Re-license `nan-curunir` as AGPL — rejected; AGPL is invasive on
  network services and the project author has commercial uses in mind.
* Use `vodozemac` (Apache-2.0) — vodozemac implements Olm/Megolm (Matrix
  E2EE), not Signal-style ratchet for OMEMO. Wire-format incompatible
  with OMEMO 2.
* Use one of the small Rust DR crates (`double-ratchet-2`, etc.) —
  rejected; all stale (last update 2022) and not maintained.
* Roll our own Double Ratchet from spec — chosen, but with the test-by-
  replay strategy (ADR-004) keeping us honest against the Syndace Python
  oracles.

### Consequences
* MIT licence chain stays clean.
* OMEMO 0.3.0-only clients cannot talk to us. As of 2026, all major
  clients (Conversations, Dino, Gajim) support OMEMO 2; the bot
  manager controls its own client roster anyway.

---

## ADR-001 — Rewrite XMPP/OMEMO instead of staying on Matrix

**Date**: 2026-04-29 (pre-implementation conversation)
**Status**: accepted
**Stage**: pre-0

### Context
`nan-curunir` is built on `matrix-sdk` 0.9 (mid-2026). Pain points
observed:
* E2EE crypto-store loss requires custom auto-rebootstrap code.
* Cross-signing UIAA requires storing bot account passwords.
* `Continuwuity` admin-room API requires bespoke HTTP polling code
  (`matrix-common::admin`, 983 LOC).
* Matrix room create / invite flow has unhelpful failure modes.

XMPP advantages:
* Mature spec, multiple stable servers.
* Trivial bot account creation (in-band registration or server-side
  admin command).
* Simpler stanza model — XML element tree, no event sourcing.
* Federation works without committee approval.

### Decision
Rewrite the bot orchestrator on XMPP. To reach feature parity with the
current E2EE setup we need OMEMO support, hence this project.

### Consequences
* New-skill territory for the project: XMPP / XEPs / PEP / SCE / OMEMO.
* The transition is easier than feared because the bot orchestration
  domain logic (~13K LOC of nan-curunir) is messenger-agnostic —
  abstracted behind a `Messenger` trait. Only `matrix-common` and
  `channel-matrix` are messenger-specific and will be replaced with
  `omemo-rs` + `omemo-pep` + a thin XMPP-side `channel` crate.
