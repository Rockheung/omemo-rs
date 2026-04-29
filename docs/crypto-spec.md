# Crypto Specification

Concrete algorithm choices and constants used by `omemo-rs`. All values
match `python-twomemo`'s `Twomemo` backend (which is the OMEMO 2 / XEP-0384
v0.9 reference implementation in MIT-licensed Python).

## 1. Curve and signatures

* **Curve**: Curve25519 (X25519 form for DH, Ed25519 form for signatures).
* **Identity signing**: XEdDSA — see `docs/decisions.md` ADR-003 for the
  libxeddsa-variant we implement (no `calculate_key_pair` step).
* **Clamping**: RFC 7748 standard
    - `priv[0] &= 0xF8`
    - `priv[31] &= 0x7F`
    - `priv[31] |= 0x40`
* **Scalar reduction**: Always operate on `Scalar` values reduced mod
  `q = 2^252 + 27742317777372353535851937790883648493` (Curve25519 group order).
  In Rust this is `Scalar::from_bytes_mod_order` (32-byte input) or
  `from_bytes_mod_order_wide` (64-byte input).

## 2. Hash function family

* **Primary**: SHA-256 (used by both KDFs and AEAD HMAC).
* **For Ed25519 / XEdDSA**: SHA-512 (RFC 8032 mandates this).
* **For seed expansion** (`seed_to_priv`): SHA-512 then take 32 bytes,
  then clamp.

## 3. Root chain KDF (HKDF)

Per `python-doubleratchet/recommended/kdf_hkdf.py`:

* Algorithm: HKDF-SHA-256 (RFC 5869).
* `salt`  ← KDF "key" parameter.
* `IKM`   ← KDF "data" parameter.
* `info`  ← per-class constant string.

For OMEMO 2 root chain:

* `info = b"OMEMO Root Chain"` (UTF-8, 16 bytes)
* `length = 64` (32 bytes new root key || 32 bytes new chain key)

## 4. Message chain KDF (Separate HMACs)

Per `python-doubleratchet/recommended/kdf_separate_hmacs.py`. Two separate
HMAC-SHA-256 invocations from the chain key:

```
new_chain_key = HMAC-SHA-256(chain_key, b"\x02")
message_key   = HMAC-SHA-256(chain_key, b"\x01")
```

(The `\x01` / `\x02` constant bytes are what python-doubleratchet's
`kdf_separate_hmacs` does. They are NOT the Signal spec's "0x01" /
"0x02" 32-bit-LE constants; they are single literal bytes.)

## 5. AEAD (AES-256-CBC + HMAC-SHA-256, truncated)

Per `python-twomemo/twomemo/twomemo.py` `AEADImpl`:

```
input:
  message_key: 32 bytes (from message chain KDF)
  associated_data: bytes
  plaintext: bytes

derived material:
  hkdf_out = HKDF-SHA-256(
      salt = 32 zero bytes,
      ikm  = message_key,
      info = b"OMEMO Message Key Material",
      length = 80
  )
  encryption_key = hkdf_out[0..32]      # 32 bytes for AES-256
  auth_key       = hkdf_out[32..64]     # 32 bytes for HMAC-SHA-256
  iv             = hkdf_out[64..80]     # 16 bytes IV for AES-CBC

ciphertext = AES-256-CBC(
    key = encryption_key,
    iv  = iv,
    plaintext = pkcs7_pad(plaintext, block_size=16)
)

mac_full = HMAC-SHA-256(
    key = auth_key,
    msg = associated_data || ciphertext
)
mac = mac_full[..16]                    # truncate to 16 bytes

return (ciphertext, mac)
```

The associated data construction is the Double Ratchet "AD" from the spec:
`AD = encode(IK_alice) || encode(IK_bob)` where `encode` is the public-key
encoding for that backend (32-byte Curve25519 public key for OMEMO 2).
**Order matters**: alice's IK first, bob's second, regardless of who is
sending.

## 6. X3DH

Per `python-x3dh` and X3DH spec (Signal Foundation, 2016).

* **Curve**: Curve25519.
* **Hash**: SHA-256.
* **F constant** (DH input prefix): `b"\xFF" * 32` for Curve25519.
* **Info** for the X3DH KDF: `b"OMEMO X3DH"` for OMEMO 2 (per python-x3dh
  default — verify before locking in).
* **DH steps**:
    - DH1 = DH(IKA, SPKB)
    - DH2 = DH(EKA, IKB)
    - DH3 = DH(EKA, SPKB)
    - DH4 = DH(EKA, OPKB)  (only if Bob has a OPK)
* **SK derivation**:
  ```
  SK = HKDF-SHA-256(
      salt   = 32 zero bytes,
      ikm    = F || DH1 || DH2 || DH3 [|| DH4],
      info   = "OMEMO X3DH",
      length = 32
  )
  ```
* **AD** = `encode(IKA_pub) || encode(IKB_pub)` (alice's first).

## 7. DH Ratchet

Per `python-doubleratchet/recommended/diffie_hellman_ratchet_curve25519.py`.

* **Generate fresh DH keypair**: random clamped 32-byte scalar, then
  `priv * BasePoint` for the X25519 public.
* **Step on receiving** new DH from peer:
    1. `dh_out = X25519(our_dh_priv, peer_dh_pub)`
    2. Apply root chain KDF: `(new_root_key, recv_chain_key) = HKDF(root_key, dh_out, info="OMEMO Root Chain", 64)`.
    3. Generate new DH keypair on our side.
    4. `dh_out2 = X25519(new_dh_priv, peer_dh_pub)`
    5. `(newer_root_key, send_chain_key) = HKDF(new_root_key, dh_out2, info="OMEMO Root Chain", 64)`.

## 8. Skipped message keys

Cap on stored skipped keys: `MAX_SKIP = 1000` per chain (matches
python-doubleratchet default `max_skip`). When this is exceeded, decryption
fails.

Skipped keys may have a TTL — for OMEMO 2, the spec leaves this to
implementations. We will use 30 days, deleted by a background sweep that
runs at session-load time.

## 9. Wire format

Defined in `test-vectors/twomemo/twomemo.proto` (committed copy from
upstream). Three messages, all proto2:

* `OMEMOMessage` — single ratchet message (no MAC, no key exchange).
* `OMEMOAuthenticatedMessage` — `OMEMOMessage` + 16-byte truncated MAC.
* `OMEMOKeyExchange` — initial X3DH key exchange + first
  `OMEMOAuthenticatedMessage`.

The Rust implementation will use `prost` (codegen at build time) so the
wire format is enforced by the `.proto` file rather than by hand.

## 10. SCE (XEP-0420 Stanza Content Encryption)

OMEMO 2 carries plaintext as an XEP-0420 envelope:

```xml
<envelope xmlns="urn:xmpp:sce:1">
  <content>
    <body xmlns="jabber:client">Hello</body>
    <!-- arbitrary stanza content here -->
  </content>
  <rpad xmlns="urn:xmpp:sce:1">random padding bytes (base64)</rpad>
  <time stamp="2026-04-29T12:34:56Z" />
  <to jid="bob@example.org" />
  <from jid="alice@example.org/desktop" />
</envelope>
```

Padding (`<rpad>`) is required and must contain `0..200` random bytes
chosen uniformly. Time must be UTC with seconds precision. To/from must be
present.

The envelope is serialised as XML, then encrypted (per §5) and the
ciphertext is base64-encoded into `<payload>` of the OMEMO `<encrypted>`
stanza.
