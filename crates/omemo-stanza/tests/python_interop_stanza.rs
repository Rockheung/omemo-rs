//! Cross-impl byte-exact tests for the XEP-0384 v0.3 (axolotl /
//! oldmemo) stanza encoders against the `python-omemo` reference.
//!
//! These tests spawn the `test-vectors/.venv` Python interpreter and
//! drive `oldmemo.etree.serialize_bundle` / `serialize_device_list` /
//! `serialize_message` for the same logical input, then compare with
//! what our Rust encoder emits.
//!
//! Because Python's `xml.etree.ElementTree` and our `quick-xml` both
//! emit syntactically-different-but-semantically-equal XML (ns
//! prefixes, attribute ordering, base64 form), the comparison is done
//! at the **structured / decoded** level:
//!
//!   * Each side dumps a deterministic JSON-like dict (rid lists,
//!     attribute values, base64-decoded blobs).
//!   * Our test asserts that dict matches byte-for-byte.
//!
//! Two intentional divergences are pinned by explicit asserts:
//!   * `<key rid=... prekey="false">` ALWAYS emitted by the Rust
//!     encoder; python-omemo only emits `prekey="true"`. Required for
//!     iOS Monal compatibility (see `axolotl_stanza.rs` doc comment).
//!     A regression would be either side dropping/adding the
//!     attribute when it shouldn't.
//!   * Sign-bit-stuffing in the oldmemo SPK signature byte 63 bit 7
//!     must match exactly on both sides (the v0.3 spec's only way to
//!     recover the Ed25519 IK from a Curve25519 wire IK).
//!
//! Marked `#[ignore]` — these only run when the venv is present:
//!
//!     cargo test -p omemo-stanza --test python_interop_stanza -- --ignored
//!
//! Or set `$OMEMO_RS_PYTHON` to point at a Python with `oldmemo`,
//! `twomemo`, `x3dh`, `xeddsa` installed.

use std::path::PathBuf;
use std::process::Command;

use omemo_stanza::axolotl_stanza::{Bundle, DeviceList, Encrypted, KeyEntry, PreKey};

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // .../crates
    p.pop(); // repo root
    p
}

fn python_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("OMEMO_RS_PYTHON") {
        return PathBuf::from(p);
    }
    repo_root().join("test-vectors/.venv/bin/python")
}

/// Run a Python snippet that prints a JSON line on stdout. Returns
/// the raw stdout (panics on any error / non-zero exit).
fn run_py(code: &str) -> String {
    let out = Command::new(python_bin())
        .arg("-c")
        .arg(code)
        .output()
        .unwrap_or_else(|e| panic!("spawn python: {e} (binary: {:?})", python_bin()));
    if !out.status.success() {
        panic!(
            "python failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8(out.stdout).expect("python stdout utf-8")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a string as a Python source-level string literal. Used to
/// embed user-controlled bytes safely in the inline Python snippets
/// driven by [`run_py`].
fn py_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!(r"\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Strip xmlns/ns-prefix noise from a fragment of XML and parse it
/// into a flat list of `(tag, attrs_sorted, text)` tuples for
/// byte-comparison.
fn canonicalise_xml_via_python(xml: &str) -> String {
    let snippet = format!(
        r#"
import sys, json, re
import xml.etree.ElementTree as ET
xml = {xml_lit}
root = ET.fromstring(xml)
def walk(e):
    tag = re.sub(r'^\{{.*\}}', '', e.tag)
    attrs = sorted(e.attrib.items())
    txt = (e.text or '').strip()
    return [tag, attrs, txt, [walk(c) for c in e]]
print(json.dumps(walk(root), sort_keys=False))
"#,
        xml_lit = py_str(xml),
    );
    run_py(&snippet).trim().to_string()
}

// ---------------------------------------------------------------------------
// Test 1 — oldmemo `<list>` device list byte-exact (canonicalised).
// ---------------------------------------------------------------------------
//
// Coverage gap: row 16 "Devicelist serialize". Previously only an
// internal Rust round-trip existed. python-oldmemo strips device
// labels (the v0.3 spec has no label support) so we don't carry one.

#[test]
#[ignore = "requires test-vectors/.venv"]
fn oldmemo_device_list_matches_python() {
    // Use only LOW-half u32 ids here; the high-bit Monal-compat rendering
    // is a deliberate divergence pinned by
    // `oldmemo_device_list_monal_compat_signed_high_bit_diverges` below.
    let device_ids: Vec<u32> = vec![1, 4711, i32::MAX as u32];

    let dl = DeviceList {
        devices: device_ids.clone(),
    };
    let rust_xml = dl.encode().unwrap();
    let rust_canon = canonicalise_xml_via_python(&rust_xml);

    let py_code = format!(
        r#"
import json, re
import xml.etree.ElementTree as ET
from oldmemo.etree import serialize_device_list
ids = {ids:?}
dl = {{i: None for i in ids}}
el = serialize_device_list(dl)
xml = ET.tostring(el, encoding='unicode')
root = ET.fromstring(xml)
def walk(e):
    tag = re.sub(r'^\{{.*\}}', '', e.tag)
    attrs = sorted(e.attrib.items())
    txt = (e.text or '').strip()
    return [tag, attrs, txt, [walk(c) for c in e]]
print(json.dumps(walk(root), sort_keys=False))
"#,
        ids = device_ids,
    );
    let py_canon = run_py(&py_code).trim().to_string();

    assert_eq!(
        rust_canon, py_canon,
        "oldmemo device-list canonical XML mismatch\nrust: {rust_canon}\npy:   {py_canon}"
    );
}

/// Pin the documented Monal-compat divergence: when a device id has
/// the high bit set, our Rust encoder emits the SIGNED-i32 form so
/// iOS Monal (which treats device ids as int32 internally) can match.
/// python-oldmemo emits the UNSIGNED form. Both are spec-conformant
/// — XEP-0384 takes `xs:unsignedInt` on the wire and Conversations
/// happens to accept either. Asserting the divergence here means a
/// future "fix" that drops the signed branch breaks this test loudly
/// instead of silently breaking Monal interop in the field.
#[test]
#[ignore = "requires test-vectors/.venv"]
fn oldmemo_device_list_monal_compat_signed_high_bit_diverges() {
    let dl = DeviceList {
        devices: vec![0xDEAD_BEEF],
    };
    let rust_xml = dl.encode().unwrap();
    assert!(
        rust_xml.contains(r#"id="-559038737""#),
        "expected SIGNED-i32 rendering for high-bit id (Monal-compat); got: {rust_xml}"
    );
    // Sanity: python emits the unsigned form.
    let py_out = run_py(
        r#"
import xml.etree.ElementTree as ET
from oldmemo.etree import serialize_device_list
el = serialize_device_list({0xDEADBEEF: None})
print(ET.tostring(el, encoding='unicode'))
"#,
    );
    assert!(
        py_out.contains(r#"id="3735928559""#),
        "python upstream changed: it no longer emits the unsigned form. \
         Reconsider whether the Monal-compat branch is still needed: {py_out}"
    );
}

#[test]
#[ignore = "requires test-vectors/.venv"]
fn oldmemo_device_list_empty_matches_python() {
    let dl = DeviceList::default();
    let rust_xml = dl.encode().unwrap();
    let rust_canon = canonicalise_xml_via_python(&rust_xml);

    let py_canon = run_py(
        r#"
import json, re
import xml.etree.ElementTree as ET
from oldmemo.etree import serialize_device_list
el = serialize_device_list({})
xml = ET.tostring(el, encoding='unicode')
root = ET.fromstring(xml)
def walk(e):
    tag = re.sub(r'^\{.*\}', '', e.tag)
    attrs = sorted(e.attrib.items())
    txt = (e.text or '').strip()
    return [tag, attrs, txt, [walk(c) for c in e]]
print(json.dumps(walk(root), sort_keys=False))
"#,
    )
    .trim()
    .to_string();

    assert_eq!(rust_canon, py_canon);
}

// ---------------------------------------------------------------------------
// Test 2 — oldmemo `<bundle>` byte-exact (canonicalised). Includes the
// sign-bit-stuffing on SPK sig byte 63 bit 7 — a very dark corner that
// only this kind of cross-comparison exercises.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires test-vectors/.venv"]
fn oldmemo_bundle_serialize_matches_python_with_sign_bit_stuffing() {
    // Pick a deterministic Ed25519 IK from a known seed so the
    // resulting curve25519 view (and its disambiguation sign bit) is
    // reproducible across runs.
    let seed = [0x42u8; 32];
    let ik_priv = omemo_xeddsa::seed_to_priv(&seed);
    let ik_ed = omemo_xeddsa::priv_to_ed25519_pub(&ik_priv);

    // Pick a Curve25519 SPK derived from a fixed scalar.
    let spk_priv = [0x33u8; 32];
    let spk_pub = omemo_xeddsa::priv_to_curve25519_pub(&spk_priv);

    // Construct a deterministic 64-byte sig (NOT a real signature) with
    // byte-63 bit-7 cleared, the precondition before stuffing.
    let mut sig = [0u8; 64];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    sig[63] &= 0x7F;

    let opks: Vec<PreKey> = vec![
        PreKey {
            id: 1,
            pub_key: [0x10u8; 32],
        },
        PreKey {
            id: 2,
            pub_key: [0x20u8; 32],
        },
    ];

    let bundle = Bundle {
        signed_prekey_id: 99,
        signed_prekey_pub: spk_pub,
        signed_prekey_sig: sig,
        identity_key_ed: ik_ed,
        prekeys: opks.clone(),
    };
    let rust_xml = bundle.encode().unwrap();
    let rust_canon = canonicalise_xml_via_python(&rust_xml);

    let opks_hex: Vec<String> = opks.iter().map(|p| hex::encode(p.pub_key)).collect();
    let py_code = format!(
        r#"
import json, re, base64
import xml.etree.ElementTree as ET
import x3dh, xeddsa
from oldmemo.oldmemo import BundleImpl, StateImpl
from oldmemo.etree import serialize_bundle

ik = bytes.fromhex("{ik_hex}")
spk = bytes.fromhex("{spk_hex}")
sig = bytes.fromhex("{sig_hex}")
opks_hex = {opks_hex:?}
opks = [bytes.fromhex(h) for h in opks_hex]
pre_key_ids = {{opks[0]: 1, opks[1]: 2}}
b = BundleImpl(
    'alice@example.org', 1234,
    x3dh.Bundle(ik, spk, sig, frozenset(opks)),
    99, pre_key_ids,
)
el = serialize_bundle(b)
xml = ET.tostring(el, encoding='unicode')
root = ET.fromstring(xml)
def walk(e):
    tag = re.sub(r'^\{{.*\}}', '', e.tag)
    attrs = sorted(e.attrib.items())
    txt = (e.text or '').strip()
    return [tag, attrs, txt, [walk(c) for c in e]]
# Sort prekeys by id so dict-iteration noise on the python side doesn't
# poison the comparison. Our encoder emits them in input order, which
# we keep sorted-by-id too — matching what callers actually pass in.
def normalize(t):
    tag, attrs, txt, kids = t
    if tag == 'prekeys':
        def key(k):
            for a, v in k[1]:
                if a == 'preKeyId':
                    return int(v)
            return 0
        kids = sorted(kids, key=key)
    return [tag, attrs, txt, [normalize(k) for k in kids]]
print(json.dumps(normalize(walk(root)), sort_keys=False))
"#,
        ik_hex = hex::encode(ik_ed),
        spk_hex = hex::encode(spk_pub),
        sig_hex = hex::encode(sig),
        opks_hex = opks_hex,
    );
    let py_canon = run_py(&py_code).trim().to_string();

    // The Rust encoder emits prekeys in input order; we deliberately
    // input them sorted-by-id above. The python side sorts the same
    // way in `normalize`. So the canonical forms should match.
    assert_eq!(
        rust_canon, py_canon,
        "oldmemo bundle canonical XML mismatch (sign-bit stuffing / wire form)\nrust: {rust_canon}\npy:   {py_canon}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — oldmemo `<encrypted>` stanza, multi-recipient. Pins the
// `prekey="false"` divergence: python-oldmemo omits the attribute,
// our Rust encoder ALWAYS emits it. The semantic round-trip (decoded
// bytes / rid / prekey-bool) must match.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires test-vectors/.venv"]
fn oldmemo_encrypted_message_matches_python_semantics() {
    // 3-recipient, mix of prekey=true / prekey=false. The data blobs
    // are deterministic and short so the test stays readable.
    let e = Encrypted {
        sid: 27183,
        keys: vec![
            KeyEntry {
                rid: 100,
                prekey: true,
                data: b"kex-key-for-alice".to_vec(),
            },
            KeyEntry {
                rid: 200,
                prekey: false,
                data: b"follow-up-for-bob".to_vec(),
            },
            KeyEntry {
                rid: 300,
                prekey: false,
                data: b"follow-up-for-carol".to_vec(),
            },
        ],
        iv: (0u8..12).collect(),
        payload: Some(b"three-recipient-payload".to_vec()),
    };
    let rust_xml = e.encode().unwrap();

    // Parse our wire output and pull out a semantic dict.
    let parsed_back = Encrypted::parse(&rust_xml).unwrap();
    let rust_keys: Vec<(u32, bool, Vec<u8>)> = parsed_back
        .keys
        .iter()
        .map(|k| (k.rid, k.prekey, k.data.clone()))
        .collect();
    let rust_iv = parsed_back.iv.clone();
    let rust_payload = parsed_back.payload.clone().unwrap();

    // PIN THE DELIBERATE DIVERGENCE: the wire bytes must contain
    // `prekey="false"` for the non-kex entries. python-oldmemo will
    // not, but our wire output (Monal interop reason — see
    // `axolotl_stanza.rs`) does.
    assert!(
        rust_xml.contains(r#"rid="200" prekey="false""#),
        "Rust encoder must emit prekey=\"false\" explicitly; missing in: {rust_xml}"
    );
    assert!(
        rust_xml.contains(r#"rid="300" prekey="false""#),
        "Rust encoder must emit prekey=\"false\" explicitly; missing in: {rust_xml}"
    );

    // Build the SAME logical message in python and serialise it.
    let py_code = r#"
import json, base64
import x3dh
from oldmemo.oldmemo import EncryptedKeyMaterialImpl, KeyExchangeImpl, ContentImpl
from oldmemo.etree import serialize_message
from omemo.message import Message
import xml.etree.ElementTree as ET

# python-oldmemo's `EncryptedKeyMaterialImpl.serialize()` reads
# `self.__encrypted_message.ciphertext` (the raw OMEMOAuthenticatedMessage
# bytes; see `oldmemo/oldmemo.py:551`). We don't have a real ratchet
# session here, so we stub with a tiny shim that exposes `.ciphertext`.

class FakeEnc:
    def __init__(self, raw):
        self.ciphertext = raw
        self.header = None

def km(bjid, did, raw):
    return EncryptedKeyMaterialImpl(bjid, did, FakeEnc(raw))

# For the KEX entry, build a real `KeyExchangeImpl` (the `etree.py`
# code path asserts isinstance), then monkey-patch its `.serialize`
# to return the raw bytes verbatim — that's what we'd compare against
# on the Rust side anyway.
hdr = x3dh.Header(b'\x01' * 32, b'\x02' * 32, b'\x03' * 32, b'\x04' * 32)
kex = KeyExchangeImpl(hdr, 99, 100)
kex.serialize = lambda am: (am, False)

iv = bytes(range(12))
content = ContentImpl(b'three-recipient-payload', iv)
keys = frozenset([
    (km('a@x', 100, b'kex-key-for-alice'), kex),
    (km('a@x', 200, b'follow-up-for-bob'), None),
    (km('a@x', 300, b'follow-up-for-carol'), None),
])
msg = Message('eu.siacs.conversations.axolotl', 'a@x', 27183, content, keys)
el = serialize_message(msg)
xml = ET.tostring(el, encoding='unicode')

# Pull semantic shape.
ns = '{eu.siacs.conversations.axolotl}'
hdr = el.find(ns + 'header')
sid = int(hdr.get('sid'))
key_entries = []
for k in hdr.findall(ns + 'key'):
    rid = int(k.get('rid'))
    prekey = k.get('prekey', None)
    raw = base64.b64decode(k.text)
    key_entries.append([rid, prekey == 'true', list(raw)])
key_entries.sort()
iv = list(base64.b64decode(hdr.find(ns + 'iv').text))
pl = el.find(ns + 'payload')
payload = list(base64.b64decode(pl.text)) if pl is not None else None
# Also report whether python emitted the prekey attribute on the
# non-kex entries — used by the Rust side to assert the documented
# divergence.
python_emits_prekey_false = any(
    k.get('prekey') == 'false'
    for k in hdr.findall(ns + 'key')
)
print(json.dumps({
    'sid': sid,
    'keys': key_entries,
    'iv': iv,
    'payload': payload,
    'python_emits_prekey_false': python_emits_prekey_false,
}))
"#
    .to_string();

    let py_out = run_py(&py_code);
    let py_json: serde_json::Value = serde_json::from_str(py_out.trim()).expect("py json");

    // Semantic comparison.
    assert_eq!(
        py_json["sid"].as_u64().unwrap() as u32,
        parsed_back.sid,
        "sid mismatch"
    );

    let py_keys: Vec<(u32, bool, Vec<u8>)> = py_json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let arr = k.as_array().unwrap();
            (
                arr[0].as_u64().unwrap() as u32,
                arr[1].as_bool().unwrap(),
                arr[2]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap() as u8)
                    .collect(),
            )
        })
        .collect();
    let mut rust_keys_sorted = rust_keys.clone();
    rust_keys_sorted.sort();
    assert_eq!(
        rust_keys_sorted, py_keys,
        "rid / prekey-bool / blob mismatch vs python"
    );

    let py_iv: Vec<u8> = py_json["iv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(py_iv, rust_iv, "iv mismatch");

    let py_pl: Vec<u8> = py_json["payload"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(py_pl, rust_payload, "payload mismatch");

    // Document the divergence: python does NOT emit prekey="false".
    assert!(
        !py_json["python_emits_prekey_false"].as_bool().unwrap(),
        "python-oldmemo upstream changed: it now emits prekey=\"false\" on follow-ups. \
         Re-check whether the Rust-side explicit-emit is still needed for iOS Monal."
    );
}

// ---------------------------------------------------------------------------
// Test 4 — twomemo `<bundle xmlns='urn:xmpp:omemo:2'>` byte-exact
// (canonicalised). Different element names (`spk`, `spks`, `ik`,
// `pk`), no sign-bit stuffing. Coverage gap: row 14 twomemo bundle
// serialise.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires test-vectors/.venv"]
fn twomemo_bundle_serialize_matches_python() {
    use omemo_stanza::{Bundle as TwomemoBundle, PreKey as TwomemoPreKey, SignedPreKey};

    // 32B IK in twomemo's wire form (raw Ed25519, no curve conversion).
    let ik = (0u8..32).collect::<Vec<u8>>();
    let spk_bytes = (32u8..64).collect::<Vec<u8>>();
    let sig: Vec<u8> = (0u8..64).collect();
    let opks: Vec<TwomemoPreKey> = vec![
        TwomemoPreKey {
            id: 7,
            pub_key: vec![0x70u8; 32],
        },
        TwomemoPreKey {
            id: 8,
            pub_key: vec![0x80u8; 32],
        },
    ];

    let b = TwomemoBundle {
        spk: SignedPreKey {
            id: 11,
            pub_key: spk_bytes.clone(),
        },
        spks: sig.clone(),
        ik: ik.clone(),
        prekeys: opks.clone(),
    };
    let rust_xml = b.encode().unwrap();
    let rust_canon = canonicalise_xml_via_python(&rust_xml);

    let py_code = format!(
        r#"
import json, re
import xml.etree.ElementTree as ET
import x3dh
from twomemo.twomemo import BundleImpl
from twomemo.etree import serialize_bundle
ik = bytes.fromhex("{ik_hex}")
spk = bytes.fromhex("{spk_hex}")
sig = bytes.fromhex("{sig_hex}")
opks = [bytes([0x70])*32, bytes([0x80])*32]
b = BundleImpl(
    'alice@x', 1, x3dh.Bundle(ik, spk, sig, frozenset(opks)),
    11, {{opks[0]: 7, opks[1]: 8}}
)
el = serialize_bundle(b)
xml = ET.tostring(el, encoding='unicode')
root = ET.fromstring(xml)
def walk(e):
    tag = re.sub(r'^\{{.*\}}', '', e.tag)
    attrs = sorted(e.attrib.items())
    txt = (e.text or '').strip()
    return [tag, attrs, txt, [walk(c) for c in e]]
def normalize(t):
    tag, attrs, txt, kids = t
    if tag == 'prekeys':
        def key(k):
            for a, v in k[1]:
                if a == 'id':
                    return int(v)
            return 0
        kids = sorted(kids, key=key)
    return [tag, attrs, txt, [normalize(k) for k in kids]]
print(json.dumps(normalize(walk(root)), sort_keys=False))
"#,
        ik_hex = hex::encode(&ik),
        spk_hex = hex::encode(&spk_bytes),
        sig_hex = hex::encode(&sig),
    );
    let py_canon = run_py(&py_code).trim().to_string();
    assert_eq!(
        rust_canon, py_canon,
        "twomemo bundle canonical XML mismatch\nrust: {rust_canon}\npy:   {py_canon}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — AES-128-GCM seal byte-exact: the oldmemo wire body
// AEAD path. Pins our (key, iv, plaintext) → (ciphertext, tag)
// against python `cryptography` AES-GCM, which is what python-omemo
// uses under the hood. Coverage gap: row 9 oldmemo body seal.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires test-vectors/.venv"]
fn oldmemo_aes_128_gcm_seal_matches_python() {
    use omemo_stanza::axolotl_aead::seal_payload_with_key_iv;

    // Two cases: tiny plaintext, long-with-trailing-zeros plaintext.
    for (label, key, iv, pt) in [
        (
            "short",
            [0x11u8; 16],
            [0x22u8; 12],
            b"the quick brown fox jumps over the lazy dog".to_vec(),
        ),
        ("with-nulls", [0xABu8; 16], [0xCDu8; 12], {
            let mut v = Vec::new();
            v.extend_from_slice(b"prefix");
            v.extend(std::iter::repeat_n(0u8, 7));
            v.extend_from_slice(b"suffix");
            v
        }),
    ] {
        let (rust_ct, rust_blob) = seal_payload_with_key_iv(&key, &iv, &pt);
        let rust_tag = &rust_blob[16..];

        let py_code = format!(
            r#"
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = bytes.fromhex("{key_hex}")
iv = bytes.fromhex("{iv_hex}")
pt = bytes.fromhex("{pt_hex}")
ct_plus_tag = AESGCM(key).encrypt(iv, pt, b'')
ct = ct_plus_tag[:-16]
tag = ct_plus_tag[-16:]
print(json.dumps({{'ct': ct.hex(), 'tag': tag.hex()}}))
"#,
            key_hex = hex::encode(key),
            iv_hex = hex::encode(iv),
            pt_hex = hex::encode(&pt),
        );
        let py_out = run_py(&py_code);
        let py_json: serde_json::Value = serde_json::from_str(py_out.trim()).expect("py json");

        let py_ct = hex::decode(py_json["ct"].as_str().unwrap()).unwrap();
        let py_tag = hex::decode(py_json["tag"].as_str().unwrap()).unwrap();

        assert_eq!(
            rust_ct,
            py_ct,
            "[{label}] ciphertext mismatch: rust={} py={}",
            hex::encode(&rust_ct),
            hex::encode(&py_ct)
        );
        assert_eq!(
            rust_tag,
            py_tag.as_slice(),
            "[{label}] GCM tag mismatch: rust={} py={}",
            hex::encode(rust_tag),
            hex::encode(&py_tag)
        );
    }
}

// ---------------------------------------------------------------------------
// Test 6 — twomemo `<encrypted xmlns='urn:xmpp:omemo:2'>` byte-exact
// (canonicalised). Mirrors test 3 (oldmemo) at the OMEMO 2 layer:
// `<keys jid=...>` grouping, `kex="true"` for KEX entries (default
// false / omitted on follow-ups), namespace `urn:xmpp:omemo:2`. No
// payload-divergence pin — OMEMO 2 wraps via SCE so there's no
// Monal-compat fudge.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires test-vectors/.venv"]
fn twomemo_encrypted_message_matches_python() {
    use omemo_stanza::{Encrypted as TwomemoEncrypted, Key as TwomemoKey, KeysGroup};

    // Two recipient JIDs, three devices total: bob has two devices,
    // carol has one. Mix of kex=true / kex=false.
    let e = TwomemoEncrypted {
        sid: 90210,
        keys: vec![
            KeysGroup {
                jid: "bob@example.org".to_string(),
                keys: vec![
                    TwomemoKey {
                        rid: 11,
                        kex: true,
                        data: b"kex-for-bob-dev-11".to_vec(),
                    },
                    TwomemoKey {
                        rid: 12,
                        kex: false,
                        data: b"follow-up-for-bob-dev-12".to_vec(),
                    },
                ],
            },
            KeysGroup {
                jid: "carol@example.org".to_string(),
                keys: vec![TwomemoKey {
                    rid: 21,
                    kex: false,
                    data: b"follow-up-for-carol".to_vec(),
                }],
            },
        ],
        payload: Some(b"sce-envelope-ciphertext-stub".to_vec()),
    };
    let rust_xml = e.encode().unwrap();
    let rust_canon = canonicalise_xml_via_python(&rust_xml);

    // Build the same logical message on the python side. The twomemo
    // serializer takes a flat frozenset of (EncryptedKeyMaterialImpl,
    // Optional[KeyExchangeImpl]) and groups by `bare_jid`. We stub
    // `.serialize()` on both so the wire bytes match our test inputs.
    let py_code = r#"
import json, base64
import x3dh
import xml.etree.ElementTree as ET
from twomemo.twomemo import EncryptedKeyMaterialImpl, KeyExchangeImpl, ContentImpl
from twomemo.etree import serialize_message
from omemo.message import Message

# `serialize_message` reads `EncryptedKeyMaterialImpl.serialize()` —
# which on twomemo returns `self.__encrypted_message.ciphertext` (see
# twomemo/twomemo.py:418). Stub the underlying object so we control
# the raw bytes.
class FakeEnc:
    def __init__(self, raw):
        self.ciphertext = raw
        self.header = None

def km(jid, did, raw):
    return EncryptedKeyMaterialImpl(jid, did, FakeEnc(raw))

# For KEX entries, build a real `KeyExchangeImpl` (etree asserts
# isinstance) then monkey-patch `.serialize` to return our raw bytes.
hdr = x3dh.Header(b'\x01' * 32, b'\x02' * 32, b'\x03' * 32, b'\x04' * 32)
kex = KeyExchangeImpl(hdr, 99, 100)
kex.serialize = lambda am: am  # twomemo returns bytes, not (bytes,bool)

# ContentImpl(ciphertext): a single positional arg in twomemo (no IV
# parameter — SCE handles authentication separately).
content = ContentImpl(b'sce-envelope-ciphertext-stub')

keys = frozenset([
    (km('bob@example.org', 11, b'kex-for-bob-dev-11'), kex),
    (km('bob@example.org', 12, b'follow-up-for-bob-dev-12'), None),
    (km('carol@example.org', 21, b'follow-up-for-carol'), None),
])
msg = Message('urn:xmpp:omemo:2', 'sender@example.org', 90210, content, keys)
el = serialize_message(msg)
xml = ET.tostring(el, encoding='unicode')

# Re-walk canonically (mirrors `canonicalise_xml_via_python` on the
# Rust side: strip namespaces, sort attributes, no whitespace).
import re
root = ET.fromstring(xml)
def walk(e):
    tag = re.sub(r'^\{.*\}', '', e.tag)
    attrs = sorted(e.attrib.items())
    txt = (e.text or '').strip()
    return [tag, attrs, txt, [walk(c) for c in e]]

# python's frozenset/dict-iteration order is nondeterministic; sort
# `<keys>` blocks by jid and `<key>` rows by rid so the canonical form
# matches the Rust encoder, which emits them in input order.
def normalize(t):
    tag, attrs, txt, kids = t
    if tag == 'header':
        def jid_key(k):
            for a, v in k[1]:
                if a == 'jid':
                    return v
            return ''
        kids = sorted(kids, key=jid_key)
    if tag == 'keys':
        def rid_key(k):
            for a, v in k[1]:
                if a == 'rid':
                    return int(v)
            return 0
        kids = sorted(kids, key=rid_key)
    return [tag, attrs, txt, [normalize(k) for k in kids]]
print(json.dumps(normalize(walk(root)), sort_keys=False))
"#
    .to_string();
    let py_canon = run_py(&py_code).trim().to_string();

    // The Rust encoder emits keys-groups in input order, and keys
    // within a group in input order; we pass them sorted by JID then
    // by rid above so canonical comparison succeeds.
    assert_eq!(
        rust_canon, py_canon,
        "twomemo encrypted canonical XML mismatch\nrust: {rust_canon}\npy:   {py_canon}"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — XEP-0420 SCE envelope: structural gap.
// ---------------------------------------------------------------------------
//
// **No Python reference encoder exists.** We checked:
//   * `slixmpp_omemo/xep_0384.py:1051` has the literal "Here I would
//     prepare the plaintext for omemo:2 using my SCE plugin ... IF I
//     HAD ONE!!!" line and `:1218` raises `NotImplementedError("SCE
//     not supported yet.")`.
//   * `python-twomemo` does not implement SCE either (it punts to the
//     XMPP-client layer for the envelope).
//   * `slixmpp` core has no `urn:xmpp:sce:1` plugin.
//
// Therefore the byte-exact comparison here is against **ADR-locked
// golden bytes**: a fixture we commit into the test. The encoder is
// expected to be deterministic for fixed inputs (we control rpad,
// timestamp, to, from, and the content child verbatim). If the Rust
// encoder drifts, this test fails. If/when a Python SCE encoder
// arrives upstream, this should be replaced with a byte-exact compare
// against it.
//
// **Do not change the golden bytes without a spec update.**

#[test]
fn sce_envelope_adr_locked_golden_bytes() {
    use omemo_stanza::sce::SceEnvelope;

    // Fixture inputs chosen for readability + diversity (entity
    // escaping inside <body>, non-empty rpad, a full ISO-8601 stamp).
    let env = SceEnvelope {
        content: r#"<body xmlns="jabber:client">hello &amp; goodbye</body>"#.to_string(),
        rpad: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        timestamp: "2026-04-29T12:34:56Z".to_string(),
        to: "bob@example.org".to_string(),
        from: "alice@example.org/desktop".to_string(),
    };
    let wire = env.encode().unwrap();

    // ADR-locked golden bytes. Element order is canonical (content,
    // rpad, time, to, from). Time/to/from are emitted self-closing.
    // base64 of [01 02 03 04 05] = "AQIDBAU=".
    //
    // No python reference; this is the ADR-locked shape — change only
    // on spec update.
    let expected = r#"<envelope xmlns="urn:xmpp:sce:1"><content><body xmlns="jabber:client">hello &amp; goodbye</body></content><rpad>AQIDBAU=</rpad><time stamp="2026-04-29T12:34:56Z"/><to jid="bob@example.org"/><from jid="alice@example.org/desktop"/></envelope>"#;

    assert_eq!(
        wire, expected,
        "SCE envelope golden bytes drift (no python reference encoder \
         exists — this is the ADR-locked canonical form). \
         Update the golden ONLY on a spec change.\n\
         got:      {wire}\n\
         expected: {expected}"
    );

    // Round-trip sanity: decoding our wire must restore the inputs
    // (content verbatim, rpad bytes, all three attribute fields).
    let back = SceEnvelope::parse(&wire).unwrap();
    assert_eq!(back, env, "SCE envelope round-trip drift");
}

#[test]
#[ignore = "requires test-vectors/.venv (documents structural gap)"]
fn sce_envelope_no_python_reference_documented() {
    // This test EXISTS to assert the structural gap stays
    // documented: if python-omemo or slixmpp ever ship a SCE encoder
    // upstream, this test should start failing (because the strings
    // get found) and we should replace
    // `sce_envelope_adr_locked_golden_bytes` with a real cross-impl
    // byte-equal compare.
    let probe = run_py(
        r#"
import json, importlib, importlib.util
checks = {}
for name in ['slixmpp_omemo', 'twomemo', 'omemo', 'slixmpp']:
    try:
        m = importlib.import_module(name)
        # Walk submodules looking for any reference to the XEP-0420 namespace.
        found = False
        try:
            import pkgutil
            for sub in pkgutil.walk_packages(m.__path__, m.__name__ + '.'):
                spec = importlib.util.find_spec(sub.name)
                if spec is None or spec.origin is None: continue
                try:
                    with open(spec.origin, 'r') as f:
                        src = f.read()
                    if 'urn:xmpp:sce' in src:
                        found = True
                        break
                except Exception:
                    pass
        except Exception:
            pass
        checks[name] = found
    except Exception:
        checks[name] = None
print(json.dumps(checks))
"#,
    );
    let probe_json: serde_json::Value = serde_json::from_str(probe.trim()).expect("py json");
    // `slixmpp_omemo` has a comment "Do SCE unpacking here" but no
    // actual encoder. None of the other libs reference the namespace
    // at all. If this assertion ever flips, replace the golden test
    // above with a real cross-impl byte-equal compare.
    let xep0384 = probe_json["slixmpp_omemo"].as_bool().unwrap_or(false);
    let twomemo = probe_json["twomemo"].as_bool().unwrap_or(false);
    let omemo = probe_json["omemo"].as_bool().unwrap_or(false);
    let slixmpp = probe_json["slixmpp"].as_bool().unwrap_or(false);

    // slixmpp_omemo references the SCE namespace only in comments /
    // NotImplementedError messages — it's still a structural gap
    // from our perspective because there is no concrete builder.
    // Therefore we only fail loudly if twomemo / omemo (core) /
    // slixmpp itself start emitting one.
    assert!(
        !twomemo && !omemo && !slixmpp,
        "Upstream python now references urn:xmpp:sce:1: {probe}. \
         A real SCE builder may now exist — replace \
         `sce_envelope_adr_locked_golden_bytes` with a byte-equal \
         cross-impl compare against it."
    );
    let _ = xep0384; // informational only
}

// ---------------------------------------------------------------------------
// Test 8 — SPK rotation: byte-exact signature over the 33-byte
// encoded form `0x05 || curve25519_spk_pub`. Both sides feed the same
// 32-byte IK seed and the same 64-byte XEdDSA nonce to
// `ed25519_priv_sign`, then assert the produced 64-byte signature
// matches and verifies against the Ed25519 IK pub.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires test-vectors/.venv"]
fn spk_signature_over_encoded_curve25519_matches_python() {
    // Fixed seeds — deterministic and reproducible across runs.
    let ik_seed: [u8; 32] = [0x42; 32];
    let spk_priv: [u8; 32] = [0x33; 32];
    let nonce: [u8; 64] = {
        let mut n = [0u8; 64];
        for (i, b) in n.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13);
        }
        n
    };

    // Rust side: clamp seed → priv, Curve25519 SPK pub from `spk_priv`,
    // encode as `0x05 || pub`, then xeddsa-sign with the deterministic
    // nonce. The Rust force-sign-bit in `store_old.rs` clamps the IK
    // priv to have sign bit 0; reproduce here so the comparison is
    // apples-to-apples with `python-x3dh`'s `__generate_spk` path.
    let ik_priv_clamped = omemo_xeddsa::seed_to_priv(&ik_seed);
    let ik_priv_sign_forced = omemo_xeddsa::priv_force_sign(&ik_priv_clamped, false);
    let ik_pub_ed = omemo_xeddsa::priv_to_ed25519_pub(&ik_priv_sign_forced);

    let spk_pub_curve = omemo_xeddsa::priv_to_curve25519_pub(&spk_priv);
    let mut encoded_spk = [0u8; 33];
    encoded_spk[0] = 0x05;
    encoded_spk[1..].copy_from_slice(&spk_pub_curve);

    let rust_sig = omemo_xeddsa::ed25519_priv_sign(&ik_priv_sign_forced, &encoded_spk, &nonce);

    let py_code = format!(
        r#"
import json, xeddsa
ik_seed = bytes.fromhex("{ik_seed_hex}")
spk_priv = bytes.fromhex("{spk_priv_hex}")
nonce = bytes.fromhex("{nonce_hex}")
ik_priv = xeddsa.seed_to_priv(ik_seed)
# Match the x3dh BaseState path: force the sign bit on the IK priv
# (Curve25519 identity-key format) before signing.
ik_priv = xeddsa.priv_force_sign(ik_priv, False)
ik_pub_ed = xeddsa.priv_to_ed25519_pub(ik_priv)
# `_encode_public_key` for oldmemo prepends 0x05 to the 32-byte
# Curve25519 SPK pub.
spk_pub = xeddsa.priv_to_curve25519_pub(spk_priv)
encoded_spk = b'\x05' + spk_pub
sig = xeddsa.ed25519_priv_sign(ik_priv, encoded_spk, nonce)
ok = xeddsa.ed25519_verify(sig, ik_pub_ed, encoded_spk)
print(json.dumps({{
    'ik_pub_ed': ik_pub_ed.hex(),
    'spk_pub': spk_pub.hex(),
    'sig': sig.hex(),
    'verify': ok,
}}))
"#,
        ik_seed_hex = hex::encode(ik_seed),
        spk_priv_hex = hex::encode(spk_priv),
        nonce_hex = hex::encode(nonce),
    );
    let py_out = run_py(&py_code);
    let py_json: serde_json::Value = serde_json::from_str(py_out.trim()).expect("py json");

    let py_ik_pub = hex::decode(py_json["ik_pub_ed"].as_str().unwrap()).unwrap();
    let py_spk_pub = hex::decode(py_json["spk_pub"].as_str().unwrap()).unwrap();
    let py_sig = hex::decode(py_json["sig"].as_str().unwrap()).unwrap();
    assert!(
        py_json["verify"].as_bool().unwrap(),
        "python xeddsa.ed25519_verify rejected its own signature \
         — this should be impossible. Inputs may have drifted."
    );

    assert_eq!(
        py_ik_pub,
        ik_pub_ed.to_vec(),
        "Ed25519 IK pub drift between rust and python xeddsa primitives"
    );
    assert_eq!(
        py_spk_pub,
        spk_pub_curve.to_vec(),
        "Curve25519 SPK pub drift between rust and python xeddsa primitives"
    );
    assert_eq!(
        rust_sig.to_vec(),
        py_sig,
        "SPK signature bytes drift (input: 0x05 || curve25519_spk_pub)\n\
         rust: {}\n\
         py:   {}",
        hex::encode(rust_sig),
        hex::encode(&py_sig),
    );

    // Round-trip: Rust's verify must accept python's signature too.
    let ok = omemo_xeddsa::ed25519_verify(&rust_sig, &ik_pub_ed, &encoded_spk);
    assert!(
        ok,
        "rust ed25519_verify rejected the cross-impl signature \
         — sign-bit-stuffing or scalar handling drifted"
    );
}
