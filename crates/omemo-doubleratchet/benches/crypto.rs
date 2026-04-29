//! Microbenchmarks for the OMEMO 2 crypto-layer hot paths.
//!
//! Run a single bench:
//!   cargo bench -p omemo-doubleratchet -- aead_encrypt
//! Compare two checkouts:
//!   cargo bench -p omemo-doubleratchet -- --save-baseline before
//!   <make changes>
//!   cargo bench -p omemo-doubleratchet -- --baseline before
//!
//! These numbers are not comparable across machines; use them for
//! before/after deltas, not absolute claims.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hkdf::Hkdf;
use sha2::Sha256;

use omemo_doubleratchet::aead::{decrypt, encrypt, HashFunction};
use omemo_doubleratchet::dh_ratchet::{
    DiffieHellmanRatchet, FixedDhPrivProvider, OsRngDhPrivProvider,
};
use omemo_doubleratchet::kdf::Kdf;
use omemo_doubleratchet::kdf_hkdf::{HkdfKdf, HkdfParams};
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};

struct OmemoRoot;
impl HkdfParams for OmemoRoot {
    const HASH: HashFunction = HashFunction::Sha256;
    const INFO: &'static [u8] = b"OMEMO Root Chain";
}
struct OmemoMsg;
impl SeparateHmacsParams for OmemoMsg {
    const HASH: HashFunction = HashFunction::Sha256;
}

const AEAD_INFO: &[u8] = b"OMEMO Message Key Material";
const ROOT_INFO: &[u8] = b"OMEMO Root Chain";

fn bench_hkdf(c: &mut Criterion) {
    let salt = [0u8; 32];
    let ikm = [0x33u8; 32];
    let mut group = c.benchmark_group("hkdf_sha256");
    for &len in &[32usize, 64, 80] {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, &len| {
            b.iter(|| {
                let mut out = vec![0u8; len];
                Hkdf::<Sha256>::new(Some(&salt), &ikm)
                    .expand(ROOT_INFO, &mut out)
                    .unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_aead_encrypt(c: &mut Criterion) {
    let key = [0x55u8; 32];
    let ad = [0xAAu8; 64];
    let mut group = c.benchmark_group("aead_encrypt");
    for &len in &[64usize, 1024, 16 * 1024] {
        let pt = vec![0xFFu8; len];
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| {
                let ct = encrypt(
                    HashFunction::Sha256,
                    AEAD_INFO,
                    black_box(&key),
                    black_box(&ad),
                    black_box(&pt),
                );
                black_box(ct);
            });
        });
    }
    group.finish();
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let key = [0x55u8; 32];
    let ad = [0xAAu8; 64];
    let pt = vec![0xFFu8; 1024];
    let ct = encrypt(HashFunction::Sha256, AEAD_INFO, &key, &ad, &pt);
    c.bench_function("aead_decrypt/1024", |b| {
        b.iter(|| {
            let pt = decrypt(
                HashFunction::Sha256,
                AEAD_INFO,
                black_box(&key),
                black_box(&ad),
                black_box(&ct),
            )
            .unwrap();
            black_box(pt);
        });
    });
}

fn bench_dh_ratchet_step(c: &mut Criterion) {
    type DR = DiffieHellmanRatchet<HkdfKdf<OmemoRoot>, SeparateHmacsKdf<OmemoMsg>>;

    // Build a fresh active DR per iteration would dominate runtime; instead
    // we reuse a long-running ratchet and just benchmark the per-step work
    // (which is identical regardless of chain length).
    let mut dr: DR = DR::create_active(
        [0x10u8; 32],
        vec![0x20u8; 32],
        b"\x02\x01".to_vec(),
        1000,
        Box::new(FixedDhPrivProvider::new(vec![[0x30u8; 32]; 1])),
    )
    .unwrap();

    c.bench_function("dh_ratchet_next_encryption_key", |b| {
        b.iter(|| {
            let (mk, hdr) = dr.next_encryption_key().unwrap();
            black_box((mk, hdr));
        });
    });
}

fn bench_x25519(c: &mut Criterion) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let priv_a: [u8; 32] = [0x42u8; 32];
    let priv_b: [u8; 32] = [0x43u8; 32];
    let pub_b = PublicKey::from(&StaticSecret::from(priv_b));
    let secret_a = StaticSecret::from(priv_a);

    c.bench_function("x25519_dh", |b| {
        b.iter(|| {
            let shared = secret_a.diffie_hellman(black_box(&pub_b));
            black_box(*shared.as_bytes());
        });
    });
}

fn bench_message_chain_step(c: &mut Criterion) {
    type Kdf2 = SeparateHmacsKdf<OmemoMsg>;
    let key = vec![0x77u8; 32];
    c.bench_function("separate_hmacs_kdf_chain_step", |b| {
        b.iter(|| {
            let out = <Kdf2 as Kdf>::derive(black_box(&key), black_box(b"\x02\x01"), 64);
            black_box(out);
        });
    });
}

fn bench_os_rng(c: &mut Criterion) {
    use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
    let mut p = OsRngDhPrivProvider;
    c.bench_function("osrng_generate_priv_32", |b| {
        b.iter(|| {
            let priv_bytes = p.generate_priv();
            black_box(priv_bytes);
        });
    });
}

criterion_group!(
    benches,
    bench_hkdf,
    bench_aead_encrypt,
    bench_aead_decrypt,
    bench_dh_ratchet_step,
    bench_x25519,
    bench_message_chain_step,
    bench_os_rng,
);
criterion_main!(benches);
