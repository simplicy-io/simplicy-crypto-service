#![allow(unused_imports)]
extern crate rand;
use std::{thread, time};

use criterion::{black_box as bb, criterion_group, criterion_main, Criterion};
use crypto_service::crypto_service::Aes256;
use rand::{thread_rng, Rng};

//encrypt                 time:   [2.4807 µs 2.4810 µs 2.4813 µs]
fn bench_encrypt(c: &mut Criterion) {
    let mut key: [u8; 32] = [0u8; 32];
    let mut nonce: [u8; 12] = [0u8; 12];
    thread_rng().fill(&mut key[..]);
    thread_rng().fill(&mut nonce[..]);

    let aes256: Aes256 = Aes256::new(key).unwrap();
    let plaintext: &[u8; 12] = b"Hello World!";

    c.bench_function("encrypt", |f| f.iter(|| aes256.encrypt(&nonce, plaintext).unwrap()));
}

//decrypt                 time:   [2.7354 µs 2.7419 µs 2.7538 µs]
fn bench_decrypt(c: &mut Criterion) {
    let mut key: [u8; 32] = [0u8; 32];
    let mut nonce: [u8; 12] = [0u8; 12];
    thread_rng().fill(&mut key[..]);
    thread_rng().fill(&mut nonce[..]);

    let aes256: Aes256 = Aes256::new(key).unwrap();
    let plaintext: &[u8; 12] = b"Hello World!";
    let encrypted_data: Vec<u8> = aes256.encrypt(&nonce, plaintext).unwrap();

    c.bench_function("decrypt", |f| f.iter(|| aes256.decrypt(&nonce, &encrypted_data).unwrap()));
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
