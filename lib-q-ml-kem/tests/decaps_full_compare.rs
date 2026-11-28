//! Decapsulation must compare the re-encryption against every byte and every compressed
//! coefficient of the ciphertext. A comparison that leaves even one coordinate unchecked accepts a
//! forged ciphertext, returns the real shared key, and turns decapsulation into a key-recovery
//! oracle. Each test perturbs one position at a time and requires the implicit-rejection key
//! `J(z || c')` back.

use lib_q_ml_kem::kem::Decapsulate;
use lib_q_ml_kem::{
    Ciphertext, Encapsulate, KemCore, MlKem512, MlKem768, MlKem1024, Seed, SharedKey,
};
use lib_q_random::LibQRng;
use lib_q_sha3::{ExtendableOutput, Shake256, Update, XofReader};

struct Shape {
    k: usize,
    du: usize,
    dv: usize,
}

const ML_KEM_512: Shape = Shape {
    k: 2,
    du: 10,
    dv: 4,
};
const ML_KEM_768: Shape = Shape {
    k: 3,
    du: 10,
    dv: 4,
};
const ML_KEM_1024: Shape = Shape {
    k: 4,
    du: 11,
    dv: 5,
};

fn implicit_rejection_key(z: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(z);
    h.update(ct);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

// FIPS 203 ByteEncode_d packs coefficient j of a polynomial into bits j*d .. j*d+d-1 of that
// polynomial's block, least significant bit first.
fn read_bits(bytes: &[u8], bit_offset: usize, d: usize) -> u32 {
    (0..d).fold(0u32, |acc, i| {
        let b = bit_offset + i;
        acc | (u32::from((bytes[b / 8] >> (b % 8)) & 1) << i)
    })
}

fn write_bits(bytes: &mut [u8], bit_offset: usize, d: usize, value: u32) {
    for i in 0..d {
        let b = bit_offset + i;
        let bit = u8::try_from((value >> i) & 1).unwrap();
        bytes[b / 8] = (bytes[b / 8] & !(1 << (b % 8))) | (bit << (b % 8));
    }
}

/// `(byte offset of the polynomial block, coefficient index, bit width)` for every coordinate of
/// `u` (all `k` polynomials) followed by every coordinate of `v`.
fn coordinates(shape: &Shape) -> Vec<(usize, usize, usize)> {
    let u_block = 32 * shape.du;
    let mut out = Vec::with_capacity((shape.k + 1) * 256);
    for poly in 0..shape.k {
        for j in 0..256 {
            out.push((poly * u_block, j, shape.du));
        }
    }
    let v_offset = shape.k * u_block;
    for j in 0..256 {
        out.push((v_offset, j, shape.dv));
    }
    out
}

fn setup<K: KemCore>(
    shape: &Shape,
) -> (K::DecapsulationKey, [u8; 32], Ciphertext<K>, SharedKey<K>) {
    let mut rng = LibQRng::new_secure().expect("secure RNG");
    let (seed, dk, ek): (_, K::DecapsulationKey, K::EncapsulationKey) =
        K::generate_with_seed(&mut rng);
    let seed: &Seed = &seed;
    let mut z = [0u8; 32];
    z.copy_from_slice(&seed[32..]);

    let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
    assert_eq!(ct.len(), 32 * (shape.k * shape.du + shape.dv));
    assert_eq!(dk.decapsulate(&ct).unwrap(), k_send);
    (dk, z, ct, k_send)
}

fn assert_rejected<K: KemCore>(
    dk: &K::DecapsulationKey,
    z: &[u8; 32],
    forged: &Ciphertext<K>,
    k_send: &SharedKey<K>,
    what: &str,
) {
    let got = dk.decapsulate(forged).unwrap();
    assert_ne!(
        got.as_slice(),
        k_send.as_slice(),
        "{what}: forged ciphertext decapsulated to the real shared key"
    );
    assert_eq!(
        got.as_slice(),
        implicit_rejection_key(z, forged.as_slice()),
        "{what}: forged ciphertext did not yield the implicit-rejection key"
    );
}

fn every_byte_rejected<K: KemCore>(shape: &Shape) {
    let (dk, z, ct, k_send) = setup::<K>(shape);
    for pos in 0..ct.len() {
        for mask in [0x01u8, 0x80] {
            let mut forged = ct.clone();
            forged[pos] ^= mask;
            assert_rejected::<K>(
                &dk,
                &z,
                &forged,
                &k_send,
                &format!("byte {pos} ^ {mask:#04x}"),
            );
        }
    }
}

// Stepping one compressed coefficient by one grid point is the smallest change to a single
// coordinate, and is what a noise-measuring sweep over an unverified coordinate submits.
fn every_coordinate_rejected<K: KemCore>(shape: &Shape) {
    let (dk, z, ct, k_send) = setup::<K>(shape);
    for (n, (block, j, d)) in coordinates(shape).into_iter().enumerate() {
        let mut forged = ct.clone();
        let bits = &mut forged.as_mut_slice()[block..];
        let old = read_bits(bits, j * d, d);
        write_bits(bits, j * d, d, (old + 1) % (1 << d));
        assert_ne!(forged, ct);
        let which = if n < shape.k * 256 {
            format!("u[{}][{j}]", n / 256)
        } else {
            format!("v[{j}]")
        };
        assert_rejected::<K>(
            &dk,
            &z,
            &forged,
            &k_send,
            &format!("coordinate {which} + 1"),
        );
    }
}

#[test]
fn ml_kem_512_rejects_every_single_byte_change() {
    every_byte_rejected::<MlKem512>(&ML_KEM_512);
}

#[test]
fn ml_kem_768_rejects_every_single_byte_change() {
    every_byte_rejected::<MlKem768>(&ML_KEM_768);
}

#[test]
fn ml_kem_1024_rejects_every_single_byte_change() {
    every_byte_rejected::<MlKem1024>(&ML_KEM_1024);
}

#[test]
fn ml_kem_512_rejects_every_single_coordinate_change() {
    every_coordinate_rejected::<MlKem512>(&ML_KEM_512);
}

#[test]
fn ml_kem_768_rejects_every_single_coordinate_change() {
    every_coordinate_rejected::<MlKem768>(&ML_KEM_768);
}

#[test]
fn ml_kem_1024_rejects_every_single_coordinate_change() {
    every_coordinate_rejected::<MlKem1024>(&ML_KEM_1024);
}
