use lib_q_hqc::Hqc1Params;
use lib_q_hqc::hqc_kem::HqcKem;
use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
use rand_core::Rng;

// `test_kat_intermediate_values_count_0` (an `#[ignore]`d comparison of computed `seed_ek`/`s`
// against a hardcoded "expected_pk" byte string) was deleted here rather than repaired.
//
// Investigation (lane `e-kat-provenance`, card t_71d4f79a) found the hardcoded expectation was
// NOT reference data for this parameter set at all: it was 2225 bytes long while
// `Hqc1Params::PUBLIC_KEY_BYTES` is 2241 (and the committed regression-pin `.rsp` `pk` for the
// same seed measures 2241 bytes). Of the 2193 `s`-bytes actually compared, 2185 differed --
// 2193/256 ~= 8.6 coincidental matches are expected between two UNRELATED byte strings of that
// length, and 8 were observed. That is the fingerprint of two unrelated blobs, not of a
// near-miss implementation divergence. The test's `#[ignore] // ... implementation differences
// with reference` reason was therefore inaccurate: it never held reference data to differ from,
// and there is nothing to repair it against.
//
// A genuine replacement (comparing against `reference/hqc/kats/ref/hqc-1/intermediates_values`,
// the official HQC v5.0.0 reference's real intermediate-value dump) was deliberately NOT added
// in its place: that `reference/` tree is untracked (`.gitignore:236 /reference`) and present on
// this machine only, so a test reading it would either be silently skipped or hard-fail in CI
// depending on how it's written -- exactly the kind of gate-that-cannot-be-trusted this card
// exists to remove. Wiring a real comparison requires first committing an extracted, hashed
// upstream vector set (tracked follow-up work), not another local-only comparison.
#[test]
fn test_kat_encapsulation_intermediate_values() {
    println!("=== KAT Encapsulation Intermediate Values (count=0) ===");

    // Use the exact 48-byte seed from official KAT file (count=0)
    let seed_kem = hex::decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1").unwrap();
    let seed_kem_array: [u8; 48] = seed_kem.try_into().unwrap();

    // Generate keypair using KEM
    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    let (_pk, _sk) = kem.keygen_with_seed(&seed_kem_array).unwrap();

    // Generate theta for encapsulation using the same PRNG approach
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mut rng = create_shake256_prng_rng(entropy_input);

    let mut theta = [0u8; 64];
    rng.fill_bytes(&mut theta);

    println!("theta: {:02x?}", theta);

    // Perform encapsulation
    let mut rng_for_encaps = create_shake256_prng_rng(entropy_input);
    // Skip the seed generation bytes
    let mut _skip = [0u8; 32];
    rng_for_encaps.fill_bytes(&mut _skip);
    let (_ct, _ss) = kem.encapsulate(&_pk, &mut rng_for_encaps).unwrap();

    println!("Ciphertext created successfully");
    println!("Shared secret created successfully");

    // For now, just verify that encapsulation works
    // Full KAT comparison would require extracting the raw bytes
    println!("✅ Encapsulation completed successfully");
}
