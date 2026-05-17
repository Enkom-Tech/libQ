use libq::{
    Algorithm,
    AlgorithmCategory,
    SignatureContext,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Core algorithm registry (lib-q-core): stable ids for all registered schemes.
    // Concrete implementations are still selected via providers and `lib-q` feature flags.
    let algorithms = libq::supported_algorithms();
    let signature_algorithms = libq::algorithms_by_category(AlgorithmCategory::Signature);
    let kem_algorithms = libq::algorithms_by_category(AlgorithmCategory::Kem);

    println!("Total algorithms: {}", algorithms.len());
    println!("Signature algorithms: {}", signature_algorithms.len());
    println!("KEM algorithms: {}", kem_algorithms.len());

    // ML-DSA (FIPS 204)
    assert!(signature_algorithms.contains(&Algorithm::MlDsa44));
    assert!(signature_algorithms.contains(&Algorithm::MlDsa65));
    assert!(signature_algorithms.contains(&Algorithm::MlDsa87));

    // SLH-DSA (FIPS 205) — hash-based signatures in the same registry category
    assert!(signature_algorithms.contains(&Algorithm::SlhDsaSha256128fRobust));
    assert!(signature_algorithms.contains(&Algorithm::SlhDsaSha256192fRobust));
    assert!(signature_algorithms.contains(&Algorithm::SlhDsaSha256256fRobust));
    assert!(signature_algorithms.contains(&Algorithm::SlhDsaShake256128fRobust));
    assert!(signature_algorithms.contains(&Algorithm::SlhDsaShake256192fRobust));
    assert!(signature_algorithms.contains(&Algorithm::SlhDsaShake256256fRobust));

    // FN-DSA (FIPS 206) — ids are registered; `fn-dsa` on `lib-q` wires the implementation crate
    assert!(signature_algorithms.contains(&Algorithm::FnDsa));
    assert!(signature_algorithms.contains(&Algorithm::FnDsa512));
    assert!(signature_algorithms.contains(&Algorithm::FnDsa1024));

    // KEM ids used elsewhere in the workspace (ML-KEM, CB-KEM, HQC)
    assert!(kem_algorithms.contains(&Algorithm::MlKem512));
    assert!(kem_algorithms.contains(&Algorithm::MlKem768));
    assert!(kem_algorithms.contains(&Algorithm::MlKem1024));
    assert!(kem_algorithms.contains(&Algorithm::CbKem348864));
    assert!(kem_algorithms.contains(&Algorithm::Hqc128));

    println!("✅ Registry lists ML-DSA, SLH-DSA, FN-DSA, ML-KEM, CB-KEM, and HQC algorithm ids.");

    // Use the default LibQCryptoProvider so signature ops hit the core stub (NotImplemented),
    // not ProviderNotConfigured from an empty context.
    let mut sig_ctx = SignatureContext::with_default_provider();

    // Note: The core provider returns NotImplemented for signature operations
    // Users should use `lib_q_sig::LibQSignatureProvider` (or the `libq` re-export when
    // the `ml-dsa` / `slh-dsa` features are enabled) for real implementations.
    println!("ℹ️  Core provider correctly returns NotImplemented for signature operations");

    // This demonstrates the correct architecture - core provider doesn't implement algorithms
    let result = sig_ctx.generate_keypair(Algorithm::MlDsa65, None);
    match result {
        Err(libq::Error::NotImplemented { feature }) => {
            println!(
                "✅ Core provider correctly returns NotImplemented: {}",
                feature
            );
        }
        _ => panic!("Expected NotImplemented error from core provider"),
    }

    println!("🎉 Umbrella registry + core stub behavior check completed successfully!");
    println!(
        "📝 Note: For real ML-DSA / SLH-DSA operations use `lib_q_sig::LibQSignatureProvider` or `libq::LibQSignatureProvider` (feature-gated on the `lib-q` dependency)."
    );

    Ok(())
}
