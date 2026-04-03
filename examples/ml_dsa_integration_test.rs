use libq::{
    Algorithm,
    AlgorithmCategory,
    SignatureContext,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test that ML-DSA algorithms are available
    let algorithms = libq::supported_algorithms();
    let signature_algorithms = libq::algorithms_by_category(AlgorithmCategory::Signature);

    println!("Total algorithms: {}", algorithms.len());
    println!("Signature algorithms: {}", signature_algorithms.len());

    // Check that ML-DSA algorithms are present
    assert!(signature_algorithms.contains(&Algorithm::MlDsa44));
    assert!(signature_algorithms.contains(&Algorithm::MlDsa65));
    assert!(signature_algorithms.contains(&Algorithm::MlDsa87));

    println!("✅ ML-DSA algorithms are properly integrated!");

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

    println!("🎉 ML-DSA integration test completed successfully!");
    println!(
        "📝 Note: For real ML-DSA operations use `lib_q_sig::LibQSignatureProvider` or `libq::LibQSignatureProvider` (enabled here via `ml-dsa` on the `lib-q` dependency)."
    );

    Ok(())
}
