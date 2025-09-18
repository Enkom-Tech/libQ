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

    // Test that we can create a signature context
    let mut sig_ctx = SignatureContext::new();

    // Note: The core provider returns NotImplemented for signature operations
    // Users should use LibQSignatureProvider directly for actual operations
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
    println!("📝 Note: For actual ML-DSA operations, use LibQSignatureProvider directly");

    Ok(())
}
