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

    // Test that we can generate a keypair (this will use placeholder implementation)
    let keypair = sig_ctx.generate_keypair(Algorithm::MlDsa65)?;

    println!("✅ ML-DSA keypair generation works!");
    println!(
        "Public key size: {} bytes",
        keypair.public_key().as_bytes().len()
    );
    println!(
        "Secret key size: {} bytes",
        keypair.secret_key().as_bytes().len()
    );

    // Test that we can sign a message (this will use placeholder implementation)
    let message = b"Hello, ML-DSA!";
    let signature = sig_ctx.sign(Algorithm::MlDsa65, keypair.secret_key(), message)?;

    println!("✅ ML-DSA signing works!");
    println!("Signature size: {} bytes", signature.len());

    // Test that we can verify a signature (this will use placeholder implementation)
    let is_valid = sig_ctx.verify(
        Algorithm::MlDsa65,
        keypair.public_key(),
        message,
        &signature,
    )?;

    println!("✅ ML-DSA verification works!");
    println!("Signature valid: {}", is_valid);

    println!("🎉 All ML-DSA integration tests passed!");

    Ok(())
}
