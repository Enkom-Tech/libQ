//! Advanced FN-DSA Integration Examples
//!
//! This example demonstrates advanced integration scenarios for FN-DSA,
//! including multi-party protocols, certificate chains, and enterprise
//! security configurations.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_core::{
    Result,
    SecurityLevel,
};
use lib_q_fn_dsa::*;

/// Advanced integration scenarios for FN-DSA
pub struct AdvancedFnDsaIntegration {
    /// Certificate authority instance
    ca_instance: FnDsa1024,
    /// User instances for different security levels
    user_instances: Vec<FnDsa512>,
    /// Enterprise configuration
    enterprise_config: EnterpriseConfig,
}

/// Enterprise security configuration
#[derive(Debug, Clone)]
pub struct EnterpriseConfig {
    /// Minimum security level for operations
    pub min_security_level: SecurityLevel,
    /// Maximum key lifetime in seconds
    pub max_key_lifetime: u64,
    /// Required signature verification depth
    pub verification_depth: usize,
    /// Enable audit logging
    pub audit_logging: bool,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            min_security_level: SecurityLevel::Level1,
            max_key_lifetime: 86400 * 365, // 1 year
            verification_depth: 3,
            audit_logging: true,
        }
    }
}

impl AdvancedFnDsaIntegration {
    /// Create a new advanced integration instance
    pub fn new(config: EnterpriseConfig) -> Result<Self> {
        let ca_instance = FnDsa1024::new();
        let user_instances = vec![FnDsa512::new(), FnDsa512::new(), FnDsa512::new()];

        Ok(Self {
            ca_instance,
            user_instances,
            enterprise_config: config,
        })
    }

    /// Demonstrate multi-party signature protocol
    pub fn multi_party_signature_protocol(&self) -> Result<MultiPartyResult> {
        // Validate enterprise configuration
        if self.enterprise_config.verification_depth < 2 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 2,
                actual: self.enterprise_config.verification_depth,
            });
        }

        // Generate keypairs for all parties
        let mut party_keypairs = Vec::new();
        for instance in &self.user_instances {
            let keypair = instance.generate_keypair()?;
            party_keypairs.push(keypair);
        }

        // Create a message that requires multi-party approval
        let message = b"Enterprise contract approval - Q4 2024 budget allocation";

        // Each party signs the message
        let mut signatures = Vec::new();
        for (i, (instance, keypair)) in self
            .user_instances
            .iter()
            .zip(party_keypairs.iter())
            .enumerate()
        {
            let signature = instance.sign(&keypair.secret_key, message)?;
            signatures.push(PartySignature {
                party_id: i,
                signature,
                public_key: keypair.public_key.clone(),
            });
        }

        // Verify all signatures with enterprise verification depth
        let mut verification_results = Vec::new();
        for sig in &signatures {
            let instance = &self.user_instances[sig.party_id];
            let mut is_valid = instance.verify(&sig.public_key, message, &sig.signature)?;

            // Apply enterprise verification depth (multiple verification rounds)
            for _ in 1..self.enterprise_config.verification_depth {
                let recheck = instance.verify(&sig.public_key, message, &sig.signature)?;
                is_valid = is_valid && recheck;
            }

            verification_results.push(is_valid);
        }

        // Check if all signatures are valid
        let all_valid = verification_results.iter().all(|&valid| valid);

        Ok(MultiPartyResult {
            message: message.to_vec(),
            signatures,
            all_valid,
            verification_results,
        })
    }

    /// Demonstrate certificate chain validation
    pub fn certificate_chain_validation(&self) -> Result<CertificateChainResult> {
        // Check enterprise configuration for audit logging
        if self.enterprise_config.audit_logging {
            // In a real implementation, this would log the certificate chain validation
            // For now, we'll just validate the configuration
            if self.enterprise_config.max_key_lifetime == 0 {
                return Err(lib_q_core::Error::InvalidKeySize {
                    expected: 1,
                    actual: 0,
                });
            }
        }

        // Generate CA keypair (root certificate authority)
        let ca_keypair = self.ca_instance.generate_keypair()?;

        // Generate intermediate CA keypair
        let intermediate_keypair = self.ca_instance.generate_keypair()?;

        // Generate end-entity keypair
        let end_entity_keypair = self.user_instances[0].generate_keypair()?;

        // Create certificate chain
        let root_cert = Certificate {
            subject: "Root CA".to_string(),
            issuer: "Root CA".to_string(),
            public_key: ca_keypair.public_key.clone(),
            signature: Vec::new(), // Self-signed
        };

        // Sign intermediate certificate with root CA
        let intermediate_cert_data = format!(
            "Intermediate CA:{}",
            hex::encode(intermediate_keypair.public_key.as_bytes())
        );
        let intermediate_signature = self
            .ca_instance
            .sign(&ca_keypair.secret_key, intermediate_cert_data.as_bytes())?;

        let intermediate_cert = Certificate {
            subject: "Intermediate CA".to_string(),
            issuer: "Root CA".to_string(),
            public_key: intermediate_keypair.public_key.clone(),
            signature: intermediate_signature,
        };

        // Sign end-entity certificate with intermediate CA
        let end_entity_cert_data = format!(
            "End Entity:{}",
            hex::encode(end_entity_keypair.public_key.as_bytes())
        );
        let end_entity_signature = self.ca_instance.sign(
            &intermediate_keypair.secret_key,
            end_entity_cert_data.as_bytes(),
        )?;

        let end_entity_cert = Certificate {
            subject: "End Entity".to_string(),
            issuer: "Intermediate CA".to_string(),
            public_key: end_entity_keypair.public_key.clone(),
            signature: end_entity_signature,
        };

        // Validate certificate chain
        let chain_validation =
            self.validate_certificate_chain(&[&root_cert, &intermediate_cert, &end_entity_cert])?;

        Ok(CertificateChainResult {
            certificates: vec![root_cert, intermediate_cert, end_entity_cert],
            validation_result: chain_validation,
        })
    }

    /// Validate a certificate chain
    fn validate_certificate_chain(
        &self,
        certificates: &[&Certificate],
    ) -> Result<ChainValidationResult> {
        if certificates.is_empty() {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        let mut validation_results = Vec::new();

        // Validate each certificate in the chain
        for (i, cert) in certificates.iter().enumerate() {
            if i == 0 {
                // Root certificate (self-signed)
                validation_results.push(CertificateValidationResult {
                    certificate_index: i,
                    is_valid: true, // Assume root is trusted
                    validation_details: "Root certificate (trusted anchor)".to_string(),
                });
            } else {
                // Validate against parent certificate
                let parent_cert = certificates[i - 1];
                let cert_data = format!(
                    "{}:{}",
                    cert.subject,
                    hex::encode(cert.public_key.as_bytes())
                );

                let is_valid = self.ca_instance.verify(
                    &parent_cert.public_key,
                    cert_data.as_bytes(),
                    &cert.signature,
                )?;

                validation_results.push(CertificateValidationResult {
                    certificate_index: i,
                    is_valid,
                    validation_details: if is_valid {
                        "Valid signature from parent certificate".to_string()
                    } else {
                        "Invalid signature from parent certificate".to_string()
                    },
                });
            }
        }

        let chain_valid = validation_results.iter().all(|result| result.is_valid);

        Ok(ChainValidationResult {
            chain_valid,
            certificate_validations: validation_results,
        })
    }

    /// Demonstrate threshold signature scheme
    pub fn threshold_signature_scheme(&self, threshold: usize) -> Result<ThresholdSignatureResult> {
        if threshold > self.user_instances.len() {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: self.user_instances.len(),
                actual: threshold,
            });
        }

        // Generate keypairs for all participants
        let mut participant_keypairs = Vec::new();
        for instance in &self.user_instances {
            let keypair = instance.generate_keypair()?;
            participant_keypairs.push(keypair);
        }

        let message = b"Threshold signature: Critical system update approval";

        // Collect signatures from threshold number of participants
        let mut threshold_signatures = Vec::new();
        for i in 0..threshold {
            let instance = &self.user_instances[i];
            let keypair = &participant_keypairs[i];
            let signature = instance.sign(&keypair.secret_key, message)?;

            threshold_signatures.push(ThresholdSignature {
                participant_id: i,
                signature,
                public_key: keypair.public_key.clone(),
            });
        }

        // Verify threshold signatures
        let mut verification_results = Vec::new();
        for sig in &threshold_signatures {
            let instance = &self.user_instances[sig.participant_id];
            let is_valid = instance.verify(&sig.public_key, message, &sig.signature)?;
            verification_results.push(is_valid);
        }

        let threshold_met =
            verification_results.iter().filter(|&&valid| valid).count() >= threshold;
        let all_valid = verification_results.iter().all(|&valid| valid);

        Ok(ThresholdSignatureResult {
            message: message.to_vec(),
            threshold,
            signatures: threshold_signatures,
            threshold_met,
            all_valid,
            verification_results,
        })
    }

    /// Demonstrate secure key rotation
    pub fn secure_key_rotation(&self) -> Result<KeyRotationResult> {
        // Check enterprise configuration for key lifetime
        if self.enterprise_config.max_key_lifetime == 0 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        // Generate current keypair
        let current_keypair = self.user_instances[0].generate_keypair()?;

        // Generate new keypair for rotation
        let new_keypair = self.user_instances[0].generate_keypair()?;

        // Create rotation message
        let rotation_message = format!(
            "Key rotation: {} -> {}",
            hex::encode(current_keypair.public_key.as_bytes()),
            hex::encode(new_keypair.public_key.as_bytes())
        );

        // Sign rotation message with current key
        let rotation_signature = self.user_instances[0]
            .sign(&current_keypair.secret_key, rotation_message.as_bytes())?;

        // Verify rotation signature
        let rotation_valid = self.user_instances[0].verify(
            &current_keypair.public_key,
            rotation_message.as_bytes(),
            &rotation_signature,
        )?;

        // Test new keypair
        let test_message = b"Testing new keypair after rotation";
        let test_signature = self.user_instances[0].sign(&new_keypair.secret_key, test_message)?;

        let test_verification = self.user_instances[0].verify(
            &new_keypair.public_key,
            test_message,
            &test_signature,
        )?;

        Ok(KeyRotationResult {
            old_keypair: current_keypair,
            new_keypair,
            rotation_message,
            rotation_signature,
            rotation_valid,
            test_verification,
        })
    }

    /// Get enterprise configuration
    pub fn get_enterprise_config(&self) -> &EnterpriseConfig {
        &self.enterprise_config
    }

    /// Validate enterprise configuration
    pub fn validate_enterprise_config(&self) -> Result<bool> {
        // Check minimum security level
        if self.enterprise_config.min_security_level != SecurityLevel::Level1 &&
            self.enterprise_config.min_security_level != SecurityLevel::Level5
        {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        // Check verification depth
        if self.enterprise_config.verification_depth == 0 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        // Check key lifetime
        if self.enterprise_config.max_key_lifetime == 0 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        Ok(true)
    }
}

/// Multi-party signature result
#[derive(Debug)]
pub struct MultiPartyResult {
    pub message: Vec<u8>,
    pub signatures: Vec<PartySignature>,
    pub all_valid: bool,
    pub verification_results: Vec<bool>,
}

/// Party signature information
#[derive(Debug)]
pub struct PartySignature {
    pub party_id: usize,
    pub signature: Vec<u8>,
    pub public_key: lib_q_core::SigPublicKey,
}

/// Certificate structure
#[derive(Debug, Clone)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub public_key: lib_q_core::SigPublicKey,
    pub signature: Vec<u8>,
}

/// Certificate chain validation result
#[derive(Debug)]
pub struct CertificateChainResult {
    pub certificates: Vec<Certificate>,
    pub validation_result: ChainValidationResult,
}

/// Chain validation result
#[derive(Debug)]
pub struct ChainValidationResult {
    pub chain_valid: bool,
    pub certificate_validations: Vec<CertificateValidationResult>,
}

/// Individual certificate validation result
#[derive(Debug)]
pub struct CertificateValidationResult {
    pub certificate_index: usize,
    pub is_valid: bool,
    pub validation_details: String,
}

/// Threshold signature result
#[derive(Debug)]
pub struct ThresholdSignatureResult {
    pub message: Vec<u8>,
    pub threshold: usize,
    pub signatures: Vec<ThresholdSignature>,
    pub threshold_met: bool,
    pub all_valid: bool,
    pub verification_results: Vec<bool>,
}

/// Threshold signature information
#[derive(Debug)]
pub struct ThresholdSignature {
    pub participant_id: usize,
    pub signature: Vec<u8>,
    pub public_key: lib_q_core::SigPublicKey,
}

/// Key rotation result
pub struct KeyRotationResult {
    pub old_keypair: lib_q_core::SigKeypair,
    pub new_keypair: lib_q_core::SigKeypair,
    pub rotation_message: String,
    pub rotation_signature: Vec<u8>,
    pub rotation_valid: bool,
    pub test_verification: bool,
}

/// Hex encoding utility (simplified for no_std)
mod hex {

    pub fn encode(data: &[u8]) -> String {
        let mut hex = String::new();
        for byte in data {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }
}

#[cfg(feature = "std")]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Advanced FN-DSA Integration Examples");
    println!("=====================================\n");

    // Create advanced integration instance
    let config = EnterpriseConfig {
        min_security_level: SecurityLevel::Level1,
        max_key_lifetime: 86400 * 365, // 1 year
        verification_depth: 3,
        audit_logging: true,
    };

    let integration = AdvancedFnDsaIntegration::new(config)?;

    // Validate enterprise configuration
    println!("🔧 Enterprise Configuration Validation");
    println!("-----------------------------------");
    let config_valid = integration.validate_enterprise_config()?;
    println!("✅ Enterprise configuration valid: {}", config_valid);
    let enterprise_config = integration.get_enterprise_config();
    println!(
        "   Security Level: {:?}",
        enterprise_config.min_security_level
    );
    println!(
        "   Max Key Lifetime: {} seconds",
        enterprise_config.max_key_lifetime
    );
    println!(
        "   Verification Depth: {}",
        enterprise_config.verification_depth
    );
    println!("   Audit Logging: {}", enterprise_config.audit_logging);
    println!();

    // Demonstrate multi-party signature protocol
    println!("🤝 Multi-Party Signature Protocol");
    println!("--------------------------------");
    let multi_party_result = integration.multi_party_signature_protocol()?;
    println!("✅ Multi-party protocol completed");
    println!(
        "   Signatures collected: {}",
        multi_party_result.signatures.len()
    );
    println!("   All signatures valid: {}", multi_party_result.all_valid);
    println!();

    // Demonstrate certificate chain validation
    println!("🔗 Certificate Chain Validation");
    println!("------------------------------");
    let chain_result = integration.certificate_chain_validation()?;
    println!("✅ Certificate chain validation completed");
    println!(
        "   Certificates in chain: {}",
        chain_result.certificates.len()
    );
    println!(
        "   Chain valid: {}",
        chain_result.validation_result.chain_valid
    );
    println!();

    // Demonstrate threshold signature scheme
    println!("🎯 Threshold Signature Scheme");
    println!("----------------------------");
    let threshold_result = integration.threshold_signature_scheme(2)?;
    println!("✅ Threshold signature scheme completed");
    println!("   Threshold: {}", threshold_result.threshold);
    println!("   Threshold met: {}", threshold_result.threshold_met);
    println!("   All signatures valid: {}", threshold_result.all_valid);
    println!();

    // Demonstrate secure key rotation
    println!("🔄 Secure Key Rotation");
    println!("---------------------");
    let rotation_result = integration.secure_key_rotation()?;
    println!("✅ Key rotation completed");
    println!("   Rotation valid: {}", rotation_result.rotation_valid);
    println!(
        "   New key test passed: {}",
        rotation_result.test_verification
    );
    println!();

    println!("🎉 All advanced integration examples completed successfully!");

    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> core::result::Result<(), alloc::boxed::Box<dyn core::error::Error>> {
    // In no_std environment, just run the integration tests
    let config = EnterpriseConfig::default();
    let integration = AdvancedFnDsaIntegration::new(config)?;

    // Run all integration scenarios
    let _multi_party = integration.multi_party_signature_protocol()?;
    let _chain = integration.certificate_chain_validation()?;
    let _threshold = integration.threshold_signature_scheme(2)?;
    let _rotation = integration.secure_key_rotation()?;

    Ok(())
}
