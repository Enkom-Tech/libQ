//! Advanced Security Configuration Examples for FN-DSA
//!
//! This example demonstrates advanced security configurations, including
//! custom security policies, audit logging, and compliance frameworks.

#![allow(clippy::collapsible_if)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use lib_q_core::{
    Result,
    SecurityLevel,
};
use lib_q_fn_dsa::*;

/// Advanced security configuration for FN-DSA
#[derive(Debug, Clone)]
pub struct AdvancedSecurityConfig {
    /// Security policy settings
    pub security_policy: SecurityPolicy,
    /// Audit logging configuration
    pub audit_config: AuditConfig,
    /// Compliance framework settings
    pub compliance_config: ComplianceConfig,
    /// Key management policy
    pub key_management: KeyManagementPolicy,
    /// Performance vs security trade-offs
    pub performance_config: PerformanceConfig,
}

/// Security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Minimum security level for operations
    pub min_security_level: SecurityLevel,
    /// Maximum key lifetime in seconds
    pub max_key_lifetime: u64,
    /// Required signature verification depth
    pub verification_depth: usize,
    /// Enable constant-time operations
    pub constant_time_operations: bool,
    /// Enable side-channel resistance
    pub side_channel_resistance: bool,
    /// Enable key zeroization
    pub key_zeroization: bool,
    /// Enable signature uniqueness validation
    pub signature_uniqueness: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            min_security_level: SecurityLevel::Level1,
            max_key_lifetime: 86400 * 365, // 1 year
            verification_depth: 3,
            constant_time_operations: true,
            side_channel_resistance: true,
            key_zeroization: true,
            signature_uniqueness: true,
        }
    }
}

/// Audit logging configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Log level for audit events
    pub log_level: AuditLogLevel,
    /// Include cryptographic operations in logs
    pub log_crypto_operations: bool,
    /// Include key operations in logs
    pub log_key_operations: bool,
    /// Include performance metrics in logs
    pub log_performance_metrics: bool,
    /// Maximum log entry size
    pub max_log_entry_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: AuditLogLevel::Info,
            log_crypto_operations: true,
            log_key_operations: true,
            log_performance_metrics: false,
            max_log_entry_size: 1024,
        }
    }
}

/// Audit log levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuditLogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Compliance framework configuration
#[derive(Debug, Clone)]
pub struct ComplianceConfig {
    /// FIPS 140-2 compliance mode
    pub fips_140_2: bool,
    /// Common Criteria compliance mode
    pub common_criteria: bool,
    /// NIST SP 800-57 compliance mode
    pub nist_sp_800_57: bool,
    /// ISO 27001 compliance mode
    pub iso_27001: bool,
    /// Custom compliance requirements
    pub custom_requirements: Vec<String>,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            fips_140_2: true,
            common_criteria: false,
            nist_sp_800_57: true,
            iso_27001: false,
            custom_requirements: Vec::new(),
        }
    }
}

/// Key management policy
#[derive(Debug, Clone)]
pub struct KeyManagementPolicy {
    /// Enable automatic key rotation
    pub auto_key_rotation: bool,
    /// Key rotation interval in seconds
    pub rotation_interval: u64,
    /// Enable key escrow
    pub key_escrow: bool,
    /// Enable key recovery
    pub key_recovery: bool,
    /// Maximum number of key versions to keep
    pub max_key_versions: usize,
    /// Enable key derivation
    pub key_derivation: bool,
}

impl Default for KeyManagementPolicy {
    fn default() -> Self {
        Self {
            auto_key_rotation: false,
            rotation_interval: 86400 * 30, // 30 days
            key_escrow: false,
            key_recovery: false,
            max_key_versions: 5,
            key_derivation: true,
        }
    }
}

/// Performance configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable performance optimizations
    pub enable_optimizations: bool,
    /// Enable AVX2 optimizations
    pub enable_avx2: bool,
    /// Enable parallel processing
    pub enable_parallel: bool,
    /// Maximum number of parallel threads
    pub max_parallel_threads: usize,
    /// Enable memory pooling
    pub enable_memory_pooling: bool,
    /// Cache size for frequently used operations
    pub cache_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_optimizations: true,
            enable_avx2: true,
            enable_parallel: false,
            max_parallel_threads: 4,
            enable_memory_pooling: true,
            cache_size: 1024 * 1024, // 1MB
        }
    }
}

/// Advanced security manager for FN-DSA
pub struct AdvancedSecurityManager {
    config: AdvancedSecurityConfig,
    audit_logger: AuditLogger,
    key_manager: KeyManager,
    performance_monitor: PerformanceMonitor,
}

/// Audit logger for security events
pub struct AuditLogger {
    config: AuditConfig,
    #[cfg(feature = "std")]
    log_entries: Vec<AuditLogEntry>,
}

/// Audit log entry
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub timestamp: u64,
    pub level: AuditLogLevel,
    pub operation: String,
    pub details: String,
    pub success: bool,
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "std")]
            log_entries: Vec::new(),
        }
    }

    pub fn log(&mut self, level: AuditLogLevel, operation: &str, details: &str, success: bool) {
        if !self.config.enabled {
            return;
        }

        if level as u8 >= self.config.log_level as u8 {
            let entry = AuditLogEntry {
                timestamp: self.get_timestamp(),
                level,
                operation: operation.to_string(),
                details: details.to_string(),
                success,
            };

            #[cfg(feature = "std")]
            {
                self.log_entries.push(entry);
            }
        }
    }

    fn get_timestamp(&self) -> u64 {
        #[cfg(feature = "std")]
        {
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std environment, use a simple counter for demonstration
            // In real implementation, use hardware timer or RTC
            0 // Placeholder
        }
    }
}

/// Key manager for advanced key operations
pub struct KeyManager {
    config: KeyManagementPolicy,
    #[cfg(feature = "std")]
    key_registry: BTreeMap<String, KeyMetadata>,
}

/// Key metadata for tracking
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: u64,
    pub last_used: u64,
    pub usage_count: u64,
    pub security_level: SecurityLevel,
    pub rotation_scheduled: Option<u64>,
}

impl KeyManager {
    pub fn new(config: KeyManagementPolicy) -> Self {
        Self {
            config,
            #[cfg(feature = "std")]
            key_registry: BTreeMap::new(),
        }
    }

    pub fn register_key(&mut self, key_id: String, security_level: SecurityLevel) {
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            created_at: self.get_timestamp(),
            last_used: 0,
            usage_count: 0,
            security_level,
            rotation_scheduled: if self.config.auto_key_rotation {
                Some(self.get_timestamp() + self.config.rotation_interval)
            } else {
                None
            },
        };

        #[cfg(feature = "std")]
        {
            self.key_registry.insert(key_id, metadata);
        }
    }

    pub fn update_key_usage(&mut self, key_id: &str) {
        #[cfg(feature = "std")]
        {
            if let Some(metadata) = self.key_registry.get_mut(key_id) {
                metadata.last_used = 0; // Use placeholder timestamp
                metadata.usage_count += 1;
            }
        }
    }

    pub fn check_key_rotation(&mut self, key_id: &str) -> bool {
        #[cfg(feature = "std")]
        {
            if let Some(metadata) = self.key_registry.get(key_id) {
                if let Some(rotation_time) = metadata.rotation_scheduled {
                    return self.get_timestamp() >= rotation_time;
                }
            }
        }
        false
    }

    fn get_timestamp(&self) -> u64 {
        #[cfg(feature = "std")]
        {
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std environment, use a simple counter for demonstration
            // In real implementation, use hardware timer or RTC
            0 // Placeholder
        }
    }
}

/// Performance monitor for security operations
pub struct PerformanceMonitor {
    config: PerformanceConfig,
    #[cfg(feature = "std")]
    metrics: BTreeMap<String, PerformanceMetric>,
}

/// Performance metric
#[derive(Debug, Clone)]
pub struct PerformanceMetric {
    pub operation: String,
    pub count: u64,
    pub total_time: u64,
    pub min_time: u64,
    pub max_time: u64,
    pub avg_time: f64,
}

impl PerformanceMonitor {
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "std")]
            metrics: BTreeMap::new(),
        }
    }

    pub fn record_operation(&mut self, operation: &str, duration: u64) {
        // Check if performance monitoring is enabled
        if !self.config.enable_optimizations {
            return;
        }

        #[cfg(feature = "std")]
        {
            let metric = self
                .metrics
                .entry(operation.to_string())
                .or_insert(PerformanceMetric {
                    operation: operation.to_string(),
                    count: 0,
                    total_time: 0,
                    min_time: u64::MAX,
                    max_time: 0,
                    avg_time: 0.0,
                });

            metric.count += 1;
            metric.total_time += duration;
            metric.min_time = metric.min_time.min(duration);
            metric.max_time = metric.max_time.max(duration);
            metric.avg_time = metric.total_time as f64 / metric.count as f64;

            // Check if we need to limit cache size based on config
            if self.metrics.len() > self.config.cache_size / 1024 {
                // Remove oldest entries to maintain cache size limit
                let keys_to_remove: Vec<String> = self.metrics.keys().take(10).cloned().collect();
                for key in keys_to_remove {
                    self.metrics.remove(&key);
                }
            }
        }
    }

    pub fn get_metrics(&self) -> Vec<PerformanceMetric> {
        if !self.config.enable_optimizations {
            return Vec::new();
        }

        #[cfg(feature = "std")]
        {
            self.metrics.values().cloned().collect()
        }
        #[cfg(not(feature = "std"))]
        {
            Vec::new()
        }
    }

    /// Get performance configuration
    pub fn get_config(&self) -> &PerformanceConfig {
        &self.config
    }

    /// Check if AVX2 optimizations are enabled
    pub fn is_avx2_enabled(&self) -> bool {
        self.config.enable_avx2
    }

    /// Check if parallel processing is enabled
    pub fn is_parallel_enabled(&self) -> bool {
        self.config.enable_parallel
    }
}

impl AdvancedSecurityManager {
    /// Create a new advanced security manager
    pub fn new(config: AdvancedSecurityConfig) -> Self {
        let audit_logger = AuditLogger::new(config.audit_config.clone());
        let key_manager = KeyManager::new(config.key_management.clone());
        let performance_monitor = PerformanceMonitor::new(config.performance_config.clone());

        Self {
            config,
            audit_logger,
            key_manager,
            performance_monitor,
        }
    }

    /// Demonstrate secure key generation with audit logging
    pub fn secure_key_generation(&mut self) -> Result<SecureKeyGenerationResult> {
        let start_time = self.get_timestamp();

        // Generate keypair based on security policy
        let fn_dsa = FnDsa512::new(); // Use Level 1 for consistency

        let keypair = fn_dsa.generate_keypair()?;
        let key_id = self.generate_key_id();

        // Register key with key manager
        self.key_manager.register_key(
            key_id.clone(),
            self.config.security_policy.min_security_level,
        );

        // Log the operation
        self.audit_logger.log(
            AuditLogLevel::Info,
            "key_generation",
            &format!("Generated keypair with ID: {}", key_id),
            true,
        );

        let end_time = self.get_timestamp();
        let duration = end_time - start_time;

        // Record performance metrics
        self.performance_monitor
            .record_operation("key_generation", duration);

        Ok(SecureKeyGenerationResult {
            keypair,
            key_id,
            generation_time: duration,
            security_level: self.config.security_policy.min_security_level,
        })
    }

    /// Demonstrate secure signing with compliance checks
    pub fn secure_signing(
        &mut self,
        keypair: &lib_q_core::SigKeypair,
        message: &[u8],
    ) -> Result<SecureSigningResult> {
        let start_time = self.get_timestamp();

        // Check key rotation if enabled
        let key_id = self.get_key_id_from_keypair(keypair);
        let rotation_required = self.key_manager.check_key_rotation(&key_id);

        if rotation_required {
            self.audit_logger.log(
                AuditLogLevel::Warning,
                "key_rotation_required",
                &format!("Key {} requires rotation", key_id),
                false,
            );
        }

        // Perform signing
        let fn_dsa = FnDsa512::new(); // Use Level 1 for consistency

        let signature = fn_dsa.sign(&keypair.secret_key, message)?;

        // Update key usage
        self.key_manager.update_key_usage(&key_id);

        // Log the operation
        self.audit_logger.log(
            AuditLogLevel::Info,
            "signing",
            &format!("Signed message with key: {}", key_id),
            true,
        );

        let end_time = self.get_timestamp();
        let duration = end_time - start_time;

        // Record performance metrics
        self.performance_monitor
            .record_operation("signing", duration);

        Ok(SecureSigningResult {
            signature,
            key_id,
            signing_time: duration,
            rotation_required,
        })
    }

    /// Demonstrate secure verification with compliance checks
    pub fn secure_verification(
        &mut self,
        public_key: &lib_q_core::SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<SecureVerificationResult> {
        let start_time = self.get_timestamp();

        // Perform verification
        let fn_dsa = FnDsa512::new(); // Use Level 1 for consistency

        let is_valid = fn_dsa.verify(public_key, message, signature)?;

        // Log the operation
        self.audit_logger.log(
            AuditLogLevel::Info,
            "verification",
            &format!(
                "Verified signature: {}",
                if is_valid { "valid" } else { "invalid" }
            ),
            is_valid,
        );

        let end_time = self.get_timestamp();
        let duration = end_time - start_time;

        // Record performance metrics
        self.performance_monitor
            .record_operation("verification", duration);

        Ok(SecureVerificationResult {
            is_valid,
            verification_time: duration,
        })
    }

    /// Demonstrate compliance framework validation
    pub fn validate_compliance(&self) -> Result<ComplianceValidationResult> {
        let mut compliance_results = Vec::new();

        // FIPS 140-2 compliance check
        if self.config.compliance_config.fips_140_2 {
            let fips_compliant = self.validate_fips_140_2();
            compliance_results.push(ComplianceResult {
                framework: "FIPS 140-2".to_string(),
                compliant: fips_compliant,
                details: if fips_compliant {
                    "All FIPS 140-2 requirements met".to_string()
                } else {
                    "FIPS 140-2 requirements not fully met".to_string()
                },
            });
        }

        // NIST SP 800-57 compliance check
        if self.config.compliance_config.nist_sp_800_57 {
            let nist_compliant = self.validate_nist_sp_800_57();
            compliance_results.push(ComplianceResult {
                framework: "NIST SP 800-57".to_string(),
                compliant: nist_compliant,
                details: if nist_compliant {
                    "All NIST SP 800-57 requirements met".to_string()
                } else {
                    "NIST SP 800-57 requirements not fully met".to_string()
                },
            });
        }

        let overall_compliant = compliance_results.iter().all(|r| r.compliant);
        Ok(ComplianceValidationResult {
            compliance_results,
            overall_compliant,
        })
    }

    /// Validate FIPS 140-2 compliance
    fn validate_fips_140_2(&self) -> bool {
        // Check security policy requirements
        self.config.security_policy.constant_time_operations &&
            self.config.security_policy.side_channel_resistance &&
            self.config.security_policy.key_zeroization &&
            self.config.security_policy.signature_uniqueness
    }

    /// Validate NIST SP 800-57 compliance
    fn validate_nist_sp_800_57(&self) -> bool {
        // Check key management requirements
        self.config.key_management.key_derivation &&
            self.config.key_management.max_key_versions > 0 &&
            self.config.security_policy.max_key_lifetime > 0
    }

    /// Generate a unique key ID
    fn generate_key_id(&self) -> String {
        // In real implementation, generate a proper unique ID
        format!("key_{}", self.get_timestamp())
    }

    /// Get key ID from keypair (simplified)
    fn get_key_id_from_keypair(&self, _keypair: &lib_q_core::SigKeypair) -> String {
        // In real implementation, extract or map key ID
        "key_123".to_string()
    }

    /// Get current timestamp (placeholder)
    fn get_timestamp(&self) -> u64 {
        #[cfg(feature = "std")]
        {
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std environment, use a simple counter for demonstration
            // In real implementation, use hardware timer or RTC
            0 // Placeholder
        }
    }
}

/// Secure key generation result
pub struct SecureKeyGenerationResult {
    pub keypair: lib_q_core::SigKeypair,
    pub key_id: String,
    pub generation_time: u64,
    pub security_level: SecurityLevel,
}

/// Secure signing result
#[derive(Debug)]
pub struct SecureSigningResult {
    pub signature: Vec<u8>,
    pub key_id: String,
    pub signing_time: u64,
    pub rotation_required: bool,
}

/// Secure verification result
#[derive(Debug)]
pub struct SecureVerificationResult {
    pub is_valid: bool,
    pub verification_time: u64,
}

/// Compliance validation result
#[derive(Debug)]
pub struct ComplianceValidationResult {
    pub compliance_results: Vec<ComplianceResult>,
    pub overall_compliant: bool,
}

/// Individual compliance result
#[derive(Debug)]
pub struct ComplianceResult {
    pub framework: String,
    pub compliant: bool,
    pub details: String,
}

#[cfg(feature = "std")]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Advanced Security Configuration Examples");
    println!("==========================================\n");

    // Create advanced security configuration
    let config = AdvancedSecurityConfig {
        security_policy: SecurityPolicy {
            min_security_level: SecurityLevel::Level1,
            max_key_lifetime: 86400 * 365, // 1 year
            verification_depth: 3,
            constant_time_operations: true,
            side_channel_resistance: true,
            key_zeroization: true,
            signature_uniqueness: true,
        },
        audit_config: AuditConfig {
            enabled: true,
            log_level: AuditLogLevel::Info,
            log_crypto_operations: true,
            log_key_operations: true,
            log_performance_metrics: true,
            max_log_entry_size: 1024,
        },
        compliance_config: ComplianceConfig {
            fips_140_2: true,
            common_criteria: false,
            nist_sp_800_57: true,
            iso_27001: false,
            custom_requirements: vec!["Custom requirement 1".to_string()],
        },
        key_management: KeyManagementPolicy {
            auto_key_rotation: true,
            rotation_interval: 86400 * 30, // 30 days
            key_escrow: false,
            key_recovery: false,
            max_key_versions: 5,
            key_derivation: true,
        },
        performance_config: PerformanceConfig {
            enable_optimizations: true,
            enable_avx2: true,
            enable_parallel: false,
            max_parallel_threads: 4,
            enable_memory_pooling: true,
            cache_size: 1024 * 1024, // 1MB
        },
    };

    // Create advanced security manager
    let mut security_manager = AdvancedSecurityManager::new(config);

    // Demonstrate secure key generation
    println!("🔑 Secure Key Generation");
    println!("----------------------");
    let keygen_result = security_manager.secure_key_generation()?;
    println!("✅ Secure key generation completed");
    println!("   Key ID: {}", keygen_result.key_id);
    println!("   Security Level: {:?}", keygen_result.security_level);
    println!(
        "   Generation Time: {}ns ({:.3}μs)",
        keygen_result.generation_time,
        keygen_result.generation_time as f64 / 1000.0
    );
    println!();

    // Demonstrate secure signing
    println!("✍️ Secure Signing");
    println!("---------------");
    let message = b"Secure message for advanced security demo";
    let signing_result = security_manager.secure_signing(&keygen_result.keypair, message)?;
    println!("✅ Secure signing completed");
    println!("   Key ID: {}", signing_result.key_id);
    println!(
        "   Signing Time: {}ns ({:.3}μs)",
        signing_result.signing_time,
        signing_result.signing_time as f64 / 1000.0
    );
    println!("   Rotation Required: {}", signing_result.rotation_required);
    println!();

    // Demonstrate secure verification
    println!("🔍 Secure Verification");
    println!("--------------------");
    let verification_result = security_manager.secure_verification(
        &keygen_result.keypair.public_key,
        message,
        &signing_result.signature,
    )?;
    println!("✅ Secure verification completed");
    println!("   Signature Valid: {}", verification_result.is_valid);
    println!(
        "   Verification Time: {}ns ({:.3}μs)",
        verification_result.verification_time,
        verification_result.verification_time as f64 / 1000.0
    );
    println!();

    // Demonstrate compliance validation
    println!("📋 Compliance Validation");
    println!("----------------------");
    let compliance_result = security_manager.validate_compliance()?;
    println!("✅ Compliance validation completed");
    println!(
        "   Overall Compliant: {}",
        compliance_result.overall_compliant
    );
    for result in &compliance_result.compliance_results {
        println!(
            "   {}: {} - {}",
            result.framework,
            if result.compliant { "✅" } else { "❌" },
            result.details
        );
    }
    println!();

    // Demonstrate performance metrics
    println!("📊 Performance Metrics");
    println!("--------------------");
    let performance_config = security_manager.performance_monitor.get_config();
    println!(
        "   Performance optimizations enabled: {}",
        performance_config.enable_optimizations
    );
    println!(
        "   AVX2 optimizations enabled: {}",
        performance_config.enable_avx2
    );
    println!(
        "   Parallel processing enabled: {}",
        performance_config.enable_parallel
    );
    println!("   Cache size: {} bytes", performance_config.cache_size);

    let metrics = security_manager.performance_monitor.get_metrics();
    for metric in &metrics {
        println!(
            "   {}: {} operations, avg {:.2}ns ({:.3}μs)",
            metric.operation,
            metric.count,
            metric.avg_time,
            metric.avg_time / 1000.0
        );
    }
    println!();

    println!("🎉 Advanced security configuration examples completed successfully!");

    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> core::result::Result<(), alloc::boxed::Box<dyn core::error::Error>> {
    // In no_std environment, just run the security tests
    let config = AdvancedSecurityConfig {
        security_policy: SecurityPolicy::default(),
        audit_config: AuditConfig::default(),
        compliance_config: ComplianceConfig::default(),
        key_management: KeyManagementPolicy::default(),
        performance_config: PerformanceConfig::default(),
    };

    let mut security_manager = AdvancedSecurityManager::new(config);
    let _keygen = security_manager.secure_key_generation()?;
    let _compliance = security_manager.validate_compliance()?;

    Ok(())
}
