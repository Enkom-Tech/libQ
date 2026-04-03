//! Performance metrics collection for HPKE operations

#[cfg(feature = "alloc")]
use alloc::{
    string::String,
    vec::Vec,
};

// Use a simple Vec-based approach instead of HashMap for no_std compatibility
#[cfg(feature = "alloc")]
type MetadataMap = Vec<(String, String)>;

// use crate::error::HpkeError; // TODO: Will be used when implementing error handling in metrics
use crate::types::*;

/// Performance metrics for HPKE operations
#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceMetrics {
    /// Operation type
    pub operation: OperationType,
    /// Algorithm used
    pub algorithm: AlgorithmType,
    /// Execution time in nanoseconds
    pub execution_time_ns: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: usize,
    /// Number of iterations
    pub iterations: u32,
    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,
    /// Additional metadata
    pub metadata: MetadataMap,
}

/// Types of operations that can be benchmarked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// KEM key generation
    KemKeyGeneration,
    /// KEM encapsulation
    KemEncapsulation,
    /// KEM decapsulation
    KemDecapsulation,
    /// KDF extract operation
    KdfExtract,
    /// KDF expand operation
    KdfExpand,
    /// AEAD seal operation
    AeadSeal,
    /// AEAD open operation
    AeadOpen,
    /// HPKE setup sender
    HpkeSetupSender,
    /// HPKE setup receiver
    HpkeSetupReceiver,
    /// HPKE seal operation
    HpkeSeal,
    /// HPKE open operation
    HpkeOpen,
    /// HPKE export operation
    HpkeExport,
}

/// Types of algorithms that can be benchmarked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmType {
    /// ML-KEM-512
    MlKem512,
    /// ML-KEM-768
    MlKem768,
    /// ML-KEM-1024
    MlKem1024,
    /// HKDF-SHAKE128
    HkdfShake128,
    /// HKDF-SHAKE256
    HkdfShake256,
    /// HKDF-SHA3-256
    HkdfSha3_256,
    /// HKDF-SHA3-512
    HkdfSha3_512,
    /// Saturnin-256
    Saturnin256,
    /// SHAKE256 AEAD
    Shake256Aead,
    /// Duplex-sponge AEAD (Keccak-f[1600])
    DuplexSpongeAead,
    /// Export-only
    ExportOnly,
}

impl PerformanceMetrics {
    /// Create new performance metrics
    pub fn new(
        operation: OperationType,
        algorithm: AlgorithmType,
        execution_time_ns: u64,
        memory_usage_bytes: usize,
        iterations: u32,
        success_rate: f64,
    ) -> Self {
        Self {
            operation,
            algorithm,
            execution_time_ns,
            memory_usage_bytes,
            iterations,
            success_rate,
            metadata: Vec::new(),
        }
    }

    /// Add metadata to the metrics
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.push((key, value));
        self
    }

    /// Get average execution time per iteration
    pub fn avg_execution_time_ns(&self) -> f64 {
        if self.iterations > 0 {
            self.execution_time_ns as f64 / self.iterations as f64
        } else {
            0.0
        }
    }

    /// Get throughput (operations per second)
    pub fn throughput_ops_per_sec(&self) -> f64 {
        if self.execution_time_ns > 0 {
            1_000_000_000.0 / self.avg_execution_time_ns()
        } else {
            0.0
        }
    }

    /// Get memory efficiency (bytes per operation)
    pub fn memory_efficiency_bytes_per_op(&self) -> f64 {
        if self.iterations > 0 {
            self.memory_usage_bytes as f64 / self.iterations as f64
        } else {
            0.0
        }
    }
}

/// Performance metrics collector
pub struct MetricsCollector {
    metrics: Vec<PerformanceMetrics>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
        }
    }

    /// Add metrics to the collector
    pub fn add_metrics(&mut self, metrics: PerformanceMetrics) {
        self.metrics.push(metrics);
    }

    /// Get all metrics
    pub fn get_metrics(&self) -> &[PerformanceMetrics] {
        &self.metrics
    }

    /// Get metrics for a specific operation
    pub fn get_metrics_for_operation(&self, operation: OperationType) -> Vec<&PerformanceMetrics> {
        self.metrics
            .iter()
            .filter(|m| m.operation == operation)
            .collect()
    }

    /// Get metrics for a specific algorithm
    pub fn get_metrics_for_algorithm(&self, algorithm: AlgorithmType) -> Vec<&PerformanceMetrics> {
        self.metrics
            .iter()
            .filter(|m| m.algorithm == algorithm)
            .collect()
    }

    /// Get average metrics for an operation
    pub fn get_average_metrics_for_operation(
        &self,
        operation: OperationType,
    ) -> Option<PerformanceMetrics> {
        let operation_metrics: Vec<&PerformanceMetrics> = self.get_metrics_for_operation(operation);

        if operation_metrics.is_empty() {
            return None;
        }

        let total_time = operation_metrics
            .iter()
            .map(|m| m.execution_time_ns)
            .sum::<u64>();
        let total_memory = operation_metrics
            .iter()
            .map(|m| m.memory_usage_bytes)
            .sum::<usize>();
        let total_iterations = operation_metrics.iter().map(|m| m.iterations).sum::<u32>();
        let avg_success_rate = operation_metrics
            .iter()
            .map(|m| m.success_rate)
            .sum::<f64>() /
            operation_metrics.len() as f64;

        Some(PerformanceMetrics::new(
            operation,
            operation_metrics[0].algorithm, // Use the first algorithm as representative
            total_time,
            total_memory,
            total_iterations,
            avg_success_rate,
        ))
    }

    /// Clear all metrics
    pub fn clear(&mut self) {
        self.metrics.clear();
    }

    /// Get total number of metrics
    pub fn len(&self) -> usize {
        self.metrics.len()
    }

    /// Check if collector is empty
    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert HPKE types to benchmark types
impl From<HpkeKem> for AlgorithmType {
    fn from(kem: HpkeKem) -> Self {
        match kem {
            HpkeKem::MlKem512 => AlgorithmType::MlKem512,
            HpkeKem::MlKem768 => AlgorithmType::MlKem768,
            HpkeKem::MlKem1024 => AlgorithmType::MlKem1024,
        }
    }
}

impl From<HpkeKdf> for AlgorithmType {
    fn from(kdf: HpkeKdf) -> Self {
        match kdf {
            HpkeKdf::HkdfShake128 => AlgorithmType::HkdfShake128,
            HpkeKdf::HkdfShake256 => AlgorithmType::HkdfShake256,
            HpkeKdf::HkdfSha3_256 => AlgorithmType::HkdfSha3_256,
            HpkeKdf::HkdfSha3_512 => AlgorithmType::HkdfSha3_512,
        }
    }
}

impl From<HpkeAead> for AlgorithmType {
    fn from(aead: HpkeAead) -> Self {
        match aead {
            HpkeAead::Saturnin256 => AlgorithmType::Saturnin256,
            HpkeAead::Shake256 => AlgorithmType::Shake256Aead,
            HpkeAead::DuplexSpongeAead => AlgorithmType::DuplexSpongeAead,
            HpkeAead::Export => AlgorithmType::ExportOnly,
        }
    }
}
