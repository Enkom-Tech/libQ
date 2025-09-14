//! Performance reporting utilities for HPKE operations

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::String,
};

use crate::benchmarking::{
    AlgorithmType,
    MetricsCollector,
    OperationType,
    PerformanceMetrics,
};

/// Performance report generator
pub struct PerformanceReporter {
    collector: MetricsCollector,
}

impl PerformanceReporter {
    /// Create a new performance reporter
    pub fn new() -> Self {
        Self {
            collector: MetricsCollector::new(),
        }
    }

    /// Add metrics to the reporter
    pub fn add_metrics(&mut self, metrics: PerformanceMetrics) {
        self.collector.add_metrics(metrics);
    }

    /// Generate a text report
    pub fn generate_text_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== HPKE Performance Report ===\n\n");

        // Summary statistics
        report.push_str("Summary:\n");
        report.push_str(&format!("Total operations: {}\n", self.collector.len()));

        // Per-operation statistics
        for operation in [
            OperationType::KemKeyGeneration,
            OperationType::KemEncapsulation,
            OperationType::KemDecapsulation,
            OperationType::KdfExtract,
            OperationType::KdfExpand,
            OperationType::AeadSeal,
            OperationType::AeadOpen,
            OperationType::HpkeSetupSender,
            OperationType::HpkeSetupReceiver,
            OperationType::HpkeSeal,
            OperationType::HpkeOpen,
            OperationType::HpkeExport,
        ] {
            if let Some(avg_metrics) = self.collector.get_average_metrics_for_operation(operation) {
                report.push_str(&format!("\n{:?}:\n", operation));
                report.push_str(&format!(
                    "  Average time: {:.2} μs\n",
                    avg_metrics.avg_execution_time_ns() / 1000.0
                ));
                report.push_str(&format!(
                    "  Throughput: {:.2} ops/sec\n",
                    avg_metrics.throughput_ops_per_sec()
                ));
                report.push_str(&format!(
                    "  Memory efficiency: {:.2} bytes/op\n",
                    avg_metrics.memory_efficiency_bytes_per_op()
                ));
                report.push_str(&format!(
                    "  Success rate: {:.2}%\n",
                    avg_metrics.success_rate * 100.0
                ));
            }
        }

        // Per-algorithm statistics
        report.push_str("\n=== Algorithm Performance ===\n");
        for algorithm in [
            AlgorithmType::MlKem512,
            AlgorithmType::MlKem768,
            AlgorithmType::MlKem1024,
            AlgorithmType::HkdfShake128,
            AlgorithmType::HkdfShake256,
            AlgorithmType::HkdfSha3_256,
            AlgorithmType::HkdfSha3_512,
            AlgorithmType::Saturnin256,
            AlgorithmType::Shake256Aead,
            AlgorithmType::ExportOnly,
        ] {
            let algorithm_metrics = self.collector.get_metrics_for_algorithm(algorithm);
            if !algorithm_metrics.is_empty() {
                report.push_str(&format!("\n{:?}:\n", algorithm));
                let total_time: u64 = algorithm_metrics.iter().map(|m| m.execution_time_ns).sum();
                let total_ops: u32 = algorithm_metrics.iter().map(|m| m.iterations).sum();
                let avg_time = if total_ops > 0 {
                    total_time as f64 / total_ops as f64
                } else {
                    0.0
                };
                let throughput = if avg_time > 0.0 {
                    1_000_000_000.0 / avg_time
                } else {
                    0.0
                };

                report.push_str(&format!("  Average time: {:.2} μs\n", avg_time / 1000.0));
                report.push_str(&format!("  Throughput: {:.2} ops/sec\n", throughput));
                report.push_str(&format!("  Operations: {}\n", total_ops));
            }
        }

        report
    }

    /// Generate a CSV report
    pub fn generate_csv_report(&self) -> String {
        let mut csv = String::new();

        // CSV header
        csv.push_str("Operation,Algorithm,ExecutionTimeNs,MemoryUsageBytes,Iterations,SuccessRate,AvgTimeNs,ThroughputOpsPerSec,MemoryEfficiencyBytesPerOp\n");

        // CSV data
        for metrics in self.collector.get_metrics() {
            csv.push_str(&format!(
                "{:?},{:?},{},{},{},{:.4},{:.2},{:.2},{:.2}\n",
                metrics.operation,
                metrics.algorithm,
                metrics.execution_time_ns,
                metrics.memory_usage_bytes,
                metrics.iterations,
                metrics.success_rate,
                metrics.avg_execution_time_ns(),
                metrics.throughput_ops_per_sec(),
                metrics.memory_efficiency_bytes_per_op()
            ));
        }

        csv
    }

    /// Generate a JSON report
    pub fn generate_json_report(&self) -> String {
        let mut json = String::new();

        json.push_str("{\n");
        json.push_str("  \"summary\": {\n");
        json.push_str(&format!(
            "    \"total_operations\": {},\n",
            self.collector.len()
        ));
        json.push_str("  },\n");

        json.push_str("  \"operations\": [\n");
        for (i, metrics) in self.collector.get_metrics().iter().enumerate() {
            if i > 0 {
                json.push_str(",\n");
            }
            json.push_str(&format!(
                "    {{\n      \"operation\": \"{:?}\",\n      \"algorithm\": \"{:?}\",\n      \"execution_time_ns\": {},\n      \"memory_usage_bytes\": {},\n      \"iterations\": {},\n      \"success_rate\": {:.4},\n      \"avg_time_ns\": {:.2},\n      \"throughput_ops_per_sec\": {:.2},\n      \"memory_efficiency_bytes_per_op\": {:.2}\n    }}",
                metrics.operation,
                metrics.algorithm,
                metrics.execution_time_ns,
                metrics.memory_usage_bytes,
                metrics.iterations,
                metrics.success_rate,
                metrics.avg_execution_time_ns(),
                metrics.throughput_ops_per_sec(),
                metrics.memory_efficiency_bytes_per_op()
            ));
        }
        json.push_str("\n  ]\n");
        json.push_str("}\n");

        json
    }

    /// Save report to file
    #[cfg(feature = "std")]
    pub fn save_report_to_file(
        &self,
        filename: &str,
        format: ReportFormat,
    ) -> Result<(), std::io::Error> {
        use std::fs::File;
        use std::io::Write;

        let content = match format {
            ReportFormat::Text => self.generate_text_report(),
            ReportFormat::Csv => self.generate_csv_report(),
            ReportFormat::Json => self.generate_json_report(),
        };

        let mut file = File::create(filename)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Get the underlying metrics collector
    pub fn get_collector(&self) -> &MetricsCollector {
        &self.collector
    }

    /// Get mutable access to the metrics collector
    pub fn get_collector_mut(&mut self) -> &mut MetricsCollector {
        &mut self.collector
    }
}

impl Default for PerformanceReporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Report format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Plain text format
    Text,
    /// CSV format
    Csv,
    /// JSON format
    Json,
}

/// Performance comparison utilities
pub struct PerformanceComparator {
    baseline_metrics: MetricsCollector,
    current_metrics: MetricsCollector,
}

impl PerformanceComparator {
    /// Create a new performance comparator
    pub fn new() -> Self {
        Self {
            baseline_metrics: MetricsCollector::new(),
            current_metrics: MetricsCollector::new(),
        }
    }

    /// Set baseline metrics
    pub fn set_baseline(&mut self, metrics: MetricsCollector) {
        self.baseline_metrics = metrics;
    }

    /// Set current metrics
    pub fn set_current(&mut self, metrics: MetricsCollector) {
        self.current_metrics = metrics;
    }

    /// Compare performance and generate a report
    pub fn compare(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Performance Comparison Report ===\n\n");

        for operation in [
            OperationType::KemKeyGeneration,
            OperationType::KemEncapsulation,
            OperationType::KemDecapsulation,
            OperationType::KdfExtract,
            OperationType::KdfExpand,
            OperationType::AeadSeal,
            OperationType::AeadOpen,
            OperationType::HpkeSetupSender,
            OperationType::HpkeSetupReceiver,
            OperationType::HpkeSeal,
            OperationType::HpkeOpen,
            OperationType::HpkeExport,
        ] {
            let baseline_avg = self
                .baseline_metrics
                .get_average_metrics_for_operation(operation);
            let current_avg = self
                .current_metrics
                .get_average_metrics_for_operation(operation);

            if let (Some(baseline), Some(current)) = (baseline_avg, current_avg) {
                let time_improvement = if baseline.avg_execution_time_ns() > 0.0 {
                    ((baseline.avg_execution_time_ns() - current.avg_execution_time_ns()) /
                        baseline.avg_execution_time_ns()) *
                        100.0
                } else {
                    0.0
                };

                let throughput_improvement = if baseline.throughput_ops_per_sec() > 0.0 {
                    ((current.throughput_ops_per_sec() - baseline.throughput_ops_per_sec()) /
                        baseline.throughput_ops_per_sec()) *
                        100.0
                } else {
                    0.0
                };

                report.push_str(&format!("{:?}:\n", operation));
                report.push_str(&format!("  Time improvement: {:.2}%\n", time_improvement));
                report.push_str(&format!(
                    "  Throughput improvement: {:.2}%\n",
                    throughput_improvement
                ));
                report.push_str(&format!(
                    "  Baseline: {:.2} μs, Current: {:.2} μs\n",
                    baseline.avg_execution_time_ns() / 1000.0,
                    current.avg_execution_time_ns() / 1000.0
                ));
                report.push('\n');
            }
        }

        report
    }
}

impl Default for PerformanceComparator {
    fn default() -> Self {
        Self::new()
    }
}
