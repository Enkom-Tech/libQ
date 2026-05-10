//! Performance profiler for HPKE operations

#[cfg(feature = "alloc")]
use alloc::string::ToString;
use core::mem::size_of;

use crate::benchmarking::{
    AlgorithmType,
    OperationType,
    PerformanceMetrics,
};
use crate::error::HpkeError;

/// Counter-based timing implementation
///
/// Used for `no_std` targets and for `wasm32-unknown-unknown` (where
/// `SystemTime::now()` panics with "time not implemented on this platform").
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
mod no_std_timing {
    use core::sync::atomic::{
        AtomicU64,
        Ordering,
    };

    /// Get current timestamp using a simple counter
    /// This provides basic timing without unsafe code
    pub fn get_timestamp() -> u64 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Convert cycles to nanoseconds (approximate)
    /// This is a rough approximation - in practice, you'd want to calibrate
    /// this value for the specific CPU being used
    pub fn cycles_to_nanoseconds(cycles: u64) -> u64 {
        // Simple approximation: assume 1 cycle = 1 nanosecond
        // This is not accurate but provides basic timing capability
        cycles
    }
}

/// Std timing implementation using standard library
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
mod std_timing {
    use std::time::{
        SystemTime,
        UNIX_EPOCH,
    };

    /// Get current timestamp using system time
    pub fn get_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    /// Convert nanoseconds to nanoseconds (no conversion needed)
    pub fn cycles_to_nanoseconds(nanos: u64) -> u64 {
        nanos
    }
}

/// Unified timing interface
mod timing {
    #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
    pub use super::no_std_timing::*;
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    pub use super::std_timing::*;

    /// Calibrate timing for more accurate measurements
    /// This should be called once at startup to determine the actual
    /// relationship between cycle counts and real time
    pub fn calibrate_timing() -> f64 {
        #[cfg(not(feature = "std"))]
        {
            // For no_std, we use a simple calibration based on known operations
            // In a real implementation, you might want to use a more sophisticated
            // calibration method or provide a way to set the calibration factor
            1.0 // Default calibration factor
        }

        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            // For std, we can use actual system time for calibration
            use std::time::Instant;
            let start = Instant::now();
            let start_cycles = get_timestamp();

            // Perform a small delay to measure
            std::thread::sleep(std::time::Duration::from_millis(1));

            let end = Instant::now();
            let end_cycles = get_timestamp();

            let real_time_ns = end.duration_since(start).as_nanos() as u64;
            let cycle_time = end_cycles.saturating_sub(start_cycles);

            if cycle_time > 0 {
                real_time_ns as f64 / cycle_time as f64
            } else {
                1.0
            }
        }
        #[cfg(all(feature = "std", target_arch = "wasm32"))]
        {
            1.0
        }
    }
}

/// Performance profiler for measuring HPKE operations
pub struct PerformanceProfiler {
    start_time: Option<u64>, // Using u64 for timestamp in no_std
    start_memory: Option<usize>,
    operation: Option<OperationType>,
    algorithm: Option<AlgorithmType>,
    calibration_factor: f64, // Calibration factor for accurate timing
}

impl PerformanceProfiler {
    /// Create a new performance profiler
    pub fn new() -> Self {
        Self {
            start_time: None,
            start_memory: None,
            operation: None,
            algorithm: None,
            calibration_factor: timing::calibrate_timing(),
        }
    }

    /// Create a new performance profiler with custom calibration factor
    pub fn with_calibration(calibration_factor: f64) -> Self {
        Self {
            start_time: None,
            start_memory: None,
            operation: None,
            algorithm: None,
            calibration_factor,
        }
    }

    /// Start profiling an operation
    pub fn start_profiling(&mut self, operation: OperationType, algorithm: AlgorithmType) {
        self.start_time = Some(timing::get_timestamp());
        self.start_memory = Some(self.get_memory_usage());
        self.operation = Some(operation);
        self.algorithm = Some(algorithm);
    }

    /// Stop profiling and return metrics
    pub fn stop_profiling(
        &mut self,
        iterations: u32,
        success_count: u32,
    ) -> Result<PerformanceMetrics, HpkeError> {
        let end_time = timing::get_timestamp();
        let end_memory = self.get_memory_usage();

        let start_time = self
            .start_time
            .ok_or_else(|| HpkeError::CryptoError("Profiling not started".to_string()))?;

        // Calculate execution time in nanoseconds with calibration
        let raw_cycles = if end_time >= start_time {
            end_time - start_time
        } else {
            // Handle potential counter overflow
            u64::MAX - start_time + end_time + 1
        };

        let execution_time_ns =
            (timing::cycles_to_nanoseconds(raw_cycles) as f64 * self.calibration_factor) as u64;

        let memory_usage =
            end_memory.saturating_sub(self.start_memory.ok_or_else(|| {
                HpkeError::CryptoError("Memory profiling not started".to_string())
            })?);

        let operation = self
            .operation
            .ok_or_else(|| HpkeError::CryptoError("Operation not set".to_string()))?;

        let algorithm = self
            .algorithm
            .ok_or_else(|| HpkeError::CryptoError("Algorithm not set".to_string()))?;

        let success_rate = if iterations > 0 {
            success_count as f64 / iterations as f64
        } else {
            0.0
        };

        Ok(PerformanceMetrics::new(
            operation,
            algorithm,
            execution_time_ns,
            memory_usage,
            iterations,
            success_rate,
        ))
    }

    /// Get current memory usage (approximate)
    fn get_memory_usage(&self) -> usize {
        // This is a simplified memory usage calculation
        // In a real implementation, you might use more sophisticated memory tracking
        size_of::<Self>()
    }

    /// Profile a function execution
    pub fn profile_function<F, R>(
        &mut self,
        operation: OperationType,
        algorithm: AlgorithmType,
        iterations: u32,
        func: F,
    ) -> Result<(R, PerformanceMetrics), HpkeError>
    where
        F: Fn() -> Result<R, HpkeError>,
    {
        self.start_profiling(operation, algorithm);

        let mut success_count = 0u32;
        let mut result = None;

        for _ in 0..iterations {
            match func() {
                Ok(res) => {
                    success_count += 1;
                    if result.is_none() {
                        result = Some(res);
                    }
                }
                Err(e) => {
                    // Continue profiling even if some iterations fail
                    if result.is_none() {
                        return Err(e);
                    }
                }
            }
        }

        let metrics = self.stop_profiling(iterations, success_count)?;
        let final_result =
            result.ok_or_else(|| HpkeError::CryptoError("All iterations failed".to_string()))?;

        Ok((final_result, metrics))
    }

    /// Profile multiple function executions and return aggregated metrics
    pub fn profile_multiple<F, R>(
        &mut self,
        operation: OperationType,
        algorithm: AlgorithmType,
        iterations: u32,
        func: F,
    ) -> Result<PerformanceMetrics, HpkeError>
    where
        F: Fn() -> Result<R, HpkeError>,
    {
        let start_time = timing::get_timestamp();
        let start_memory = self.get_memory_usage();

        let mut success_count = 0u32;

        for _ in 0..iterations {
            match func() {
                Ok(_) => success_count += 1,
                Err(_) => {
                    // Continue profiling even if some iterations fail
                }
            }
        }

        let end_time = timing::get_timestamp();
        let raw_cycles = if end_time >= start_time {
            end_time - start_time
        } else {
            // Handle potential counter overflow
            u64::MAX - start_time + end_time + 1
        };

        let execution_time_ns =
            (timing::cycles_to_nanoseconds(raw_cycles) as f64 * self.calibration_factor) as u64;

        let end_memory = self.get_memory_usage();
        let memory_usage = end_memory.saturating_sub(start_memory);

        let success_rate = if iterations > 0 {
            success_count as f64 / iterations as f64
        } else {
            0.0
        };

        Ok(PerformanceMetrics::new(
            operation,
            algorithm,
            execution_time_ns,
            memory_usage,
            iterations,
            success_rate,
        ))
    }
}

impl Default for PerformanceProfiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro for easy profiling of operations
#[macro_export]
macro_rules! profile_operation {
    ($profiler:expr, $operation:expr, $algorithm:expr, $iterations:expr, $code:block) => {{
        let mut profiler = $profiler;
        profiler.profile_multiple($operation, $algorithm, $iterations, || $code)
    }};
}

/// Macro for profiling a single operation
#[macro_export]
macro_rules! profile_single {
    ($profiler:expr, $operation:expr, $algorithm:expr, $code:block) => {{
        let mut profiler = $profiler;
        profiler.profile_function($operation, $algorithm, 1, || $code)
    }};
}
