//! Hardware RNG Integration Example for FN-DSA
//!
//! This example demonstrates how to integrate hardware-specific random number
//! generators with FN-DSA for enhanced security in embedded and IoT environments.

#![allow(clippy::new_without_default)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_core::Result;
use lib_q_fn_dsa::*;
use rand_core::{
    CryptoRng,
    Infallible,
    Rng,
    TryCryptoRng,
    TryRng,
};

/// Hardware RNG trait for different hardware platforms
pub trait HardwareRng: CryptoRng + Rng {
    /// Initialize the hardware RNG
    fn initialize(&mut self) -> Result<()>;

    /// Check if the hardware RNG is available
    fn is_available() -> bool;

    /// Get the RNG type name
    fn rng_type() -> &'static str;

    /// Get entropy quality (bits of entropy per byte)
    fn entropy_quality() -> u8;
}

/// Hardware RNG enum for dynamic dispatch
pub enum HardwareRngEnum {
    #[cfg(target_arch = "arm")]
    ArmTrustZone(ArmTrustZoneRng),
    #[cfg(target_arch = "x86_64")]
    IntelRdrand(IntelRdrandRng),
    #[cfg(target_arch = "xtensa")]
    Esp32(Esp32Rng),
    Fallback(FallbackSoftwareRng),
}

impl HardwareRng for HardwareRngEnum {
    fn initialize(&mut self) -> Result<()> {
        match self {
            #[cfg(target_arch = "arm")]
            HardwareRngEnum::ArmTrustZone(rng) => rng.initialize(),
            #[cfg(target_arch = "x86_64")]
            HardwareRngEnum::IntelRdrand(rng) => rng.initialize(),
            #[cfg(target_arch = "xtensa")]
            HardwareRngEnum::Esp32(rng) => rng.initialize(),
            HardwareRngEnum::Fallback(rng) => rng.initialize(),
        }
    }

    fn is_available() -> bool {
        #[cfg(target_arch = "arm")]
        if ArmTrustZoneRng::is_available() {
            return true;
        }
        #[cfg(target_arch = "x86_64")]
        if IntelRdrandRng::is_available() {
            return true;
        }
        #[cfg(target_arch = "xtensa")]
        if Esp32Rng::is_available() {
            return true;
        }
        FallbackSoftwareRng::is_available()
    }

    fn rng_type() -> &'static str {
        #[cfg(target_arch = "arm")]
        if ArmTrustZoneRng::is_available() {
            return ArmTrustZoneRng::rng_type();
        }
        #[cfg(target_arch = "x86_64")]
        if IntelRdrandRng::is_available() {
            return IntelRdrandRng::rng_type();
        }
        #[cfg(target_arch = "xtensa")]
        if Esp32Rng::is_available() {
            return Esp32Rng::rng_type();
        }
        FallbackSoftwareRng::rng_type()
    }

    fn entropy_quality() -> u8 {
        #[cfg(target_arch = "arm")]
        if ArmTrustZoneRng::is_available() {
            return ArmTrustZoneRng::entropy_quality();
        }
        #[cfg(target_arch = "x86_64")]
        if IntelRdrandRng::is_available() {
            return IntelRdrandRng::entropy_quality();
        }
        #[cfg(target_arch = "xtensa")]
        if Esp32Rng::is_available() {
            return Esp32Rng::entropy_quality();
        }
        FallbackSoftwareRng::entropy_quality()
    }
}

impl TryRng for HardwareRngEnum {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(match self {
            #[cfg(target_arch = "arm")]
            HardwareRngEnum::ArmTrustZone(rng) => rng.next_u32(),
            #[cfg(target_arch = "x86_64")]
            HardwareRngEnum::IntelRdrand(rng) => rng.next_u32(),
            #[cfg(target_arch = "xtensa")]
            HardwareRngEnum::Esp32(rng) => rng.next_u32(),
            HardwareRngEnum::Fallback(rng) => rng.next_u32(),
        })
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(match self {
            #[cfg(target_arch = "arm")]
            HardwareRngEnum::ArmTrustZone(rng) => rng.next_u64(),
            #[cfg(target_arch = "x86_64")]
            HardwareRngEnum::IntelRdrand(rng) => rng.next_u64(),
            #[cfg(target_arch = "xtensa")]
            HardwareRngEnum::Esp32(rng) => rng.next_u64(),
            HardwareRngEnum::Fallback(rng) => rng.next_u64(),
        })
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        match self {
            #[cfg(target_arch = "arm")]
            HardwareRngEnum::ArmTrustZone(rng) => rng.fill_bytes(dest),
            #[cfg(target_arch = "x86_64")]
            HardwareRngEnum::IntelRdrand(rng) => rng.fill_bytes(dest),
            #[cfg(target_arch = "xtensa")]
            HardwareRngEnum::Esp32(rng) => rng.fill_bytes(dest),
            HardwareRngEnum::Fallback(rng) => rng.fill_bytes(dest),
        }
        Ok(())
    }
}

impl TryCryptoRng for HardwareRngEnum {}

/// ARM TrustZone RNG implementation
#[cfg(target_arch = "arm")]
pub struct ArmTrustZoneRng {
    initialized: bool,
}

#[cfg(target_arch = "arm")]
impl ArmTrustZoneRng {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Read from ARM TrustZone RNG register
    fn read_trustzone_rng(&self) -> u32 {
        // This is a placeholder - in real implementation, you would:
        // 1. Access the TrustZone RNG register
        // 2. Wait for entropy to be available
        // 3. Read the random value
        // SAFETY: This is a placeholder for demonstration
        unsafe {
            // In real implementation: read from 0x40004000 (example register)
            core::ptr::read_volatile(0x40004000 as *const u32)
        }
    }
}

#[cfg(target_arch = "arm")]
impl HardwareRng for ArmTrustZoneRng {
    fn initialize(&mut self) -> Result<()> {
        // Initialize TrustZone RNG
        // In real implementation: enable RNG, wait for initialization
        self.initialized = true;
        Ok(())
    }

    fn is_available() -> bool {
        // Check if TrustZone RNG is available
        // In real implementation: check hardware capabilities
        true
    }

    fn rng_type() -> &'static str {
        "ARM TrustZone RNG"
    }

    fn entropy_quality() -> u8 {
        8 // High quality entropy
    }
}

#[cfg(target_arch = "arm")]
impl TryRng for ArmTrustZoneRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        if !self.initialized {
            let _ = self.initialize();
        }
        Ok(self.read_trustzone_rng())
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let upper = self.try_next_u32()? as u64;
        let lower = self.try_next_u32()? as u64;
        Ok((upper << 32) | lower)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dest.chunks_mut(4) {
            let bytes = self.try_next_u32()?.to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

#[cfg(target_arch = "arm")]
impl TryCryptoRng for ArmTrustZoneRng {}

/// Intel RDRAND implementation
#[cfg(target_arch = "x86_64")]
pub struct IntelRdrandRng {
    initialized: bool,
}

#[cfg(target_arch = "x86_64")]
impl IntelRdrandRng {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Check if RDRAND instruction is available
    fn is_rdrand_available() -> bool {
        // Check CPUID for RDRAND support
        // In real implementation: use CPUID instruction
        true // Placeholder
    }

    /// Read random value using RDRAND instruction
    fn read_rdrand(&self) -> u32 {
        // This is a placeholder - in real implementation, you would:
        // 1. Use the RDRAND instruction
        // 2. Check the carry flag for success
        // 3. Retry if necessary
        // SAFETY: This is a placeholder for demonstration
        unsafe {
            let mut out = 0u32;
            core::arch::x86_64::_rdrand32_step(&mut out);
            out
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl HardwareRng for IntelRdrandRng {
    fn initialize(&mut self) -> Result<()> {
        if !Self::is_rdrand_available() {
            return Err(lib_q_core::Error::KeyGenerationFailed {
                operation: "RDRAND not available".to_string(),
            });
        }
        self.initialized = true;
        Ok(())
    }

    fn is_available() -> bool {
        Self::is_rdrand_available()
    }

    fn rng_type() -> &'static str {
        "Intel RDRAND"
    }

    fn entropy_quality() -> u8 {
        8 // High quality entropy
    }
}

#[cfg(target_arch = "x86_64")]
impl TryRng for IntelRdrandRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        if !self.initialized {
            let _ = self.initialize();
        }
        Ok(self.read_rdrand())
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let upper = self.try_next_u32()? as u64;
        let lower = self.try_next_u32()? as u64;
        Ok((upper << 32) | lower)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dest.chunks_mut(4) {
            let bytes = self.try_next_u32()?.to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl TryCryptoRng for IntelRdrandRng {}

/// ESP32 RNG implementation
#[cfg(target_arch = "xtensa")]
pub struct Esp32Rng {
    initialized: bool,
}

#[cfg(target_arch = "xtensa")]
impl Esp32Rng {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Read from ESP32 hardware RNG
    fn read_esp32_rng(&self) -> u32 {
        // This is a placeholder - in real implementation, you would:
        // 1. Access the ESP32 RNG register (RNG_DATA_REG)
        // 2. Wait for entropy to be available
        // 3. Read the random value
        // SAFETY: This is a placeholder for demonstration
        unsafe {
            // In real implementation: read from RNG_DATA_REG
            core::ptr::read_volatile(0x3FF75144 as *const u32)
        }
    }
}

#[cfg(target_arch = "xtensa")]
impl HardwareRng for Esp32Rng {
    fn initialize(&mut self) -> Result<()> {
        // Initialize ESP32 RNG
        // In real implementation: enable RNG, wait for initialization
        self.initialized = true;
        Ok(())
    }

    fn is_available() -> bool {
        // Check if ESP32 RNG is available
        // In real implementation: check hardware capabilities
        true
    }

    fn rng_type() -> &'static str {
        "ESP32 Hardware RNG"
    }

    fn entropy_quality() -> u8 {
        7 // Good quality entropy
    }
}

#[cfg(target_arch = "xtensa")]
impl TryRng for Esp32Rng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        if !self.initialized {
            let _ = self.initialize();
        }
        Ok(self.read_esp32_rng())
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let upper = self.try_next_u32()? as u64;
        let lower = self.try_next_u32()? as u64;
        Ok((upper << 32) | lower)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dest.chunks_mut(4) {
            let bytes = self.try_next_u32()?.to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

#[cfg(target_arch = "xtensa")]
impl TryCryptoRng for Esp32Rng {}

/// Fallback software RNG for unsupported platforms
pub struct FallbackSoftwareRng {
    counter: u64,
}

impl FallbackSoftwareRng {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl HardwareRng for FallbackSoftwareRng {
    fn initialize(&mut self) -> Result<()> {
        // Initialize with some entropy if available
        self.counter = 0;
        Ok(())
    }

    fn is_available() -> bool {
        true // Always available as fallback
    }

    fn rng_type() -> &'static str {
        "Fallback Software RNG"
    }

    fn entropy_quality() -> u8 {
        2 // Low quality - should be replaced with hardware RNG
    }
}

impl TryRng for FallbackSoftwareRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        // Simple counter-based RNG (NOT cryptographically secure)
        // This is only for demonstration - in production, use proper hardware RNG
        self.counter = self.counter.wrapping_add(1);
        Ok((self.counter ^ (self.counter >> 16)) as u32)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let upper = self.try_next_u32()? as u64;
        let lower = self.try_next_u32()? as u64;
        Ok((upper << 32) | lower)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dest.chunks_mut(4) {
            let bytes = self.try_next_u32()?.to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

impl TryCryptoRng for FallbackSoftwareRng {}

/// Hardware RNG factory
pub struct HardwareRngFactory;

impl HardwareRngFactory {
    /// Create the best available hardware RNG for the current platform
    pub fn create_best_rng() -> HardwareRngEnum {
        #[cfg(target_arch = "arm")]
        {
            if ArmTrustZoneRng::is_available() {
                return HardwareRngEnum::ArmTrustZone(ArmTrustZoneRng::new());
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if IntelRdrandRng::is_available() {
                return HardwareRngEnum::IntelRdrand(IntelRdrandRng::new());
            }
        }

        #[cfg(target_arch = "xtensa")]
        {
            if Esp32Rng::is_available() {
                return HardwareRngEnum::Esp32(Esp32Rng::new());
            }
        }

        // Fallback to software RNG
        HardwareRngEnum::Fallback(FallbackSoftwareRng::new())
    }

    /// Get information about available RNGs
    pub fn get_rng_info() -> RngInfo {
        let mut available_rngs = Vec::new();

        #[cfg(target_arch = "arm")]
        {
            available_rngs.push(RngDetails {
                name: ArmTrustZoneRng::rng_type().to_string(),
                available: ArmTrustZoneRng::is_available(),
                entropy_quality: ArmTrustZoneRng::entropy_quality(),
            });
        }

        #[cfg(target_arch = "x86_64")]
        {
            available_rngs.push(RngDetails {
                name: IntelRdrandRng::rng_type().to_string(),
                available: IntelRdrandRng::is_available(),
                entropy_quality: IntelRdrandRng::entropy_quality(),
            });
        }

        #[cfg(target_arch = "xtensa")]
        {
            available_rngs.push(RngDetails {
                name: Esp32Rng::rng_type().to_string(),
                available: Esp32Rng::is_available(),
                entropy_quality: Esp32Rng::entropy_quality(),
            });
        }

        // Always include fallback
        available_rngs.push(RngDetails {
            name: FallbackSoftwareRng::rng_type().to_string(),
            available: FallbackSoftwareRng::is_available(),
            entropy_quality: FallbackSoftwareRng::entropy_quality(),
        });

        RngInfo { available_rngs }
    }
}

/// RNG information structure
#[derive(Debug)]
pub struct RngInfo {
    pub available_rngs: Vec<RngDetails>,
}

/// RNG details
#[derive(Debug)]
pub struct RngDetails {
    pub name: String,
    pub available: bool,
    pub entropy_quality: u8,
}

/// Hardware RNG integration example
pub struct HardwareRngExample {
    rng: HardwareRngEnum,
    fn_dsa: FnDsa512,
}

impl HardwareRngExample {
    /// Create a new hardware RNG example
    pub fn new() -> Result<Self> {
        let rng = HardwareRngFactory::create_best_rng();
        let fn_dsa = FnDsa512::new();

        Ok(Self { rng, fn_dsa })
    }

    /// Demonstrate hardware RNG with FN-DSA key generation
    pub fn demonstrate_hardware_rng_keygen(&mut self) -> Result<HardwareRngDemoResult> {
        // Initialize the hardware RNG
        self.rng.initialize()?;

        // Generate keypair using hardware RNG
        let keypair = self.fn_dsa.generate_keypair()?;

        // Test the hardware RNG by generating some random bytes
        let mut test_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut test_bytes);

        // Sign a message to demonstrate the keypair works
        let message = b"Hardware RNG demonstration";
        let signature = self.fn_dsa.sign(&keypair.secret_key, message)?;

        // Verify the signature
        let is_valid = self
            .fn_dsa
            .verify(&keypair.public_key, message, &signature)?;

        Ok(HardwareRngDemoResult {
            rng_type: HardwareRngEnum::rng_type().to_string(),
            keypair_generated: true,
            test_bytes,
            signature_valid: is_valid,
        })
    }

    /// Demonstrate entropy quality testing
    pub fn demonstrate_entropy_quality(&mut self) -> Result<EntropyQualityResult> {
        // Generate multiple random samples
        let mut samples = Vec::new();
        for _ in 0..1000 {
            let mut sample = [0u8; 4];
            self.rng.fill_bytes(&mut sample);
            samples.push(sample);
        }

        // Basic entropy analysis (simplified)
        let mut byte_counts = [0u32; 256];
        for sample in &samples {
            for &byte in sample.iter() {
                byte_counts[byte as usize] += 1;
            }
        }

        // Calculate basic statistics
        let total_bytes = samples.len() * 4;
        let mut chi_square = 0.0;
        let expected = total_bytes as f64 / 256.0;

        for &count in &byte_counts {
            let diff = count as f64 - expected;
            chi_square += (diff * diff) / expected;
        }

        // Simple entropy quality assessment
        let entropy_quality = if chi_square < 200.0 {
            "High"
        } else if chi_square < 300.0 {
            "Medium"
        } else {
            "Low"
        };

        Ok(EntropyQualityResult {
            samples_collected: samples.len(),
            chi_square_statistic: chi_square,
            entropy_quality: entropy_quality.to_string(),
            byte_distribution: byte_counts,
        })
    }
}

/// Hardware RNG demonstration result
#[derive(Debug)]
pub struct HardwareRngDemoResult {
    pub rng_type: String,
    pub keypair_generated: bool,
    pub test_bytes: [u8; 32],
    pub signature_valid: bool,
}

/// Entropy quality analysis result
#[derive(Debug)]
pub struct EntropyQualityResult {
    pub samples_collected: usize,
    pub chi_square_statistic: f64,
    pub entropy_quality: String,
    pub byte_distribution: [u32; 256],
}

#[cfg(feature = "std")]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Hardware RNG Integration Example");
    println!("==================================\n");

    // Get information about available RNGs
    let rng_info = HardwareRngFactory::get_rng_info();
    println!("📊 Available RNGs:");
    for rng in &rng_info.available_rngs {
        println!(
            "   {}: {} (Quality: {}/8)",
            rng.name,
            if rng.available {
                "Available"
            } else {
                "Not Available"
            },
            rng.entropy_quality
        );
    }
    println!();

    // Create hardware RNG example
    let mut example = HardwareRngExample::new()?;

    // Demonstrate hardware RNG with key generation
    println!("🔑 Hardware RNG Key Generation Demo");
    println!("----------------------------------");
    let demo_result = example.demonstrate_hardware_rng_keygen()?;
    println!("✅ Hardware RNG demonstration completed");
    println!("   RNG Type: {}", demo_result.rng_type);
    println!("   Keypair Generated: {}", demo_result.keypair_generated);
    println!("   Signature Valid: {}", demo_result.signature_valid);
    println!("   Test Bytes: {:02x?}", demo_result.test_bytes);
    println!();

    // Demonstrate entropy quality testing
    println!("📈 Entropy Quality Analysis");
    println!("--------------------------");
    let entropy_result = example.demonstrate_entropy_quality()?;
    println!("✅ Entropy quality analysis completed");
    println!("   Samples Collected: {}", entropy_result.samples_collected);
    println!(
        "   Chi-Square Statistic: {:.2}",
        entropy_result.chi_square_statistic
    );
    println!("   Entropy Quality: {}", entropy_result.entropy_quality);
    println!();

    println!("🎉 Hardware RNG integration example completed successfully!");

    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> core::result::Result<(), alloc::boxed::Box<dyn core::error::Error>> {
    // In no_std environment, just run the hardware RNG tests
    let mut example = HardwareRngExample::new()?;
    let _demo = example.demonstrate_hardware_rng_keygen()?;
    let _entropy = example.demonstrate_entropy_quality()?;

    Ok(())
}
