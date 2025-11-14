//! Comparison Utilities for NIST Reference Validation
//!
//! This module provides utilities for comparing our implementation
//! with the NIST reference implementation.

use std::fmt;

/// Hex diff result showing differences between two byte arrays
#[derive(Debug, Clone)]
pub struct HexDiff {
    pub position: usize,
    pub our_byte: u8,
    pub nist_byte: u8,
    pub context: Vec<u8>,
    pub nist_context: Vec<u8>,
}

impl fmt::Display for HexDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Mismatch at byte {}:", self.position)?;
        writeln!(f, "  Our:  {:02x}", self.our_byte)?;
        writeln!(f, "  NIST: {:02x}", self.nist_byte)?;
        writeln!(f, "  Context:")?;
        writeln!(f, "    Our:  {:02x?}", self.context)?;
        writeln!(f, "    NIST: {:02x?}", self.nist_context)?;
        Ok(())
    }
}

/// Compare two byte arrays and return detailed diff information
pub fn compare_bytes(our_data: &[u8], nist_data: &[u8]) -> Result<Vec<HexDiff>, String> {
    if our_data.len() != nist_data.len() {
        return Err(format!(
            "Length mismatch: our={}, nist={}",
            our_data.len(),
            nist_data.len()
        ));
    }

    let mut diffs = Vec::new();
    let context_size = 8;

    for (idx, (our, nist)) in our_data.iter().zip(nist_data.iter()).enumerate() {
        if our != nist {
            let start = idx.saturating_sub(context_size / 2);
            let end = (idx + context_size / 2).min(our_data.len());

            diffs.push(HexDiff {
                position: idx,
                our_byte: *our,
                nist_byte: *nist,
                context: our_data[start..end].to_vec(),
                nist_context: nist_data[start..end].to_vec(),
            });
        }
    }

    Ok(diffs)
}

/// Statistical analysis of byte differences
#[derive(Debug)]
pub struct ByteAnalysis {
    pub total_bytes: usize,
    pub different_bytes: usize,
    pub hamming_distance: usize,
    pub byte_frequency_our: [usize; 256],
    pub byte_frequency_nist: [usize; 256],
}

impl ByteAnalysis {
    pub fn new(our_data: &[u8], nist_data: &[u8]) -> Self {
        let mut byte_frequency_our = [0usize; 256];
        let mut byte_frequency_nist = [0usize; 256];
        let mut different_bytes = 0;
        let mut hamming_distance = 0;

        for (our, nist) in our_data.iter().zip(nist_data.iter()) {
            byte_frequency_our[*our as usize] += 1;
            byte_frequency_nist[*nist as usize] += 1;

            if our != nist {
                different_bytes += 1;
                hamming_distance += (our ^ nist).count_ones() as usize;
            }
        }

        Self {
            total_bytes: our_data.len(),
            different_bytes,
            hamming_distance,
            byte_frequency_our,
            byte_frequency_nist,
        }
    }

    pub fn similarity_percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        ((self.total_bytes - self.different_bytes) as f64 / self.total_bytes as f64) * 100.0
    }

    pub fn print_analysis(&self) {
        println!("Byte Analysis:");
        println!("  Total bytes: {}", self.total_bytes);
        println!("  Different bytes: {}", self.different_bytes);
        println!("  Similarity: {:.2}%", self.similarity_percentage());
        println!("  Hamming distance: {}", self.hamming_distance);

        if self.different_bytes > 0 {
            println!("  Most frequent differences:");
            let mut differences = Vec::new();
            for i in 0..256 {
                let our_freq = self.byte_frequency_our[i];
                let nist_freq = self.byte_frequency_nist[i];
                if our_freq != nist_freq {
                    differences.push((i as u8, our_freq, nist_freq));
                }
            }
            differences.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));

            for (byte, our_freq, nist_freq) in differences.iter().take(10) {
                println!(
                    "    Byte 0x{:02x}: our={}, nist={}",
                    byte, our_freq, nist_freq
                );
            }
        }
    }
}

/// Bit-level analysis for subtle differences
#[derive(Debug)]
pub struct BitAnalysis {
    pub bit_differences: [usize; 8],
    pub total_bits: usize,
}

impl BitAnalysis {
    pub fn new(our_data: &[u8], nist_data: &[u8]) -> Self {
        let mut bit_differences = [0usize; 8];
        let mut total_bits = 0;

        for (our, nist) in our_data.iter().zip(nist_data.iter()) {
            let diff = our ^ nist;
            for bit_pos in 0..8 {
                if (diff >> bit_pos) & 1 == 1 {
                    bit_differences[bit_pos] += 1;
                }
            }
            total_bits += 8;
        }

        Self {
            bit_differences,
            total_bits,
        }
    }

    pub fn print_analysis(&self) {
        println!("Bit Analysis:");
        for (bit_pos, count) in self.bit_differences.iter().enumerate() {
            let percentage = (*count as f64 / self.total_bits as f64) * 100.0;
            println!(
                "  Bit {}: {} differences ({:.2}%)",
                bit_pos, count, percentage
            );
        }
    }
}

/// Comprehensive comparison result
#[derive(Debug)]
pub struct ComparisonResult {
    pub diffs: Vec<HexDiff>,
    pub byte_analysis: ByteAnalysis,
    pub bit_analysis: BitAnalysis,
    pub is_identical: bool,
}

impl ComparisonResult {
    pub fn new(our_data: &[u8], nist_data: &[u8]) -> Self {
        let diffs = compare_bytes(our_data, nist_data).unwrap_or_default();
        let byte_analysis = ByteAnalysis::new(our_data, nist_data);
        let bit_analysis = BitAnalysis::new(our_data, nist_data);
        let is_identical = diffs.is_empty();

        Self {
            diffs,
            byte_analysis,
            bit_analysis,
            is_identical,
        }
    }

    pub fn print_report(&self, data_type: &str) {
        println!("=== Comparison Report for {} ===", data_type);

        if self.is_identical {
            println!("✓ Perfect match with NIST reference");
            return;
        }

        println!("✗ Differences found:");

        // Print first few differences
        for (i, diff) in self.diffs.iter().take(5).enumerate() {
            println!("  Difference {}: {}", i + 1, diff);
        }

        if self.diffs.len() > 5 {
            println!("  ... and {} more differences", self.diffs.len() - 5);
        }

        self.byte_analysis.print_analysis();
        self.bit_analysis.print_analysis();
    }
}

/// Utility function to save comparison results to file
pub fn save_comparison_report(
    result: &ComparisonResult,
    data_type: &str,
    filename: &str,
) -> Result<(), std::io::Error> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(filename)?;
    writeln!(file, "Comparison Report for {}", data_type)?;
    writeln!(file, "Generated at: {:?}", std::time::SystemTime::now())?;
    writeln!(file)?;

    if result.is_identical {
        writeln!(file, "✓ Perfect match with NIST reference")?;
    } else {
        writeln!(file, "✗ Differences found:")?;
        for diff in &result.diffs {
            writeln!(file, "{}", diff)?;
        }
    }

    writeln!(file)?;
    writeln!(file, "Byte Analysis:")?;
    writeln!(file, "  Total bytes: {}", result.byte_analysis.total_bytes)?;
    writeln!(
        file,
        "  Different bytes: {}",
        result.byte_analysis.different_bytes
    )?;
    writeln!(
        file,
        "  Similarity: {:.2}%",
        result.byte_analysis.similarity_percentage()
    )?;
    writeln!(
        file,
        "  Hamming distance: {}",
        result.byte_analysis.hamming_distance
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_arrays() {
        let data1 = [0x00, 0x01, 0x02, 0x03];
        let data2 = [0x00, 0x01, 0x02, 0x03];

        let result = ComparisonResult::new(&data1, &data2);
        assert!(result.is_identical);
        assert!(result.diffs.is_empty());
    }

    #[test]
    fn test_different_arrays() {
        let data1 = [0x00, 0x01, 0x02, 0x03];
        let data2 = [0x00, 0x01, 0xFF, 0x03];

        let result = ComparisonResult::new(&data1, &data2);
        assert!(!result.is_identical);
        assert_eq!(result.diffs.len(), 1);
        assert_eq!(result.diffs[0].position, 2);
        assert_eq!(result.diffs[0].our_byte, 0x02);
        assert_eq!(result.diffs[0].nist_byte, 0xFF);
    }

    #[test]
    fn test_length_mismatch() {
        let data1 = [0x00, 0x01, 0x02];
        let data2 = [0x00, 0x01, 0x02, 0x03];

        let result = compare_bytes(&data1, &data2);
        assert!(result.is_err());
    }
}
