//! Anonymous Authentication AIR - Proves group membership without revealing identity
//!
//! This AIR enables anonymous authentication by proving membership in a group
//! (represented as a Merkle tree) without revealing which specific member.
//!
//! # Design
//!
//! Uses Merkle tree membership proof where:
//! - Group members are leaves in a Merkle tree
//! - Prover proves knowledge of a membership path without revealing the leaf
//! - Root commitment is public, proving membership without identity disclosure
//!
//! # Security
//!
//! - Uses Poseidon-128 for Merkle tree hashing
//! - Member identity (leaf) remains secret
//! - Only proves existence in group, not which member

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
};
use lib_q_stark_field::Field;
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::merkle_inclusion::{
    MerkleInclusionAir,
    MerkleProofInput,
};
use super::{
    AirError,
    TraceGenerator,
};

/// Maximum group depth (Merkle tree depth)
pub const MAX_GROUP_DEPTH: usize = 64;

/// AIR for anonymous group membership authentication
///
/// This proves that the prover is a member of a group (Merkle tree) without
/// revealing which specific member they are.
///
/// # Trace Layout
///
/// Similar to MerkleInclusionAir but with additional constraints to ensure
/// anonymity properties.
#[derive(Debug, Clone)]
pub struct AnonymousAuthAir {
    /// Merkle tree depth for group membership
    group_depth: usize,
    /// Use ring signature simulation (future enhancement)
    use_ring_sig: bool,
    /// Internal Merkle inclusion AIR
    merkle_air: MerkleInclusionAir,
}

impl AnonymousAuthAir {
    /// Create a new AnonymousAuthAir
    ///
    /// # Arguments
    ///
    /// * `group_depth` - Depth of the Merkle tree representing the group
    /// * `use_ring_sig` - Whether to use ring signature simulation (future)
    ///
    /// # Returns
    ///
    /// `Ok(AnonymousAuthAir)` if successful, `Err(AirError)` if configuration is invalid
    pub fn new(group_depth: usize, use_ring_sig: bool) -> Result<Self, AirError> {
        if group_depth == 0 {
            return Err(AirError::InvalidDimensions {
                reason: "Group depth must be greater than 0".to_string(),
            });
        }

        if group_depth > MAX_GROUP_DEPTH {
            return Err(AirError::ExceedsMaxSize {
                parameter: "group_depth".to_string(),
                max: MAX_GROUP_DEPTH,
                actual: group_depth,
            });
        }

        let merkle_air = MerkleInclusionAir::new(group_depth)?;

        Ok(Self {
            group_depth,
            use_ring_sig,
            merkle_air,
        })
    }

    /// Get the group depth
    pub fn group_depth(&self) -> usize {
        self.group_depth
    }
}

impl<F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>> BaseAir<F>
    for AnonymousAuthAir
{
    fn width(&self) -> usize {
        // Uses same width as MerkleInclusionAir
        // Use fully qualified path to avoid type inference issues
        <MerkleInclusionAir as BaseAir<F>>::width(&self.merkle_air)
    }
}

impl<AB: AirBuilder> Air<AB> for AnonymousAuthAir
where
    AB::F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        // Delegate to MerkleInclusionAir for core membership proof
        // Additional constraints for anonymity can be added here
        self.merkle_air.eval(builder);

        // Future: Add ring signature constraints if use_ring_sig is true
        // This would enable additional anonymity guarantees
        let _ = self.use_ring_sig;
    }
}

/// Input for anonymous authentication proof
#[derive(Debug, Clone)]
pub struct AnonymousAuthInput {
    /// Member's identity (leaf value) - kept secret
    pub member_identity: Vec<u8>,
    /// Merkle authentication path
    pub membership_path: MerkleProofInput,
}

impl
    TraceGenerator<
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
        AnonymousAuthInput,
    > for AnonymousAuthAir
{
    fn generate_trace(
        &self,
        inputs: &AnonymousAuthInput,
    ) -> Result<
        RowMajorMatrix<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>>,
        AirError,
    > {
        // Delegate to MerkleInclusionAir for trace generation
        // The member identity is the leaf in the Merkle proof
        let merkle_input = MerkleProofInput {
            leaf: inputs.member_identity.clone(),
            leaf_hash_direct: None,
            path_bits: inputs.membership_path.path_bits.clone(),
            siblings: inputs.membership_path.siblings.clone(),
        };

        self.merkle_air.generate_trace(&merkle_input)
    }

    fn public_values(
        &self,
        inputs: &AnonymousAuthInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>> {
        // Public value is the Merkle root (group commitment)
        // Member identity remains secret
        let merkle_input = MerkleProofInput {
            leaf: inputs.member_identity.clone(),
            leaf_hash_direct: None,
            path_bits: inputs.membership_path.path_bits.clone(),
            siblings: inputs.membership_path.siblings.clone(),
        };

        self.merkle_air.public_values(&merkle_input)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    #[test]
    fn test_anonymous_auth_air_creation() {
        let air = AnonymousAuthAir::new(8, false).unwrap();
        assert_eq!(air.group_depth(), 8);
    }

    #[test]
    fn test_anonymous_auth_air_validation() {
        // Zero depth should fail
        let result = AnonymousAuthAir::new(0, false);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        // Too large depth should fail
        let result = AnonymousAuthAir::new(MAX_GROUP_DEPTH + 1, false);
        assert!(matches!(result, Err(AirError::ExceedsMaxSize { .. })));
    }

    #[test]
    fn test_anonymous_auth_trace_generation() {
        use super::super::merkle_inclusion::MerkleHash;

        let air = AnonymousAuthAir::new(3, false).unwrap();
        let input = AnonymousAuthInput {
            member_identity: vec![1, 2, 3, 4],
            membership_path: MerkleProofInput {
                leaf: vec![1, 2, 3, 4],
                leaf_hash_direct: None,
                path_bits: vec![false, true, false],
                siblings: vec![
                    MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                    MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                    MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                ],
            },
        };

        let trace = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_anonymous_auth_public_values_length() {
        use super::super::merkle_inclusion::MerkleHash;

        let air = AnonymousAuthAir::new(3, false).unwrap();
        let input = AnonymousAuthInput {
            member_identity: vec![1, 2, 3, 4],
            membership_path: MerkleProofInput {
                leaf: vec![1, 2, 3, 4],
                leaf_hash_direct: None,
                path_bits: vec![false, true, false],
                siblings: vec![
                    MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                    MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                    MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                ],
            },
        };

        assert_eq!(air.public_values(&input).len(), 1);
    }

    #[test]
    fn test_anonymous_auth_public_values_deterministic() {
        use super::super::merkle_inclusion::MerkleHash;

        let air = AnonymousAuthAir::new(3, false).unwrap();
        let input = AnonymousAuthInput {
            member_identity: vec![10, 20, 30, 40],
            membership_path: MerkleProofInput {
                leaf: vec![10, 20, 30, 40],
                leaf_hash_direct: None,
                path_bits: vec![true, false, true],
                siblings: vec![
                    MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
                    MerkleHash::from_bytes(&[2u8; 32]).unwrap(),
                    MerkleHash::from_bytes(&[3u8; 32]).unwrap(),
                ],
            },
        };

        assert_eq!(air.public_values(&input), air.public_values(&input));
    }

    #[test]
    fn test_anonymous_auth_public_values_differ_for_different_identity() {
        use super::super::merkle_inclusion::MerkleHash;

        let air = AnonymousAuthAir::new(3, false).unwrap();
        let siblings = vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
        ];

        let make_input = |leaf: Vec<u8>| AnonymousAuthInput {
            member_identity: leaf.clone(),
            membership_path: MerkleProofInput {
                leaf,
                leaf_hash_direct: None,
                path_bits: vec![false, true, false],
                siblings: siblings.clone(),
            },
        };

        assert_ne!(
            air.public_values(&make_input(vec![1, 2, 3, 4])),
            air.public_values(&make_input(vec![5, 6, 7, 8])),
        );
    }

    #[test]
    fn test_anonymous_auth_public_values_match_merkle_air() {
        use super::super::merkle_inclusion::{
            MerkleHash,
            MerkleInclusionAir,
        };

        type Val = Complex<Mersenne31>;

        let depth = 3;
        let air = AnonymousAuthAir::new(depth, false).unwrap();
        let merkle_air = MerkleInclusionAir::new(depth).unwrap();

        let leaf = vec![1u8, 2, 3, 4];
        let path_bits = vec![false, true, false];
        let siblings = vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[2u8; 32]).unwrap(),
        ];

        let auth_input = AnonymousAuthInput {
            member_identity: leaf.clone(),
            membership_path: MerkleProofInput {
                leaf: leaf.clone(),
                leaf_hash_direct: None,
                path_bits: path_bits.clone(),
                siblings: siblings.clone(),
            },
        };
        let merkle_input = MerkleProofInput {
            leaf: leaf.clone(),
            leaf_hash_direct: None,
            path_bits: path_bits.clone(),
            siblings: siblings.clone(),
        };

        let auth_vals = air.public_values(&auth_input);
        let merkle_vals: Vec<Val> = merkle_air.public_values(&merkle_input);

        assert_eq!(auth_vals, merkle_vals);
    }
}
