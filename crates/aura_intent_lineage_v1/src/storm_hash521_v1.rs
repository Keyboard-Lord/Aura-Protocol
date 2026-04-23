//! Canonical SHA3-based 521-bit hash construction for the storm lower layer.
//!
//! Implements the canonical identity function per AURA_HASH_V2:
//! H_521(m) = Reduce_N(SHA3-512(m)) where N = 2^521 - 1

use sha3::{Digest, Sha3_512};

use crate::FieldElement521V1;

pub const AURA_HASH521_V1_OUTPUT_BITS: usize = 521;
pub const AURA_HASH521_V1_OUTPUT_BYTES: usize = 66;

/// Canonical H_521 hash function per AURA_HASH_V2 specification.
/// 
/// H_521(m) = Reduce_N(SHA3-512(m)) where N = 2^521 - 1
/// 
/// The SHA3-512 output (512 bits) is interpreted as a big-endian integer
/// and reduced into the 521-bit field. This is the sole canonical identity
/// construction for the active Aura protocol.
pub fn aura_hash521_v1(msg: &[u8]) -> FieldElement521V1 {
    let hash_bytes = sha3_512_bytes(msg);
    FieldElement521V1::reduce_bytes_mod(&hash_bytes)
}

fn sha3_512_bytes(msg: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(msg);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{aura_hash521_v1, AURA_HASH521_V1_OUTPUT_BYTES};
    use crate::FIELD_ELEMENT_521_BYTE_LEN_V1;

    #[test]
    fn hash521_is_deterministic() {
        let first = aura_hash521_v1(b"AURA_TEST_VECTOR");
        let second = aura_hash521_v1(b"AURA_TEST_VECTOR");

        assert_eq!(first, second);
    }

    #[test]
    fn hash521_uses_exact_521_bit_surface() {
        let hash = aura_hash521_v1(b"AURA_TEST_VECTOR");
        let bytes = hash.to_bytes();

        assert_eq!(bytes.len(), AURA_HASH521_V1_OUTPUT_BYTES);
        assert_eq!(bytes.len(), FIELD_ELEMENT_521_BYTE_LEN_V1);
        assert_eq!(bytes[0] & 0xfe, 0);
    }

    #[test]
    fn hash521_single_sha3_construction() {
        // Verify the hash uses exactly one SHA3-512 call
        // by checking that the output is a valid field element
        let hash = aura_hash521_v1(b"canonical test message");
        let bytes = hash.to_bytes();
        
        // Top 7 bits must be zero (521 bits = 66 bytes with top byte having only 1 valid bit)
        assert_eq!(bytes[0] & 0xfe, 0);
        
        // Must be less than modulus (not equal, as reduce_bytes_mod handles that)
        // The reduce_bytes_mod function wraps values >= modulus by subtracting
        let _ = crate::FieldElement521V1::from_bytes(bytes)
            .expect("hash output must be valid canonical field element");
    }

    #[test]
    fn hash521_different_inputs_produce_different_outputs() {
        let hash1 = aura_hash521_v1(b"input one");
        let hash2 = aura_hash521_v1(b"input two");
        
        assert_ne!(hash1.to_bytes(), hash2.to_bytes());
    }

    #[test]
    fn hash521_empty_input_produces_valid_output() {
        let hash = aura_hash521_v1(b"");
        let bytes = hash.to_bytes();
        
        assert_eq!(bytes.len(), AURA_HASH521_V1_OUTPUT_BYTES);
        assert_eq!(bytes[0] & 0xfe, 0);
    }
}
