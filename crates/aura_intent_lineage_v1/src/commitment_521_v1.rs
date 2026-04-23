//! Deterministic 521-bit-native commitment primitive for research/supporting upper layers.
//!
//! This primitive is intentionally field-native, but it does not absorb canonical bytes through
//! the older low-degree accumulator any longer.
//!
//! The current supporting-only replacement keeps the exact canonical commitment input bytes, then
//! expands them with two domain-separated `SHA-512` calls and reduces the resulting 1024-bit
//! string into the `2^521 - 1` field. That preserves deterministic replay and the 521-bit-native
//! output form while removing the previously confirmed fixed-prefix bias.

use core::fmt;

use crate::field_521_v1::{FieldElement521V1, FieldElementErrorV1, FIELD_ELEMENT_521_BYTE_LEN_V1};
use sha2::{Digest, Sha512};

pub const DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1: usize = FIELD_ELEMENT_521_BYTE_LEN_V1;
pub const AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_DETERMINISTIC_COMMITMENT_521_V1";
const AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_X_V1: &[u8] =
    b"AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_X_V1";
const AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_Y_V1: &[u8] =
    b"AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_Y_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeterministicCommitment521V1 {
    element: FieldElement521V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterministicCommitment521ErrorV1 {
    InvalidCanonicalBytes(FieldElementErrorV1),
}

impl fmt::Display for DeterministicCommitment521ErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCanonicalBytes(error) => {
                write!(f, "invalid deterministic commitment bytes: {error}")
            }
        }
    }
}

impl std::error::Error for DeterministicCommitment521ErrorV1 {}

impl DeterministicCommitment521V1 {
    const fn from_field_element(element: FieldElement521V1) -> Self {
        Self { element }
    }

    pub fn from_bytes(
        bytes: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    ) -> Result<Self, DeterministicCommitment521ErrorV1> {
        FieldElement521V1::from_bytes(bytes)
            .map(Self::from_field_element)
            .map_err(DeterministicCommitment521ErrorV1::InvalidCanonicalBytes)
    }

    pub fn to_bytes(self) -> [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1] {
        self.element.to_bytes()
    }

    pub fn is_zero(self) -> bool {
        self.element.is_zero()
    }
}

pub fn derive_deterministic_commitment_521_v1(
    domain_separator: &[u8],
    body: &[u8],
) -> DeterministicCommitment521V1 {
    let canonical_input = canonical_commitment_input_bytes_v1(domain_separator, body);
    let expanded = expand_commitment_bytes_v1(&canonical_input);
    DeterministicCommitment521V1::from_field_element(FieldElement521V1::reduce_bytes_mod(
        &expanded,
    ))
}

fn canonical_commitment_input_bytes_v1(domain_separator: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1.len()
            + 8
            + domain_separator.len()
            + 8
            + body.len(),
    );
    bytes.extend_from_slice(AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&(domain_separator.len() as u64).to_le_bytes());
    bytes.extend_from_slice(domain_separator);
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn expand_commitment_bytes_v1(canonical_input: &[u8]) -> [u8; 128] {
    let expand_x = sha512_domain_separated_bytes_v1(
        AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_X_V1,
        canonical_input,
    );
    let expand_y = sha512_domain_separated_bytes_v1(
        AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_Y_V1,
        canonical_input,
    );

    let mut output = [0u8; 128];
    output[..64].copy_from_slice(&expand_x);
    output[64..].copy_from_slice(&expand_y);
    output
}

fn sha512_domain_separated_bytes_v1(domain_separator: &[u8], body: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update((domain_separator.len() as u64).to_le_bytes());
    hasher.update(domain_separator);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        derive_deterministic_commitment_521_v1, expand_commitment_bytes_v1,
        sha512_domain_separated_bytes_v1, DeterministicCommitment521V1,
        AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_X_V1,
        AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_Y_V1,
        DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
    };

    #[test]
    fn deterministic_commitment_bytes_round_trip() {
        let commitment = derive_deterministic_commitment_521_v1(b"TEST_DOMAIN", b"test-body");
        let bytes = commitment.to_bytes();
        let reparsed = DeterministicCommitment521V1::from_bytes(bytes).unwrap();

        assert_eq!(bytes.len(), DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1);
        assert_eq!(reparsed, commitment);
    }

    #[test]
    fn deterministic_commitment_changes_with_domain_separator() {
        let first = derive_deterministic_commitment_521_v1(b"DOMAIN_A", b"same-body");
        let second = derive_deterministic_commitment_521_v1(b"DOMAIN_B", b"same-body");

        assert_ne!(first, second);
    }

    #[test]
    fn deterministic_commitment_changes_with_body() {
        let first = derive_deterministic_commitment_521_v1(b"DOMAIN", b"body-a");
        let second = derive_deterministic_commitment_521_v1(b"DOMAIN", b"body-b");

        assert_ne!(first, second);
    }

    #[test]
    fn deterministic_commitment_is_reproducible() {
        let first = derive_deterministic_commitment_521_v1(
            b"AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_V1",
            b"deterministic-body",
        );
        let second = derive_deterministic_commitment_521_v1(
            b"AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_V1",
            b"deterministic-body",
        );

        assert_eq!(first, second);
        assert!(!first.is_zero());
    }

    #[test]
    fn deterministic_commitment_uses_two_distinct_sha512_expansion_tags() {
        let canonical_input = b"same-canonical-input";
        let expand_x =
            sha512_domain_separated_bytes_v1(AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_X_V1, canonical_input);
        let expand_y =
            sha512_domain_separated_bytes_v1(AURA_DETERMINISTIC_COMMITMENT_521_EXPAND_Y_V1, canonical_input);
        let expanded = expand_commitment_bytes_v1(canonical_input);

        assert_ne!(expand_x, expand_y);
        assert_eq!(&expanded[..64], expand_x.as_slice());
        assert_eq!(&expanded[64..], expand_y.as_slice());
    }
}
