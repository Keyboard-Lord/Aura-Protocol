//! Canonical storm-native binding material for Aura Session Encryption V1.

use core::fmt;

use crate::{
    FieldElement521V1, StormClaim521V1, StormPublicInputs521V1, HASH_LEN_V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1,
};

pub const STORM_ENCRYPTION_BINDING_V1_LEN: usize =
    HASH_LEN_V1 * 6 + FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;
pub const AURA_STORM_ENCRYPTION_BINDING_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_STORM_ENCRYPTION_BINDING_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormEncryptionBindingV1 {
    pub storm_claim_digest: [u8; HASH_LEN_V1],
    pub trace_root: [u8; HASH_LEN_V1],
    pub final_state_x: [u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
    pub final_state_y: [u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
    pub context_hash: [u8; HASH_LEN_V1],
    pub sender_id: [u8; HASH_LEN_V1],
    pub receiver_id: [u8; HASH_LEN_V1],
    pub session_key_id: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormEncryptionBindingErrorV1 {
    InvalidFinalStateX,
    InvalidFinalStateY,
}

impl fmt::Display for StormEncryptionBindingErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFinalStateX => {
                write!(f, "invalid storm encryption binding final_state_x")
            }
            Self::InvalidFinalStateY => {
                write!(f, "invalid storm encryption binding final_state_y")
            }
        }
    }
}

impl std::error::Error for StormEncryptionBindingErrorV1 {}

pub fn build_storm_encryption_binding_v1(
    lower_layer_claim: &StormClaim521V1,
    lower_layer_public_inputs: &StormPublicInputs521V1,
    storm_claim_digest: [u8; HASH_LEN_V1],
    sender_id: [u8; HASH_LEN_V1],
    receiver_id: [u8; HASH_LEN_V1],
    session_key_id: [u8; HASH_LEN_V1],
) -> StormEncryptionBindingV1 {
    StormEncryptionBindingV1 {
        storm_claim_digest,
        trace_root: lower_layer_claim.trace_root,
        final_state_x: lower_layer_claim.final_state.x.to_bytes(),
        final_state_y: lower_layer_claim.final_state.y.to_bytes(),
        context_hash: lower_layer_public_inputs.context_hash,
        sender_id,
        receiver_id,
        session_key_id,
    }
}

pub fn encode_storm_encryption_binding_v1(
    binding: &StormEncryptionBindingV1,
) -> Result<[u8; STORM_ENCRYPTION_BINDING_V1_LEN], StormEncryptionBindingErrorV1> {
    validate_storm_encryption_binding_v1(binding)?;

    let mut bytes = [0u8; STORM_ENCRYPTION_BINDING_V1_LEN];
    let mut cursor = 0usize;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&binding.storm_claim_digest);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&binding.trace_root);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + FIELD_ELEMENT_521_BYTE_LEN_V1].copy_from_slice(&binding.final_state_x);
    cursor += FIELD_ELEMENT_521_BYTE_LEN_V1;

    bytes[cursor..cursor + FIELD_ELEMENT_521_BYTE_LEN_V1].copy_from_slice(&binding.final_state_y);
    cursor += FIELD_ELEMENT_521_BYTE_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&binding.context_hash);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&binding.sender_id);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&binding.receiver_id);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&binding.session_key_id);

    Ok(bytes)
}

pub fn derive_storm_encryption_binding_hash_v1(
    binding: &StormEncryptionBindingV1,
) -> Result<[u8; HASH_LEN_V1], StormEncryptionBindingErrorV1> {
    let bytes = encode_storm_encryption_binding_v1(binding)?;
    Ok(crate::sha256_domain_separated(
        AURA_STORM_ENCRYPTION_BINDING_V1_DOMAIN_SEPARATOR,
        &bytes,
    ))
}

pub fn validate_storm_encryption_binding_v1(
    binding: &StormEncryptionBindingV1,
) -> Result<(), StormEncryptionBindingErrorV1> {
    FieldElement521V1::from_bytes(binding.final_state_x)
        .map_err(|_| StormEncryptionBindingErrorV1::InvalidFinalStateX)?;
    FieldElement521V1::from_bytes(binding.final_state_y)
        .map_err(|_| StormEncryptionBindingErrorV1::InvalidFinalStateY)?;
    Ok(())
}
