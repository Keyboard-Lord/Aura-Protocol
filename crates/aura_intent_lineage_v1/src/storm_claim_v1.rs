//! Canonical storm claim and public-input surfaces.

use core::fmt;

use sha3::{Digest, Sha3_256};

use crate::{
    compute_storm_trace_root, decode_row_bytes, execute_storm_v1, validate_context_bytes_v1,
    StormContextErrorV1, StormExecutionInputsV1, StormState521V1, StormStateEncodingErrorV1,
    HASH_LEN_V1, STORM_CONTEXT_V1_LEN, STORM_SIDE_INPUT_LEN_V1, STORM_STATE_521_ROW_BYTE_LEN_V1,
};

pub const STORM_CLAIM_521_V1_VERSION: u8 = 0x01;
pub const STORM_MODULUS_ID_521_V1: u8 = 0x01;
pub const STORM_CLAIM_521_CANONICAL_BYTE_LEN_V1: usize = 1
    + 1
    + 8
    + STORM_SIDE_INPUT_LEN_V1
    + STORM_SIDE_INPUT_LEN_V1
    + STORM_CONTEXT_V1_LEN
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + HASH_LEN_V1
    + HASH_LEN_V1
    + HASH_LEN_V1;
pub const STORM_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1: usize = 1
    + 1
    + 8
    + HASH_LEN_V1
    + HASH_LEN_V1
    + HASH_LEN_V1
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + HASH_LEN_V1;
pub const AURA_STORM_SIDE_A_HASH_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_STORM_SIDE_A_HASH_V1";
pub const AURA_STORM_SIDE_B_HASH_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_STORM_SIDE_B_HASH_V1";
pub const AURA_STORM_CONTEXT_HASH_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_STORM_CONTEXT_HASH_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormClaim521V1 {
    pub version: u8,
    pub modulus_id: u8,
    pub iteration_count: u64,
    pub side_a: [u8; STORM_SIDE_INPUT_LEN_V1],
    pub side_b: [u8; STORM_SIDE_INPUT_LEN_V1],
    pub context_bytes_v1: [u8; STORM_CONTEXT_V1_LEN],
    pub initial_state: StormState521V1,
    pub final_state: StormState521V1,
    pub trace_root: [u8; HASH_LEN_V1],
    pub legacy_commitment_root: [u8; HASH_LEN_V1],
    pub legacy_trace_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormPublicInputs521V1 {
    pub version: u8,
    pub modulus_id: u8,
    pub iteration_count: u64,
    pub side_a_hash: [u8; HASH_LEN_V1],
    pub side_b_hash: [u8; HASH_LEN_V1],
    pub context_hash: [u8; HASH_LEN_V1],
    pub initial_state: StormState521V1,
    pub final_state: StormState521V1,
    pub trace_root: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormClaimErrorV1 {
    InvalidVersion { expected: u8, actual: u8 },
    InvalidModulusId { expected: u8, actual: u8 },
    InvalidContext(StormContextErrorV1),
    InitialStateMismatch {
        expected: StormState521V1,
        actual: StormState521V1,
    },
    FinalStateMismatch {
        expected: StormState521V1,
        actual: StormState521V1,
    },
    TraceRootMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for StormClaimErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(f, "invalid storm claim version: expected {expected}, got {actual}")
            }
            Self::InvalidModulusId { expected, actual } => {
                write!(
                    f,
                    "invalid storm modulus id: expected {expected}, got {actual}"
                )
            }
            Self::InvalidContext(error) => write!(f, "invalid storm claim context: {error}"),
            Self::InitialStateMismatch { expected, actual } => {
                write!(
                    f,
                    "storm claim initial state mismatch: expected {:?}, got {:?}",
                    expected, actual
                )
            }
            Self::FinalStateMismatch { expected, actual } => {
                write!(
                    f,
                    "storm claim final state mismatch: expected {:?}, got {:?}",
                    expected, actual
                )
            }
            Self::TraceRootMismatch { .. } => write!(f, "storm claim trace root mismatch"),
        }
    }
}

impl std::error::Error for StormClaimErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormClaimEncodingErrorV1 {
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    InvalidInitialState(StormStateEncodingErrorV1),
    InvalidFinalState(StormStateEncodingErrorV1),
}

impl fmt::Display for StormClaimEncodingErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => write!(
                f,
                "invalid storm claim canonical length: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidInitialState(error) => {
                write!(f, "invalid canonical storm claim initial state: {error}")
            }
            Self::InvalidFinalState(error) => {
                write!(f, "invalid canonical storm claim final state: {error}")
            }
        }
    }
}

impl std::error::Error for StormClaimEncodingErrorV1 {}

impl StormClaim521V1 {
    pub fn trace_state_count(&self) -> u64 {
        self.iteration_count
            .checked_add(1)
            .expect("validated storm iteration count must not overflow")
    }

    pub fn validate(&self) -> Result<(), StormClaimErrorV1> {
        if self.version != STORM_CLAIM_521_V1_VERSION {
            return Err(StormClaimErrorV1::InvalidVersion {
                expected: STORM_CLAIM_521_V1_VERSION,
                actual: self.version,
            });
        }

        if self.modulus_id != STORM_MODULUS_ID_521_V1 {
            return Err(StormClaimErrorV1::InvalidModulusId {
                expected: STORM_MODULUS_ID_521_V1,
                actual: self.modulus_id,
            });
        }

        validate_context_bytes_v1(&self.context_bytes_v1)
            .map_err(StormClaimErrorV1::InvalidContext)?;

        let inputs = StormExecutionInputsV1 {
            side_a: self.side_a,
            side_b: self.side_b,
            context_bytes_v1: self.context_bytes_v1,
            iteration_count: self.iteration_count,
        };
        let execution = execute_storm_v1(&inputs);

        if self.initial_state != execution.initial_state {
            return Err(StormClaimErrorV1::InitialStateMismatch {
                expected: execution.initial_state,
                actual: self.initial_state,
            });
        }

        if self.final_state != execution.final_state {
            return Err(StormClaimErrorV1::FinalStateMismatch {
                expected: execution.final_state,
                actual: self.final_state,
            });
        }

        let expected_trace_root = compute_storm_trace_root(&execution.trace);
        if self.trace_root != expected_trace_root {
            return Err(StormClaimErrorV1::TraceRootMismatch {
                expected: expected_trace_root,
                actual: self.trace_root,
            });
        }

        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STORM_CLAIM_521_CANONICAL_BYTE_LEN_V1);
        bytes.push(self.version);
        bytes.push(self.modulus_id);
        bytes.extend_from_slice(&self.iteration_count.to_le_bytes());
        bytes.extend_from_slice(&self.side_a);
        bytes.extend_from_slice(&self.side_b);
        bytes.extend_from_slice(&self.context_bytes_v1);
        bytes.extend_from_slice(&self.initial_state.encode_row_bytes());
        bytes.extend_from_slice(&self.final_state.encode_row_bytes());
        bytes.extend_from_slice(&self.trace_root);
        bytes.extend_from_slice(&self.legacy_commitment_root);
        bytes.extend_from_slice(&self.legacy_trace_commitment);
        bytes
    }
}

impl StormPublicInputs521V1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STORM_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1);
        bytes.push(self.version);
        bytes.push(self.modulus_id);
        bytes.extend_from_slice(&self.iteration_count.to_le_bytes());
        bytes.extend_from_slice(&self.side_a_hash);
        bytes.extend_from_slice(&self.side_b_hash);
        bytes.extend_from_slice(&self.context_hash);
        bytes.extend_from_slice(&self.initial_state.encode_row_bytes());
        bytes.extend_from_slice(&self.final_state.encode_row_bytes());
        bytes.extend_from_slice(&self.trace_root);
        bytes
    }
}

pub fn decode_storm_claim_canonical_bytes_v1(
    bytes: &[u8],
) -> Result<StormClaim521V1, StormClaimEncodingErrorV1> {
    if bytes.len() != STORM_CLAIM_521_CANONICAL_BYTE_LEN_V1 {
        return Err(StormClaimEncodingErrorV1::InvalidLength {
            expected: STORM_CLAIM_521_CANONICAL_BYTE_LEN_V1,
            actual: bytes.len(),
        });
    }

    let mut offset = 0usize;

    let version = bytes[offset];
    offset += 1;

    let modulus_id = bytes[offset];
    offset += 1;

    let mut iteration_count_bytes = [0u8; 8];
    iteration_count_bytes.copy_from_slice(&bytes[offset..offset + 8]);
    let iteration_count = u64::from_le_bytes(iteration_count_bytes);
    offset += 8;

    let mut side_a = [0u8; STORM_SIDE_INPUT_LEN_V1];
    side_a.copy_from_slice(&bytes[offset..offset + STORM_SIDE_INPUT_LEN_V1]);
    offset += STORM_SIDE_INPUT_LEN_V1;

    let mut side_b = [0u8; STORM_SIDE_INPUT_LEN_V1];
    side_b.copy_from_slice(&bytes[offset..offset + STORM_SIDE_INPUT_LEN_V1]);
    offset += STORM_SIDE_INPUT_LEN_V1;

    let mut context_bytes_v1 = [0u8; STORM_CONTEXT_V1_LEN];
    context_bytes_v1.copy_from_slice(&bytes[offset..offset + STORM_CONTEXT_V1_LEN]);
    offset += STORM_CONTEXT_V1_LEN;

    let initial_state = decode_row_bytes(&bytes[offset..offset + STORM_STATE_521_ROW_BYTE_LEN_V1])
        .map_err(StormClaimEncodingErrorV1::InvalidInitialState)?;
    offset += STORM_STATE_521_ROW_BYTE_LEN_V1;

    let final_state = decode_row_bytes(&bytes[offset..offset + STORM_STATE_521_ROW_BYTE_LEN_V1])
        .map_err(StormClaimEncodingErrorV1::InvalidFinalState)?;
    offset += STORM_STATE_521_ROW_BYTE_LEN_V1;

    let mut trace_root = [0u8; HASH_LEN_V1];
    trace_root.copy_from_slice(&bytes[offset..offset + HASH_LEN_V1]);
    offset += HASH_LEN_V1;

    let mut legacy_commitment_root = [0u8; HASH_LEN_V1];
    legacy_commitment_root.copy_from_slice(&bytes[offset..offset + HASH_LEN_V1]);
    offset += HASH_LEN_V1;

    let mut legacy_trace_commitment = [0u8; HASH_LEN_V1];
    legacy_trace_commitment.copy_from_slice(&bytes[offset..offset + HASH_LEN_V1]);

    Ok(StormClaim521V1 {
        version,
        modulus_id,
        iteration_count,
        side_a,
        side_b,
        context_bytes_v1,
        initial_state,
        final_state,
        trace_root,
        legacy_commitment_root,
        legacy_trace_commitment,
    })
}

pub fn build_storm_claim_v1(
    inputs: &StormExecutionInputsV1,
    legacy_commitment_root: [u8; HASH_LEN_V1],
    legacy_trace_commitment: [u8; HASH_LEN_V1],
) -> StormClaim521V1 {
    let execution = execute_storm_v1(inputs);

    StormClaim521V1 {
        version: STORM_CLAIM_521_V1_VERSION,
        modulus_id: STORM_MODULUS_ID_521_V1,
        iteration_count: inputs.iteration_count,
        side_a: inputs.side_a,
        side_b: inputs.side_b,
        context_bytes_v1: inputs.context_bytes_v1,
        initial_state: execution.initial_state,
        final_state: execution.final_state,
        trace_root: compute_storm_trace_root(&execution.trace),
        legacy_commitment_root,
        legacy_trace_commitment,
    }
}

pub fn build_storm_public_inputs_v1(claim: &StormClaim521V1) -> StormPublicInputs521V1 {
    StormPublicInputs521V1 {
        version: claim.version,
        modulus_id: claim.modulus_id,
        iteration_count: claim.iteration_count,
        side_a_hash: sha3_256_domain_separated(
            AURA_STORM_SIDE_A_HASH_V1_DOMAIN_SEPARATOR,
            &claim.side_a,
        ),
        side_b_hash: sha3_256_domain_separated(
            AURA_STORM_SIDE_B_HASH_V1_DOMAIN_SEPARATOR,
            &claim.side_b,
        ),
        context_hash: sha3_256_domain_separated(
            AURA_STORM_CONTEXT_HASH_V1_DOMAIN_SEPARATOR,
            &claim.context_bytes_v1,
        ),
        initial_state: claim.initial_state,
        final_state: claim.final_state,
        trace_root: claim.trace_root,
    }
}

fn sha3_256_domain_separated(domain_separator: &[u8], payload: &[u8]) -> [u8; HASH_LEN_V1] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain_separator);
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut output = [0u8; HASH_LEN_V1];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use crate::{StormContextV1, STORM_CONTEXT_V1_VERSION};

    use super::{
        build_storm_claim_v1, build_storm_public_inputs_v1,
        AURA_STORM_CONTEXT_HASH_V1_DOMAIN_SEPARATOR, STORM_CLAIM_521_V1_VERSION,
        STORM_MODULUS_ID_521_V1,
    };
    use crate::StormExecutionInputsV1;

    fn sample_inputs() -> StormExecutionInputsV1 {
        StormExecutionInputsV1 {
            side_a: [0x11; 110],
            side_b: [0x22; 110],
            context_bytes_v1: StormContextV1 {
                context_version: STORM_CONTEXT_V1_VERSION,
                network_id: [0x33; 32],
                intent_hash: [0x44; 32],
                freshness_nonce: [0x55; 32],
                valid_from: 12,
                valid_until: 34,
                controller_id: [0x66; 32],
                route_tag: [0x77; 32],
            }
            .to_bytes(),
            iteration_count: 3,
        }
    }

    #[test]
    fn built_storm_claim_validates() {
        let claim = build_storm_claim_v1(&sample_inputs(), [0u8; 32], [0u8; 32]);

        assert_eq!(claim.version, STORM_CLAIM_521_V1_VERSION);
        assert_eq!(claim.modulus_id, STORM_MODULUS_ID_521_V1);
        claim.validate().unwrap();
    }

    #[test]
    fn public_inputs_bind_claim_surfaces() {
        let claim = build_storm_claim_v1(&sample_inputs(), [1u8; 32], [2u8; 32]);
        let public_inputs = build_storm_public_inputs_v1(&claim);

        assert_eq!(public_inputs.version, claim.version);
        assert_eq!(public_inputs.final_state, claim.final_state);
        assert_eq!(public_inputs.trace_root, claim.trace_root);
        assert_ne!(public_inputs.context_hash, [0u8; 32]);
        assert!(!AURA_STORM_CONTEXT_HASH_V1_DOMAIN_SEPARATOR.is_empty());
    }
}
