//! Versioned widening path for the lower-layer execution root.
//!
//! This module introduces a 521-bit authoritative lower-layer execution commitment for the
//! versioned V2 path while retaining the existing 32-byte lower-layer roots only as helper-only
//! compatibility surfaces carried alongside the widened root.

use core::fmt;

use crate::{
    canonical_dcm_air_trace_bytes_v1, derive_dcm_commitment_root_521_v1,
    derive_deterministic_commitment_521_v1, derive_trace_commitment_521_v1, DcmAirTraceV1,
    DcmConfig521V1, DcmExecution521ErrorV1, DcmExecution521V1, DcmInput521V1, DcmState521V1,
    DcmTraceCommitment521ErrorV1, DeterministicCommitment521ErrorV1, DeterministicCommitment521V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1, HASH_LEN_V1,
    STORM_CONTEXT_V1_LEN, STORM_SIDE_INPUT_LEN_V1, STORM_CLAIM_521_V1_VERSION,
    STORM_MODULUS_ID_521_V1, StormExecutionErrorV1, StormExecutionInputsV1, StormState521V1,
    compute_storm_trace_root, derive_a, derive_b, derive_x0, derive_y0, execute_storm_v1,
};

pub const LOWER_LAYER_EXECUTION_COMMITMENT_V2_VERSION: u8 = 2;
pub const AURA_LOWER_LAYER_EXECUTION_COMMITMENT_V2_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LOWER_LAYER_EXECUTION_COMMITMENT_V2";
pub const AURA_LOWER_LAYER_EXECUTION_COMMITMENT_STORM_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LOWER_LAYER_EXECUTION_COMMITMENT_STORM_V1";
pub const DCM_CLAIM_521_V2_CANONICAL_BYTE_LEN_V1: usize =
    1 + FIELD_ELEMENT_521_BYTE_LEN_V1 + 8 + 132 + 132 + 66 + HASH_LEN_V1 + HASH_LEN_V1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerLayerExecutionCommitmentV2 {
    commitment: DeterministicCommitment521V1,
}

impl LowerLayerExecutionCommitmentV2 {
    const fn from_commitment(commitment: DeterministicCommitment521V1) -> Self {
        Self { commitment }
    }

    pub fn from_bytes(
        bytes: [u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
    ) -> Result<Self, DeterministicCommitment521ErrorV1> {
        DeterministicCommitment521V1::from_bytes(bytes).map(Self::from_commitment)
    }

    pub fn to_bytes(self) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
        self.commitment.to_bytes()
    }

    pub fn is_zero(self) -> bool {
        self.commitment.is_zero()
    }

    pub const fn as_commitment(self) -> DeterministicCommitment521V1 {
        self.commitment
    }
}

impl From<LowerLayerExecutionCommitmentV2> for DeterministicCommitment521V1 {
    fn from(value: LowerLayerExecutionCommitmentV2) -> Self {
        value.commitment
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmClaim521V2 {
    pub claim_version: u8,
    pub config: DcmConfig521V1,
    pub initial_state: DcmState521V1,
    pub final_state: DcmState521V1,
    pub execution_commitment: LowerLayerExecutionCommitmentV2,
    pub legacy_commitment_root: [u8; HASH_LEN_V1],
    pub legacy_trace_commitment: [u8; HASH_LEN_V1],
}

impl DcmClaim521V2 {
    pub fn trace_state_count(&self) -> u64 {
        self.config
            .iteration_count
            .checked_add(1)
            .expect("validated iteration count must not overflow")
    }

    pub fn canonical_bytes(&self) -> [u8; DCM_CLAIM_521_V2_CANONICAL_BYTE_LEN_V1] {
        let mut bytes = [0u8; DCM_CLAIM_521_V2_CANONICAL_BYTE_LEN_V1];
        let mut cursor = 0usize;

        bytes[cursor] = self.claim_version;
        cursor += 1;

        bytes[cursor..cursor + FIELD_ELEMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&FIELD_MODULUS_521_V1);
        cursor += FIELD_ELEMENT_521_BYTE_LEN_V1;

        bytes[cursor..cursor + 8].copy_from_slice(&self.config.iteration_count.to_le_bytes());
        cursor += 8;

        let initial_state_bytes = self.initial_state.canonical_bytes();
        bytes[cursor..cursor + initial_state_bytes.len()].copy_from_slice(&initial_state_bytes);
        cursor += initial_state_bytes.len();

        let final_state_bytes = self.final_state.canonical_bytes();
        bytes[cursor..cursor + final_state_bytes.len()].copy_from_slice(&final_state_bytes);
        cursor += final_state_bytes.len();

        let execution_commitment_bytes = self.execution_commitment.to_bytes();
        bytes[cursor..cursor + execution_commitment_bytes.len()]
            .copy_from_slice(&execution_commitment_bytes);
        cursor += execution_commitment_bytes.len();

        bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&self.legacy_commitment_root);
        cursor += HASH_LEN_V1;

        bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&self.legacy_trace_commitment);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowerLayerExecutionCommitmentV2Error {
    Layer1ParametersInvalid(DcmExecution521ErrorV1),
    EmptyTrace,
    TraceLengthFieldMismatch {
        expected: u64,
        actual: u64,
    },
    FinalStateFieldMismatch {
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    LegacyTraceCommitmentRejected(DcmTraceCommitment521ErrorV1),
    LegacyTraceCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for LowerLayerExecutionCommitmentV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layer1ParametersInvalid(error) => write!(f, "layer1 parameters invalid: {error}"),
            Self::EmptyTrace => write!(f, "lower-layer execution trace must not be empty"),
            Self::TraceLengthFieldMismatch { expected, actual } => write!(
                f,
                "lower-layer execution trace_length mismatch: expected {expected}, got {actual}"
            ),
            Self::FinalStateFieldMismatch { expected, actual } => write!(
                f,
                "lower-layer execution final_state mismatch: expected {expected}, got {actual}"
            ),
            Self::LegacyTraceCommitmentRejected(error) => {
                write!(f, "legacy trace commitment rejected execution material: {error}")
            }
            Self::LegacyTraceCommitmentMismatch { expected, actual } => write!(
                f,
                "legacy trace commitment mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
        }
    }
}

impl std::error::Error for LowerLayerExecutionCommitmentV2Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LowerLayerExecutionCommitmentStormV1 {
    pub version: u8,
    pub modulus_id: u8,
    pub iteration_count: u64,
    pub side_a: [u8; STORM_SIDE_INPUT_LEN_V1],
    pub side_b: [u8; STORM_SIDE_INPUT_LEN_V1],
    pub context_bytes_v1: [u8; STORM_CONTEXT_V1_LEN],
    pub initial_state: StormState521V1,
    pub final_state: StormState521V1,
    pub a: crate::FieldElement521V1,
    pub b: crate::FieldElement521V1,
    pub canonical_trace_bytes: Vec<u8>,
    pub trace_root: [u8; HASH_LEN_V1],
}

impl LowerLayerExecutionCommitmentStormV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            1 + 1 + 8 + STORM_SIDE_INPUT_LEN_V1 * 2 + STORM_CONTEXT_V1_LEN + 132 + 132 + 66 + 66 + 8 + self.canonical_trace_bytes.len() + HASH_LEN_V1,
        );
        bytes.push(self.version);
        bytes.push(self.modulus_id);
        bytes.extend_from_slice(&self.iteration_count.to_le_bytes());
        bytes.extend_from_slice(&self.side_a);
        bytes.extend_from_slice(&self.side_b);
        bytes.extend_from_slice(&self.context_bytes_v1);
        bytes.extend_from_slice(&self.initial_state.encode_row_bytes());
        bytes.extend_from_slice(&self.final_state.encode_row_bytes());
        bytes.extend_from_slice(&self.a.to_bytes());
        bytes.extend_from_slice(&self.b.to_bytes());
        bytes.extend_from_slice(&(self.canonical_trace_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.canonical_trace_bytes);
        bytes.extend_from_slice(&self.trace_root);
        bytes
    }
}

pub fn build_lower_layer_execution_commitment_storm_v1(
    inputs: &StormExecutionInputsV1,
) -> Result<LowerLayerExecutionCommitmentStormV1, StormExecutionErrorV1> {
    inputs.validate()?;
    let execution = execute_storm_v1(inputs);
    let canonical_trace_bytes = execution
        .trace
        .iter()
        .flat_map(StormState521V1::encode_row_bytes)
        .collect::<Vec<_>>();

    Ok(LowerLayerExecutionCommitmentStormV1 {
        version: STORM_CLAIM_521_V1_VERSION,
        modulus_id: STORM_MODULUS_ID_521_V1,
        iteration_count: inputs.iteration_count,
        side_a: inputs.side_a,
        side_b: inputs.side_b,
        context_bytes_v1: inputs.context_bytes_v1,
        initial_state: StormState521V1 {
            x: derive_x0(&inputs.side_a),
            y: derive_y0(&inputs.side_b),
        },
        final_state: execution.final_state,
        a: derive_a(&inputs.context_bytes_v1),
        b: derive_b(&inputs.context_bytes_v1),
        canonical_trace_bytes,
        trace_root: compute_storm_trace_root(&execution.trace),
    })
}

pub fn derive_lower_layer_execution_commitment_v2_from_storm_v1(
    material: &LowerLayerExecutionCommitmentStormV1,
) -> LowerLayerExecutionCommitmentV2 {
    LowerLayerExecutionCommitmentV2::from_commitment(derive_deterministic_commitment_521_v1(
        AURA_LOWER_LAYER_EXECUTION_COMMITMENT_STORM_V1_DOMAIN_SEPARATOR,
        &material.canonical_bytes(),
    ))
}

pub fn derive_lower_layer_execution_commitment_v2(
    config: &DcmConfig521V1,
    execution: &DcmExecution521V1,
) -> Result<LowerLayerExecutionCommitmentV2, LowerLayerExecutionCommitmentV2Error> {
    let material = canonical_lower_layer_execution_commitment_material_bytes_v2(config, execution)?;
    Ok(LowerLayerExecutionCommitmentV2::from_commitment(
        derive_deterministic_commitment_521_v1(
            AURA_LOWER_LAYER_EXECUTION_COMMITMENT_V2_DOMAIN_SEPARATOR,
            &material,
        ),
    ))
}

pub fn build_dcm_claim_521_v2(
    config: &DcmConfig521V1,
    execution: &DcmExecution521V1,
) -> Result<DcmClaim521V2, LowerLayerExecutionCommitmentV2Error> {
    validate_execution_against_helpers_v2(config, execution)?;

    let initial_state = execution.states[0];
    let legacy_commitment_root = derive_dcm_commitment_root_521_v1(config, execution);
    let execution_commitment = derive_lower_layer_execution_commitment_v2(config, execution)?;

    Ok(DcmClaim521V2 {
        claim_version: LOWER_LAYER_EXECUTION_COMMITMENT_V2_VERSION,
        config: *config,
        initial_state,
        final_state: execution.final_state,
        execution_commitment,
        legacy_commitment_root,
        legacy_trace_commitment: execution.trace_commitment,
    })
}

pub fn canonical_lower_layer_execution_commitment_material_bytes_v2(
    config: &DcmConfig521V1,
    execution: &DcmExecution521V1,
) -> Result<Vec<u8>, LowerLayerExecutionCommitmentV2Error> {
    validate_execution_against_helpers_v2(config, execution)?;

    let trace = DcmAirTraceV1::new(execution.states.clone());
    let trace_bytes = canonical_dcm_air_trace_bytes_v1(&trace);
    let initial_state = execution.states[0];
    let mut bytes = Vec::with_capacity(
        1 + FIELD_MODULUS_521_V1.len()
            + 8
            + 8
            + initial_state.canonical_bytes().len()
            + execution.final_state.canonical_bytes().len()
            + trace_bytes.len(),
    );
    bytes.push(LOWER_LAYER_EXECUTION_COMMITMENT_V2_VERSION);
    bytes.extend_from_slice(&FIELD_MODULUS_521_V1);
    bytes.extend_from_slice(&config.iteration_count.to_le_bytes());
    bytes.extend_from_slice(&execution.trace_length.to_le_bytes());
    bytes.extend_from_slice(&initial_state.canonical_bytes());
    bytes.extend_from_slice(&execution.final_state.canonical_bytes());
    bytes.extend_from_slice(&trace_bytes);
    Ok(bytes)
}

fn validate_execution_against_helpers_v2(
    config: &DcmConfig521V1,
    execution: &DcmExecution521V1,
) -> Result<(), LowerLayerExecutionCommitmentV2Error> {
    config
        .validate()
        .map_err(LowerLayerExecutionCommitmentV2Error::Layer1ParametersInvalid)?;

    if execution.states.is_empty() {
        return Err(LowerLayerExecutionCommitmentV2Error::EmptyTrace);
    }

    let actual_trace_length = execution.states.len() as u64;
    if execution.trace_length != actual_trace_length {
        return Err(LowerLayerExecutionCommitmentV2Error::TraceLengthFieldMismatch {
            expected: actual_trace_length,
            actual: execution.trace_length,
        });
    }

    let actual_final_state = *execution
        .states
        .last()
        .expect("checked non-empty states for lower-layer execution commitment");
    if execution.final_state != actual_final_state {
        return Err(LowerLayerExecutionCommitmentV2Error::FinalStateFieldMismatch {
            expected: actual_final_state,
            actual: execution.final_state,
        });
    }

    let reconstructed_input = DcmInput521V1 {
        x0: execution.states[0].x,
        y0: execution.states[0].y,
    };
    let expected_trace_commitment =
        derive_trace_commitment_521_v1(config, &reconstructed_input, &execution.states)
            .map_err(LowerLayerExecutionCommitmentV2Error::LegacyTraceCommitmentRejected)?;
    if execution.trace_commitment != expected_trace_commitment {
        return Err(LowerLayerExecutionCommitmentV2Error::LegacyTraceCommitmentMismatch {
            expected: expected_trace_commitment,
            actual: execution.trace_commitment,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_dcm_claim_521_v2, derive_lower_layer_execution_commitment_v2,
        canonical_lower_layer_execution_commitment_material_bytes_v2,
        LowerLayerExecutionCommitmentV2Error, DCM_CLAIM_521_V2_CANONICAL_BYTE_LEN_V1,
        AURA_LOWER_LAYER_EXECUTION_COMMITMENT_V2_DOMAIN_SEPARATOR,
    };
    use crate::{
        derive_deterministic_commitment_521_v1, DcmConfig521V1, DcmExecution521V1, DcmInput521V1,
        DcmState521V1, FieldElement521V1,
    };

    #[test]
    fn lower_layer_execution_commitment_v2_is_deterministic() {
        let config = canonical_config();
        let execution = canonical_execution();

        let first = derive_lower_layer_execution_commitment_v2(&config, &execution).unwrap();
        let second = derive_lower_layer_execution_commitment_v2(&config, &execution).unwrap();

        assert_eq!(first, second);
        assert!(!first.is_zero());
    }

    #[test]
    fn lower_layer_execution_commitment_v2_changes_when_execution_changes() {
        let first = canonical_execution();
        let second = DcmExecution521V1::run(
            &canonical_config(),
            &DcmInput521V1::from_u64(5, 8),
        )
        .unwrap();

        let first_commitment =
            derive_lower_layer_execution_commitment_v2(&canonical_config(), &first).unwrap();
        let second_commitment =
            derive_lower_layer_execution_commitment_v2(&canonical_config(), &second).unwrap();

        assert_ne!(first_commitment, second_commitment);
    }

    #[test]
    fn lower_layer_execution_commitment_v2_rejects_tampered_legacy_trace_helper() {
        let config = canonical_config();
        let mut execution = canonical_execution();
        execution.trace_commitment[0] ^= 0x80;

        let error = derive_lower_layer_execution_commitment_v2(&config, &execution).unwrap_err();
        assert!(matches!(
            error,
            LowerLayerExecutionCommitmentV2Error::LegacyTraceCommitmentMismatch { .. }
        ));
    }

    #[test]
    fn dcm_claim_521_v2_binds_authoritative_and_legacy_roots() {
        let config = canonical_config();
        let execution = canonical_execution();
        let claim = build_dcm_claim_521_v2(&config, &execution).unwrap();

        assert_eq!(claim.claim_version, 2);
        assert_eq!(claim.trace_state_count(), execution.trace_length);
        assert_eq!(claim.initial_state, execution.states[0]);
        assert_eq!(claim.final_state, execution.final_state);
        assert_eq!(claim.legacy_trace_commitment, execution.trace_commitment);
        assert_eq!(claim.canonical_bytes().len(), DCM_CLAIM_521_V2_CANONICAL_BYTE_LEN_V1);
    }

    #[test]
    fn canonical_material_bytes_match_domain_commitment_replay() {
        let config = canonical_config();
        let execution = canonical_execution();
        let material =
            canonical_lower_layer_execution_commitment_material_bytes_v2(&config, &execution)
                .unwrap();
        let expected = derive_deterministic_commitment_521_v1(
            AURA_LOWER_LAYER_EXECUTION_COMMITMENT_V2_DOMAIN_SEPARATOR,
            &material,
        );
        let actual = derive_lower_layer_execution_commitment_v2(&config, &execution).unwrap();

        assert_eq!(expected, actual.as_commitment());
    }

    fn canonical_config() -> DcmConfig521V1 {
        DcmConfig521V1 { iteration_count: 2 }
    }

    fn canonical_execution() -> DcmExecution521V1 {
        DcmExecution521V1::run(
            &canonical_config(),
            &DcmInput521V1 {
                x0: max_minus_one(),
                y0: small_value(1),
            },
        )
        .unwrap()
    }

    fn max_minus_one() -> FieldElement521V1 {
        let mut bytes = crate::FIELD_MODULUS_521_V1;
        bytes[crate::FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }

    fn small_value(value: u8) -> FieldElement521V1 {
        let mut bytes = [0u8; crate::FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[crate::FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }

    #[allow(dead_code)]
    fn state(x: FieldElement521V1, y: FieldElement521V1) -> DcmState521V1 {
        DcmState521V1 { x, y }
    }
}
