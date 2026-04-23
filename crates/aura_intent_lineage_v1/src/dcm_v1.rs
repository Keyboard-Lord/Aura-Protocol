// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Layer 1 deterministic cat-map execution and canonical trace commitment helpers.
//! This module is the source of truth for Aura's lower-layer pair-state runtime.

use core::fmt;

use crate::{
    derive_dcm_air_commitment_root_521_v1, sha256_bytes, FieldElement521V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1, HASH_LEN_V1,
};

pub const AURA_DCM_V1_STATE_LEAF_DOMAIN_SEPARATOR: &[u8] = b"AURA_CAT_V1_STATE_LEAF";
pub const AURA_DCM_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR: &[u8] = b"AURA_CAT_V1_TRACE_COMMITMENT";
pub const AURA_DCM_V1_COMMITMENT_ROOT_DOMAIN_SEPARATOR: &[u8] = b"AURA_CAT_V1_COMMITMENT_ROOT";
pub const AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR: &[u8] = b"AURA_CAT_521_V1_STATE_LEAF";
pub const AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_CAT_521_V1_TRACE_COMMITMENT";
pub const AURA_DCM_521_V1_COMMITMENT_ROOT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_CAT_521_V1_COMMITMENT_ROOT";
pub const DCM_STATE_521_CANONICAL_BYTE_LEN_V1: usize = FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;
pub const DCM_CLAIM_521_CANONICAL_BYTE_LEN_V1: usize =
    FIELD_ELEMENT_521_BYTE_LEN_V1 + 8 + DCM_STATE_521_CANONICAL_BYTE_LEN_V1 * 2 + HASH_LEN_V1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmStateV1 {
    pub x: u64,
    pub y: u64,
}

impl DcmStateV1 {
    // Legacy small-modulus cat-map helper retained for toy-prime exhaustive proofs and
    // migration audits. Active lower-layer runtime surfaces use `DcmState521V1`.
    pub fn canonical_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.x.to_le_bytes());
        bytes[8..].copy_from_slice(&self.y.to_le_bytes());
        bytes
    }
}

impl fmt::Display for DcmStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmState521V1 {
    pub x: FieldElement521V1,
    pub y: FieldElement521V1,
}

impl DcmState521V1 {
    pub fn from_u64(x: u64, y: u64) -> Self {
        Self {
            x: FieldElement521V1::from_u64(x),
            y: FieldElement521V1::from_u64(y),
        }
    }

    pub fn canonical_bytes(&self) -> [u8; DCM_STATE_521_CANONICAL_BYTE_LEN_V1] {
        let mut bytes = [0u8; DCM_STATE_521_CANONICAL_BYTE_LEN_V1];
        bytes[..FIELD_ELEMENT_521_BYTE_LEN_V1].copy_from_slice(&self.x.to_bytes());
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1..].copy_from_slice(&self.y.to_bytes());
        bytes
    }
}

impl fmt::Display for DcmState521V1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?}, {:?})", self.x, self.y)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmMatrix521V1 {
    pub a11: FieldElement521V1,
    pub a12: FieldElement521V1,
    pub a21: FieldElement521V1,
    pub a22: FieldElement521V1,
}

impl DcmMatrix521V1 {
    pub fn identity() -> Self {
        Self {
            a11: FieldElement521V1::one(),
            a12: FieldElement521V1::zero(),
            a21: FieldElement521V1::zero(),
            a22: FieldElement521V1::one(),
        }
    }

    pub fn arnold_cat() -> Self {
        Self {
            a11: FieldElement521V1::one(),
            a12: FieldElement521V1::one(),
            a21: FieldElement521V1::one(),
            a22: FieldElement521V1::from_u64(2),
        }
    }

    pub fn arnold_cat_inverse() -> Self {
        let neg_one = FieldElement521V1::zero().sub_mod(&FieldElement521V1::one());
        Self {
            a11: FieldElement521V1::from_u64(2),
            a12: neg_one,
            a21: neg_one,
            a22: FieldElement521V1::one(),
        }
    }

    pub fn multiply(&self, rhs: &Self) -> Self {
        Self {
            a11: self
                .a11
                .mul_mod(&rhs.a11)
                .add_mod(&self.a12.mul_mod(&rhs.a21)),
            a12: self
                .a11
                .mul_mod(&rhs.a12)
                .add_mod(&self.a12.mul_mod(&rhs.a22)),
            a21: self
                .a21
                .mul_mod(&rhs.a11)
                .add_mod(&self.a22.mul_mod(&rhs.a21)),
            a22: self
                .a21
                .mul_mod(&rhs.a12)
                .add_mod(&self.a22.mul_mod(&rhs.a22)),
        }
    }

    pub fn apply(&self, state: &DcmState521V1) -> DcmState521V1 {
        DcmState521V1 {
            x: self
                .a11
                .mul_mod(&state.x)
                .add_mod(&self.a12.mul_mod(&state.y)),
            y: self
                .a21
                .mul_mod(&state.x)
                .add_mod(&self.a22.mul_mod(&state.y)),
        }
    }

    pub fn pow(&self, exponent: u64) -> Self {
        let mut result = Self::identity();
        let mut base = *self;
        let mut power = exponent;

        while power > 0 {
            if power & 1 == 1 {
                result = result.multiply(&base);
            }
            base = base.multiply(&base);
            power >>= 1;
        }

        result
    }

    pub fn determinant(&self) -> FieldElement521V1 {
        self.a11
            .mul_mod(&self.a22)
            .sub_mod(&self.a12.mul_mod(&self.a21))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmConfigV1 {
    pub modulus: u64,
    pub iteration_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmInputV1 {
    pub x0: u64,
    pub y0: u64,
}

impl DcmInputV1 {
    pub const fn initial_state(&self) -> DcmStateV1 {
        DcmStateV1 {
            x: self.x0,
            y: self.y0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmExecutionV1 {
    // Legacy small-modulus trace format: states includes the normalized initial state and then
    // every successive cat-map state. Active lower-layer bindings use `DcmExecution521V1`.
    pub states: Vec<DcmStateV1>,
    pub final_state: DcmStateV1,
    pub trace_length: u64,
    pub trace_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmExecutionErrorV1 {
    InvalidModulus {
        actual: u64,
    },
    IterationCountTooLarge {
        actual: u64,
    },
    InputOutOfRange {
        field: &'static str,
        value: u64,
        modulus: u64,
    },
}

impl fmt::Display for DcmExecutionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModulus { actual } => {
                write!(f, "invalid modulus: expected >= 2, got {actual}")
            }
            Self::IterationCountTooLarge { actual } => {
                write!(
                    f,
                    "iteration count too large for this legacy path: {actual}"
                )
            }
            Self::InputOutOfRange {
                field,
                value,
                modulus,
            } => write!(
                f,
                "input out of range: {field}={value} must be less than modulus {modulus}"
            ),
        }
    }
}

impl std::error::Error for DcmExecutionErrorV1 {}

impl DcmConfigV1 {
    pub fn validate(&self) -> Result<(), DcmExecutionErrorV1> {
        if self.modulus < 2 {
            return Err(DcmExecutionErrorV1::InvalidModulus {
                actual: self.modulus,
            });
        }

        let iteration_count = usize::try_from(self.iteration_count).map_err(|_| {
            DcmExecutionErrorV1::IterationCountTooLarge {
                actual: self.iteration_count,
            }
        })?;
        let _ =
            iteration_count
                .checked_add(1)
                .ok_or(DcmExecutionErrorV1::IterationCountTooLarge {
                    actual: self.iteration_count,
                })?;

        Ok(())
    }
}

impl DcmInputV1 {
    pub fn validate(&self, config: &DcmConfigV1) -> Result<(), DcmExecutionErrorV1> {
        config.validate()?;

        if self.x0 >= config.modulus {
            return Err(DcmExecutionErrorV1::InputOutOfRange {
                field: "x0",
                value: self.x0,
                modulus: config.modulus,
            });
        }

        if self.y0 >= config.modulus {
            return Err(DcmExecutionErrorV1::InputOutOfRange {
                field: "y0",
                value: self.y0,
                modulus: config.modulus,
            });
        }

        Ok(())
    }
}

impl DcmExecutionV1 {
    pub fn run(config: &DcmConfigV1, input: &DcmInputV1) -> Result<Self, DcmExecutionErrorV1> {
        input.validate(config)?;

        let iteration_count = usize::try_from(config.iteration_count).map_err(|_| {
            DcmExecutionErrorV1::IterationCountTooLarge {
                actual: config.iteration_count,
            }
        })?;
        let trace_capacity =
            iteration_count
                .checked_add(1)
                .ok_or(DcmExecutionErrorV1::IterationCountTooLarge {
                    actual: config.iteration_count,
                })?;

        let mut states = Vec::with_capacity(trace_capacity);
        let mut state = input.initial_state();
        states.push(state);

        for _ in 0..iteration_count {
            state = advance_dcm_state_v1(state, config.modulus);
            states.push(state);
        }

        let trace_commitment = derive_trace_commitment_v1(config, input, &states);

        Ok(Self {
            final_state: state,
            trace_length: states.len() as u64,
            states,
            trace_commitment,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmConfig521V1 {
    pub iteration_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmInput521V1 {
    pub x0: FieldElement521V1,
    pub y0: FieldElement521V1,
}

impl DcmInput521V1 {
    pub fn from_u64(x0: u64, y0: u64) -> Self {
        Self {
            x0: FieldElement521V1::from_u64(x0),
            y0: FieldElement521V1::from_u64(y0),
        }
    }

    pub fn from_seed_bytes(user_entropy: &[u8], verifier_challenge: &[u8]) -> Self {
        Self {
            x0: FieldElement521V1::reduce_bytes_mod(user_entropy),
            y0: FieldElement521V1::reduce_bytes_mod(verifier_challenge),
        }
    }

    pub const fn initial_state(&self) -> DcmState521V1 {
        DcmState521V1 {
            x: self.x0,
            y: self.y0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmExecution521V1 {
    // The canonical 521-bit trace includes the initial pair-state followed by each successive
    // forward cat-map state.
    pub states: Vec<DcmState521V1>,
    pub final_state: DcmState521V1,
    pub trace_length: u64,
    pub trace_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmClaim521V1 {
    pub config: DcmConfig521V1,
    pub initial_state: DcmState521V1,
    pub final_state: DcmState521V1,
    pub commitment_root: [u8; HASH_LEN_V1],
}

impl DcmClaim521V1 {
    pub fn trace_state_count(&self) -> u64 {
        self.config
            .iteration_count
            .checked_add(1)
            .expect("validated iteration count must not overflow")
    }

    pub fn canonical_bytes(&self) -> [u8; DCM_CLAIM_521_CANONICAL_BYTE_LEN_V1] {
        let mut bytes = [0u8; DCM_CLAIM_521_CANONICAL_BYTE_LEN_V1];
        let mut cursor = 0usize;

        bytes[cursor..cursor + FIELD_ELEMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&FIELD_MODULUS_521_V1);
        cursor += FIELD_ELEMENT_521_BYTE_LEN_V1;

        bytes[cursor..cursor + 8].copy_from_slice(&self.config.iteration_count.to_le_bytes());
        cursor += 8;

        bytes[cursor..cursor + DCM_STATE_521_CANONICAL_BYTE_LEN_V1]
            .copy_from_slice(&self.initial_state.canonical_bytes());
        cursor += DCM_STATE_521_CANONICAL_BYTE_LEN_V1;

        bytes[cursor..cursor + DCM_STATE_521_CANONICAL_BYTE_LEN_V1]
            .copy_from_slice(&self.final_state.canonical_bytes());
        cursor += DCM_STATE_521_CANONICAL_BYTE_LEN_V1;

        bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&self.commitment_root);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmExecution521ErrorV1 {
    IterationCountTooLarge { actual: u64 },
}

impl fmt::Display for DcmExecution521ErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IterationCountTooLarge { actual } => {
                write!(
                    f,
                    "iteration count too large for this 521-bit path: {actual}"
                )
            }
        }
    }
}

impl std::error::Error for DcmExecution521ErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmTraceCommitment521ErrorV1 {
    IterationCountTooLarge {
        actual: u64,
    },
    TraceLengthMismatch {
        expected: u64,
        actual: u64,
    },
    InitialStateMismatch {
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    TransitionMismatch {
        index: u64,
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
}

impl fmt::Display for DcmTraceCommitment521ErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IterationCountTooLarge { actual } => {
                write!(
                    f,
                    "iteration count too large for 521-bit trace commitment: {actual}"
                )
            }
            Self::TraceLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "trace length mismatch for 521-bit trace commitment: expected {expected}, got {actual}"
                )
            }
            Self::InitialStateMismatch { expected, actual } => {
                write!(
                    f,
                    "initial state mismatch for 521-bit trace commitment: expected {expected}, got {actual}"
                )
            }
            Self::TransitionMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "transition mismatch for 521-bit trace commitment at index {index}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for DcmTraceCommitment521ErrorV1 {}

impl DcmConfig521V1 {
    pub fn validate(&self) -> Result<(), DcmExecution521ErrorV1> {
        let iteration_count = usize::try_from(self.iteration_count).map_err(|_| {
            DcmExecution521ErrorV1::IterationCountTooLarge {
                actual: self.iteration_count,
            }
        })?;
        let _ = iteration_count.checked_add(1).ok_or(
            DcmExecution521ErrorV1::IterationCountTooLarge {
                actual: self.iteration_count,
            },
        )?;

        Ok(())
    }
}

impl DcmInput521V1 {
    pub fn validate(&self, config: &DcmConfig521V1) -> Result<(), DcmExecution521ErrorV1> {
        config.validate()?;
        Ok(())
    }
}

impl DcmExecution521V1 {
    pub fn run(
        config: &DcmConfig521V1,
        input: &DcmInput521V1,
    ) -> Result<Self, DcmExecution521ErrorV1> {
        input.validate(config)?;

        let iteration_count = usize::try_from(config.iteration_count).map_err(|_| {
            DcmExecution521ErrorV1::IterationCountTooLarge {
                actual: config.iteration_count,
            }
        })?;
        let trace_capacity = iteration_count.checked_add(1).ok_or(
            DcmExecution521ErrorV1::IterationCountTooLarge {
                actual: config.iteration_count,
            },
        )?;

        let mut states = Vec::with_capacity(trace_capacity);
        let mut state = input.initial_state();
        states.push(state);

        for _ in 0..iteration_count {
            state = advance_dcm_state_521_v1(state);
            states.push(state);
        }

        let trace_commitment = derive_trace_commitment_521_v1(config, input, &states)
            .expect("materialized 521-bit cat-map trace must satisfy commitment invariants");

        Ok(Self {
            final_state: state,
            trace_length: states.len() as u64,
            states,
            trace_commitment,
        })
    }
}

pub fn derive_dcm_commitment_root_521_v1(
    config: &DcmConfig521V1,
    execution: &DcmExecution521V1,
) -> [u8; HASH_LEN_V1] {
    derive_dcm_air_commitment_root_521_v1(config, &execution.states)
}

pub fn build_dcm_claim_521_v1(
    config: &DcmConfig521V1,
    input: &DcmInput521V1,
    execution: &DcmExecution521V1,
) -> DcmClaim521V1 {
    DcmClaim521V1 {
        config: *config,
        initial_state: input.initial_state(),
        final_state: execution.final_state,
        commitment_root: derive_dcm_commitment_root_521_v1(config, execution),
    }
}

pub fn coordinate_recurrence_next_v1(previous: u64, current: u64, modulus: u64) -> u64 {
    mod_sub_u64(mod_mul_u64(3, current, modulus), previous, modulus)
}

pub fn coordinate_recurrence_next_521_v1(
    previous: FieldElement521V1,
    current: FieldElement521V1,
) -> FieldElement521V1 {
    current
        .add_mod(&current)
        .add_mod(&current)
        .sub_mod(&previous)
}

pub fn advance_dcm_state_v1(state: DcmStateV1, modulus: u64) -> DcmStateV1 {
    DcmStateV1 {
        x: mod_add_u64(state.x, state.y, modulus),
        y: mod_add_u64(state.x, mod_add_u64(state.y, state.y, modulus), modulus),
    }
}

pub fn rewind_dcm_state_v1(state: DcmStateV1, modulus: u64) -> DcmStateV1 {
    DcmStateV1 {
        x: mod_sub_u64(mod_add_u64(state.x, state.x, modulus), state.y, modulus),
        y: mod_sub_u64(state.y, state.x, modulus),
    }
}

pub fn fast_forward_dcm_state_v1(state: DcmStateV1, step_count: u64, modulus: u64) -> DcmStateV1 {
    matrix_pow_u64(cat_matrix_u64(modulus), step_count, modulus).apply(state, modulus)
}

pub fn fast_rewind_dcm_state_v1(state: DcmStateV1, step_count: u64, modulus: u64) -> DcmStateV1 {
    matrix_pow_u64(cat_inverse_matrix_u64(modulus), step_count, modulus).apply(state, modulus)
}

pub fn advance_dcm_state_521_v1(state: DcmState521V1) -> DcmState521V1 {
    dcm_cat_map_matrix_521_v1().apply(&state)
}

pub fn rewind_dcm_state_521_v1(state: DcmState521V1) -> DcmState521V1 {
    dcm_cat_map_inverse_matrix_521_v1().apply(&state)
}

pub fn fast_forward_dcm_state_521_v1(state: DcmState521V1, step_count: u64) -> DcmState521V1 {
    dcm_cat_map_matrix_521_v1().pow(step_count).apply(&state)
}

pub fn fast_rewind_dcm_state_521_v1(state: DcmState521V1, step_count: u64) -> DcmState521V1 {
    dcm_cat_map_inverse_matrix_521_v1()
        .pow(step_count)
        .apply(&state)
}

pub fn dcm_cat_map_matrix_521_v1() -> DcmMatrix521V1 {
    DcmMatrix521V1::arnold_cat()
}

pub fn dcm_cat_map_inverse_matrix_521_v1() -> DcmMatrix521V1 {
    DcmMatrix521V1::arnold_cat_inverse()
}

pub fn derive_trace_commitment_v1(
    config: &DcmConfigV1,
    input: &DcmInputV1,
    states: &[DcmStateV1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_DCM_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR.len() + 8 * 4 + HASH_LEN_V1 * states.len(),
    );
    preimage.extend_from_slice(AURA_DCM_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR);
    preimage.extend_from_slice(&config.modulus.to_le_bytes());
    preimage.extend_from_slice(&config.iteration_count.to_le_bytes());
    preimage.extend_from_slice(&input.x0.to_le_bytes());
    preimage.extend_from_slice(&input.y0.to_le_bytes());
    preimage.extend_from_slice(&(states.len() as u64).to_le_bytes());

    for (index, state) in states.iter().enumerate() {
        preimage.extend_from_slice(&state_leaf_hash(index as u64, *state));
    }

    sha256_bytes(&preimage)
}

fn state_leaf_hash(index: u64, state: DcmStateV1) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(AURA_DCM_V1_STATE_LEAF_DOMAIN_SEPARATOR.len() + 24);
    preimage.extend_from_slice(AURA_DCM_V1_STATE_LEAF_DOMAIN_SEPARATOR);
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.extend_from_slice(&state.canonical_bytes());
    sha256_bytes(&preimage)
}

pub fn derive_trace_commitment_521_v1(
    config: &DcmConfig521V1,
    input: &DcmInput521V1,
    states: &[DcmState521V1],
) -> Result<[u8; HASH_LEN_V1], DcmTraceCommitment521ErrorV1> {
    validate_trace_commitment_inputs_521_v1(config, input, states)?;

    let mut preimage = Vec::with_capacity(
        AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR.len()
            + FIELD_MODULUS_521_V1.len()
            + 8 * 2
            + DCM_STATE_521_CANONICAL_BYTE_LEN_V1
            + HASH_LEN_V1 * states.len(),
    );
    preimage.extend_from_slice(AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR);
    preimage.extend_from_slice(&FIELD_MODULUS_521_V1);
    preimage.extend_from_slice(&config.iteration_count.to_le_bytes());
    preimage.extend_from_slice(&input.x0.to_bytes());
    preimage.extend_from_slice(&input.y0.to_bytes());
    preimage.extend_from_slice(&(states.len() as u64).to_le_bytes());

    for (index, state) in states.iter().enumerate() {
        preimage.extend_from_slice(&state_leaf_hash_521_v1(index as u64, state));
    }

    Ok(sha256_bytes(&preimage))
}

fn state_leaf_hash_521_v1(index: u64, state: &DcmState521V1) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR.len() + 8 + DCM_STATE_521_CANONICAL_BYTE_LEN_V1,
    );
    preimage.extend_from_slice(AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR);
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.extend_from_slice(&state.canonical_bytes());
    sha256_bytes(&preimage)
}

fn validate_trace_commitment_inputs_521_v1(
    config: &DcmConfig521V1,
    input: &DcmInput521V1,
    states: &[DcmState521V1],
) -> Result<(), DcmTraceCommitment521ErrorV1> {
    let iteration_count = usize::try_from(config.iteration_count).map_err(|_| {
        DcmTraceCommitment521ErrorV1::IterationCountTooLarge {
            actual: config.iteration_count,
        }
    })?;
    let expected_len = iteration_count.checked_add(1).ok_or(
        DcmTraceCommitment521ErrorV1::IterationCountTooLarge {
            actual: config.iteration_count,
        },
    )?;

    if states.len() != expected_len {
        return Err(DcmTraceCommitment521ErrorV1::TraceLengthMismatch {
            expected: expected_len as u64,
            actual: states.len() as u64,
        });
    }

    let expected_initial_state = input.initial_state();
    let actual_initial_state = states[0];
    if actual_initial_state != expected_initial_state {
        return Err(DcmTraceCommitment521ErrorV1::InitialStateMismatch {
            expected: expected_initial_state,
            actual: actual_initial_state,
        });
    }

    for (index, pair) in states.windows(2).enumerate() {
        let expected = advance_dcm_state_521_v1(pair[0]);
        let actual = pair[1];
        if actual != expected {
            return Err(DcmTraceCommitment521ErrorV1::TransitionMismatch {
                index: index as u64,
                expected,
                actual,
            });
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct DcmMatrixV1 {
    a11: u64,
    a12: u64,
    a21: u64,
    a22: u64,
}

impl DcmMatrixV1 {
    fn identity() -> Self {
        Self {
            a11: 1,
            a12: 0,
            a21: 0,
            a22: 1,
        }
    }

    fn multiply(self, rhs: Self, modulus: u64) -> Self {
        Self {
            a11: mod_add_u64(
                mod_mul_u64(self.a11, rhs.a11, modulus),
                mod_mul_u64(self.a12, rhs.a21, modulus),
                modulus,
            ),
            a12: mod_add_u64(
                mod_mul_u64(self.a11, rhs.a12, modulus),
                mod_mul_u64(self.a12, rhs.a22, modulus),
                modulus,
            ),
            a21: mod_add_u64(
                mod_mul_u64(self.a21, rhs.a11, modulus),
                mod_mul_u64(self.a22, rhs.a21, modulus),
                modulus,
            ),
            a22: mod_add_u64(
                mod_mul_u64(self.a21, rhs.a12, modulus),
                mod_mul_u64(self.a22, rhs.a22, modulus),
                modulus,
            ),
        }
    }

    fn apply(self, state: DcmStateV1, modulus: u64) -> DcmStateV1 {
        DcmStateV1 {
            x: mod_add_u64(
                mod_mul_u64(self.a11, state.x, modulus),
                mod_mul_u64(self.a12, state.y, modulus),
                modulus,
            ),
            y: mod_add_u64(
                mod_mul_u64(self.a21, state.x, modulus),
                mod_mul_u64(self.a22, state.y, modulus),
                modulus,
            ),
        }
    }
}

fn cat_matrix_u64(_modulus: u64) -> DcmMatrixV1 {
    DcmMatrixV1 {
        a11: 1,
        a12: 1,
        a21: 1,
        a22: 2,
    }
}

fn cat_inverse_matrix_u64(modulus: u64) -> DcmMatrixV1 {
    DcmMatrixV1 {
        a11: 2 % modulus,
        a12: mod_sub_u64(0, 1, modulus),
        a21: mod_sub_u64(0, 1, modulus),
        a22: 1,
    }
}

fn matrix_pow_u64(mut base: DcmMatrixV1, exponent: u64, modulus: u64) -> DcmMatrixV1 {
    let mut result = DcmMatrixV1::identity();
    let mut power = exponent;

    while power > 0 {
        if power & 1 == 1 {
            result = result.multiply(base, modulus);
        }
        base = base.multiply(base, modulus);
        power >>= 1;
    }

    result
}

fn mod_add_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 + rhs as u128) % modulus as u128) as u64
}

fn mod_sub_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 + modulus as u128 - rhs as u128) % modulus as u128) as u64
}

fn mod_mul_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 * rhs as u128) % modulus as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::{
        coordinate_recurrence_next_521_v1, coordinate_recurrence_next_v1,
        derive_trace_commitment_521_v1, fast_forward_dcm_state_521_v1, fast_forward_dcm_state_v1,
        rewind_dcm_state_521_v1, rewind_dcm_state_v1, state_leaf_hash_521_v1, DcmConfig521V1,
        DcmConfigV1, DcmExecution521V1, DcmExecutionV1, DcmInput521V1, DcmInputV1, DcmState521V1,
        DcmStateV1, DcmTraceCommitment521ErrorV1, AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR,
        AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR, FIELD_MODULUS_521_V1,
    };
    use crate::{sha256_bytes, FieldElement521V1, FIELD_ELEMENT_521_BYTE_LEN_V1, HASH_LEN_V1};

    #[test]
    fn u64_fast_forward_matches_materialized_execution() {
        let config = DcmConfigV1 {
            modulus: 97,
            iteration_count: 5,
        };
        let input = DcmInputV1 { x0: 3, y0: 7 };
        let execution = DcmExecutionV1::run(&config, &input).unwrap();

        assert_eq!(
            fast_forward_dcm_state_v1(
                input.initial_state(),
                config.iteration_count,
                config.modulus
            ),
            execution.final_state
        );
    }

    #[test]
    fn u64_inverse_recovers_previous_state() {
        let state = DcmStateV1 { x: 27, y: 44 };
        let next = super::advance_dcm_state_v1(state, 97);

        assert_eq!(rewind_dcm_state_v1(next, 97), state);
    }

    #[test]
    fn u64_coordinate_recurrence_matches_trace_coordinates() {
        let execution = DcmExecutionV1::run(
            &DcmConfigV1 {
                modulus: 97,
                iteration_count: 5,
            },
            &DcmInputV1 { x0: 3, y0: 7 },
        )
        .unwrap();

        assert_eq!(
            coordinate_recurrence_next_v1(execution.states[0].x, execution.states[1].x, 97),
            execution.states[2].x
        );
        assert_eq!(
            coordinate_recurrence_next_v1(execution.states[0].y, execution.states[1].y, 97),
            execution.states[2].y
        );
    }

    #[test]
    fn identical_trace_commitments_match_for_521_bit_execution() {
        let execution = canonical_execution();
        let config = canonical_config();
        let input = canonical_input();

        let first = derive_trace_commitment_521_v1(&config, &input, &execution.states).unwrap();
        let second = derive_trace_commitment_521_v1(&config, &input, &execution.states).unwrap();

        assert_eq!(first, second);
        assert_eq!(execution.trace_commitment, first);
    }

    #[test]
    fn mutating_single_state_changes_521_bit_trace_commitment() {
        let execution = canonical_execution();
        let config = canonical_config();
        let input = canonical_input();
        let mut mutated_states = execution.states.clone();
        mutated_states[1] = DcmState521V1 {
            x: small_value(9),
            y: small_value(9),
        };

        let mutated_commitment =
            derive_trace_commitment_521_v1(&config, &input, &mutated_states).unwrap_err();

        assert_eq!(
            mutated_commitment,
            DcmTraceCommitment521ErrorV1::TransitionMismatch {
                index: 0,
                expected: execution.states[1],
                actual: mutated_states[1],
            }
        );
    }

    #[test]
    fn state_leaf_hash_521_uses_canonical_pair_encoding() {
        let state = DcmState521V1 {
            x: top_bit_value(10),
            y: small_value(1),
        };
        let state_bytes = state.canonical_bytes();

        assert_eq!(state_bytes.len(), FIELD_ELEMENT_521_BYTE_LEN_V1 * 2);

        let mut preimage = Vec::with_capacity(
            AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR.len()
                + 8
                + FIELD_ELEMENT_521_BYTE_LEN_V1 * 2,
        );
        preimage.extend_from_slice(AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR);
        preimage.extend_from_slice(&7u64.to_le_bytes());
        preimage.extend_from_slice(&state_bytes);

        let expected = sha256_bytes(&preimage);
        let actual = state_leaf_hash_521_v1(7, &state);

        assert_eq!(expected, actual);
    }

    #[test]
    fn fast_forward_521_matches_materialized_execution() {
        let config = canonical_config();
        let input = canonical_input();
        let execution = canonical_execution();

        assert_eq!(
            fast_forward_dcm_state_521_v1(input.initial_state(), config.iteration_count),
            execution.final_state
        );
    }

    #[test]
    fn inverse_521_recovers_previous_state() {
        let state = canonical_input().initial_state();
        let next = super::advance_dcm_state_521_v1(state);

        assert_eq!(rewind_dcm_state_521_v1(next), state);
    }

    #[test]
    fn coordinate_recurrence_521_matches_trace_coordinates() {
        let execution = canonical_execution();

        assert_eq!(
            coordinate_recurrence_next_521_v1(execution.states[0].x, execution.states[1].x),
            execution.states[2].x
        );
        assert_eq!(
            coordinate_recurrence_next_521_v1(execution.states[0].y, execution.states[1].y),
            execution.states[2].y
        );
    }

    #[test]
    fn derive_trace_commitment_521_matches_manual_rebuild() {
        let config = canonical_config();
        let input = canonical_input();
        let execution = canonical_execution();
        let expected = manual_trace_commitment(&config, &input, &execution.states);

        assert_eq!(
            derive_trace_commitment_521_v1(&config, &input, &execution.states).unwrap(),
            expected
        );
        assert_eq!(execution.trace_commitment, expected);
    }

    fn canonical_config() -> DcmConfig521V1 {
        DcmConfig521V1 { iteration_count: 2 }
    }

    fn canonical_input() -> DcmInput521V1 {
        DcmInput521V1 {
            x0: max_minus_one(),
            y0: small_value(1),
        }
    }

    fn canonical_execution() -> DcmExecution521V1 {
        DcmExecution521V1::run(&canonical_config(), &canonical_input()).unwrap()
    }

    fn manual_trace_commitment(
        config: &DcmConfig521V1,
        input: &DcmInput521V1,
        states: &[DcmState521V1],
    ) -> [u8; HASH_LEN_V1] {
        let mut preimage = Vec::with_capacity(
            AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR.len()
                + FIELD_MODULUS_521_V1.len()
                + 8 * 2
                + FIELD_ELEMENT_521_BYTE_LEN_V1 * 2
                + HASH_LEN_V1 * states.len(),
        );
        preimage.extend_from_slice(AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR);
        preimage.extend_from_slice(&FIELD_MODULUS_521_V1);
        preimage.extend_from_slice(&config.iteration_count.to_le_bytes());
        preimage.extend_from_slice(&input.x0.to_bytes());
        preimage.extend_from_slice(&input.y0.to_bytes());
        preimage.extend_from_slice(&(states.len() as u64).to_le_bytes());

        for (index, state) in states.iter().enumerate() {
            preimage.extend_from_slice(&state_leaf_hash_521_v1(index as u64, state));
        }

        sha256_bytes(&preimage)
    }

    fn small_value(value: u8) -> FieldElement521V1 {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }

    fn max_minus_one() -> FieldElement521V1 {
        let mut bytes = FIELD_MODULUS_521_V1;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }

    fn top_bit_value(low_byte: u8) -> FieldElement521V1 {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[0] = 0x01;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = low_byte;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }
}
