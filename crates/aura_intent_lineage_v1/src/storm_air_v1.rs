//! Placeholder AIR-facing validation surfaces for the storm lower layer.

use core::fmt;
use std::collections::HashMap;

use crate::{
    build_storm_public_inputs_v1, compute_storm_trace_root, decode_row_bytes, derive_a, derive_b,
    derive_phi_n, derive_psi_n, execute_storm_v1, storm_step, validate_context_bytes_v1,
    FieldElement521V1, FieldElementErrorV1, StormClaim521V1, StormContextErrorV1,
    StormExecutionInputsV1, StormState521V1, StormStateEncodingErrorV1,
    FIELD_ELEMENT_521_BYTE_LEN_V1, HASH_LEN_V1, STORM_CONTEXT_V1_LEN, STORM_SIDE_INPUT_LEN_V1,
    STORM_STATE_521_ROW_BYTE_LEN_V1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormAirPublicInputsV1 {
    pub version: u8,
    pub modulus_id: u8,
    pub iteration_count: u64,
    pub side_a_hash: [u8; 32],
    pub side_b_hash: [u8; 32],
    pub context_hash: [u8; 32],
    pub initial_state: StormState521V1,
    pub final_state: StormState521V1,
    pub trace_root: [u8; 32],
}

pub const STORM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1: usize = 1
    + 1
    + 8
    + HASH_LEN_V1
    + HASH_LEN_V1
    + HASH_LEN_V1
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + HASH_LEN_V1;
pub const STORM_TRACE_STEP_WITNESS_521_CANONICAL_BYTE_LEN_V1: usize = 8
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + STORM_STATE_521_ROW_BYTE_LEN_V1
    + FIELD_ELEMENT_521_BYTE_LEN_V1
    + FIELD_ELEMENT_521_BYTE_LEN_V1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StormTraceWitnessV1 {
    pub public_inputs: StormAirPublicInputsV1,
    pub a: FieldElement521V1,
    pub b: FieldElement521V1,
    pub trace_root: [u8; 32],
    pub trace: Vec<StormState521V1>,
    pub steps: Vec<StormTraceStepWitnessV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormTraceStepWitnessV1 {
    pub step_index: u64,
    pub state: StormState521V1,
    pub next_state: StormState521V1,
    pub phi_n: FieldElement521V1,
    pub psi_n: FieldElement521V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormTraceWitnessEncodingErrorV1 {
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidPublicInputs {
        field: &'static str,
    },
    InvalidState {
        field: &'static str,
        error: StormStateEncodingErrorV1,
    },
    InvalidFieldElement {
        field: &'static str,
        error: FieldElementErrorV1,
    },
    TrailingBytes {
        remaining: usize,
    },
}

impl fmt::Display for StormTraceWitnessEncodingErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid storm witness length for {field}: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidPublicInputs { field } => {
                write!(f, "invalid canonical storm public inputs field: {field}")
            }
            Self::InvalidState { field, error } => {
                write!(f, "invalid storm witness state {field}: {error}")
            }
            Self::InvalidFieldElement { field, error } => {
                write!(f, "invalid storm witness field element {field}: {error}")
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "storm witness decode left {remaining} trailing bytes")
            }
        }
    }
}

impl std::error::Error for StormTraceWitnessEncodingErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormAirValidationErrorV1 {
    InvalidClaim(crate::StormClaimErrorV1),
    InvalidContext(StormContextErrorV1),
    TraceLengthMismatch { expected: u64, actual: u64 },
    StepCountMismatch { expected: u64, actual: u64 },
    InitialStateMismatch {
        expected: StormState521V1,
        actual: StormState521V1,
    },
    RepeatedState {
        first_index: u64,
        second_index: u64,
    },
    StepIndexMismatch { expected: u64, actual: u64 },
    StepStateMismatch {
        index: u64,
        field: &'static str,
    },
    GeometryMismatch {
        field: &'static str,
    },
    ForcingMismatch {
        index: u64,
        field: &'static str,
    },
    PublicInputsMismatch {
        field: &'static str,
    },
    TransitionMismatch {
        index: u64,
        expected: StormState521V1,
        actual: StormState521V1,
    },
    FinalStateMismatch {
        expected: StormState521V1,
        actual: StormState521V1,
    },
    TraceRootMismatch { expected: [u8; 32], actual: [u8; 32] },
}

impl fmt::Display for StormAirValidationErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClaim(error) => write!(f, "invalid storm claim: {error}"),
            Self::InvalidContext(error) => write!(f, "invalid storm AIR context: {error}"),
            Self::TraceLengthMismatch { expected, actual } => write!(
                f,
                "storm trace length mismatch: expected {expected}, got {actual}"
            ),
            Self::StepCountMismatch { expected, actual } => write!(
                f,
                "storm step count mismatch: expected {expected}, got {actual}"
            ),
            Self::InitialStateMismatch { expected, actual } => write!(
                f,
                "storm trace initial state mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::RepeatedState {
                first_index,
                second_index,
            } => write!(
                f,
                "storm trace repeated state detected: first at {first_index}, repeated at {second_index}"
            ),
            Self::StepIndexMismatch { expected, actual } => write!(
                f,
                "storm step index mismatch: expected {expected}, got {actual}"
            ),
            Self::StepStateMismatch { index, field } => {
                write!(f, "storm step state mismatch at step {index}: {field}")
            }
            Self::GeometryMismatch { field } => write!(f, "storm geometry mismatch: {field}"),
            Self::ForcingMismatch { index, field } => {
                write!(f, "storm forcing mismatch at step {index}: {field}")
            }
            Self::PublicInputsMismatch { field } => {
                write!(f, "storm public inputs mismatch: {field}")
            }
            Self::TransitionMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "storm trace transition mismatch at step {index}: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::FinalStateMismatch { expected, actual } => write!(
                f,
                "storm trace final state mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::TraceRootMismatch { .. } => write!(f, "storm trace root mismatch"),
        }
    }
}

impl std::error::Error for StormAirValidationErrorV1 {}

impl StormAirPublicInputsV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STORM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1);
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

pub fn build_storm_air_public_inputs_v1(claim: &StormClaim521V1) -> StormAirPublicInputsV1 {
    let public_inputs = build_storm_public_inputs_v1(claim);
    StormAirPublicInputsV1 {
        version: public_inputs.version,
        modulus_id: public_inputs.modulus_id,
        iteration_count: public_inputs.iteration_count,
        side_a_hash: public_inputs.side_a_hash,
        side_b_hash: public_inputs.side_b_hash,
        context_hash: public_inputs.context_hash,
        initial_state: public_inputs.initial_state,
        final_state: public_inputs.final_state,
        trace_root: public_inputs.trace_root,
    }
}

pub fn build_storm_trace_witness_v1(
    claim: &StormClaim521V1,
) -> Result<StormTraceWitnessV1, StormAirValidationErrorV1> {
    claim.validate().map_err(StormAirValidationErrorV1::InvalidClaim)?;
    validate_context_bytes_v1(&claim.context_bytes_v1)
        .map_err(StormAirValidationErrorV1::InvalidContext)?;

    let inputs = StormExecutionInputsV1 {
        side_a: claim.side_a,
        side_b: claim.side_b,
        context_bytes_v1: claim.context_bytes_v1,
        iteration_count: claim.iteration_count,
    };
    let execution = execute_storm_v1(&inputs);
    let trace_root = compute_storm_trace_root(&execution.trace);
    let a = derive_a(context_bytes(&claim.context_bytes_v1));
    let b = derive_b(context_bytes(&claim.context_bytes_v1));

    let mut steps = Vec::with_capacity(execution.trace.len().saturating_sub(1));
    for (index, pair) in execution.trace.windows(2).enumerate() {
        let step_index = index as u64;
        steps.push(StormTraceStepWitnessV1 {
            step_index,
            state: pair[0],
            next_state: pair[1],
            phi_n: derive_phi_n(
                side_a(&claim.side_a),
                side_b(&claim.side_b),
                context_bytes(&claim.context_bytes_v1),
                step_index,
            ),
            psi_n: derive_psi_n(
                side_a(&claim.side_a),
                side_b(&claim.side_b),
                context_bytes(&claim.context_bytes_v1),
                step_index,
            ),
        });
    }

    Ok(StormTraceWitnessV1 {
        public_inputs: build_storm_air_public_inputs_v1(claim),
        a,
        b,
        trace_root,
        trace: execution.trace,
        steps,
    })
}

pub fn canonical_storm_trace_witness_bytes_v1(witness: &StormTraceWitnessV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        STORM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1
            + FIELD_ELEMENT_521_BYTE_LEN_V1 * 2
            + HASH_LEN_V1
            + 8
            + witness.trace.len() * STORM_STATE_521_ROW_BYTE_LEN_V1
            + 8
            + witness.steps.len() * STORM_TRACE_STEP_WITNESS_521_CANONICAL_BYTE_LEN_V1,
    );
    bytes.extend_from_slice(&witness.public_inputs.canonical_bytes());
    bytes.extend_from_slice(&witness.a.to_bytes());
    bytes.extend_from_slice(&witness.b.to_bytes());
    bytes.extend_from_slice(&witness.trace_root);
    bytes.extend_from_slice(&(witness.trace.len() as u64).to_le_bytes());
    for state in &witness.trace {
        bytes.extend_from_slice(&state.encode_row_bytes());
    }
    bytes.extend_from_slice(&(witness.steps.len() as u64).to_le_bytes());
    for step in &witness.steps {
        bytes.extend_from_slice(&step.step_index.to_le_bytes());
        bytes.extend_from_slice(&step.state.encode_row_bytes());
        bytes.extend_from_slice(&step.next_state.encode_row_bytes());
        bytes.extend_from_slice(&step.phi_n.to_bytes());
        bytes.extend_from_slice(&step.psi_n.to_bytes());
    }
    bytes
}

pub fn decode_storm_trace_witness_bytes_v1(
    bytes: &[u8],
) -> Result<StormTraceWitnessV1, StormTraceWitnessEncodingErrorV1> {
    let mut offset = 0usize;

    let public_inputs =
        decode_storm_air_public_inputs_from_bytes_v1(bytes, &mut offset)?;
    let a = decode_field_element_from_bytes_v1(bytes, &mut offset, "a")?;
    let b = decode_field_element_from_bytes_v1(bytes, &mut offset, "b")?;

    let trace_root = read_fixed_bytes_v1::<HASH_LEN_V1>(bytes, &mut offset, "trace_root")?;

    let trace_len = decode_u64_from_bytes_v1(bytes, &mut offset, "trace_len")? as usize;
    let mut trace = Vec::with_capacity(trace_len);
    for index in 0..trace_len {
        trace.push(
            decode_row_bytes(read_slice_v1(
                bytes,
                &mut offset,
                STORM_STATE_521_ROW_BYTE_LEN_V1,
                "trace_state",
            )?)
            .map_err(|error| StormTraceWitnessEncodingErrorV1::InvalidState {
                field: if index == 0 { "trace_state_0" } else { "trace_state_n" },
                error,
            })?,
        );
    }

    let step_len = decode_u64_from_bytes_v1(bytes, &mut offset, "step_len")? as usize;
    let mut steps = Vec::with_capacity(step_len);
    for _ in 0..step_len {
        let step_index = decode_u64_from_bytes_v1(bytes, &mut offset, "step_index")?;
        let state = decode_row_bytes(read_slice_v1(
            bytes,
            &mut offset,
            STORM_STATE_521_ROW_BYTE_LEN_V1,
            "step_state",
        )?)
        .map_err(|error| StormTraceWitnessEncodingErrorV1::InvalidState {
            field: "step_state",
            error,
        })?;
        let next_state = decode_row_bytes(read_slice_v1(
            bytes,
            &mut offset,
            STORM_STATE_521_ROW_BYTE_LEN_V1,
            "step_next_state",
        )?)
        .map_err(|error| StormTraceWitnessEncodingErrorV1::InvalidState {
            field: "step_next_state",
            error,
        })?;
        let phi_n = decode_field_element_from_bytes_v1(bytes, &mut offset, "phi_n")?;
        let psi_n = decode_field_element_from_bytes_v1(bytes, &mut offset, "psi_n")?;
        steps.push(StormTraceStepWitnessV1 {
            step_index,
            state,
            next_state,
            phi_n,
            psi_n,
        });
    }

    if offset != bytes.len() {
        return Err(StormTraceWitnessEncodingErrorV1::TrailingBytes {
            remaining: bytes.len() - offset,
        });
    }

    Ok(StormTraceWitnessV1 {
        public_inputs,
        a,
        b,
        trace_root,
        trace,
        steps,
    })
}

pub fn validate_trace_against_claim(
    claim: &StormClaim521V1,
    trace: &[StormState521V1],
) -> Result<(), StormAirValidationErrorV1> {
    claim.validate().map_err(StormAirValidationErrorV1::InvalidClaim)?;
    validate_context_bytes_v1(&claim.context_bytes_v1)
        .map_err(StormAirValidationErrorV1::InvalidContext)?;

    let expected_len = claim
        .iteration_count
        .checked_add(1)
        .expect("validated storm iteration count must not overflow");
    if trace.len() as u64 != expected_len {
        return Err(StormAirValidationErrorV1::TraceLengthMismatch {
            expected: expected_len,
            actual: trace.len() as u64,
        });
    }

    if trace[0] != claim.initial_state {
        return Err(StormAirValidationErrorV1::InitialStateMismatch {
            expected: claim.initial_state,
            actual: trace[0],
        });
    }

    let mut seen = HashMap::with_capacity(trace.len());
    for (index, state) in trace.iter().enumerate() {
        let row = state.encode_row_bytes();
        if let Some(first_index) = seen.insert(row, index as u64) {
            return Err(StormAirValidationErrorV1::RepeatedState {
                first_index,
                second_index: index as u64,
            });
        }
    }

    let a = derive_a(context_bytes(&claim.context_bytes_v1));
    let b = derive_b(context_bytes(&claim.context_bytes_v1));

    for (index, pair) in trace.windows(2).enumerate() {
        let expected = storm_step(
            &pair[0],
            &a,
            &b,
            &derive_phi_n(side_a(&claim.side_a), side_b(&claim.side_b), context_bytes(&claim.context_bytes_v1), index as u64),
            &derive_psi_n(side_a(&claim.side_a), side_b(&claim.side_b), context_bytes(&claim.context_bytes_v1), index as u64),
        );
        let actual = pair[1];
        if actual != expected {
            return Err(StormAirValidationErrorV1::TransitionMismatch {
                index: index as u64,
                expected,
                actual,
            });
        }
    }

    let final_state = *trace
        .last()
        .expect("storm trace length check guarantees at least one row");
    if final_state != claim.final_state {
        return Err(StormAirValidationErrorV1::FinalStateMismatch {
            expected: claim.final_state,
            actual: final_state,
        });
    }

    let expected_trace_root = compute_storm_trace_root(trace);
    if expected_trace_root != claim.trace_root {
        return Err(StormAirValidationErrorV1::TraceRootMismatch {
            expected: claim.trace_root,
            actual: expected_trace_root,
        });
    }

    Ok(())
}

pub fn validate_trace_witness_against_claim(
    claim: &StormClaim521V1,
    witness: &StormTraceWitnessV1,
) -> Result<(), StormAirValidationErrorV1> {
    claim.validate().map_err(StormAirValidationErrorV1::InvalidClaim)?;
    validate_context_bytes_v1(&claim.context_bytes_v1)
        .map_err(StormAirValidationErrorV1::InvalidContext)?;

    let expected_public_inputs = build_storm_air_public_inputs_v1(claim);
    if witness.public_inputs != expected_public_inputs {
        return Err(StormAirValidationErrorV1::PublicInputsMismatch {
            field: "public_inputs",
        });
    }

    let expected_a = derive_a(context_bytes(&claim.context_bytes_v1));
    if witness.a != expected_a {
        return Err(StormAirValidationErrorV1::GeometryMismatch { field: "a" });
    }

    let expected_b = derive_b(context_bytes(&claim.context_bytes_v1));
    if witness.b != expected_b {
        return Err(StormAirValidationErrorV1::GeometryMismatch { field: "b" });
    }

    validate_trace_against_claim(claim, &witness.trace)?;

    let expected_trace_root = compute_storm_trace_root(&witness.trace);
    if witness.trace_root != expected_trace_root {
        return Err(StormAirValidationErrorV1::TraceRootMismatch {
            expected: expected_trace_root,
            actual: witness.trace_root,
        });
    }

    let expected_step_count = claim.iteration_count;
    if witness.steps.len() as u64 != expected_step_count {
        return Err(StormAirValidationErrorV1::StepCountMismatch {
            expected: expected_step_count,
            actual: witness.steps.len() as u64,
        });
    }

    for (index, step) in witness.steps.iter().enumerate() {
        let expected_index = index as u64;
        if step.step_index != expected_index {
            return Err(StormAirValidationErrorV1::StepIndexMismatch {
                expected: expected_index,
                actual: step.step_index,
            });
        }
        if step.state != witness.trace[index] {
            return Err(StormAirValidationErrorV1::StepStateMismatch {
                index: expected_index,
                field: "state",
            });
        }
        if step.next_state != witness.trace[index + 1] {
            return Err(StormAirValidationErrorV1::StepStateMismatch {
                index: expected_index,
                field: "next_state",
            });
        }

        let expected_phi = derive_phi_n(
            side_a(&claim.side_a),
            side_b(&claim.side_b),
            context_bytes(&claim.context_bytes_v1),
            expected_index,
        );
        if step.phi_n != expected_phi {
            return Err(StormAirValidationErrorV1::ForcingMismatch {
                index: expected_index,
                field: "phi_n",
            });
        }

        let expected_psi = derive_psi_n(
            side_a(&claim.side_a),
            side_b(&claim.side_b),
            context_bytes(&claim.context_bytes_v1),
            expected_index,
        );
        if step.psi_n != expected_psi {
            return Err(StormAirValidationErrorV1::ForcingMismatch {
                index: expected_index,
                field: "psi_n",
            });
        }

        let expected_next = storm_step(&step.state, &witness.a, &witness.b, &step.phi_n, &step.psi_n);
        if step.next_state != expected_next {
            return Err(StormAirValidationErrorV1::TransitionMismatch {
                index: expected_index,
                expected: expected_next,
                actual: step.next_state,
            });
        }
    }

    Ok(())
}

fn side_a(bytes: &[u8; STORM_SIDE_INPUT_LEN_V1]) -> &[u8; STORM_SIDE_INPUT_LEN_V1] {
    bytes
}

fn side_b(bytes: &[u8; STORM_SIDE_INPUT_LEN_V1]) -> &[u8; STORM_SIDE_INPUT_LEN_V1] {
    bytes
}

fn context_bytes(bytes: &[u8; STORM_CONTEXT_V1_LEN]) -> &[u8; STORM_CONTEXT_V1_LEN] {
    bytes
}

fn decode_storm_air_public_inputs_from_bytes_v1(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<StormAirPublicInputsV1, StormTraceWitnessEncodingErrorV1> {
    let version = *read_slice_v1(bytes, offset, 1, "public_inputs.version")?
        .first()
        .ok_or(StormTraceWitnessEncodingErrorV1::InvalidPublicInputs {
            field: "version",
        })?;
    let modulus_id = *read_slice_v1(bytes, offset, 1, "public_inputs.modulus_id")?
        .first()
        .ok_or(StormTraceWitnessEncodingErrorV1::InvalidPublicInputs {
            field: "modulus_id",
        })?;
    let iteration_count = decode_u64_from_bytes_v1(bytes, offset, "public_inputs.iteration_count")?;
    let side_a_hash = read_fixed_bytes_v1::<HASH_LEN_V1>(bytes, offset, "public_inputs.side_a_hash")?;
    let side_b_hash = read_fixed_bytes_v1::<HASH_LEN_V1>(bytes, offset, "public_inputs.side_b_hash")?;
    let context_hash = read_fixed_bytes_v1::<HASH_LEN_V1>(bytes, offset, "public_inputs.context_hash")?;
    let initial_state = decode_row_bytes(read_slice_v1(
        bytes,
        offset,
        STORM_STATE_521_ROW_BYTE_LEN_V1,
        "public_inputs.initial_state",
    )?)
    .map_err(|error| StormTraceWitnessEncodingErrorV1::InvalidState {
        field: "public_inputs.initial_state",
        error,
    })?;
    let final_state = decode_row_bytes(read_slice_v1(
        bytes,
        offset,
        STORM_STATE_521_ROW_BYTE_LEN_V1,
        "public_inputs.final_state",
    )?)
    .map_err(|error| StormTraceWitnessEncodingErrorV1::InvalidState {
        field: "public_inputs.final_state",
        error,
    })?;
    let trace_root = read_fixed_bytes_v1::<HASH_LEN_V1>(bytes, offset, "public_inputs.trace_root")?;

    Ok(StormAirPublicInputsV1 {
        version,
        modulus_id,
        iteration_count,
        side_a_hash,
        side_b_hash,
        context_hash,
        initial_state,
        final_state,
        trace_root,
    })
}

fn decode_field_element_from_bytes_v1(
    bytes: &[u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<FieldElement521V1, StormTraceWitnessEncodingErrorV1> {
    let raw = read_fixed_bytes_v1::<FIELD_ELEMENT_521_BYTE_LEN_V1>(bytes, offset, field)?;
    FieldElement521V1::from_bytes(raw).map_err(|error| {
        StormTraceWitnessEncodingErrorV1::InvalidFieldElement { field, error }
    })
}

fn decode_u64_from_bytes_v1(
    bytes: &[u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<u64, StormTraceWitnessEncodingErrorV1> {
    let raw = read_fixed_bytes_v1::<8>(bytes, offset, field)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_fixed_bytes_v1<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<[u8; N], StormTraceWitnessEncodingErrorV1> {
    let slice = read_slice_v1(bytes, offset, N, field)?;
    let mut output = [0u8; N];
    output.copy_from_slice(slice);
    Ok(output)
}

fn read_slice_v1<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], StormTraceWitnessEncodingErrorV1> {
    if bytes.len().saturating_sub(*offset) < len {
        return Err(StormTraceWitnessEncodingErrorV1::InvalidLength {
            field,
            expected: len,
            actual: bytes.len().saturating_sub(*offset),
        });
    }
    let start = *offset;
    let end = start + len;
    *offset = end;
    Ok(&bytes[start..end])
}

#[cfg(test)]
mod tests {
    use crate::{
        build_storm_claim_v1, execute_storm_v1, StormContextV1, StormExecutionInputsV1,
        STORM_CONTEXT_V1_VERSION,
    };

    use super::{
        build_storm_air_public_inputs_v1, build_storm_trace_witness_v1,
        canonical_storm_trace_witness_bytes_v1, decode_storm_trace_witness_bytes_v1,
        validate_trace_against_claim, validate_trace_witness_against_claim,
        StormAirValidationErrorV1,
    };

    fn sample_inputs() -> StormExecutionInputsV1 {
        StormExecutionInputsV1 {
            side_a: [0x91; 110],
            side_b: [0x19; 110],
            context_bytes_v1: StormContextV1 {
                context_version: STORM_CONTEXT_V1_VERSION,
                network_id: [0x10; 32],
                intent_hash: [0x20; 32],
                freshness_nonce: [0x30; 32],
                valid_from: 1,
                valid_until: 2,
                controller_id: [0x40; 32],
                route_tag: [0x50; 32],
            }
            .to_bytes(),
            iteration_count: 4,
        }
    }

    #[test]
    fn trace_validator_accepts_canonical_execution() {
        let inputs = sample_inputs();
        let execution = execute_storm_v1(&inputs);
        let claim = build_storm_claim_v1(&inputs, [0u8; 32], [0u8; 32]);

        validate_trace_against_claim(&claim, &execution.trace).unwrap();
    }

    #[test]
    fn trace_witness_builder_produces_air_ready_material() {
        let inputs = sample_inputs();
        let claim = build_storm_claim_v1(&inputs, [0u8; 32], [0u8; 32]);
        let witness = build_storm_trace_witness_v1(&claim).unwrap();

        assert_eq!(witness.public_inputs, build_storm_air_public_inputs_v1(&claim));
        assert_eq!(witness.trace_root, claim.trace_root);
        assert_eq!(witness.trace.len(), 5);
        assert_eq!(witness.steps.len(), 4);
        validate_trace_witness_against_claim(&claim, &witness).unwrap();
    }

    #[test]
    fn trace_witness_validator_rejects_tampered_forcing() {
        let inputs = sample_inputs();
        let claim = build_storm_claim_v1(&inputs, [0u8; 32], [0u8; 32]);
        let mut witness = build_storm_trace_witness_v1(&claim).unwrap();
        witness.steps[0].phi_n = witness.steps[1].phi_n;

        let error = validate_trace_witness_against_claim(&claim, &witness).unwrap_err();
        assert_eq!(
            error,
            StormAirValidationErrorV1::ForcingMismatch {
                index: 0,
                field: "phi_n",
            }
        );
    }

    #[test]
    fn trace_witness_bytes_round_trip() {
        let inputs = sample_inputs();
        let claim = build_storm_claim_v1(&inputs, [0u8; 32], [0u8; 32]);
        let witness = build_storm_trace_witness_v1(&claim).unwrap();
        let encoded = canonical_storm_trace_witness_bytes_v1(&witness);
        let decoded = decode_storm_trace_witness_bytes_v1(&encoded).unwrap();

        assert_eq!(decoded, witness);
    }

    #[test]
    fn trace_validator_rejects_repeated_states() {
        let inputs = sample_inputs();
        let claim = build_storm_claim_v1(&inputs, [0u8; 32], [0u8; 32]);
        let mut trace = execute_storm_v1(&inputs).trace;
        trace[4] = trace[1];

        let error = validate_trace_against_claim(&claim, &trace).unwrap_err();
        assert_eq!(
            error,
            StormAirValidationErrorV1::RepeatedState {
                first_index: 1,
                second_index: 4,
            }
        );
    }
}
