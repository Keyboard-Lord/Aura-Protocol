// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Legacy AIR-style recurrence evaluator for the 521-bit cat-map path.
//!
//! This module defines only:
//! - a two-column pair-state trace object
//! - explicit public inputs `(initial_state, iteration_count, final_state)`
//! - AIR-style evaluation frames `(current_row, next_row)`
//! - direct forward transition residuals
//! - deterministic boundary and transition evaluation
//!
//! Storm V1 is now the active lower-layer proof authority. This file is retained for
//! explicit legacy cat-map compatibility surfaces only.
//!
//! It does not define:
//! - prover logic
//! - verifier logic
//! - polynomial commitments
//! - FRI
//! - proof bytes

use core::fmt;

use crate::{
    DcmClaim521V1, DcmState521V1, FieldElement521V1, DCM_STATE_521_CANONICAL_BYTE_LEN_V1,
    HASH_LEN_V1,
};

pub const DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1: usize =
    DCM_STATE_521_CANONICAL_BYTE_LEN_V1 * 2 + 8 + HASH_LEN_V1;
pub const DCM_AIR_TRACE_WIDTH_V1: u8 = 2;
pub const DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmAirTraceV1 {
    rows: Vec<DcmState521V1>,
}

impl DcmAirTraceV1 {
    pub fn new(rows: Vec<DcmState521V1>) -> Self {
        Self { rows }
    }

    pub(crate) fn rows(&self) -> &[DcmState521V1] {
        &self.rows
    }

    pub fn row_count(&self) -> u64 {
        self.rows.len() as u64
    }

    pub fn row(&self, index: usize) -> Option<DcmState521V1> {
        self.rows.get(index).copied()
    }

    pub fn frame(&self, row_index: usize) -> Option<DcmAirFrameV1> {
        let next_index = row_index.checked_add(1)?;
        Some(DcmAirFrameV1 {
            current_row: self.row(row_index)?,
            next_row: self.row(next_index)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirPublicInputsV1 {
    pub initial_state: DcmState521V1,
    pub iteration_count: u64,
    pub final_state: DcmState521V1,
    pub commitment_root: [u8; HASH_LEN_V1],
}

impl DcmAirPublicInputsV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1);
        bytes.extend_from_slice(&self.initial_state.canonical_bytes());
        bytes.extend_from_slice(&self.iteration_count.to_le_bytes());
        bytes.extend_from_slice(&self.final_state.canonical_bytes());
        bytes.extend_from_slice(&self.commitment_root);
        bytes
    }
}

pub fn dcm_air_public_inputs_from_claim_521_v1(claim: &DcmClaim521V1) -> DcmAirPublicInputsV1 {
    DcmAirPublicInputsV1 {
        initial_state: claim.initial_state,
        iteration_count: claim.config.iteration_count,
        final_state: claim.final_state,
        commitment_root: claim.commitment_root,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirFrameV1 {
    pub current_row: DcmState521V1,
    pub next_row: DcmState521V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirTransitionConstraintEvaluationV1 {
    pub x_transition_residual: FieldElement521V1,
    pub y_transition_residual: FieldElement521V1,
}

impl DcmAirTransitionConstraintEvaluationV1 {
    pub fn is_satisfied(&self) -> bool {
        self.x_transition_residual.is_zero() && self.y_transition_residual.is_zero()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirEvaluationSummaryV1 {
    pub row_count: u64,
    pub checked_transition_count: u64,
    pub first_row: DcmState521V1,
    pub final_row: DcmState521V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirEvaluationResultV1 {
    Accept(DcmAirEvaluationSummaryV1),
    Reject(DcmAirErrorV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirErrorV1 {
    EmptyTrace,
    RowCountMismatch {
        expected: u64,
        actual: u64,
    },
    FirstRowMismatch {
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    FinalRowMismatch {
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    TransitionConstraintViolation {
        row_index: u64,
        expected: DcmState521V1,
        actual: DcmState521V1,
        x_transition_residual: FieldElement521V1,
        y_transition_residual: FieldElement521V1,
    },
    IterationCountMismatch {
        expected: u64,
        actual: u64,
    },
    MissingRequiredValue {
        field: &'static str,
    },
}

impl fmt::Display for DcmAirErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "trace must not be empty"),
            Self::RowCountMismatch { expected, actual } => {
                write!(f, "row count mismatch: expected {expected}, got {actual}")
            }
            Self::FirstRowMismatch { .. } => write!(f, "first row does not match initial_state"),
            Self::FinalRowMismatch { .. } => write!(f, "final row does not match final_state"),
            Self::TransitionConstraintViolation { row_index, .. } => {
                write!(f, "transition constraint violation at row {row_index}")
            }
            Self::IterationCountMismatch { expected, actual } => {
                write!(
                    f,
                    "iteration count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MissingRequiredValue { field } => {
                write!(f, "missing required value: {field}")
            }
        }
    }
}

impl std::error::Error for DcmAirErrorV1 {}

pub fn canonical_dcm_air_trace_bytes_v1(trace: &DcmAirTraceV1) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(8 + trace.rows().len() * DCM_STATE_521_CANONICAL_BYTE_LEN_V1);
    bytes.extend_from_slice(&trace.row_count().to_le_bytes());

    for row in trace.rows() {
        bytes.extend_from_slice(&row.canonical_bytes());
    }

    bytes
}

pub fn evaluate_dcm_air_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
) -> DcmAirEvaluationResultV1 {
    match validate_dcm_air_v1(public_inputs, trace) {
        Ok(summary) => DcmAirEvaluationResultV1::Accept(summary),
        Err(error) => DcmAirEvaluationResultV1::Reject(error),
    }
}

pub fn evaluate_dcm_air_transition_constraints_v1(
    frame: &DcmAirFrameV1,
) -> DcmAirTransitionConstraintEvaluationV1 {
    let expected_x_next = frame.current_row.x.add_mod(&frame.current_row.y);
    let expected_y_next = frame
        .current_row
        .x
        .add_mod(&frame.current_row.y.add_mod(&frame.current_row.y));

    DcmAirTransitionConstraintEvaluationV1 {
        x_transition_residual: frame.next_row.x.sub_mod(&expected_x_next),
        y_transition_residual: frame.next_row.y.sub_mod(&expected_y_next),
    }
}

pub fn expected_next_dcm_air_row_v1(frame: &DcmAirFrameV1) -> DcmState521V1 {
    DcmState521V1 {
        x: frame.current_row.x.add_mod(&frame.current_row.y),
        y: frame
            .current_row
            .x
            .add_mod(&frame.current_row.y.add_mod(&frame.current_row.y)),
    }
}

pub fn validate_dcm_air_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
) -> Result<DcmAirEvaluationSummaryV1, DcmAirErrorV1> {
    let actual_row_count = trace.row_count();
    if actual_row_count == 0 {
        return Err(DcmAirErrorV1::EmptyTrace);
    }

    let expected_row_count = public_inputs.iteration_count.checked_add(1).ok_or(
        DcmAirErrorV1::IterationCountMismatch {
            expected: public_inputs.iteration_count,
            actual: actual_row_count.saturating_sub(1),
        },
    )?;
    if actual_row_count != expected_row_count {
        return Err(DcmAirErrorV1::RowCountMismatch {
            expected: expected_row_count,
            actual: actual_row_count,
        });
    }

    let actual_iteration_count = actual_row_count - 1;
    if actual_iteration_count != public_inputs.iteration_count {
        return Err(DcmAirErrorV1::IterationCountMismatch {
            expected: public_inputs.iteration_count,
            actual: actual_iteration_count,
        });
    }

    let first_row = trace
        .row(0)
        .ok_or(DcmAirErrorV1::MissingRequiredValue { field: "trace[0]" })?;
    if first_row != public_inputs.initial_state {
        return Err(DcmAirErrorV1::FirstRowMismatch {
            expected: public_inputs.initial_state,
            actual: first_row,
        });
    }

    let final_row = trace
        .rows
        .last()
        .copied()
        .ok_or(DcmAirErrorV1::MissingRequiredValue {
            field: "trace[last]",
        })?;
    if final_row != public_inputs.final_state {
        return Err(DcmAirErrorV1::FinalRowMismatch {
            expected: public_inputs.final_state,
            actual: final_row,
        });
    }

    for row_index in 0..(actual_row_count as usize).saturating_sub(1) {
        let frame = trace
            .frame(row_index)
            .ok_or(DcmAirErrorV1::MissingRequiredValue {
                field: "trace[row_index,row_index+1]",
            })?;
        let constraint_evaluation = evaluate_dcm_air_transition_constraints_v1(&frame);
        if !constraint_evaluation.is_satisfied() {
            return Err(DcmAirErrorV1::TransitionConstraintViolation {
                row_index: row_index as u64,
                expected: expected_next_dcm_air_row_v1(&frame),
                actual: frame.next_row,
                x_transition_residual: constraint_evaluation.x_transition_residual,
                y_transition_residual: constraint_evaluation.y_transition_residual,
            });
        }
    }

    Ok(DcmAirEvaluationSummaryV1 {
        row_count: actual_row_count,
        checked_transition_count: actual_iteration_count,
        first_row,
        final_row,
    })
}
