// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Minimal prover-facing adapter for the 521-bit cat-map AIR evaluator.
//!
//! This module packages AIR-shaped recurrence inputs only.
//! It is:
//! - not a proof
//! - not a verifier protocol
//! - not final wire format

use core::fmt;

use crate::{
    canonical_dcm_air_trace_bytes_v1, sha256_domain_separated, validate_dcm_air_v1, DcmAirErrorV1,
    DcmAirEvaluationSummaryV1, DcmAirPublicInputsV1, DcmAirTraceV1,
    DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, HASH_LEN_V1,
};

pub const DCM_AIR_ADAPTER_PACKAGING_VERSION_V1: u8 = 1;
pub const AURA_DCM_AIR_V1_TRACE_DIGEST_DOMAIN_SEPARATOR: &[u8] = b"AURA_DCM_AIR_V1_TRACE_DIGEST";
pub const AURA_DCM_AIR_V1_SESSION_ID_DOMAIN_SEPARATOR: &[u8] = b"AURA_DCM_AIR_V1_SESSION_ID";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirProofSessionIdV1 {
    bytes: [u8; HASH_LEN_V1],
}

impl DcmAirProofSessionIdV1 {
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN_V1] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirProofSessionMetadataV1 {
    packaging_version: u8,
    trace_width: u8,
    row_count: u64,
    checked_transition_count: u64,
    transition_constraint_count: u8,
}

impl DcmAirProofSessionMetadataV1 {
    pub const fn packaging_version(&self) -> u8 {
        self.packaging_version
    }

    pub const fn trace_width(&self) -> u8 {
        self.trace_width
    }

    pub const fn row_count(&self) -> u64 {
        self.row_count
    }

    pub const fn checked_transition_count(&self) -> u64 {
        self.checked_transition_count
    }

    pub const fn transition_constraint_count(&self) -> u8 {
        self.transition_constraint_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverInputV1 {
    // This is a future-prover handoff bundle only. It is not a proof and not final wire format.
    packaging_version: u8,
    trace_width: u8,
    trace: DcmAirTraceV1,
    public_inputs: DcmAirPublicInputsV1,
    evaluation_summary: DcmAirEvaluationSummaryV1,
    transition_constraint_count: u8,
    trace_digest: [u8; HASH_LEN_V1],
}

impl ProverInputV1 {
    pub const fn packaging_version(&self) -> u8 {
        self.packaging_version
    }

    pub const fn trace_width(&self) -> u8 {
        self.trace_width
    }

    pub const fn trace(&self) -> &DcmAirTraceV1 {
        &self.trace
    }

    pub const fn public_inputs(&self) -> &DcmAirPublicInputsV1 {
        &self.public_inputs
    }

    pub const fn evaluation_summary(&self) -> &DcmAirEvaluationSummaryV1 {
        &self.evaluation_summary
    }

    pub const fn transition_constraint_count(&self) -> u8 {
        self.transition_constraint_count
    }

    pub const fn trace_digest(&self) -> &[u8; HASH_LEN_V1] {
        &self.trace_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierInputV1 {
    // This is a future-verifier handoff bundle only. It is not a verifier protocol and not final
    // wire format.
    packaging_version: u8,
    trace_width: u8,
    public_inputs: DcmAirPublicInputsV1,
    row_count: u64,
    checked_transition_count: u64,
    transition_constraint_count: u8,
    trace_digest: [u8; HASH_LEN_V1],
}

impl VerifierInputV1 {
    pub const fn packaging_version(&self) -> u8 {
        self.packaging_version
    }

    pub const fn trace_width(&self) -> u8 {
        self.trace_width
    }

    pub const fn public_inputs(&self) -> &DcmAirPublicInputsV1 {
        &self.public_inputs
    }

    pub const fn row_count(&self) -> u64 {
        self.row_count
    }

    pub const fn checked_transition_count(&self) -> u64 {
        self.checked_transition_count
    }

    pub const fn transition_constraint_count(&self) -> u8 {
        self.transition_constraint_count
    }

    pub const fn trace_digest(&self) -> &[u8; HASH_LEN_V1] {
        &self.trace_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmAirProofSessionV1 {
    session_id: DcmAirProofSessionIdV1,
    session_metadata: DcmAirProofSessionMetadataV1,
    prover_input: ProverInputV1,
    verifier_input: VerifierInputV1,
}

impl DcmAirProofSessionV1 {
    pub const fn session_id(&self) -> &DcmAirProofSessionIdV1 {
        &self.session_id
    }

    pub const fn session_metadata(&self) -> &DcmAirProofSessionMetadataV1 {
        &self.session_metadata
    }

    pub const fn prover_input(&self) -> &ProverInputV1 {
        &self.prover_input
    }

    pub const fn verifier_input(&self) -> &VerifierInputV1 {
        &self.verifier_input
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirAdapterErrorV1 {
    AirEvaluationFailed(DcmAirErrorV1),
    PackagingInvariantViolation { field: &'static str },
}

impl fmt::Display for DcmAirAdapterErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AirEvaluationFailed(error) => write!(f, "air evaluation failed: {error}"),
            Self::PackagingInvariantViolation { field } => {
                write!(f, "packaging invariant violation: {field}")
            }
        }
    }
}

impl std::error::Error for DcmAirAdapterErrorV1 {}

pub fn package_dcm_air_proof_session_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
) -> Result<DcmAirProofSessionV1, DcmAirAdapterErrorV1> {
    let evaluation_summary = validate_dcm_air_v1(public_inputs, trace)
        .map_err(DcmAirAdapterErrorV1::AirEvaluationFailed)?;
    validate_packaging_invariants_v1(public_inputs, trace, &evaluation_summary)?;
    let trace_digest = derive_dcm_air_trace_digest_v1(trace);
    let session_metadata = DcmAirProofSessionMetadataV1 {
        packaging_version: DCM_AIR_ADAPTER_PACKAGING_VERSION_V1,
        trace_width: DCM_AIR_TRACE_WIDTH_V1,
        row_count: evaluation_summary.row_count,
        checked_transition_count: evaluation_summary.checked_transition_count,
        transition_constraint_count: DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1,
    };
    let prover_input = ProverInputV1 {
        packaging_version: DCM_AIR_ADAPTER_PACKAGING_VERSION_V1,
        trace_width: DCM_AIR_TRACE_WIDTH_V1,
        trace: trace.clone(),
        public_inputs: *public_inputs,
        evaluation_summary,
        transition_constraint_count: DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1,
        trace_digest,
    };
    let verifier_input = VerifierInputV1 {
        packaging_version: DCM_AIR_ADAPTER_PACKAGING_VERSION_V1,
        trace_width: DCM_AIR_TRACE_WIDTH_V1,
        public_inputs: *public_inputs,
        row_count: evaluation_summary.row_count,
        checked_transition_count: evaluation_summary.checked_transition_count,
        transition_constraint_count: DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1,
        trace_digest,
    };
    let session_id = DcmAirProofSessionIdV1 {
        bytes: derive_dcm_air_session_id_v1(&verifier_input, &session_metadata),
    };

    Ok(DcmAirProofSessionV1 {
        session_id,
        session_metadata,
        prover_input,
        verifier_input,
    })
}

fn validate_packaging_invariants_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
    evaluation_summary: &DcmAirEvaluationSummaryV1,
) -> Result<(), DcmAirAdapterErrorV1> {
    if DCM_AIR_TRACE_WIDTH_V1 != 2 {
        return Err(DcmAirAdapterErrorV1::PackagingInvariantViolation {
            field: "trace_width",
        });
    }

    if DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1 != 2 {
        return Err(DcmAirAdapterErrorV1::PackagingInvariantViolation {
            field: "transition_constraint_count",
        });
    }

    if evaluation_summary.row_count != trace.row_count() {
        return Err(DcmAirAdapterErrorV1::PackagingInvariantViolation { field: "row_count" });
    }

    if evaluation_summary.checked_transition_count != public_inputs.iteration_count {
        return Err(DcmAirAdapterErrorV1::PackagingInvariantViolation {
            field: "checked_transition_count",
        });
    }

    let first_row = trace
        .row(0)
        .ok_or(DcmAirAdapterErrorV1::PackagingInvariantViolation { field: "trace[0]" })?;
    if evaluation_summary.first_row != public_inputs.initial_state
        || evaluation_summary.first_row != first_row
    {
        return Err(DcmAirAdapterErrorV1::PackagingInvariantViolation { field: "first_row" });
    }

    let final_row =
        trace
            .rows()
            .last()
            .copied()
            .ok_or(DcmAirAdapterErrorV1::PackagingInvariantViolation {
                field: "trace[last]",
            })?;
    if evaluation_summary.final_row != public_inputs.final_state
        || evaluation_summary.final_row != final_row
    {
        return Err(DcmAirAdapterErrorV1::PackagingInvariantViolation { field: "final_row" });
    }

    Ok(())
}

fn derive_dcm_air_trace_digest_v1(trace: &DcmAirTraceV1) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_V1_TRACE_DIGEST_DOMAIN_SEPARATOR,
        &canonical_dcm_air_trace_bytes_v1(trace),
    )
}

fn derive_dcm_air_session_id_v1(
    verifier_input: &VerifierInputV1,
    session_metadata: &DcmAirProofSessionMetadataV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_V1_SESSION_ID_DOMAIN_SEPARATOR,
        &canonical_session_id_payload_v1(verifier_input, session_metadata),
    )
}

fn canonical_session_id_payload_v1(
    verifier_input: &VerifierInputV1,
    session_metadata: &DcmAirProofSessionMetadataV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 1
            + 8
            + 8
            + 1
            + DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1
            + 1
            + 8
            + 8
            + 1
            + HASH_LEN_V1,
    );
    bytes.push(session_metadata.packaging_version);
    bytes.push(session_metadata.trace_width);
    bytes.extend_from_slice(&session_metadata.row_count.to_le_bytes());
    bytes.extend_from_slice(&session_metadata.checked_transition_count.to_le_bytes());
    bytes.push(session_metadata.transition_constraint_count);
    bytes.extend_from_slice(&verifier_input.public_inputs.canonical_bytes());
    bytes.push(verifier_input.trace_width);
    bytes.extend_from_slice(&verifier_input.row_count.to_le_bytes());
    bytes.extend_from_slice(&verifier_input.checked_transition_count.to_le_bytes());
    bytes.push(verifier_input.transition_constraint_count);
    bytes.extend_from_slice(&verifier_input.trace_digest);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_session_id_payload_v1, package_dcm_air_proof_session_v1,
        validate_packaging_invariants_v1, DcmAirAdapterErrorV1, DcmAirEvaluationSummaryV1,
    };
    use crate::{
        DcmAirPublicInputsV1, DcmAirTraceV1, DcmConfig521V1, DcmExecution521V1, DcmInput521V1,
        FieldElement521V1, DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1, DCM_AIR_TRACE_WIDTH_V1,
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, FIELD_ELEMENT_521_BYTE_LEN_V1,
        FIELD_MODULUS_521_V1, HASH_LEN_V1,
    };

    #[test]
    fn packaging_invariants_reject_summary_row_count_mismatch() {
        let trace = canonical_trace();
        let public_inputs = canonical_public_inputs();
        let invalid_summary = DcmAirEvaluationSummaryV1 {
            row_count: 4,
            checked_transition_count: 2,
            first_row: canonical_public_inputs().initial_state,
            final_row: canonical_public_inputs().final_state,
        };

        assert_eq!(
            validate_packaging_invariants_v1(&public_inputs, &trace, &invalid_summary),
            Err(DcmAirAdapterErrorV1::PackagingInvariantViolation { field: "row_count" })
        );
    }

    #[test]
    fn verifier_visible_payload_is_fixed_width_and_trace_free() {
        let short_session =
            package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace())
                .unwrap();
        let long_session =
            package_dcm_air_proof_session_v1(&alternate_public_inputs(), &alternate_trace())
                .unwrap();

        let short_payload = canonical_session_id_payload_v1(
            short_session.verifier_input(),
            short_session.session_metadata(),
        );
        let long_payload = canonical_session_id_payload_v1(
            long_session.verifier_input(),
            long_session.session_metadata(),
        );
        let expected_payload_len = 1
            + 1
            + 8
            + 8
            + 1
            + DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1
            + 1
            + 8
            + 8
            + 1
            + HASH_LEN_V1;

        assert_eq!(
            short_session.session_metadata().trace_width(),
            DCM_AIR_TRACE_WIDTH_V1
        );
        assert_eq!(
            short_session
                .session_metadata()
                .transition_constraint_count(),
            DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
        );
        assert_eq!(
            short_session.verifier_input().trace_width(),
            DCM_AIR_TRACE_WIDTH_V1
        );
        assert_eq!(
            short_session.verifier_input().transition_constraint_count(),
            DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
        );
        assert_eq!(short_payload.len(), expected_payload_len);
        assert_eq!(long_payload.len(), expected_payload_len);
    }

    fn canonical_trace() -> DcmAirTraceV1 {
        DcmAirTraceV1::new(canonical_execution().states)
    }

    fn canonical_execution() -> DcmExecution521V1 {
        DcmExecution521V1::run(
            &DcmConfig521V1 { iteration_count: 2 },
            &DcmInput521V1 {
                x0: pinned_x0(),
                y0: small_value(1),
            },
        )
        .unwrap()
    }

    fn canonical_public_inputs() -> DcmAirPublicInputsV1 {
        let config = DcmConfig521V1 { iteration_count: 2 };
        let input = DcmInput521V1 {
            x0: pinned_x0(),
            y0: small_value(1),
        };
        let execution = canonical_execution();
        crate::dcm_air_public_inputs_from_claim_521_v1(&crate::build_dcm_claim_521_v1(
            &config, &input, &execution,
        ))
    }

    fn alternate_trace() -> DcmAirTraceV1 {
        DcmAirTraceV1::new(
            DcmExecution521V1::run(
                &DcmConfig521V1 { iteration_count: 3 },
                &DcmInput521V1 {
                    x0: zero(),
                    y0: small_value(1),
                },
            )
            .unwrap()
            .states,
        )
    }

    fn alternate_public_inputs() -> DcmAirPublicInputsV1 {
        let config = DcmConfig521V1 { iteration_count: 3 };
        let input = DcmInput521V1 {
            x0: zero(),
            y0: small_value(1),
        };
        let execution = DcmExecution521V1::run(&config, &input).unwrap();
        crate::dcm_air_public_inputs_from_claim_521_v1(&crate::build_dcm_claim_521_v1(
            &config, &input, &execution,
        ))
    }

    fn pinned_x0() -> FieldElement521V1 {
        let mut bytes = FIELD_MODULUS_521_V1;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }

    fn zero() -> FieldElement521V1 {
        FieldElement521V1::zero()
    }

    fn small_value(value: u8) -> FieldElement521V1 {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }
}
