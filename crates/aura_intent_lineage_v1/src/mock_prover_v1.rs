// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Deterministic mock proving skeleton for the 521-bit cat-map AIR binding contract.
//! This module does not implement a cryptographic proof system.

use core::fmt;

use crate::{
    package_dcm_air_proof_session_v1, sha256_domain_separated, validate_dcm_air_v1,
    DcmAirAdapterErrorV1, DcmAirErrorV1, DcmAirProofSessionV1, DcmAirPublicInputsV1, DcmAirTraceV1,
    LowerHex32, VerifierInputV1, AURA_DCM_AIR_V1_SESSION_ID_DOMAIN_SEPARATOR,
    DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1, HASH_LEN_V1,
};

pub const DCM_AIR_MOCK_PROOF_VERSION_V1: u8 = 1;
pub const AURA_DCM_AIR_MOCK_PROOF_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_AIR_MOCK_PROOF_V1_PUBLIC_INPUTS";
pub const AURA_DCM_AIR_MOCK_PROOF_V1_CONSTRAINT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_AIR_MOCK_PROOF_V1_CONSTRAINTS";
pub const AURA_DCM_AIR_MOCK_PROOF_V1_PLACEHOLDER_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_AIR_MOCK_PROOF_V1_PLACEHOLDER";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirMockVerifierBindingsV1 {
    // These are verifier-visible adapter bindings only. They are not witness material.
    pub packaging_version: u8,
    pub trace_width: u8,
    pub public_inputs: DcmAirPublicInputsV1,
    pub row_count: u64,
    pub checked_transition_count: u64,
    pub transition_constraint_count: u8,
    pub trace_digest: [u8; HASH_LEN_V1],
}

impl From<&VerifierInputV1> for DcmAirMockVerifierBindingsV1 {
    fn from(value: &VerifierInputV1) -> Self {
        Self {
            packaging_version: value.packaging_version(),
            trace_width: value.trace_width(),
            public_inputs: *value.public_inputs(),
            row_count: value.row_count(),
            checked_transition_count: value.checked_transition_count(),
            transition_constraint_count: value.transition_constraint_count(),
            trace_digest: *value.trace_digest(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirMockProofArtifactV1 {
    // This is a deterministic placeholder binding artifact only.
    // It is not a cryptographic proof and does not claim soundness.
    pub proof_version: u8,
    pub bound_public_input_digest: [u8; HASH_LEN_V1],
    pub bound_constraint_digest: [u8; HASH_LEN_V1],
    pub bound_session_id: [u8; HASH_LEN_V1],
    pub proof_placeholder_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirMockProverOutputV1 {
    pub verifier_bindings: DcmAirMockVerifierBindingsV1,
    pub mock_proof_artifact: DcmAirMockProofArtifactV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirMockProverErrorV1 {
    AirEvaluationFailed(DcmAirErrorV1),
    AdapterPackagingFailed(DcmAirAdapterErrorV1),
    SessionBindingMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for DcmAirMockProverErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AirEvaluationFailed(error) => write!(f, "air evaluation failed: {error}"),
            Self::AdapterPackagingFailed(error) => write!(f, "adapter packaging failed: {error}"),
            Self::SessionBindingMismatch { expected, actual } => write!(
                f,
                "session binding mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
        }
    }
}

impl std::error::Error for DcmAirMockProverErrorV1 {}

pub fn prove_dcm_air_with_mock_proof_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
) -> Result<DcmAirMockProverOutputV1, DcmAirMockProverErrorV1> {
    validate_dcm_air_v1(public_inputs, trace)
        .map_err(DcmAirMockProverErrorV1::AirEvaluationFailed)?;

    let session = package_dcm_air_proof_session_v1(public_inputs, trace)
        .map_err(DcmAirMockProverErrorV1::AdapterPackagingFailed)?;

    build_mock_prover_output_from_session_v1(&session)
}

fn build_mock_prover_output_from_session_v1(
    session: &DcmAirProofSessionV1,
) -> Result<DcmAirMockProverOutputV1, DcmAirMockProverErrorV1> {
    let verifier_bindings = DcmAirMockVerifierBindingsV1::from(session.verifier_input());
    let bound_public_input_digest =
        derive_dcm_air_mock_public_input_digest_v1(&verifier_bindings.public_inputs);
    let bound_constraint_digest = derive_dcm_air_mock_constraint_digest_v1(&verifier_bindings);
    let expected_session_id = derive_dcm_air_mock_session_id_v1(&verifier_bindings);
    let actual_session_id = *session.session_id().as_bytes();

    if expected_session_id != actual_session_id {
        return Err(DcmAirMockProverErrorV1::SessionBindingMismatch {
            expected: expected_session_id,
            actual: actual_session_id,
        });
    }

    let mock_proof_artifact = DcmAirMockProofArtifactV1 {
        proof_version: DCM_AIR_MOCK_PROOF_VERSION_V1,
        bound_public_input_digest,
        bound_constraint_digest,
        bound_session_id: actual_session_id,
        proof_placeholder_digest: derive_dcm_air_mock_placeholder_digest_v1(
            DCM_AIR_MOCK_PROOF_VERSION_V1,
            &bound_public_input_digest,
            &bound_constraint_digest,
            &actual_session_id,
        ),
    };

    Ok(DcmAirMockProverOutputV1 {
        verifier_bindings,
        mock_proof_artifact,
    })
}

pub(crate) fn derive_dcm_air_mock_public_input_digest_v1(
    public_inputs: &DcmAirPublicInputsV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_MOCK_PROOF_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
        &public_inputs.canonical_bytes(),
    )
}

pub(crate) fn derive_dcm_air_mock_constraint_digest_v1(
    verifier_bindings: &DcmAirMockVerifierBindingsV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_MOCK_PROOF_V1_CONSTRAINT_DOMAIN_SEPARATOR,
        &canonical_constraint_bytes_v1(verifier_bindings),
    )
}

pub(crate) fn derive_dcm_air_mock_session_id_v1(
    verifier_bindings: &DcmAirMockVerifierBindingsV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_V1_SESSION_ID_DOMAIN_SEPARATOR,
        &canonical_session_binding_bytes_v1(verifier_bindings),
    )
}

pub(crate) fn derive_dcm_air_mock_placeholder_digest_v1(
    proof_version: u8,
    bound_public_input_digest: &[u8; HASH_LEN_V1],
    bound_constraint_digest: &[u8; HASH_LEN_V1],
    bound_session_id: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_MOCK_PROOF_V1_PLACEHOLDER_DOMAIN_SEPARATOR,
        &canonical_placeholder_bytes_v1(
            proof_version,
            bound_public_input_digest,
            bound_constraint_digest,
            bound_session_id,
        ),
    )
}

fn canonical_constraint_bytes_v1(verifier_bindings: &DcmAirMockVerifierBindingsV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 1 + 8 + 8 + 1 + HASH_LEN_V1);
    bytes.push(verifier_bindings.packaging_version);
    bytes.push(verifier_bindings.trace_width);
    bytes.extend_from_slice(&verifier_bindings.row_count.to_le_bytes());
    bytes.extend_from_slice(&verifier_bindings.checked_transition_count.to_le_bytes());
    bytes.push(verifier_bindings.transition_constraint_count);
    bytes.extend_from_slice(&verifier_bindings.trace_digest);
    bytes
}

fn canonical_session_binding_bytes_v1(verifier_bindings: &DcmAirMockVerifierBindingsV1) -> Vec<u8> {
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
    bytes.push(verifier_bindings.packaging_version);
    bytes.push(verifier_bindings.trace_width);
    bytes.extend_from_slice(&verifier_bindings.row_count.to_le_bytes());
    bytes.extend_from_slice(&verifier_bindings.checked_transition_count.to_le_bytes());
    bytes.push(verifier_bindings.transition_constraint_count);
    bytes.extend_from_slice(&verifier_bindings.public_inputs.canonical_bytes());
    bytes.push(verifier_bindings.trace_width);
    bytes.extend_from_slice(&verifier_bindings.row_count.to_le_bytes());
    bytes.extend_from_slice(&verifier_bindings.checked_transition_count.to_le_bytes());
    bytes.push(verifier_bindings.transition_constraint_count);
    bytes.extend_from_slice(&verifier_bindings.trace_digest);
    bytes
}

fn canonical_placeholder_bytes_v1(
    proof_version: u8,
    bound_public_input_digest: &[u8; HASH_LEN_V1],
    bound_constraint_digest: &[u8; HASH_LEN_V1],
    bound_session_id: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + HASH_LEN_V1 * 3);
    bytes.push(proof_version);
    bytes.extend_from_slice(bound_public_input_digest);
    bytes.extend_from_slice(bound_constraint_digest);
    bytes.extend_from_slice(bound_session_id);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_constraint_bytes_v1, canonical_session_binding_bytes_v1,
        derive_dcm_air_mock_constraint_digest_v1, derive_dcm_air_mock_public_input_digest_v1,
        derive_dcm_air_mock_session_id_v1, DcmAirMockVerifierBindingsV1,
    };
    use crate::{
        package_dcm_air_proof_session_v1, DcmAirPublicInputsV1, DcmAirTraceV1, DcmConfig521V1,
        DcmExecution521V1, DcmInput521V1, FieldElement521V1,
        DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1, DCM_AIR_TRACE_WIDTH_V1,
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, FIELD_ELEMENT_521_BYTE_LEN_V1,
        FIELD_MODULUS_521_V1, HASH_LEN_V1,
    };

    #[test]
    fn mock_binding_payloads_are_fixed_width() {
        let session =
            package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace())
                .unwrap();
        let verifier_bindings = DcmAirMockVerifierBindingsV1::from(session.verifier_input());

        assert_eq!(verifier_bindings.trace_width, DCM_AIR_TRACE_WIDTH_V1);
        assert_eq!(
            verifier_bindings.transition_constraint_count,
            DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
        );
        assert_eq!(
            canonical_constraint_bytes_v1(&verifier_bindings).len(),
            1 + 1 + 8 + 8 + 1 + HASH_LEN_V1
        );
        assert_eq!(
            canonical_session_binding_bytes_v1(&verifier_bindings).len(),
            1 + 1
                + 8
                + 8
                + 1
                + DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1
                + 1
                + 8
                + 8
                + 1
                + HASH_LEN_V1
        );
    }

    #[test]
    fn mock_session_id_matches_adapter_session_id_for_canonical_case() {
        let session =
            package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace())
                .unwrap();
        let verifier_bindings = DcmAirMockVerifierBindingsV1::from(session.verifier_input());

        assert_eq!(
            derive_dcm_air_mock_session_id_v1(&verifier_bindings),
            *session.session_id().as_bytes()
        );
    }

    #[test]
    fn changing_public_inputs_changes_mock_binding_digests() {
        let first =
            package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace())
                .unwrap();
        let second =
            package_dcm_air_proof_session_v1(&alternate_public_inputs(), &alternate_trace())
                .unwrap();
        let first_bindings = DcmAirMockVerifierBindingsV1::from(first.verifier_input());
        let second_bindings = DcmAirMockVerifierBindingsV1::from(second.verifier_input());

        assert_ne!(
            derive_dcm_air_mock_public_input_digest_v1(&first_bindings.public_inputs),
            derive_dcm_air_mock_public_input_digest_v1(&second_bindings.public_inputs)
        );
        assert_ne!(
            derive_dcm_air_mock_constraint_digest_v1(&first_bindings),
            derive_dcm_air_mock_constraint_digest_v1(&second_bindings)
        );
        assert_ne!(
            derive_dcm_air_mock_session_id_v1(&first_bindings),
            derive_dcm_air_mock_session_id_v1(&second_bindings)
        );
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
