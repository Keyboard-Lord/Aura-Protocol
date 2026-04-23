// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Deterministic mock verifier skeleton for the 521-bit DCM AIR binding contract.
//! This module checks binding consistency only. It does not verify a cryptographic proof.

use core::fmt;

use crate::{
    derive_dcm_air_mock_constraint_digest_v1, derive_dcm_air_mock_placeholder_digest_v1,
    derive_dcm_air_mock_public_input_digest_v1, derive_dcm_air_mock_session_id_v1,
    DcmAirMockProofArtifactV1, DcmAirMockVerifierBindingsV1, LowerHex32,
    DCM_AIR_ADAPTER_PACKAGING_VERSION_V1, DCM_AIR_MOCK_PROOF_VERSION_V1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, HASH_LEN_V1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirMockVerifierErrorV1 {
    UnsupportedProofVersion {
        expected: u8,
        actual: u8,
    },
    UnsupportedAdapterPackagingVersion {
        expected: u8,
        actual: u8,
    },
    UnsupportedTraceWidth {
        expected: u8,
        actual: u8,
    },
    UnsupportedTransitionConstraintCount {
        expected: u8,
        actual: u8,
    },
    IterationCountOverflow,
    RowCountInvariantMismatch {
        expected: u64,
        actual: u64,
    },
    CheckedTransitionCountInvariantMismatch {
        expected: u64,
        actual: u64,
    },
    PublicInputDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ConstraintDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    SessionIdMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofPlaceholderDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for DcmAirMockVerifierErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProofVersion { expected, actual } => write!(
                f,
                "unsupported mock proof version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAdapterPackagingVersion { expected, actual } => write!(
                f,
                "unsupported adapter packaging version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedTraceWidth { expected, actual } => {
                write!(
                    f,
                    "unsupported trace width: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedTransitionConstraintCount { expected, actual } => write!(
                f,
                "unsupported transition constraint count: expected {expected}, got {actual}"
            ),
            Self::IterationCountOverflow => write!(f, "iteration count overflow"),
            Self::RowCountInvariantMismatch { expected, actual } => write!(
                f,
                "row count invariant mismatch: expected {expected}, got {actual}"
            ),
            Self::CheckedTransitionCountInvariantMismatch { expected, actual } => write!(
                f,
                "checked transition count invariant mismatch: expected {expected}, got {actual}"
            ),
            Self::PublicInputDigestMismatch { expected, actual } => write!(
                f,
                "public input digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ConstraintDigestMismatch { expected, actual } => write!(
                f,
                "constraint digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::SessionIdMismatch { expected, actual } => write!(
                f,
                "session id mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofPlaceholderDigestMismatch { expected, actual } => write!(
                f,
                "proof placeholder digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
        }
    }
}

impl std::error::Error for DcmAirMockVerifierErrorV1 {}

pub fn verify_dcm_air_mock_proof_v1(
    verifier_bindings: &DcmAirMockVerifierBindingsV1,
    proof_artifact: &DcmAirMockProofArtifactV1,
) -> Result<(), DcmAirMockVerifierErrorV1> {
    if proof_artifact.proof_version != DCM_AIR_MOCK_PROOF_VERSION_V1 {
        return Err(DcmAirMockVerifierErrorV1::UnsupportedProofVersion {
            expected: DCM_AIR_MOCK_PROOF_VERSION_V1,
            actual: proof_artifact.proof_version,
        });
    }

    if verifier_bindings.packaging_version != DCM_AIR_ADAPTER_PACKAGING_VERSION_V1 {
        return Err(
            DcmAirMockVerifierErrorV1::UnsupportedAdapterPackagingVersion {
                expected: DCM_AIR_ADAPTER_PACKAGING_VERSION_V1,
                actual: verifier_bindings.packaging_version,
            },
        );
    }

    if verifier_bindings.trace_width != DCM_AIR_TRACE_WIDTH_V1 {
        return Err(DcmAirMockVerifierErrorV1::UnsupportedTraceWidth {
            expected: DCM_AIR_TRACE_WIDTH_V1,
            actual: verifier_bindings.trace_width,
        });
    }

    if verifier_bindings.transition_constraint_count != DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1 {
        return Err(
            DcmAirMockVerifierErrorV1::UnsupportedTransitionConstraintCount {
                expected: DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1,
                actual: verifier_bindings.transition_constraint_count,
            },
        );
    }

    let expected_row_count = verifier_bindings
        .public_inputs
        .iteration_count
        .checked_add(1)
        .ok_or(DcmAirMockVerifierErrorV1::IterationCountOverflow)?;
    if verifier_bindings.row_count != expected_row_count {
        return Err(DcmAirMockVerifierErrorV1::RowCountInvariantMismatch {
            expected: expected_row_count,
            actual: verifier_bindings.row_count,
        });
    }

    if verifier_bindings.checked_transition_count != verifier_bindings.public_inputs.iteration_count
    {
        return Err(
            DcmAirMockVerifierErrorV1::CheckedTransitionCountInvariantMismatch {
                expected: verifier_bindings.public_inputs.iteration_count,
                actual: verifier_bindings.checked_transition_count,
            },
        );
    }

    let expected_public_input_digest =
        derive_dcm_air_mock_public_input_digest_v1(&verifier_bindings.public_inputs);
    if proof_artifact.bound_public_input_digest != expected_public_input_digest {
        return Err(DcmAirMockVerifierErrorV1::PublicInputDigestMismatch {
            expected: expected_public_input_digest,
            actual: proof_artifact.bound_public_input_digest,
        });
    }

    let expected_constraint_digest = derive_dcm_air_mock_constraint_digest_v1(verifier_bindings);
    if proof_artifact.bound_constraint_digest != expected_constraint_digest {
        return Err(DcmAirMockVerifierErrorV1::ConstraintDigestMismatch {
            expected: expected_constraint_digest,
            actual: proof_artifact.bound_constraint_digest,
        });
    }

    let expected_session_id = derive_dcm_air_mock_session_id_v1(verifier_bindings);
    if proof_artifact.bound_session_id != expected_session_id {
        return Err(DcmAirMockVerifierErrorV1::SessionIdMismatch {
            expected: expected_session_id,
            actual: proof_artifact.bound_session_id,
        });
    }

    let expected_placeholder_digest = derive_dcm_air_mock_placeholder_digest_v1(
        DCM_AIR_MOCK_PROOF_VERSION_V1,
        &expected_public_input_digest,
        &expected_constraint_digest,
        &expected_session_id,
    );
    if proof_artifact.proof_placeholder_digest != expected_placeholder_digest {
        return Err(DcmAirMockVerifierErrorV1::ProofPlaceholderDigestMismatch {
            expected: expected_placeholder_digest,
            actual: proof_artifact.proof_placeholder_digest,
        });
    }

    Ok(())
}
