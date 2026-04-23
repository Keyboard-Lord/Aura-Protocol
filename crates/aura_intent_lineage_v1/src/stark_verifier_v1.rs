// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Verifier surfaces for Aura's lower-layer proof paths.
//!
//! Active path:
//! - a storm-native verifier that replays the canonical storm witness and rejects any mismatch
//!
//! Retained staged path:
//! - the earlier scaffold verifier that checks deterministic opening/binding artifacts only
//! - the older Winterfell-backed cat-map verifier, which remains legacy coverage only
//!
//! The active storm path does not claim in-AIR SHA3 hashing. It verifies by decoding the bound
//! storm claim and witness, recomputing the public inputs, and validating the full recurrence and
//! trace-root semantics. The retained Winterfell cat-map path is legacy only.

use core::fmt;

use crate::{
    decode_storm_real_proof_bytes_v1, derive_storm_air_real_proof_binding_digest_v1,
    derive_storm_air_real_proof_bytes_digest_v1, derive_storm_air_real_public_input_digest_v1,
    derive_dcm_air_real_stark_proof_binding_digest_v1,
    derive_dcm_air_real_stark_proof_bytes_digest_v1, derive_dcm_air_stark_proof_artifact_digest_v1,
    derive_dcm_air_stark_public_input_digest_v1, derive_dcm_air_stark_transcript_v1,
    derive_dcm_air_winterfell_public_inputs_v1, derive_real_stark_internal_trace_length_v1,
    derive_stark_trace_tree_height_from_leaf_count_v1, evaluate_dcm_air_transition_constraints_v1,
    expected_next_dcm_air_row_v1, verify_stark_trace_merkle_opening_v1, DcmAirFrameV1,
    DcmAirPublicInputsV1, DcmAirRealStarkProofArtifactV1, DcmAirRealStarkWinterfellAirV1,
    DcmAirStarkProofArtifactV1, DcmAirStarkTransitionOpeningsV1, DcmState521V1, FieldElement521V1,
    LowerHex32, StarkTraceCommitmentErrorV1, StarkTraceCommitmentV1, StormAirPublicInputsV1,
    StormAirRealProofArtifactV1, StormAirRealProofDecodeErrorV1, StormTraceWitnessV1,
    DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1, DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1,
    DCM_AIR_REAL_STARK_PROOF_VERSION_V1, DCM_AIR_REAL_STARK_TRACE_WIDTH_V1,
    DCM_AIR_STARK_PROOF_SCAFFOLD_VERSION_V1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, HASH_LEN_V1, STARK_TRACE_COMMITMENT_VERSION_V1,
    STORM_AIR_REAL_PROOF_BACKEND_WITNESS_V1, STORM_AIR_REAL_PROOF_CONSTRAINT_COUNT_V1,
    STORM_AIR_REAL_PROOF_TRACE_WIDTH_V1, STORM_AIR_REAL_PROOF_VERSION_V1,
};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::fields::f128::BaseElement,
    verify, AcceptableOptions, Proof, VerifierError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirStarkVerifierAcceptanceV1 {
    pub verified_trace_commitment_root: [u8; HASH_LEN_V1],
    pub verified_transition_query_count: u8,
    pub verified_transition_row_index: u64,
    pub verified_proof_artifact_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirStarkVerifierErrorV1 {
    UnsupportedProofVersion {
        expected: u8,
        actual: u8,
    },
    UnsupportedTraceShape {
        reason: &'static str,
    },
    PublicInputBindingMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    TranscriptMismatch {
        field: &'static str,
    },
    OpeningMismatch {
        field: &'static str,
    },
    CommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    TransitionOpeningViolation {
        row_index: u64,
        expected: DcmState521V1,
        actual: DcmState521V1,
        x_transition_residual: FieldElement521V1,
        y_transition_residual: FieldElement521V1,
    },
    ProofArtifactDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for DcmAirStarkVerifierErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProofVersion { expected, actual } => write!(
                f,
                "unsupported proof version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedTraceShape { reason } => {
                write!(f, "unsupported trace shape for verifier scaffold: {reason}")
            }
            Self::PublicInputBindingMismatch { expected, actual } => write!(
                f,
                "public input binding mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::TranscriptMismatch { field } => {
                write!(f, "transcript mismatch: {field}")
            }
            Self::OpeningMismatch { field } => {
                write!(f, "opening mismatch: {field}")
            }
            Self::CommitmentMismatch { expected, actual } => write!(
                f,
                "trace commitment mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::TransitionOpeningViolation {
                row_index,
                expected,
                actual,
                ..
            } => write!(
                f,
                "transition opening violation at row {row_index}: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::ProofArtifactDigestMismatch { expected, actual } => write!(
                f,
                "proof artifact digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
        }
    }
}

impl std::error::Error for DcmAirStarkVerifierErrorV1 {}

pub fn verify_dcm_air_stark_scaffold_v1(
    public_inputs: &DcmAirPublicInputsV1,
    proof_artifact: &DcmAirStarkProofArtifactV1,
) -> Result<DcmAirStarkVerifierAcceptanceV1, DcmAirStarkVerifierErrorV1> {
    if proof_artifact.proof_version != DCM_AIR_STARK_PROOF_SCAFFOLD_VERSION_V1 {
        return Err(DcmAirStarkVerifierErrorV1::UnsupportedProofVersion {
            expected: DCM_AIR_STARK_PROOF_SCAFFOLD_VERSION_V1,
            actual: proof_artifact.proof_version,
        });
    }

    let expected_trace_row_count = public_inputs.iteration_count.checked_add(1).ok_or(
        DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "iteration_count_overflow",
        },
    )?;
    if proof_artifact.opening_metadata.trace_row_count != expected_trace_row_count {
        return Err(DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "trace_row_count_mismatch",
        });
    }

    let expected_tree_height =
        derive_stark_trace_tree_height_from_leaf_count_v1(expected_trace_row_count);
    if proof_artifact.opening_metadata.commitment_tree_height != expected_tree_height {
        return Err(DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "commitment_tree_height_mismatch",
        });
    }

    let expected_transition_query_count = if expected_trace_row_count > 1 { 1 } else { 0 };
    if proof_artifact.opening_metadata.transition_query_count != expected_transition_query_count {
        return Err(DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "transition_query_count_mismatch",
        });
    }
    if proof_artifact.opening_metadata.trace_width != DCM_AIR_TRACE_WIDTH_V1 {
        return Err(DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "trace_width_mismatch",
        });
    }
    if proof_artifact.opening_metadata.transition_constraint_count
        != DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    {
        return Err(DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "transition_constraint_count_mismatch",
        });
    }

    let expected_public_input_digest = derive_dcm_air_stark_public_input_digest_v1(public_inputs);
    if proof_artifact.public_input_digest != expected_public_input_digest {
        return Err(DcmAirStarkVerifierErrorV1::PublicInputBindingMismatch {
            expected: expected_public_input_digest,
            actual: proof_artifact.public_input_digest,
        });
    }

    let trace_commitment = StarkTraceCommitmentV1 {
        commitment_version: STARK_TRACE_COMMITMENT_VERSION_V1,
        leaf_count: proof_artifact.opening_metadata.trace_row_count,
        tree_height: proof_artifact.opening_metadata.commitment_tree_height,
        root: proof_artifact.trace_commitment_root,
    };
    let transcript =
        derive_dcm_air_stark_transcript_v1(public_inputs, &trace_commitment).map_err(|_| {
            DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
                reason: "transcript_construction_failed",
            }
        })?;
    if proof_artifact.transcript_digest != transcript.transcript_digest {
        return Err(DcmAirStarkVerifierErrorV1::TranscriptMismatch {
            field: "transcript_digest",
        });
    }
    if proof_artifact.query_challenge_digest != transcript.query_challenge_digest {
        return Err(DcmAirStarkVerifierErrorV1::TranscriptMismatch {
            field: "query_challenge_digest",
        });
    }

    verify_boundary_opening_v1(
        &trace_commitment,
        &proof_artifact.boundary_first_row_opening,
        0,
        public_inputs.initial_state,
        "boundary_first_row",
    )?;
    verify_boundary_opening_v1(
        &trace_commitment,
        &proof_artifact.boundary_last_row_opening,
        expected_trace_row_count - 1,
        public_inputs.final_state,
        "boundary_last_row",
    )?;

    let verified_transition_row_index = if transcript.transition_query_count == 0 {
        if proof_artifact.queried_transition_openings.is_some() {
            return Err(DcmAirStarkVerifierErrorV1::OpeningMismatch {
                field: "queried_transition_openings",
            });
        }
        0
    } else {
        let transition_openings = proof_artifact.queried_transition_openings.as_ref().ok_or(
            DcmAirStarkVerifierErrorV1::OpeningMismatch {
                field: "queried_transition_openings",
            },
        )?;
        verify_transition_openings_v1(
            public_inputs,
            &trace_commitment,
            &transcript,
            transition_openings,
        )?;
        transition_openings.row_index
    };

    let expected_proof_artifact_digest =
        derive_dcm_air_stark_proof_artifact_digest_v1(proof_artifact);
    if proof_artifact.proof_artifact_digest != expected_proof_artifact_digest {
        return Err(DcmAirStarkVerifierErrorV1::ProofArtifactDigestMismatch {
            expected: expected_proof_artifact_digest,
            actual: proof_artifact.proof_artifact_digest,
        });
    }

    Ok(DcmAirStarkVerifierAcceptanceV1 {
        verified_trace_commitment_root: proof_artifact.trace_commitment_root,
        verified_transition_query_count: transcript.transition_query_count,
        verified_transition_row_index,
        verified_proof_artifact_digest: proof_artifact.proof_artifact_digest,
    })
}

fn verify_boundary_opening_v1(
    trace_commitment: &StarkTraceCommitmentV1,
    opening: &crate::StarkTraceMerkleOpeningV1,
    expected_row_index: u64,
    expected_row_value: DcmState521V1,
    field_prefix: &'static str,
) -> Result<(), DcmAirStarkVerifierErrorV1> {
    if opening.row_index != expected_row_index {
        return Err(DcmAirStarkVerifierErrorV1::OpeningMismatch {
            field: match field_prefix {
                "boundary_first_row" => "boundary_first_row_index",
                _ => "boundary_last_row_index",
            },
        });
    }
    if opening.row_value != expected_row_value {
        return Err(DcmAirStarkVerifierErrorV1::OpeningMismatch {
            field: match field_prefix {
                "boundary_first_row" => "boundary_first_row_value",
                _ => "boundary_last_row_value",
            },
        });
    }
    verify_opening_against_commitment_v1(trace_commitment, opening)
}

fn verify_transition_openings_v1(
    _public_inputs: &DcmAirPublicInputsV1,
    trace_commitment: &StarkTraceCommitmentV1,
    transcript: &crate::DcmAirStarkTranscriptV1,
    transition_openings: &DcmAirStarkTransitionOpeningsV1,
) -> Result<(), DcmAirStarkVerifierErrorV1> {
    if transition_openings.row_index != transcript.queried_transition_row_index {
        return Err(DcmAirStarkVerifierErrorV1::TranscriptMismatch {
            field: "queried_transition_row_index",
        });
    }
    if transition_openings.current_row_opening.row_index != transition_openings.row_index {
        return Err(DcmAirStarkVerifierErrorV1::OpeningMismatch {
            field: "transition_current_row_index",
        });
    }
    if transition_openings.next_row_opening.row_index != transition_openings.row_index + 1 {
        return Err(DcmAirStarkVerifierErrorV1::OpeningMismatch {
            field: "transition_next_row_index",
        });
    }

    verify_opening_against_commitment_v1(
        trace_commitment,
        &transition_openings.current_row_opening,
    )?;
    verify_opening_against_commitment_v1(trace_commitment, &transition_openings.next_row_opening)?;

    let frame = DcmAirFrameV1 {
        current_row: transition_openings.current_row_opening.row_value,
        next_row: transition_openings.next_row_opening.row_value,
    };
    let constraint_evaluation = evaluate_dcm_air_transition_constraints_v1(&frame);
    if !constraint_evaluation.is_satisfied() {
        return Err(DcmAirStarkVerifierErrorV1::TransitionOpeningViolation {
            row_index: transition_openings.row_index,
            expected: expected_next_dcm_air_row_v1(&frame),
            actual: transition_openings.next_row_opening.row_value,
            x_transition_residual: constraint_evaluation.x_transition_residual,
            y_transition_residual: constraint_evaluation.y_transition_residual,
        });
    }

    Ok(())
}

fn verify_opening_against_commitment_v1(
    trace_commitment: &StarkTraceCommitmentV1,
    opening: &crate::StarkTraceMerkleOpeningV1,
) -> Result<(), DcmAirStarkVerifierErrorV1> {
    let actual_root = verify_stark_trace_merkle_opening_v1(trace_commitment, opening)
        .map_err(map_trace_commitment_error_to_verifier_error_v1)?;
    if actual_root != trace_commitment.root {
        return Err(DcmAirStarkVerifierErrorV1::CommitmentMismatch {
            expected: trace_commitment.root,
            actual: actual_root,
        });
    }
    Ok(())
}

fn map_trace_commitment_error_to_verifier_error_v1(
    error: StarkTraceCommitmentErrorV1,
) -> DcmAirStarkVerifierErrorV1 {
    match error {
        StarkTraceCommitmentErrorV1::RowIndexOutOfRange { .. }
        | StarkTraceCommitmentErrorV1::OpeningPathLengthMismatch { .. } => {
            DcmAirStarkVerifierErrorV1::OpeningMismatch {
                field: "trace_merkle_opening",
            }
        }
        StarkTraceCommitmentErrorV1::EmptyTrace => {
            DcmAirStarkVerifierErrorV1::UnsupportedTraceShape {
                reason: "empty_trace_commitment",
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormAirRealVerifierAcceptanceV1 {
    pub verified_public_input_digest: [u8; HASH_LEN_V1],
    pub verified_proof_bytes_digest: [u8; HASH_LEN_V1],
    pub verified_proof_binding_digest: [u8; HASH_LEN_V1],
    pub verified_trace_state_count: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StormAirRealVerifierErrorV1 {
    UnsupportedBackendKind { expected: u32, actual: u32 },
    UnsupportedProofVersion { expected: u8, actual: u8 },
    UnsupportedTraceShape { reason: &'static str },
    PublicInputDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofBytesDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofBindingDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofDecode(StormAirRealProofDecodeErrorV1),
    ClaimValidationFailed(crate::StormClaimErrorV1),
    PublicInputsMismatch { field: &'static str },
    WitnessValidationFailed(crate::StormAirValidationErrorV1),
}

impl fmt::Display for StormAirRealVerifierErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBackendKind { expected, actual } => write!(
                f,
                "unsupported storm proof backend kind: expected {expected}, got {actual}"
            ),
            Self::UnsupportedProofVersion { expected, actual } => write!(
                f,
                "unsupported storm proof version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedTraceShape { reason } => {
                write!(f, "unsupported storm proof trace shape: {reason}")
            }
            Self::PublicInputDigestMismatch { expected, actual } => write!(
                f,
                "storm public input digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofBytesDigestMismatch { expected, actual } => write!(
                f,
                "storm proof-bytes digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofBindingDigestMismatch { expected, actual } => write!(
                f,
                "storm proof binding digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofDecode(error) => write!(f, "storm proof decode failed: {error}"),
            Self::ClaimValidationFailed(error) => write!(f, "storm claim validation failed: {error}"),
            Self::PublicInputsMismatch { field } => {
                write!(f, "storm public inputs mismatch: {field}")
            }
            Self::WitnessValidationFailed(error) => {
                write!(f, "storm witness validation failed: {error}")
            }
        }
    }
}

impl std::error::Error for StormAirRealVerifierErrorV1 {}

pub fn verify_storm_air_real_v1(
    public_inputs: &StormAirPublicInputsV1,
    proof_artifact: &StormAirRealProofArtifactV1,
) -> Result<StormAirRealVerifierAcceptanceV1, StormAirRealVerifierErrorV1> {
    if proof_artifact.backend_kind != STORM_AIR_REAL_PROOF_BACKEND_WITNESS_V1 {
        return Err(StormAirRealVerifierErrorV1::UnsupportedBackendKind {
            expected: STORM_AIR_REAL_PROOF_BACKEND_WITNESS_V1,
            actual: proof_artifact.backend_kind,
        });
    }
    if proof_artifact.proof_version != STORM_AIR_REAL_PROOF_VERSION_V1 {
        return Err(StormAirRealVerifierErrorV1::UnsupportedProofVersion {
            expected: STORM_AIR_REAL_PROOF_VERSION_V1,
            actual: proof_artifact.proof_version,
        });
    }

    let expected_trace_state_count = public_inputs.iteration_count.checked_add(1).ok_or(
        StormAirRealVerifierErrorV1::UnsupportedTraceShape {
            reason: "iteration_count_overflow",
        },
    )?;
    if proof_artifact.trace_state_count != expected_trace_state_count {
        return Err(StormAirRealVerifierErrorV1::UnsupportedTraceShape {
            reason: "trace_state_count_mismatch",
        });
    }
    if proof_artifact.internal_trace_length != expected_trace_state_count {
        return Err(StormAirRealVerifierErrorV1::UnsupportedTraceShape {
            reason: "internal_trace_length_mismatch",
        });
    }
    if proof_artifact.trace_width != STORM_AIR_REAL_PROOF_TRACE_WIDTH_V1 {
        return Err(StormAirRealVerifierErrorV1::UnsupportedTraceShape {
            reason: "trace_width_mismatch",
        });
    }
    if proof_artifact.backend_constraint_count != STORM_AIR_REAL_PROOF_CONSTRAINT_COUNT_V1 {
        return Err(StormAirRealVerifierErrorV1::UnsupportedTraceShape {
            reason: "backend_constraint_count_mismatch",
        });
    }

    let expected_public_input_digest = derive_storm_air_real_public_input_digest_v1(public_inputs);
    if proof_artifact.public_input_digest != expected_public_input_digest {
        return Err(StormAirRealVerifierErrorV1::PublicInputDigestMismatch {
            expected: expected_public_input_digest,
            actual: proof_artifact.public_input_digest,
        });
    }

    let expected_proof_bytes_digest =
        derive_storm_air_real_proof_bytes_digest_v1(&proof_artifact.proof_bytes);
    if proof_artifact.proof_bytes_digest != expected_proof_bytes_digest {
        return Err(StormAirRealVerifierErrorV1::ProofBytesDigestMismatch {
            expected: expected_proof_bytes_digest,
            actual: proof_artifact.proof_bytes_digest,
        });
    }

    let expected_proof_binding_digest =
        derive_storm_air_real_proof_binding_digest_v1(proof_artifact);
    if proof_artifact.proof_binding_digest != expected_proof_binding_digest {
        return Err(StormAirRealVerifierErrorV1::ProofBindingDigestMismatch {
            expected: expected_proof_binding_digest,
            actual: proof_artifact.proof_binding_digest,
        });
    }

    let (claim, witness) = decode_storm_real_proof_bytes_v1(&proof_artifact.proof_bytes)
        .map_err(StormAirRealVerifierErrorV1::ProofDecode)?;
    claim.validate()
        .map_err(StormAirRealVerifierErrorV1::ClaimValidationFailed)?;
    verify_storm_public_inputs_match_claim_v1(public_inputs, &claim, &witness)?;
    crate::validate_trace_witness_against_claim(&claim, &witness)
        .map_err(StormAirRealVerifierErrorV1::WitnessValidationFailed)?;

    Ok(StormAirRealVerifierAcceptanceV1 {
        verified_public_input_digest: proof_artifact.public_input_digest,
        verified_proof_bytes_digest: proof_artifact.proof_bytes_digest,
        verified_proof_binding_digest: proof_artifact.proof_binding_digest,
        verified_trace_state_count: proof_artifact.trace_state_count,
    })
}

fn verify_storm_public_inputs_match_claim_v1(
    public_inputs: &StormAirPublicInputsV1,
    claim: &crate::StormClaim521V1,
    witness: &StormTraceWitnessV1,
) -> Result<(), StormAirRealVerifierErrorV1> {
    let expected_public_inputs = crate::build_storm_air_public_inputs_v1(claim);
    if public_inputs != &expected_public_inputs {
        return Err(StormAirRealVerifierErrorV1::PublicInputsMismatch {
            field: "public_inputs",
        });
    }
    if witness.public_inputs != expected_public_inputs {
        return Err(StormAirRealVerifierErrorV1::PublicInputsMismatch {
            field: "witness.public_inputs",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirRealStarkVerifierAcceptanceV1 {
    pub verified_public_input_digest: [u8; HASH_LEN_V1],
    pub verified_proof_bytes_digest: [u8; HASH_LEN_V1],
    pub verified_proof_binding_digest: [u8; HASH_LEN_V1],
    pub verified_internal_trace_length: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DcmAirRealStarkVerifierErrorV1 {
    UnsupportedBackendKind {
        expected: u32,
        actual: u32,
    },
    UnsupportedProofVersion {
        expected: u8,
        actual: u8,
    },
    UnsupportedTraceShape {
        reason: &'static str,
    },
    PublicInputDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofBytesDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofBindingDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofDecode(String),
    WinterfellVerifier(String),
}

impl fmt::Display for DcmAirRealStarkVerifierErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBackendKind { expected, actual } => write!(
                f,
                "unsupported stark backend kind: expected {expected}, got {actual}"
            ),
            Self::UnsupportedProofVersion { expected, actual } => write!(
                f,
                "unsupported real stark proof version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedTraceShape { reason } => {
                write!(f, "unsupported real stark trace shape: {reason}")
            }
            Self::PublicInputDigestMismatch { expected, actual } => write!(
                f,
                "real stark public input digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofBytesDigestMismatch { expected, actual } => write!(
                f,
                "real stark proof-bytes digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofBindingDigestMismatch { expected, actual } => write!(
                f,
                "real stark proof binding digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ProofDecode(error) => write!(f, "real stark proof decode failed: {error}"),
            Self::WinterfellVerifier(error) => {
                write!(f, "winterfell verifier rejected proof: {error}")
            }
        }
    }
}

impl std::error::Error for DcmAirRealStarkVerifierErrorV1 {}

pub fn verify_dcm_air_real_stark_v1(
    public_inputs: &DcmAirPublicInputsV1,
    proof_artifact: &DcmAirRealStarkProofArtifactV1,
) -> Result<DcmAirRealStarkVerifierAcceptanceV1, DcmAirRealStarkVerifierErrorV1> {
    if proof_artifact.backend_kind != DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1 {
        return Err(DcmAirRealStarkVerifierErrorV1::UnsupportedBackendKind {
            expected: DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1,
            actual: proof_artifact.backend_kind,
        });
    }
    if proof_artifact.proof_version != DCM_AIR_REAL_STARK_PROOF_VERSION_V1 {
        return Err(DcmAirRealStarkVerifierErrorV1::UnsupportedProofVersion {
            expected: DCM_AIR_REAL_STARK_PROOF_VERSION_V1,
            actual: proof_artifact.proof_version,
        });
    }

    let expected_trace_state_count = public_inputs.iteration_count.checked_add(1).ok_or(
        DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "iteration_count_overflow",
        },
    )?;
    if proof_artifact.trace_state_count != expected_trace_state_count {
        return Err(DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "trace_state_count_mismatch",
        });
    }

    let expected_internal_trace_length =
        derive_real_stark_internal_trace_length_v1(expected_trace_state_count).map_err(|_| {
            DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape {
                reason: "internal_trace_length_derivation_failed",
            }
        })?;
    if proof_artifact.internal_trace_length != expected_internal_trace_length as u64 {
        return Err(DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "internal_trace_length_mismatch",
        });
    }
    if proof_artifact.trace_width != DCM_AIR_REAL_STARK_TRACE_WIDTH_V1 as u16 {
        return Err(DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "trace_width_mismatch",
        });
    }
    if proof_artifact.backend_constraint_count
        != DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1 as u16
    {
        return Err(DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape {
            reason: "transition_constraint_count_mismatch",
        });
    }

    let expected_public_input_digest = derive_dcm_air_stark_public_input_digest_v1(public_inputs);
    if proof_artifact.public_input_digest != expected_public_input_digest {
        return Err(DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch {
            expected: expected_public_input_digest,
            actual: proof_artifact.public_input_digest,
        });
    }

    let expected_proof_bytes_digest =
        derive_dcm_air_real_stark_proof_bytes_digest_v1(&proof_artifact.proof_bytes);
    if proof_artifact.proof_bytes_digest != expected_proof_bytes_digest {
        return Err(DcmAirRealStarkVerifierErrorV1::ProofBytesDigestMismatch {
            expected: expected_proof_bytes_digest,
            actual: proof_artifact.proof_bytes_digest,
        });
    }

    let expected_proof_binding_digest =
        derive_dcm_air_real_stark_proof_binding_digest_v1(proof_artifact);
    if proof_artifact.proof_binding_digest != expected_proof_binding_digest {
        return Err(DcmAirRealStarkVerifierErrorV1::ProofBindingDigestMismatch {
            expected: expected_proof_binding_digest,
            actual: proof_artifact.proof_binding_digest,
        });
    }

    let winterfell_proof = Proof::from_bytes(&proof_artifact.proof_bytes)
        .map_err(|error| DcmAirRealStarkVerifierErrorV1::ProofDecode(error.to_string()))?;
    let acceptable = AcceptableOptions::MinConjecturedSecurity(95);
    let winterfell_public_inputs = derive_dcm_air_winterfell_public_inputs_v1(public_inputs);

    verify::<
        DcmAirRealStarkWinterfellAirV1,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(winterfell_proof, winterfell_public_inputs, &acceptable)
    .map_err(|error: VerifierError| {
        DcmAirRealStarkVerifierErrorV1::WinterfellVerifier(error.to_string())
    })?;

    Ok(DcmAirRealStarkVerifierAcceptanceV1 {
        verified_public_input_digest: proof_artifact.public_input_digest,
        verified_proof_bytes_digest: proof_artifact.proof_bytes_digest,
        verified_proof_binding_digest: proof_artifact.proof_binding_digest,
        verified_internal_trace_length: proof_artifact.internal_trace_length,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        build_storm_air_public_inputs_v1, build_storm_claim_v1,
        canonical_storm_real_proof_bytes_v1, decode_storm_real_proof_bytes_v1,
        derive_storm_air_real_proof_binding_digest_v1,
        derive_storm_air_real_proof_bytes_digest_v1, prove_storm_air_real_v1,
        FieldElement521V1, StormContextV1, StormExecutionInputsV1, STORM_CONTEXT_V1_VERSION,
    };

    use super::{
        verify_storm_air_real_v1, StormAirRealVerifierErrorV1, StormAirRealVerifierAcceptanceV1,
    };

    #[test]
    fn storm_real_prove_and_verify_accepts_canonical_case() {
        let claim = canonical_claim();
        let public_inputs = build_storm_air_public_inputs_v1(&claim);
        let proof = prove_storm_air_real_v1(&claim, &public_inputs).unwrap();
        let acceptance = verify_storm_air_real_v1(&public_inputs, &proof).unwrap();

        assert_eq!(
            acceptance,
            StormAirRealVerifierAcceptanceV1 {
                verified_public_input_digest: proof.public_input_digest,
                verified_proof_bytes_digest: proof.proof_bytes_digest,
                verified_proof_binding_digest: proof.proof_binding_digest,
                verified_trace_state_count: proof.trace_state_count,
            }
        );
    }

    #[test]
    fn storm_real_verifier_rejects_tampered_phi_n_even_when_digests_are_recomputed() {
        let claim = canonical_claim();
        let public_inputs = build_storm_air_public_inputs_v1(&claim);
        let mut proof = prove_storm_air_real_v1(&claim, &public_inputs).unwrap();
        let (decoded_claim, mut witness) = decode_storm_real_proof_bytes_v1(&proof.proof_bytes).unwrap();
        witness.steps[0].phi_n = FieldElement521V1::from_u64(9);
        proof.proof_bytes = canonical_storm_real_proof_bytes_v1(&decoded_claim, &witness);
        proof.proof_bytes_digest = derive_storm_air_real_proof_bytes_digest_v1(&proof.proof_bytes);
        proof.proof_binding_digest = derive_storm_air_real_proof_binding_digest_v1(&proof);

        assert!(matches!(
            verify_storm_air_real_v1(&public_inputs, &proof).unwrap_err(),
            StormAirRealVerifierErrorV1::WitnessValidationFailed(_)
        ));
    }

    #[test]
    fn storm_real_verifier_rejects_tampered_trace_root_even_when_digests_are_recomputed() {
        let claim = canonical_claim();
        let public_inputs = build_storm_air_public_inputs_v1(&claim);
        let mut proof = prove_storm_air_real_v1(&claim, &public_inputs).unwrap();
        let (mut decoded_claim, witness) = decode_storm_real_proof_bytes_v1(&proof.proof_bytes).unwrap();
        decoded_claim.trace_root[0] ^= 0x01;
        proof.proof_bytes = canonical_storm_real_proof_bytes_v1(&decoded_claim, &witness);
        proof.proof_bytes_digest = derive_storm_air_real_proof_bytes_digest_v1(&proof.proof_bytes);
        proof.proof_binding_digest = derive_storm_air_real_proof_binding_digest_v1(&proof);

        assert!(matches!(
            verify_storm_air_real_v1(&public_inputs, &proof).unwrap_err(),
            StormAirRealVerifierErrorV1::ClaimValidationFailed(_)
        ));
    }

    fn canonical_claim() -> crate::StormClaim521V1 {
        let inputs = StormExecutionInputsV1 {
            side_a: [0x91; 110],
            side_b: [0x19; 110],
            context_bytes_v1: StormContextV1 {
                context_version: STORM_CONTEXT_V1_VERSION,
                network_id: [0x10; 32],
                intent_hash: [0x20; 32],
                freshness_nonce: [0x30; 32],
                valid_from: 7,
                valid_until: 11,
                controller_id: [0x40; 32],
                route_tag: [0x50; 32],
            }
            .to_bytes(),
            iteration_count: 5,
        };
        build_storm_claim_v1(&inputs, [0x7b; 32], [0x76; 32])
    }
}
