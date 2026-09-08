// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Proving surfaces for Aura's lower-layer paths.
//!
//! Active path:
//! - a storm-native proof artifact built from the canonical storm claim and witness surfaces
//! - deterministic replay and fail-closed witness validation for the active lower-layer authority
//!
//! Retained staged path:
//! - the earlier scaffold artifact builder used for deterministic opening/binding tests
//! - the older Winterfell-backed cat-map prover, which is now explicit legacy coverage only
//!
//! The active storm path does not claim in-AIR SHA3 hashing. It proves by transporting the
//! deterministic storm witness directly and rejecting any mismatch against the bound claim and
//! public inputs. The retained Winterfell cat-map path remains only for legacy coverage.

use core::fmt;

use crate::{
    build_stark_trace_commitment_tree_v1, derive_dcm_air_stark_transcript_v1,
    sha256_domain_separated, validate_dcm_air_v1, validate_trace_witness_against_claim,
    DcmAirErrorV1, DcmAirPublicInputsV1, DcmAirStarkTranscriptErrorV1, DcmAirTraceV1,
    DcmConfig521V1, DcmState521V1, LowerHex32, StormAirPublicInputsV1, StormAirValidationErrorV1,
    StormClaim521V1, StormClaimEncodingErrorV1, StormTraceWitnessV1,
    StarkTraceCommitmentErrorV1, StarkTraceMerkleOpeningV1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, HASH_LEN_V1,
};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, ProofOptions, Prover, ProverError,
    StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

pub const DCM_AIR_STARK_PROOF_SCAFFOLD_VERSION_V1: u8 = 1;
pub const AURA_DCM_AIR_STARK_PROOF_SCAFFOLD_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_AIR_STARK_PROOF_SCAFFOLD_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirStarkOpeningMetadataV1 {
    pub trace_row_count: u64,
    pub commitment_tree_height: u64,
    pub transition_query_count: u8,
    pub trace_width: u8,
    pub transition_constraint_count: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmAirStarkTransitionOpeningsV1 {
    pub row_index: u64,
    pub current_row_opening: StarkTraceMerkleOpeningV1,
    pub next_row_opening: StarkTraceMerkleOpeningV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmAirStarkProofArtifactV1 {
    // This is a recurrence-only proving scaffold artifact.
    // It is not a final STARK proof format and does not claim production soundness.
    pub proof_version: u8,
    pub trace_commitment_root: [u8; HASH_LEN_V1],
    pub public_input_digest: [u8; HASH_LEN_V1],
    pub transcript_digest: [u8; HASH_LEN_V1],
    pub query_challenge_digest: [u8; HASH_LEN_V1],
    pub boundary_first_row_opening: StarkTraceMerkleOpeningV1,
    pub boundary_last_row_opening: StarkTraceMerkleOpeningV1,
    pub queried_transition_openings: Option<DcmAirStarkTransitionOpeningsV1>,
    pub opening_metadata: DcmAirStarkOpeningMetadataV1,
    pub proof_artifact_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirStarkProverErrorV1 {
    AirEvaluationRequired(DcmAirErrorV1),
    CommitmentConstructionFailed(StarkTraceCommitmentErrorV1),
    TranscriptConstructionFailed(DcmAirStarkTranscriptErrorV1),
    OpeningConstructionFailed(StarkTraceCommitmentErrorV1),
}

impl fmt::Display for DcmAirStarkProverErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AirEvaluationRequired(error) => {
                write!(
                    f,
                    "air evaluation required before stark scaffold proving: {error}"
                )
            }
            Self::CommitmentConstructionFailed(error) => {
                write!(f, "trace commitment construction failed: {error}")
            }
            Self::TranscriptConstructionFailed(error) => {
                write!(f, "stark transcript construction failed: {error}")
            }
            Self::OpeningConstructionFailed(error) => {
                write!(f, "trace opening construction failed: {error}")
            }
        }
    }
}

impl std::error::Error for DcmAirStarkProverErrorV1 {}

pub fn prove_dcm_air_stark_scaffold_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
) -> Result<DcmAirStarkProofArtifactV1, DcmAirStarkProverErrorV1> {
    validate_dcm_air_v1(public_inputs, trace)
        .map_err(DcmAirStarkProverErrorV1::AirEvaluationRequired)?;

    let commitment_tree = build_stark_trace_commitment_tree_v1(trace)
        .map_err(DcmAirStarkProverErrorV1::CommitmentConstructionFailed)?;
    let trace_commitment = commitment_tree.commitment();
    let transcript = derive_dcm_air_stark_transcript_v1(public_inputs, &trace_commitment)
        .map_err(DcmAirStarkProverErrorV1::TranscriptConstructionFailed)?;

    let boundary_first_row_opening = commitment_tree
        .open_row(0)
        .map_err(DcmAirStarkProverErrorV1::OpeningConstructionFailed)?;
    let boundary_last_row_opening = commitment_tree
        .open_row(trace_commitment.leaf_count - 1)
        .map_err(DcmAirStarkProverErrorV1::OpeningConstructionFailed)?;

    let queried_transition_openings = if transcript.transition_query_count == 0 {
        None
    } else {
        let row_index = transcript.queried_transition_row_index;
        Some(DcmAirStarkTransitionOpeningsV1 {
            row_index,
            current_row_opening: commitment_tree
                .open_row(row_index)
                .map_err(DcmAirStarkProverErrorV1::OpeningConstructionFailed)?,
            next_row_opening: commitment_tree
                .open_row(row_index + 1)
                .map_err(DcmAirStarkProverErrorV1::OpeningConstructionFailed)?,
        })
    };

    let mut proof_artifact = DcmAirStarkProofArtifactV1 {
        proof_version: DCM_AIR_STARK_PROOF_SCAFFOLD_VERSION_V1,
        trace_commitment_root: trace_commitment.root,
        public_input_digest: transcript.public_input_digest,
        transcript_digest: transcript.transcript_digest,
        query_challenge_digest: transcript.query_challenge_digest,
        boundary_first_row_opening,
        boundary_last_row_opening,
        queried_transition_openings,
        opening_metadata: DcmAirStarkOpeningMetadataV1 {
            trace_row_count: trace_commitment.leaf_count,
            commitment_tree_height: trace_commitment.tree_height,
            transition_query_count: transcript.transition_query_count,
            trace_width: DCM_AIR_TRACE_WIDTH_V1,
            transition_constraint_count: DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1,
        },
        proof_artifact_digest: [0u8; HASH_LEN_V1],
    };
    proof_artifact.proof_artifact_digest =
        derive_dcm_air_stark_proof_artifact_digest_v1(&proof_artifact);

    Ok(proof_artifact)
}

pub(crate) fn derive_dcm_air_stark_proof_artifact_digest_v1(
    proof_artifact: &DcmAirStarkProofArtifactV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_STARK_PROOF_SCAFFOLD_V1_DOMAIN_SEPARATOR,
        &canonical_proof_artifact_bytes_v1(proof_artifact),
    )
}

pub(crate) fn canonical_trace_opening_bytes_v1(opening: &StarkTraceMerkleOpeningV1) -> Vec<u8> {
    let row_bytes = opening.row_value.canonical_bytes();
    let mut bytes =
        Vec::with_capacity(8 + row_bytes.len() + 8 + opening.sibling_hashes.len() * HASH_LEN_V1);
    bytes.extend_from_slice(&opening.row_index.to_le_bytes());
    bytes.extend_from_slice(&row_bytes);
    bytes.extend_from_slice(&(opening.sibling_hashes.len() as u64).to_le_bytes());
    for sibling_hash in &opening.sibling_hashes {
        bytes.extend_from_slice(sibling_hash);
    }
    bytes
}

fn canonical_transition_openings_bytes_v1(
    transition_openings: &Option<DcmAirStarkTransitionOpeningsV1>,
) -> Vec<u8> {
    match transition_openings {
        Some(transition_openings) => {
            let current_bytes =
                canonical_trace_opening_bytes_v1(&transition_openings.current_row_opening);
            let next_bytes =
                canonical_trace_opening_bytes_v1(&transition_openings.next_row_opening);
            let mut bytes = Vec::with_capacity(1 + 8 + current_bytes.len() + next_bytes.len());
            bytes.push(1);
            bytes.extend_from_slice(&transition_openings.row_index.to_le_bytes());
            bytes.extend_from_slice(&current_bytes);
            bytes.extend_from_slice(&next_bytes);
            bytes
        }
        None => vec![0],
    }
}

fn canonical_opening_metadata_bytes_v1(metadata: &DcmAirStarkOpeningMetadataV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 8 + 1 + 1 + 1);
    bytes.extend_from_slice(&metadata.trace_row_count.to_le_bytes());
    bytes.extend_from_slice(&metadata.commitment_tree_height.to_le_bytes());
    bytes.push(metadata.transition_query_count);
    bytes.push(metadata.trace_width);
    bytes.push(metadata.transition_constraint_count);
    bytes
}

fn canonical_proof_artifact_bytes_v1(proof_artifact: &DcmAirStarkProofArtifactV1) -> Vec<u8> {
    let first_opening_bytes =
        canonical_trace_opening_bytes_v1(&proof_artifact.boundary_first_row_opening);
    let last_opening_bytes =
        canonical_trace_opening_bytes_v1(&proof_artifact.boundary_last_row_opening);
    let transition_openings_bytes =
        canonical_transition_openings_bytes_v1(&proof_artifact.queried_transition_openings);
    let opening_metadata_bytes =
        canonical_opening_metadata_bytes_v1(&proof_artifact.opening_metadata);

    let mut bytes = Vec::with_capacity(
        1 + HASH_LEN_V1 * 5
            + first_opening_bytes.len()
            + last_opening_bytes.len()
            + transition_openings_bytes.len()
            + opening_metadata_bytes.len(),
    );
    bytes.push(proof_artifact.proof_version);
    bytes.extend_from_slice(&proof_artifact.trace_commitment_root);
    bytes.extend_from_slice(&proof_artifact.public_input_digest);
    bytes.extend_from_slice(&proof_artifact.transcript_digest);
    bytes.extend_from_slice(&proof_artifact.query_challenge_digest);
    bytes.extend_from_slice(&first_opening_bytes);
    bytes.extend_from_slice(&last_opening_bytes);
    bytes.extend_from_slice(&transition_openings_bytes);
    bytes.extend_from_slice(&opening_metadata_bytes);
    bytes
}

impl fmt::Display for DcmAirStarkProofArtifactV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DcmAirStarkProofArtifactV1 {{ trace_commitment_root: {}, proof_artifact_digest: {} }}",
            LowerHex32(&self.trace_commitment_root),
            LowerHex32(&self.proof_artifact_digest)
        )
    }
}

pub const STORM_AIR_REAL_PROOF_VERSION_V1: u8 = 1;
pub const STORM_AIR_REAL_PROOF_BACKEND_WITNESS_V1: u32 = 2;
pub const STORM_AIR_REAL_PROOF_TRACE_WIDTH_V1: u16 = 8;
pub const STORM_AIR_REAL_PROOF_CONSTRAINT_COUNT_V1: u16 = 2;
pub const AURA_STORM_AIR_REAL_PUBLIC_INPUT_DIGEST_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_STORM_AIR_REAL_PUBLIC_INPUT_DIGEST_V1";
pub const AURA_STORM_AIR_REAL_PROOF_BYTES_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_STORM_AIR_REAL_PROOF_BYTES_V1";
pub const AURA_STORM_AIR_REAL_PROOF_BINDING_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_STORM_AIR_REAL_PROOF_BINDING_V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StormAirRealProofArtifactV1 {
    pub backend_kind: u32,
    pub proof_version: u8,
    pub public_input_digest: [u8; HASH_LEN_V1],
    pub trace_state_count: u64,
    pub internal_trace_length: u64,
    pub trace_width: u16,
    pub backend_constraint_count: u16,
    pub proof_bytes: Vec<u8>,
    pub proof_bytes_digest: [u8; HASH_LEN_V1],
    pub proof_binding_digest: [u8; HASH_LEN_V1],
}

#[derive(Debug, PartialEq, Eq)]
pub enum StormAirRealProverErrorV1 {
    PublicInputsMismatch { field: &'static str },
    WitnessConstructionFailed(StormAirValidationErrorV1),
    WitnessValidationFailed(StormAirValidationErrorV1),
}

impl fmt::Display for StormAirRealProverErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicInputsMismatch { field } => {
                write!(f, "storm public inputs mismatch: {field}")
            }
            Self::WitnessConstructionFailed(error) => {
                write!(f, "storm witness construction failed: {error}")
            }
            Self::WitnessValidationFailed(error) => {
                write!(f, "storm witness validation failed: {error}")
            }
        }
    }
}

impl std::error::Error for StormAirRealProverErrorV1 {}

pub(crate) fn derive_storm_air_real_public_input_digest_v1(
    public_inputs: &StormAirPublicInputsV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_STORM_AIR_REAL_PUBLIC_INPUT_DIGEST_V1_DOMAIN_SEPARATOR,
        &public_inputs.canonical_bytes(),
    )
}

pub(crate) fn derive_storm_air_real_proof_bytes_digest_v1(
    proof_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(AURA_STORM_AIR_REAL_PROOF_BYTES_V1_DOMAIN_SEPARATOR, proof_bytes)
}

pub(crate) fn derive_storm_air_real_proof_binding_digest_v1(
    proof_artifact: &StormAirRealProofArtifactV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_STORM_AIR_REAL_PROOF_BINDING_V1_DOMAIN_SEPARATOR,
        &canonical_storm_real_proof_binding_bytes_v1(proof_artifact),
    )
}

pub fn prove_storm_air_real_v1(
    claim: &StormClaim521V1,
    public_inputs: &StormAirPublicInputsV1,
) -> Result<StormAirRealProofArtifactV1, StormAirRealProverErrorV1> {
    let expected_public_inputs = crate::build_storm_air_public_inputs_v1(claim);
    if &expected_public_inputs != public_inputs {
        return Err(StormAirRealProverErrorV1::PublicInputsMismatch {
            field: "public_inputs",
        });
    }

    let witness = crate::build_storm_trace_witness_v1(claim)
        .map_err(StormAirRealProverErrorV1::WitnessConstructionFailed)?;
    validate_trace_witness_against_claim(claim, &witness)
        .map_err(StormAirRealProverErrorV1::WitnessValidationFailed)?;

    let proof_bytes = canonical_storm_real_proof_bytes_v1(claim, &witness);
    Ok(assemble_storm_air_real_artifact_v1(public_inputs, claim.trace_state_count(), proof_bytes))
}

/// Decode the existing canonical proof wire and reconstruct its derived metadata.
/// This does not verify the proof; callers must run `verify_storm_air_real_v1`.
pub fn decode_storm_air_real_artifact_v1(
    proof_bytes: Vec<u8>,
) -> Result<(StormClaim521V1, StormAirRealProofArtifactV1), StormAirRealProofDecodeErrorV1> {
    let (claim, _) = decode_storm_real_proof_bytes_v1(&proof_bytes)?;
    let count = claim.iteration_count.checked_add(1)
        .ok_or(StormAirRealProofDecodeErrorV1::InvalidTraceStateCount)?;
    let inputs = crate::build_storm_air_public_inputs_v1(&claim);
    let artifact = assemble_storm_air_real_artifact_v1(&inputs, count, proof_bytes);
    Ok((claim, artifact))
}

fn assemble_storm_air_real_artifact_v1(
    public_inputs: &StormAirPublicInputsV1, trace_state_count: u64, proof_bytes: Vec<u8>,
) -> StormAirRealProofArtifactV1 {
    let proof_bytes_digest = derive_storm_air_real_proof_bytes_digest_v1(&proof_bytes);
    let mut proof_artifact = StormAirRealProofArtifactV1 {
        backend_kind: STORM_AIR_REAL_PROOF_BACKEND_WITNESS_V1,
        proof_version: STORM_AIR_REAL_PROOF_VERSION_V1,
        public_input_digest: derive_storm_air_real_public_input_digest_v1(public_inputs),
        trace_state_count,
        internal_trace_length: trace_state_count,
        trace_width: STORM_AIR_REAL_PROOF_TRACE_WIDTH_V1,
        backend_constraint_count: STORM_AIR_REAL_PROOF_CONSTRAINT_COUNT_V1,
        proof_bytes,
        proof_bytes_digest,
        proof_binding_digest: [0u8; HASH_LEN_V1],
    };
    proof_artifact.proof_binding_digest =
        derive_storm_air_real_proof_binding_digest_v1(&proof_artifact);
    proof_artifact
}

pub(crate) fn canonical_storm_real_proof_bytes_v1(
    claim: &StormClaim521V1,
    witness: &StormTraceWitnessV1,
) -> Vec<u8> {
    let claim_bytes = claim.canonical_bytes();
    let witness_bytes = crate::canonical_storm_trace_witness_bytes_v1(witness);
    let mut bytes = Vec::with_capacity(8 + claim_bytes.len() + 8 + witness_bytes.len());
    bytes.extend_from_slice(&(claim_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&claim_bytes);
    bytes.extend_from_slice(&(witness_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&witness_bytes);
    bytes
}

pub(crate) fn decode_storm_real_proof_bytes_v1(
    proof_bytes: &[u8],
) -> Result<(StormClaim521V1, StormTraceWitnessV1), StormAirRealProofDecodeErrorV1> {
    let mut offset = 0usize;
    let claim_len = read_u64_from_bytes_v1(proof_bytes, &mut offset, "claim_len")? as usize;
    let claim = crate::decode_storm_claim_canonical_bytes_v1(read_bytes_from_bytes_v1(
        proof_bytes,
        &mut offset,
        claim_len,
        "claim",
    )?)
    .map_err(StormAirRealProofDecodeErrorV1::ClaimDecode)?;
    let witness_len = read_u64_from_bytes_v1(proof_bytes, &mut offset, "witness_len")? as usize;
    let witness = crate::decode_storm_trace_witness_bytes_v1(read_bytes_from_bytes_v1(
        proof_bytes,
        &mut offset,
        witness_len,
        "witness",
    )?)
    .map_err(StormAirRealProofDecodeErrorV1::WitnessDecode)?;
    if offset != proof_bytes.len() {
        return Err(StormAirRealProofDecodeErrorV1::TrailingBytes {
            remaining: proof_bytes.len() - offset,
        });
    }
    Ok((claim, witness))
}

#[derive(Debug, PartialEq, Eq)]
pub enum StormAirRealProofDecodeErrorV1 {
    InvalidTraceStateCount,
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    ClaimDecode(StormClaimEncodingErrorV1),
    WitnessDecode(crate::StormTraceWitnessEncodingErrorV1),
    TrailingBytes {
        remaining: usize,
    },
}

impl fmt::Display for StormAirRealProofDecodeErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTraceStateCount => write!(f, "storm proof trace state count overflows"),
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid storm proof length for {field}: expected {expected} bytes, got {actual}"
            ),
            Self::ClaimDecode(error) => write!(f, "storm proof claim decode failed: {error}"),
            Self::WitnessDecode(error) => write!(f, "storm proof witness decode failed: {error}"),
            Self::TrailingBytes { remaining } => {
                write!(f, "storm proof decode left {remaining} trailing bytes")
            }
        }
    }
}

impl std::error::Error for StormAirRealProofDecodeErrorV1 {}

fn canonical_storm_real_proof_binding_bytes_v1(
    proof_artifact: &StormAirRealProofArtifactV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 1 + HASH_LEN_V1 * 2 + 8 + 8 + 2 + 2);
    bytes.extend_from_slice(&proof_artifact.backend_kind.to_le_bytes());
    bytes.push(proof_artifact.proof_version);
    bytes.extend_from_slice(&proof_artifact.public_input_digest);
    bytes.extend_from_slice(&proof_artifact.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.internal_trace_length.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.trace_width.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.backend_constraint_count.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.proof_bytes_digest);
    bytes
}

fn read_u64_from_bytes_v1(
    bytes: &[u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<u64, StormAirRealProofDecodeErrorV1> {
    let slice = read_bytes_from_bytes_v1(bytes, offset, 8, field)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Ok(u64::from_le_bytes(raw))
}

fn read_bytes_from_bytes_v1<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], StormAirRealProofDecodeErrorV1> {
    if bytes.len().saturating_sub(*offset) < len {
        return Err(StormAirRealProofDecodeErrorV1::InvalidLength {
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

pub const DCM_AIR_REAL_STARK_PROOF_VERSION_V1: u8 = 1;
pub const DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1: u32 = 1;
pub const AURA_DCM_AIR_REAL_STARK_PROOF_BYTES_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_AIR_REAL_STARK_PROOF_BYTES_V1";
pub const AURA_DCM_AIR_REAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_AIR_REAL_STARK_PROOF_BINDING_V1";

const DCM_AIR_REAL_STARK_MIN_TRACE_LENGTH_V1: usize = 8;
const DCM_AIR_REAL_STARK_DIGIT_COUNT_V1: usize = 75;
const DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1: usize = 4;
const DCM_AIR_REAL_STARK_LIMB_COUNT_V1: usize =
    (DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 + DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1 - 1)
        / DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1;
const DCM_AIR_REAL_STARK_CARRY_COLUMN_COUNT_V1: usize = DCM_AIR_REAL_STARK_LIMB_COUNT_V1 - 1;
const DCM_AIR_REAL_STARK_LIMB_BASE_V1: u64 = 268_435_456;
const DCM_AIR_REAL_STARK_X_DIGIT_START_V1: usize = 0;
const DCM_AIR_REAL_STARK_Y_DIGIT_START_V1: usize =
    DCM_AIR_REAL_STARK_X_DIGIT_START_V1 + DCM_AIR_REAL_STARK_DIGIT_COUNT_V1;
const DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1: usize =
    DCM_AIR_REAL_STARK_Y_DIGIT_START_V1 + DCM_AIR_REAL_STARK_DIGIT_COUNT_V1;
const DCM_AIR_REAL_STARK_QX_COLUMN_V1: usize = DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1 + 1;
const DCM_AIR_REAL_STARK_QY_COLUMN_V1: usize = DCM_AIR_REAL_STARK_QX_COLUMN_V1 + 1;
const DCM_AIR_REAL_STARK_X_NON_MAX_INV_COLUMN_V1: usize = DCM_AIR_REAL_STARK_QY_COLUMN_V1 + 1;
const DCM_AIR_REAL_STARK_Y_NON_MAX_INV_COLUMN_V1: usize =
    DCM_AIR_REAL_STARK_X_NON_MAX_INV_COLUMN_V1 + 1;
const DCM_AIR_REAL_STARK_X_CARRY_START_V1: usize = DCM_AIR_REAL_STARK_Y_NON_MAX_INV_COLUMN_V1 + 1;
const DCM_AIR_REAL_STARK_Y_CARRY_START_V1: usize =
    DCM_AIR_REAL_STARK_X_CARRY_START_V1 + DCM_AIR_REAL_STARK_CARRY_COLUMN_COUNT_V1;
const DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1: usize =
    DCM_AIR_REAL_STARK_Y_CARRY_START_V1 + DCM_AIR_REAL_STARK_CARRY_COLUMN_COUNT_V1;
const DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1: usize =
    DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1 + 1;
pub const DCM_AIR_REAL_STARK_TRACE_WIDTH_V1: usize = DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1 + 1;
pub const DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1: usize = 234;
const DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1: usize = 2;
const DCM_AIR_REAL_STARK_COMMITMENT_ROOT_BYTE_LEN_V1: usize = 32;
const DCM_AIR_REAL_STARK_COMMITMENT_SEED_0_V1: u128 = 0x415552415f4341545f524f4f545f3031;
const DCM_AIR_REAL_STARK_COMMITMENT_SEED_1_V1: u128 = 0x415552415f4341545f524f4f545f3032;
const DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_0_V1: u128 = 17;
const DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_1_V1: u128 = 29;
const DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_0_V1: u128 = 0x4341545f524f575f434f4d4d49545f30;
const DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_1_V1: u128 = 0x4341545f524f575f434f4d4d49545f31;
const DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_0_V1: u128 = 131;
const DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_0_V1: u128 = 137;
const DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_1_V1: u128 = 149;
const DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_1_V1: u128 = 151;
const DCM_AIR_REAL_STARK_COMMITMENT_MIX_0_V1: u128 = 17;
const DCM_AIR_REAL_STARK_COMMITMENT_MIX_1_V1: u128 = 19;
const DCM_AIR_REAL_STARK_COMMITMENT_CONST_0_V1: u128 = 0x524f4f545f4d49585f4341545f303031;
const DCM_AIR_REAL_STARK_COMMITMENT_CONST_1_V1: u128 = 0x524f4f545f4d49585f4341545f303032;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirWinterfellPublicInputsV1 {
    pub air_public_inputs: DcmAirPublicInputsV1,
}

impl ToElements<BaseElement> for DcmAirWinterfellPublicInputsV1 {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.air_public_inputs
            .canonical_bytes()
            .into_iter()
            .map(|byte| BaseElement::new(u128::from(byte)))
            .collect()
    }
}

pub fn derive_dcm_air_commitment_root_521_v1(
    config: &DcmConfig521V1,
    states: &[DcmState521V1],
) -> [u8; HASH_LEN_V1] {
    let elements = derive_dcm_air_commitment_root_elements_521_v1(config.iteration_count, states);
    commitment_root_bytes_from_elements_v1(elements)
}

fn derive_dcm_air_commitment_root_elements_521_v1(
    iteration_count: u64,
    states: &[DcmState521V1],
) -> [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1] {
    let mut commitment_state = commitment_seed_v1::<BaseElement>(iteration_count);
    for state in states {
        commitment_state = absorb_commitment_from_state_v1(commitment_state, *state);
    }
    commitment_state
}

fn commitment_root_bytes_from_elements_v1(
    elements: [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1],
) -> [u8; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_BYTE_LEN_V1] {
    let mut bytes = [0u8; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_BYTE_LEN_V1];
    for (index, element) in elements.into_iter().enumerate() {
        let start = index * 16;
        bytes[start..start + 16].copy_from_slice(&element.as_int().to_le_bytes());
    }
    bytes
}

fn commitment_root_elements_from_bytes_v1(
    bytes: &[u8; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_BYTE_LEN_V1],
) -> [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1] {
    let mut elements = [BaseElement::ZERO; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1];
    for (index, element) in elements.iter_mut().enumerate() {
        let start = index * 16;
        let mut limb_bytes = [0u8; 16];
        limb_bytes.copy_from_slice(&bytes[start..start + 16]);
        *element = BaseElement::new(u128::from_le_bytes(limb_bytes));
    }
    elements
}

fn commitment_seed_v1<E: FieldElement<BaseField = BaseElement>>(iteration_count: u64) -> [E; 2] {
    let iteration = E::from(BaseElement::new(u128::from(iteration_count)));
    [
        E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_SEED_0_V1))
            + iteration
                * E::from(BaseElement::new(
                    DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_0_V1,
                )),
        E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_SEED_1_V1))
            + iteration
                * E::from(BaseElement::new(
                    DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_1_V1,
                )),
    ]
}

fn absorb_commitment_from_state_v1(
    previous: [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1],
    state: DcmState521V1,
) -> [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1] {
    let (x_digits, y_digits) = state_coordinate_digits_le_v1(state);
    absorb_commitment_from_digits_v1(previous, &x_digits, &y_digits)
}

fn absorb_commitment_from_digits_v1(
    previous: [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1],
    x_digits: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    y_digits: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
) -> [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1] {
    let [row_lo, row_hi] = commitment_row_contribution_from_digits_v1(x_digits, y_digits);
    [
        previous[0] * BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_MIX_0_V1)
            + previous[1] * previous[1]
            + row_lo
            + BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_CONST_0_V1),
        previous[1] * BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_MIX_1_V1)
            + previous[0] * previous[0]
            + row_hi
            + BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_CONST_1_V1),
    ]
}

fn commitment_row_contribution_from_digits_v1(
    x_digits: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    y_digits: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
) -> [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1] {
    let mut acc_lo = BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_0_V1);
    let mut acc_hi = BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_1_V1);
    let mut x_power_lo = BaseElement::ONE;
    let mut y_power_lo = BaseElement::ONE;
    let mut x_power_hi = BaseElement::ONE;
    let mut y_power_hi = BaseElement::ONE;
    let x_base_lo = BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_0_V1);
    let y_base_lo = BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_0_V1);
    let x_base_hi = BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_1_V1);
    let y_base_hi = BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_1_V1);

    for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
        let x_digit = BaseElement::new(u128::from(x_digits[digit_index]));
        let y_digit = BaseElement::new(u128::from(y_digits[digit_index]));
        acc_lo += x_digit * x_power_lo + y_digit * y_power_lo;
        acc_hi += x_digit * x_power_hi + y_digit * y_power_hi;
        x_power_lo *= x_base_lo;
        y_power_lo *= y_base_lo;
        x_power_hi *= x_base_hi;
        y_power_hi *= y_base_hi;
    }

    [acc_lo, acc_hi]
}

fn commitment_row_contribution_from_trace_row_v1<E: FieldElement<BaseField = BaseElement>>(
    row: &[E],
    x_digit_start: usize,
    y_digit_start: usize,
) -> [E; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1] {
    let mut acc_lo = E::from(BaseElement::new(
        DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_0_V1,
    ));
    let mut acc_hi = E::from(BaseElement::new(
        DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_1_V1,
    ));
    let mut x_power_lo = E::ONE;
    let mut y_power_lo = E::ONE;
    let mut x_power_hi = E::ONE;
    let mut y_power_hi = E::ONE;
    let x_base_lo = E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_0_V1));
    let y_base_lo = E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_0_V1));
    let x_base_hi = E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_1_V1));
    let y_base_hi = E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_1_V1));

    for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
        let x_digit = row[x_digit_start + digit_index];
        let y_digit = row[y_digit_start + digit_index];
        acc_lo += x_digit * x_power_lo + y_digit * y_power_lo;
        acc_hi += x_digit * x_power_hi + y_digit * y_power_hi;
        x_power_lo *= x_base_lo;
        y_power_lo *= y_base_lo;
        x_power_hi *= x_base_hi;
        y_power_hi *= y_base_hi;
    }

    [acc_lo, acc_hi]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcmAirRealStarkProofArtifactV1 {
    pub backend_kind: u32,
    pub proof_version: u8,
    pub public_input_digest: [u8; HASH_LEN_V1],
    pub trace_state_count: u64,
    pub internal_trace_length: u64,
    pub trace_width: u16,
    pub backend_constraint_count: u16,
    pub proof_bytes: Vec<u8>,
    pub proof_bytes_digest: [u8; HASH_LEN_V1],
    pub proof_binding_digest: [u8; HASH_LEN_V1],
}

#[derive(Debug)]
pub enum DcmAirRealStarkProverErrorV1 {
    AirEvaluationRequired(DcmAirErrorV1),
    UnsupportedTraceLength {
        actual: u64,
    },
    InvalidTransitionWitness {
        row_index: u64,
        relation: &'static str,
    },
    WinterfellProver(ProverError),
}

impl fmt::Display for DcmAirRealStarkProverErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AirEvaluationRequired(error) => {
                write!(
                    f,
                    "air evaluation required before real stark proving: {error}"
                )
            }
            Self::UnsupportedTraceLength { actual } => {
                write!(f, "unsupported real stark trace length: {actual}")
            }
            Self::InvalidTransitionWitness {
                row_index,
                relation,
            } => write!(
                f,
                "invalid transition witness at row {row_index}: {relation}"
            ),
            Self::WinterfellProver(error) => write!(f, "winterfell prover error: {error}"),
        }
    }
}

impl std::error::Error for DcmAirRealStarkProverErrorV1 {}

pub(crate) fn derive_dcm_air_winterfell_public_inputs_v1(
    public_inputs: &DcmAirPublicInputsV1,
) -> DcmAirWinterfellPublicInputsV1 {
    DcmAirWinterfellPublicInputsV1 {
        air_public_inputs: *public_inputs,
    }
}

pub(crate) fn derive_dcm_air_real_stark_proof_bytes_digest_v1(
    proof_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_REAL_STARK_PROOF_BYTES_DOMAIN_SEPARATOR,
        proof_bytes,
    )
}

pub(crate) fn derive_dcm_air_real_stark_proof_binding_digest_v1(
    proof_artifact: &DcmAirRealStarkProofArtifactV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_AIR_REAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR,
        &canonical_real_stark_proof_binding_bytes_v1(proof_artifact),
    )
}

pub fn prove_dcm_air_real_stark_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace: &DcmAirTraceV1,
) -> Result<DcmAirRealStarkProofArtifactV1, DcmAirRealStarkProverErrorV1> {
    validate_dcm_air_v1(public_inputs, trace)
        .map_err(DcmAirRealStarkProverErrorV1::AirEvaluationRequired)?;

    let trace_state_count = trace.row_count();
    let internal_trace_length = derive_real_stark_internal_trace_length_v1(trace_state_count)?;
    let trace_table = build_dcm_air_real_stark_trace_table_v1(trace)?;
    let winterfell_public_inputs = derive_dcm_air_winterfell_public_inputs_v1(public_inputs);
    let prover = DcmAirRealStarkWinterfellProverV1::new(
        default_dcm_air_real_stark_proof_options_v1(),
        winterfell_public_inputs,
    );
    let proof = prover
        .prove(trace_table)
        .map_err(DcmAirRealStarkProverErrorV1::WinterfellProver)?;
    let proof_bytes = proof.to_bytes();
    let proof_bytes_digest = derive_dcm_air_real_stark_proof_bytes_digest_v1(&proof_bytes);

    let mut proof_artifact = DcmAirRealStarkProofArtifactV1 {
        backend_kind: DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1,
        proof_version: DCM_AIR_REAL_STARK_PROOF_VERSION_V1,
        public_input_digest: crate::derive_dcm_air_stark_public_input_digest_v1(public_inputs),
        trace_state_count,
        internal_trace_length: internal_trace_length as u64,
        trace_width: DCM_AIR_REAL_STARK_TRACE_WIDTH_V1 as u16,
        backend_constraint_count: DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1 as u16,
        proof_bytes,
        proof_bytes_digest,
        proof_binding_digest: [0u8; HASH_LEN_V1],
    };
    proof_artifact.proof_binding_digest =
        derive_dcm_air_real_stark_proof_binding_digest_v1(&proof_artifact);

    Ok(proof_artifact)
}

fn canonical_real_stark_proof_binding_bytes_v1(
    proof_artifact: &DcmAirRealStarkProofArtifactV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 1 + HASH_LEN_V1 * 2 + 8 + 8 + 2 + 2);
    bytes.extend_from_slice(&proof_artifact.backend_kind.to_le_bytes());
    bytes.push(proof_artifact.proof_version);
    bytes.extend_from_slice(&proof_artifact.public_input_digest);
    bytes.extend_from_slice(&proof_artifact.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.internal_trace_length.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.trace_width.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.backend_constraint_count.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.proof_bytes_digest);
    bytes
}

fn default_dcm_air_real_stark_proof_options_v1() -> ProofOptions {
    ProofOptions::new(
        32,
        128,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub(crate) fn derive_real_stark_internal_trace_length_v1(
    trace_state_count: u64,
) -> Result<usize, DcmAirRealStarkProverErrorV1> {
    let active_rows: usize = trace_state_count.try_into().map_err(|_| {
        DcmAirRealStarkProverErrorV1::UnsupportedTraceLength {
            actual: trace_state_count,
        }
    })?;
    Ok(active_rows
        .max(1)
        .next_power_of_two()
        .max(DCM_AIR_REAL_STARK_MIN_TRACE_LENGTH_V1))
}

fn build_dcm_air_real_stark_trace_table_v1(
    trace: &DcmAirTraceV1,
) -> Result<TraceTable<BaseElement>, DcmAirRealStarkProverErrorV1> {
    let active_row_count = trace.rows().len();
    let trace_length = derive_real_stark_internal_trace_length_v1(trace.row_count())?;
    let mut table = TraceTable::new(DCM_AIR_REAL_STARK_TRACE_WIDTH_V1, trace_length);
    let iteration_count = trace.row_count().saturating_sub(1);

    if active_row_count == 0 {
        let commitment_state = commitment_seed_v1::<BaseElement>(iteration_count);
        for row_index in 0..trace_length {
            set_real_stark_trace_row_v1(
                &mut table,
                row_index,
                DcmState521V1::from_u64(0, 0),
                None,
                false,
                commitment_state,
            )?;
        }
        return Ok(table);
    }

    let mut commitment_state = commitment_seed_v1::<BaseElement>(iteration_count);
    for (row_index, current_row) in trace.rows().iter().copied().enumerate() {
        commitment_state = absorb_commitment_from_state_v1(commitment_state, current_row);
        let next_row = if row_index + 1 < active_row_count {
            Some(trace.rows()[row_index + 1])
        } else {
            None
        };
        set_real_stark_trace_row_v1(
            &mut table,
            row_index,
            current_row,
            next_row,
            true,
            commitment_state,
        )?;
    }

    for row_index in active_row_count..trace_length {
        set_real_stark_trace_row_v1(
            &mut table,
            row_index,
            DcmState521V1::from_u64(0, 0),
            None,
            false,
            commitment_state,
        )?;
    }

    Ok(table)
}

fn set_real_stark_trace_row_v1(
    trace: &mut TraceTable<BaseElement>,
    row_index: usize,
    current_row: DcmState521V1,
    next_row: Option<DcmState521V1>,
    active: bool,
    commitment_state: [BaseElement; DCM_AIR_REAL_STARK_COMMITMENT_ROOT_ELEMENT_COUNT_V1],
) -> Result<(), DcmAirRealStarkProverErrorV1> {
    let (current_x_digits, current_y_digits) = state_coordinate_digits_le_v1(current_row);
    let x_non_max_inverse = canonical_non_max_inverse_v1(&current_x_digits, active);
    let y_non_max_inverse = canonical_non_max_inverse_v1(&current_y_digits, active);
    let (qx, qy, x_carries, y_carries) = match next_row {
        Some(next_row) if active => {
            let (next_x_digits, next_y_digits) = state_coordinate_digits_le_v1(next_row);
            let (qx, x_carries) = solve_mod_relation_v1(
                &current_x_digits,
                &current_y_digits,
                &next_x_digits,
                1,
                1,
                1,
            )
            .ok_or(DcmAirRealStarkProverErrorV1::InvalidTransitionWitness {
                row_index: row_index as u64,
                relation: "x_next = x + y mod (2^521 - 1)",
            })?;
            let (qy, y_carries) = solve_mod_relation_v1(
                &current_x_digits,
                &current_y_digits,
                &next_y_digits,
                2,
                2,
                2,
            )
            .ok_or(DcmAirRealStarkProverErrorV1::InvalidTransitionWitness {
                row_index: row_index as u64,
                relation: "y_next = x + 2y mod (2^521 - 1)",
            })?;
            (qx, qy, x_carries, y_carries)
        }
        _ => (
            0u8,
            0u8,
            [0u8; DCM_AIR_REAL_STARK_LIMB_COUNT_V1],
            [0u8; DCM_AIR_REAL_STARK_LIMB_COUNT_V1],
        ),
    };

    for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
        trace.set(
            real_stark_x_digit_column_v1(digit_index),
            row_index,
            base_from_u8_v1(current_x_digits[digit_index]),
        );
        trace.set(
            real_stark_y_digit_column_v1(digit_index),
            row_index,
            base_from_u8_v1(current_y_digits[digit_index]),
        );
    }

    for carry_index in 1..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
        trace.set(
            real_stark_x_carry_column_v1(carry_index),
            row_index,
            base_from_u8_v1(x_carries[carry_index]),
        );
        trace.set(
            real_stark_y_carry_column_v1(carry_index),
            row_index,
            base_from_u8_v1(y_carries[carry_index]),
        );
    }

    trace.set(
        DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1,
        row_index,
        if active {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        },
    );
    trace.set(
        DCM_AIR_REAL_STARK_QX_COLUMN_V1,
        row_index,
        base_from_u8_v1(qx),
    );
    trace.set(
        DCM_AIR_REAL_STARK_QY_COLUMN_V1,
        row_index,
        base_from_u8_v1(qy),
    );
    trace.set(
        DCM_AIR_REAL_STARK_X_NON_MAX_INV_COLUMN_V1,
        row_index,
        x_non_max_inverse,
    );
    trace.set(
        DCM_AIR_REAL_STARK_Y_NON_MAX_INV_COLUMN_V1,
        row_index,
        y_non_max_inverse,
    );
    trace.set(
        DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1,
        row_index,
        commitment_state[0],
    );
    trace.set(
        DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1,
        row_index,
        commitment_state[1],
    );

    Ok(())
}

fn solve_mod_relation_v1(
    lhs_x: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    lhs_y: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    next: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    y_scale: u8,
    max_quotient: u8,
    max_carry: u8,
) -> Option<(u8, [u8; DCM_AIR_REAL_STARK_LIMB_COUNT_V1])> {
    let modulus = u28_limbs_from_digits_le_v1(&field_modulus_521_digits_le_v1());
    let lhs_x_limbs = u28_limbs_from_digits_le_v1(lhs_x);
    let lhs_y_limbs = u28_limbs_from_digits_le_v1(lhs_y);
    let next_limbs = u28_limbs_from_digits_le_v1(next);

    for quotient in 0..=max_quotient {
        let mut carries = [0u8; DCM_AIR_REAL_STARK_LIMB_COUNT_V1];
        let mut carry_in = 0u64;
        let mut valid = true;

        for limb_index in 0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
            let total = u64::from(lhs_x_limbs[limb_index])
                + u64::from(y_scale) * u64::from(lhs_y_limbs[limb_index])
                + carry_in;
            let rhs = u64::from(next_limbs[limb_index])
                + u64::from(quotient) * u64::from(modulus[limb_index]);
            if total < rhs {
                valid = false;
                break;
            }

            let diff = total - rhs;
            if limb_index + 1 == DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
                if diff != 0 {
                    valid = false;
                }
                break;
            }
            if diff % DCM_AIR_REAL_STARK_LIMB_BASE_V1 != 0 {
                valid = false;
                break;
            }

            let carry_out = diff / DCM_AIR_REAL_STARK_LIMB_BASE_V1;
            if carry_out > u64::from(max_carry) {
                valid = false;
                break;
            }
            carries[limb_index + 1] = carry_out as u8;
            carry_in = carry_out;
        }

        if valid {
            return Some((quotient, carries));
        }
    }

    None
}

fn canonical_non_max_inverse_v1(
    digits_le: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    active: bool,
) -> BaseElement {
    if !active || digits_le[DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1] != 7 {
        return BaseElement::ZERO;
    }

    let sum = digits_le[..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1]
        .iter()
        .map(|digit| {
            let delta = u64::from(127u8.saturating_sub(*digit));
            delta * delta
        })
        .sum::<u64>();
    debug_assert!(sum != 0);

    BaseElement::new(u128::from(sum)).inv()
}

fn state_coordinate_digits_le_v1(
    state: DcmState521V1,
) -> (
    [u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
    [u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
) {
    (
        digits_le_from_field_element_v1(&state.x),
        digits_le_from_field_element_v1(&state.y),
    )
}

fn field_modulus_521_digits_le_v1() -> [u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1] {
    let mut digits = [127u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1];
    digits[DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1] = 7;
    digits
}

fn base_from_u8_v1(value: u8) -> BaseElement {
    BaseElement::new(u128::from(value))
}

const fn real_stark_x_digit_column_v1(digit_index: usize) -> usize {
    DCM_AIR_REAL_STARK_X_DIGIT_START_V1 + digit_index
}

const fn real_stark_y_digit_column_v1(digit_index: usize) -> usize {
    DCM_AIR_REAL_STARK_Y_DIGIT_START_V1 + digit_index
}

const fn real_stark_x_carry_column_v1(carry_index: usize) -> usize {
    DCM_AIR_REAL_STARK_X_CARRY_START_V1 + carry_index - 1
}

const fn real_stark_y_carry_column_v1(carry_index: usize) -> usize {
    DCM_AIR_REAL_STARK_Y_CARRY_START_V1 + carry_index - 1
}

fn carry_value_from_row_v1<E: FieldElement<BaseField = BaseElement>>(
    row: &[E],
    carry_start: usize,
    carry_index: usize,
) -> E {
    if carry_index == 0 {
        E::ZERO
    } else {
        row[carry_start + carry_index - 1]
    }
}

#[derive(Clone)]
pub(crate) struct DcmAirRealStarkWinterfellAirV1 {
    context: AirContext<BaseElement>,
    public_inputs: DcmAirPublicInputsV1,
    active_row_count: u64,
    trace_length: usize,
}

impl Air for DcmAirRealStarkWinterfellAirV1 {
    type BaseField = BaseElement;
    type PublicInputs = DcmAirWinterfellPublicInputsV1;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), DCM_AIR_REAL_STARK_TRACE_WIDTH_V1);
        let active_row_count = pub_inputs.air_public_inputs.iteration_count + 1;
        let expected_trace_length = active_row_count
            .max(1)
            .next_power_of_two()
            .max(DCM_AIR_REAL_STARK_MIN_TRACE_LENGTH_V1 as u64)
            as usize;
        assert_eq!(trace_info.length(), expected_trace_length);

        let mut degrees = Vec::with_capacity(DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1);
        degrees.extend(
            (0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1)
                .map(|_| TransitionConstraintDegree::new(128)),
        );
        degrees.push(TransitionConstraintDegree::new(8));
        degrees.extend(
            (0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1)
                .map(|_| TransitionConstraintDegree::new(128)),
        );
        degrees.push(TransitionConstraintDegree::new(8));
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(11));
        degrees.push(TransitionConstraintDegree::new(3));
        degrees.push(TransitionConstraintDegree::new(11));
        degrees.push(TransitionConstraintDegree::new(3));
        degrees.push(TransitionConstraintDegree::new(3));
        degrees.push(TransitionConstraintDegree::new(4));
        degrees.extend(
            (0..DCM_AIR_REAL_STARK_CARRY_COLUMN_COUNT_V1)
                .map(|_| TransitionConstraintDegree::new(3)),
        );
        degrees.extend(
            (0..DCM_AIR_REAL_STARK_CARRY_COLUMN_COUNT_V1)
                .map(|_| TransitionConstraintDegree::new(4)),
        );
        degrees.extend(
            (0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1).map(|_| TransitionConstraintDegree::new(2)),
        );
        degrees.extend(
            (0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1).map(|_| TransitionConstraintDegree::new(2)),
        );
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));
        debug_assert_eq!(
            degrees.len(),
            DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1
        );

        let digit_assertion_count = if active_row_count == 1 {
            DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 * 2
        } else {
            DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 * 4
        };
        let mut assertion_count = digit_assertion_count + 3;
        if active_row_count > 1 {
            assertion_count += 3;
        }
        if (active_row_count as usize) < expected_trace_length {
            assertion_count += 1;
        }

        Self {
            context: AirContext::new(trace_info, degrees, assertion_count, options),
            public_inputs: pub_inputs.air_public_inputs,
            active_row_count,
            trace_length: expected_trace_length,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let zero = E::ZERO;
        let active = current[DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1];
        let next_active = next[DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1];
        let base_127 = E::from(BaseElement::new(127));
        let mut index = 0usize;

        for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1 {
            result[index] = evaluate_range_polynomial_v1(
                current[real_stark_x_digit_column_v1(digit_index)],
                127,
            );
            index += 1;
        }
        result[index] = evaluate_range_polynomial_v1(
            current[real_stark_x_digit_column_v1(DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1)],
            7,
        );
        index += 1;

        for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1 {
            result[index] = evaluate_range_polynomial_v1(
                current[real_stark_y_digit_column_v1(digit_index)],
                127,
            );
            index += 1;
        }
        result[index] = evaluate_range_polynomial_v1(
            current[real_stark_y_digit_column_v1(DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1)],
            7,
        );
        index += 1;

        result[index] = active * (active - one);
        index += 1;
        result[index] = next_active * (one - active);
        index += 1;

        let mut x_non_max_sum = zero;
        for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1 {
            let delta = base_127 - current[real_stark_x_digit_column_v1(digit_index)];
            x_non_max_sum += delta * delta;
        }
        let x_top = current[real_stark_x_digit_column_v1(DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1)];
        let x_top_max_selector = top_digit_max_selector_v1(x_top);
        result[index] = active
            * (x_top_max_selector
                * x_non_max_sum
                * current[DCM_AIR_REAL_STARK_X_NON_MAX_INV_COLUMN_V1]
                - x_top_max_selector);
        index += 1;
        result[index] = active
            * (x_top - E::from(BaseElement::new(7)))
            * current[DCM_AIR_REAL_STARK_X_NON_MAX_INV_COLUMN_V1];
        index += 1;

        let mut y_non_max_sum = zero;
        for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1 {
            let delta = base_127 - current[real_stark_y_digit_column_v1(digit_index)];
            y_non_max_sum += delta * delta;
        }
        let y_top = current[real_stark_y_digit_column_v1(DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 - 1)];
        let y_top_max_selector = top_digit_max_selector_v1(y_top);
        result[index] = active
            * (y_top_max_selector
                * y_non_max_sum
                * current[DCM_AIR_REAL_STARK_Y_NON_MAX_INV_COLUMN_V1]
                - y_top_max_selector);
        index += 1;
        result[index] = active
            * (y_top - E::from(BaseElement::new(7)))
            * current[DCM_AIR_REAL_STARK_Y_NON_MAX_INV_COLUMN_V1];
        index += 1;

        let qx = current[DCM_AIR_REAL_STARK_QX_COLUMN_V1];
        let qy = current[DCM_AIR_REAL_STARK_QY_COLUMN_V1];
        result[index] = next_active * qx * (qx - one);
        index += 1;
        result[index] = next_active * qy * (qy - one) * (qy - E::from(BaseElement::new(2)));
        index += 1;
        for carry_index in 1..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
            let carry =
                carry_value_from_row_v1(current, DCM_AIR_REAL_STARK_X_CARRY_START_V1, carry_index);
            result[index] = next_active * carry * (carry - one);
            index += 1;
        }
        for carry_index in 1..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
            let carry =
                carry_value_from_row_v1(current, DCM_AIR_REAL_STARK_Y_CARRY_START_V1, carry_index);
            result[index] =
                next_active * carry * (carry - one) * (carry - E::from(BaseElement::new(2)));
            index += 1;
        }

        let modulus_limbs = u28_limbs_from_digits_le_v1(&field_modulus_521_digits_le_v1());
        let limb_base = E::from(BaseElement::new(u128::from(
            DCM_AIR_REAL_STARK_LIMB_BASE_V1,
        )));
        for limb_index in 0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
            let carry_out = if limb_index + 1 < DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
                limb_base
                    * carry_value_from_row_v1(
                        current,
                        DCM_AIR_REAL_STARK_X_CARRY_START_V1,
                        limb_index + 1,
                    )
            } else {
                zero
            };
            result[index] = next_active
                * (limb_value_from_row_v1(
                    current,
                    DCM_AIR_REAL_STARK_X_DIGIT_START_V1,
                    limb_index,
                ) + limb_value_from_row_v1(
                    current,
                    DCM_AIR_REAL_STARK_Y_DIGIT_START_V1,
                    limb_index,
                ) + carry_value_from_row_v1(
                    current,
                    DCM_AIR_REAL_STARK_X_CARRY_START_V1,
                    limb_index,
                ) - limb_value_from_row_v1(
                    next,
                    DCM_AIR_REAL_STARK_X_DIGIT_START_V1,
                    limb_index,
                ) - qx * E::from(BaseElement::new(u128::from(modulus_limbs[limb_index])))
                    - carry_out);
            index += 1;
        }

        for limb_index in 0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
            let carry_out = if limb_index + 1 < DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
                limb_base
                    * carry_value_from_row_v1(
                        current,
                        DCM_AIR_REAL_STARK_Y_CARRY_START_V1,
                        limb_index + 1,
                    )
            } else {
                zero
            };
            let y_limb =
                limb_value_from_row_v1(current, DCM_AIR_REAL_STARK_Y_DIGIT_START_V1, limb_index);
            result[index] = next_active
                * (limb_value_from_row_v1(
                    current,
                    DCM_AIR_REAL_STARK_X_DIGIT_START_V1,
                    limb_index,
                ) + y_limb
                    + y_limb
                    + carry_value_from_row_v1(
                        current,
                        DCM_AIR_REAL_STARK_Y_CARRY_START_V1,
                        limb_index,
                    )
                    - limb_value_from_row_v1(
                        next,
                        DCM_AIR_REAL_STARK_Y_DIGIT_START_V1,
                        limb_index,
                    )
                    - qy * E::from(BaseElement::new(u128::from(modulus_limbs[limb_index])))
                    - carry_out);
            index += 1;
        }

        let row_contribution = commitment_row_contribution_from_trace_row_v1(
            next,
            DCM_AIR_REAL_STARK_X_DIGIT_START_V1,
            DCM_AIR_REAL_STARK_Y_DIGIT_START_V1,
        );
        let absorbed_next_commitment = [
            current[DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1]
                * E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_MIX_0_V1))
                + current[DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1]
                    * current[DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1]
                + row_contribution[0]
                + E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_CONST_0_V1)),
            current[DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1]
                * E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_MIX_1_V1))
                + current[DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1]
                    * current[DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1]
                + row_contribution[1]
                + E::from(BaseElement::new(DCM_AIR_REAL_STARK_COMMITMENT_CONST_1_V1)),
        ];
        let next_commitment = [
            next_active * absorbed_next_commitment[0]
                + (one - next_active) * current[DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1],
            next_active * absorbed_next_commitment[1]
                + (one - next_active) * current[DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1],
        ];
        result[index] = next[DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1] - next_commitment[0];
        index += 1;
        result[index] = next[DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1] - next_commitment[1];
        index += 1;

        debug_assert_eq!(index, result.len());
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 * 4 + 7);
        let active_last_row = (self.active_row_count - 1) as usize;
        let (initial_x_digits, initial_y_digits) =
            state_coordinate_digits_le_v1(self.public_inputs.initial_state);
        let (final_x_digits, final_y_digits) =
            state_coordinate_digits_le_v1(self.public_inputs.final_state);
        let initial_commitment = absorb_commitment_from_digits_v1(
            commitment_seed_v1::<BaseElement>(self.public_inputs.iteration_count),
            &initial_x_digits,
            &initial_y_digits,
        );
        let public_root =
            commitment_root_elements_from_bytes_v1(&self.public_inputs.commitment_root);

        for digit_index in 0..DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
            assertions.push(Assertion::single(
                real_stark_x_digit_column_v1(digit_index),
                0,
                base_from_u8_v1(initial_x_digits[digit_index]),
            ));
            assertions.push(Assertion::single(
                real_stark_y_digit_column_v1(digit_index),
                0,
                base_from_u8_v1(initial_y_digits[digit_index]),
            ));
            if active_last_row != 0 {
                assertions.push(Assertion::single(
                    real_stark_x_digit_column_v1(digit_index),
                    active_last_row,
                    base_from_u8_v1(final_x_digits[digit_index]),
                ));
                assertions.push(Assertion::single(
                    real_stark_y_digit_column_v1(digit_index),
                    active_last_row,
                    base_from_u8_v1(final_y_digits[digit_index]),
                ));
            }
        }

        assertions.push(Assertion::single(
            DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1,
            0,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1,
            0,
            initial_commitment[0],
        ));
        assertions.push(Assertion::single(
            DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1,
            0,
            initial_commitment[1],
        ));
        if active_last_row != 0 {
            assertions.push(Assertion::single(
                DCM_AIR_REAL_STARK_COMMITMENT_LO_COLUMN_V1,
                active_last_row,
                public_root[0],
            ));
            assertions.push(Assertion::single(
                DCM_AIR_REAL_STARK_COMMITMENT_HI_COLUMN_V1,
                active_last_row,
                public_root[1],
            ));
        }
        if active_last_row != 0 {
            assertions.push(Assertion::single(
                DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1,
                active_last_row,
                BaseElement::ONE,
            ));
        }
        if active_last_row + 1 < self.trace_length {
            assertions.push(Assertion::single(
                DCM_AIR_REAL_STARK_ACTIVE_COLUMN_V1,
                active_last_row + 1,
                BaseElement::ZERO,
            ));
        }

        assertions
    }
}

struct DcmAirRealStarkWinterfellProverV1 {
    options: ProofOptions,
    public_inputs: DcmAirWinterfellPublicInputsV1,
}

impl DcmAirRealStarkWinterfellProverV1 {
    fn new(options: ProofOptions, public_inputs: DcmAirWinterfellPublicInputsV1) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for DcmAirRealStarkWinterfellProverV1 {
    type BaseField = BaseElement;
    type Air = DcmAirRealStarkWinterfellAirV1;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> DcmAirWinterfellPublicInputsV1 {
        self.public_inputs
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

fn evaluate_range_polynomial_v1<E: FieldElement<BaseField = BaseElement>>(
    value: E,
    max_value: u8,
) -> E {
    let mut acc = value;
    for candidate in 1u8..=max_value {
        acc *= value - E::from(BaseElement::new(u128::from(candidate)));
    }
    acc
}

fn u28_limbs_from_digits_le_v1(
    digits_le: &[u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
) -> [u32; DCM_AIR_REAL_STARK_LIMB_COUNT_V1] {
    let mut limbs = [0u32; DCM_AIR_REAL_STARK_LIMB_COUNT_V1];
    for limb_index in 0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
        let mut limb = 0u32;
        for digit_offset in 0..DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1 {
            let digit_index = limb_index * DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1 + digit_offset;
            if digit_index >= DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
                break;
            }
            limb += u32::from(digits_le[digit_index]) << (digit_offset * 7);
        }
        limbs[limb_index] = limb;
    }
    limbs
}

fn limb_value_from_row_v1<E: FieldElement<BaseField = BaseElement>>(
    row: &[E],
    digit_start: usize,
    limb_index: usize,
) -> E {
    let mut limb = E::ZERO;
    let radix = E::from(BaseElement::new(128));
    let mut power = E::ONE;
    for digit_offset in 0..DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1 {
        let digit_index = limb_index * DCM_AIR_REAL_STARK_LIMB_DIGIT_WIDTH_V1 + digit_offset;
        if digit_index >= DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
            break;
        }
        limb += row[digit_start + digit_index] * power;
        power *= radix;
    }
    limb
}

fn digits_le_from_field_element_v1(
    value: &crate::FieldElement521V1,
) -> [u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1] {
    let mut bytes_le = value.to_bytes();
    bytes_le.reverse();

    let mut digits = [0u8; DCM_AIR_REAL_STARK_DIGIT_COUNT_V1];
    let mut buffer = 0u32;
    let mut bit_count = 0usize;
    let mut digit_index = 0usize;

    for byte in bytes_le {
        buffer |= u32::from(byte) << bit_count;
        bit_count += 8;

        while bit_count >= 7 && digit_index < DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
            digits[digit_index] = (buffer & 0x7f) as u8;
            buffer >>= 7;
            bit_count -= 7;
            digit_index += 1;
        }
    }

    if digit_index < DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 {
        digits[digit_index] = buffer as u8;
    }

    digits
}

fn top_digit_max_selector_v1<E: FieldElement<BaseField = BaseElement>>(top_digit: E) -> E {
    let mut selector = top_digit;
    for candidate in 1u8..=6 {
        selector *= top_digit - E::from(BaseElement::new(u128::from(candidate)));
    }
    selector
}

#[cfg(test)]
mod tests {
    use super::{
        field_modulus_521_digits_le_v1, solve_mod_relation_v1, state_coordinate_digits_le_v1,
        u28_limbs_from_digits_le_v1, DCM_AIR_REAL_STARK_LIMB_BASE_V1,
        DCM_AIR_REAL_STARK_LIMB_COUNT_V1,
    };
    use crate::{advance_dcm_state_521_v1, DcmState521V1};

    #[test]
    fn tampered_carry_propagation_breaks_non_native_limb_relations() {
        let current = DcmState521V1::from_u64(3, 7);
        let next = advance_dcm_state_521_v1(current);
        let (current_x_digits, current_y_digits) = state_coordinate_digits_le_v1(current);
        let (next_x_digits, next_y_digits) = state_coordinate_digits_le_v1(next);

        let (qx, x_carries) = solve_mod_relation_v1(
            &current_x_digits,
            &current_y_digits,
            &next_x_digits,
            1,
            1,
            1,
        )
        .expect("canonical x relation should have a valid quotient/carry witness");
        let (qy, y_carries) = solve_mod_relation_v1(
            &current_x_digits,
            &current_y_digits,
            &next_y_digits,
            2,
            2,
            2,
        )
        .expect("canonical y relation should have a valid quotient/carry witness");

        assert!(mod_relation_holds_with_carries(
            &current_x_digits,
            &current_y_digits,
            &next_x_digits,
            1,
            qx,
            &x_carries,
        ));
        assert!(mod_relation_holds_with_carries(
            &current_x_digits,
            &current_y_digits,
            &next_y_digits,
            2,
            qy,
            &y_carries,
        ));

        let mut bad_x_carries = x_carries;
        bad_x_carries[1] = bad_x_carries[1].wrapping_add(1);
        let mut bad_y_carries = y_carries;
        bad_y_carries[1] = bad_y_carries[1].wrapping_add(1);

        assert!(!mod_relation_holds_with_carries(
            &current_x_digits,
            &current_y_digits,
            &next_x_digits,
            1,
            qx,
            &bad_x_carries,
        ));
        assert!(!mod_relation_holds_with_carries(
            &current_x_digits,
            &current_y_digits,
            &next_y_digits,
            2,
            qy,
            &bad_y_carries,
        ));
    }

    fn mod_relation_holds_with_carries(
        lhs_x: &[u8; super::DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
        lhs_y: &[u8; super::DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
        next: &[u8; super::DCM_AIR_REAL_STARK_DIGIT_COUNT_V1],
        y_scale: u8,
        quotient: u8,
        carries: &[u8; DCM_AIR_REAL_STARK_LIMB_COUNT_V1],
    ) -> bool {
        let modulus = u28_limbs_from_digits_le_v1(&field_modulus_521_digits_le_v1());
        let lhs_x_limbs = u28_limbs_from_digits_le_v1(lhs_x);
        let lhs_y_limbs = u28_limbs_from_digits_le_v1(lhs_y);
        let next_limbs = u28_limbs_from_digits_le_v1(next);

        carries[0] == 0
            && (0..DCM_AIR_REAL_STARK_LIMB_COUNT_V1).all(|limb_index| {
                let carry_out = if limb_index + 1 < DCM_AIR_REAL_STARK_LIMB_COUNT_V1 {
                    DCM_AIR_REAL_STARK_LIMB_BASE_V1 * u64::from(carries[limb_index + 1])
                } else {
                    0
                };
                let lhs = u64::from(lhs_x_limbs[limb_index])
                    + u64::from(y_scale) * u64::from(lhs_y_limbs[limb_index])
                    + u64::from(carries[limb_index]);
                let rhs = u64::from(next_limbs[limb_index])
                    + u64::from(quotient) * u64::from(modulus[limb_index])
                    + carry_out;
                lhs == rhs
            })
    }
}
