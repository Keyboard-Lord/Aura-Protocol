// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Cat-map transcript scaffold for the 521-bit AIR path.
//! This module derives deterministic Fiat-Shamir-style query material from
//! public inputs and the trace commitment scaffold.

use core::fmt;

use crate::{sha256_domain_separated, DcmAirPublicInputsV1, StarkTraceCommitmentV1, HASH_LEN_V1};

pub const STARK_TRANSCRIPT_VERSION_V1: u8 = 1;
pub const AURA_DCM_STARK_TRANSCRIPT_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_STARK_TRANSCRIPT_V1_PUBLIC_INPUTS";
pub const AURA_DCM_STARK_TRANSCRIPT_V1_TRANSCRIPT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_STARK_TRANSCRIPT_V1_TRANSCRIPT";
pub const AURA_DCM_STARK_TRANSCRIPT_V1_QUERY_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_DCM_STARK_TRANSCRIPT_V1_QUERY";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmAirStarkTranscriptV1 {
    pub transcript_version: u8,
    pub public_input_digest: [u8; HASH_LEN_V1],
    pub transcript_digest: [u8; HASH_LEN_V1],
    pub query_challenge_digest: [u8; HASH_LEN_V1],
    pub transition_query_count: u8,
    pub queried_transition_row_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcmAirStarkTranscriptErrorV1 {
    UnsupportedTraceShape { reason: &'static str },
}

impl fmt::Display for DcmAirStarkTranscriptErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTraceShape { reason } => {
                write!(
                    f,
                    "unsupported trace shape for transcript scaffold: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for DcmAirStarkTranscriptErrorV1 {}

pub fn derive_dcm_air_stark_public_input_digest_v1(
    public_inputs: &DcmAirPublicInputsV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_DCM_STARK_TRANSCRIPT_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
        &public_inputs.canonical_bytes(),
    )
}

pub fn derive_dcm_air_stark_transcript_v1(
    public_inputs: &DcmAirPublicInputsV1,
    trace_commitment: &StarkTraceCommitmentV1,
) -> Result<DcmAirStarkTranscriptV1, DcmAirStarkTranscriptErrorV1> {
    if trace_commitment.leaf_count == 0 {
        return Err(DcmAirStarkTranscriptErrorV1::UnsupportedTraceShape {
            reason: "trace_commitment.leaf_count_must_be_non_zero",
        });
    }

    let public_input_digest = derive_dcm_air_stark_public_input_digest_v1(public_inputs);
    let transcript_digest = sha256_domain_separated(
        AURA_DCM_STARK_TRANSCRIPT_V1_TRANSCRIPT_DOMAIN_SEPARATOR,
        &canonical_transcript_seed_bytes_v1(&public_input_digest, trace_commitment),
    );
    let query_challenge_digest = sha256_domain_separated(
        AURA_DCM_STARK_TRANSCRIPT_V1_QUERY_DOMAIN_SEPARATOR,
        &canonical_query_seed_bytes_v1(&transcript_digest, trace_commitment),
    );
    let transition_query_count = if trace_commitment.leaf_count > 1 {
        1
    } else {
        0
    };
    let queried_transition_row_index = if transition_query_count == 0 {
        0
    } else {
        reduce_challenge_digest_to_row_index_v1(
            &query_challenge_digest,
            trace_commitment.leaf_count - 1,
        )
    };

    Ok(DcmAirStarkTranscriptV1 {
        transcript_version: STARK_TRANSCRIPT_VERSION_V1,
        public_input_digest,
        transcript_digest,
        query_challenge_digest,
        transition_query_count,
        queried_transition_row_index,
    })
}

fn canonical_transcript_seed_bytes_v1(
    public_input_digest: &[u8; HASH_LEN_V1],
    trace_commitment: &StarkTraceCommitmentV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 1 + HASH_LEN_V1 * 2 + 8 + 8);
    bytes.push(STARK_TRANSCRIPT_VERSION_V1);
    bytes.push(trace_commitment.commitment_version);
    bytes.extend_from_slice(public_input_digest);
    bytes.extend_from_slice(&trace_commitment.root);
    bytes.extend_from_slice(&trace_commitment.leaf_count.to_le_bytes());
    bytes.extend_from_slice(&trace_commitment.tree_height.to_le_bytes());
    bytes
}

fn canonical_query_seed_bytes_v1(
    transcript_digest: &[u8; HASH_LEN_V1],
    trace_commitment: &StarkTraceCommitmentV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HASH_LEN_V1 + 8 + 8);
    bytes.extend_from_slice(transcript_digest);
    bytes.extend_from_slice(&trace_commitment.leaf_count.to_le_bytes());
    bytes.extend_from_slice(&trace_commitment.tree_height.to_le_bytes());
    bytes
}

fn reduce_challenge_digest_to_row_index_v1(
    challenge_digest: &[u8; HASH_LEN_V1],
    transition_count: u64,
) -> u64 {
    let mut reduced = [0u8; 8];
    reduced.copy_from_slice(&challenge_digest[..8]);
    u64::from_le_bytes(reduced) % transition_count
}
