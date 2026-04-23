// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Layer 3 transcript construction for the canonical 521-bit lower-layer claim.
//! This binds the accepted pair-state claim, witness bundle, and recurrence summary into one
//! deterministic handoff artifact for later proving/session layers.

use core::fmt;

use crate::{
    assemble_layer3_proof_claim_v1, build_storm_encryption_binding_v1, sha256_bytes,
    sha256_domain_separated,
    validate_recurrence_constraints_v1, AuthorizationEnvelopeLineageTransportKindV1,
    AuthorizationEnvelopeValidityBoundsV1, Layer3ClaimConstructionInputV1, Layer3ClaimErrorV1,
    ProofClaimAssemblyV1, PublicClaimV1, RecurrenceConstraintErrorV1,
    RecurrenceConstraintSummaryV1, StormClaim521V1, StormEncryptionBindingV1,
    StormPublicInputs521V1, WitnessBundleV1,
    DCM_CLAIM_521_CANONICAL_BYTE_LEN_V1, DCM_STATE_521_CANONICAL_BYTE_LEN_V1, HASH_LEN_V1,
};

pub const PROOF_TRANSCRIPT_VERSION_V1: u8 = 1;
pub const AURA_PROOF_TRANSCRIPT_V1_PUBLIC_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_TRANSCRIPT_V1_PUBLIC";
pub const AURA_PROOF_TRANSCRIPT_V1_WITNESS_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_TRANSCRIPT_V1_WITNESS";
pub const AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_CLAIM_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_CLAIM";
pub const AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_PUBLIC_INPUTS_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_PUBLIC_INPUTS";
pub const AURA_PROOF_TRANSCRIPT_V1_CONSTRAINTS_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_TRANSCRIPT_V1_CONSTRAINTS";
pub const AURA_PROOF_TRANSCRIPT_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_PROOF_TRANSCRIPT_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofTranscriptV1 {
    pub transcript_version: u8,
    pub lower_layer_claim: StormClaim521V1,
    pub lower_layer_public_inputs: StormPublicInputs521V1,
    pub lower_layer_claim_digest: [u8; HASH_LEN_V1],
    pub lower_layer_public_inputs_digest: [u8; HASH_LEN_V1],
    pub public_claim_digest: [u8; HASH_LEN_V1],
    pub witness_digest: [u8; HASH_LEN_V1],
    pub constraint_summary_digest: [u8; HASH_LEN_V1],
    pub checked_transition_count: u64,
    pub trace_state_count: u64,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub intent_hash: [u8; HASH_LEN_V1],
    pub storm_trace_root: [u8; HASH_LEN_V1],
    pub legacy_dcm_commitment_root: [u8; HASH_LEN_V1],
    pub transcript_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofTranscriptErrorV1 {
    ClaimAssemblyFailed(Layer3ClaimErrorV1),
    ConstraintValidationFailed(RecurrenceConstraintErrorV1),
}

impl fmt::Display for ProofTranscriptErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimAssemblyFailed(error) => write!(f, "claim assembly failed: {error}"),
            Self::ConstraintValidationFailed(error) => {
                write!(f, "constraint validation failed: {error}")
            }
        }
    }
}

impl std::error::Error for ProofTranscriptErrorV1 {}

pub fn construct_proof_transcript_v1(
    input: &Layer3ClaimConstructionInputV1,
) -> Result<ProofTranscriptV1, ProofTranscriptErrorV1> {
    let assembly = assemble_layer3_proof_claim_v1(input)
        .map_err(ProofTranscriptErrorV1::ClaimAssemblyFailed)?;
    construct_proof_transcript_from_assembly_v1(&assembly)
}

pub fn construct_proof_transcript_from_assembly_v1(
    assembly: &ProofClaimAssemblyV1,
) -> Result<ProofTranscriptV1, ProofTranscriptErrorV1> {
    let constraint_summary = validate_recurrence_constraints_v1(assembly)
        .map_err(ProofTranscriptErrorV1::ConstraintValidationFailed)?;
    Ok(build_proof_transcript_from_summary_v1(
        assembly,
        &constraint_summary,
    ))
}

pub(crate) fn build_proof_transcript_from_summary_v1(
    assembly: &ProofClaimAssemblyV1,
    constraint_summary: &RecurrenceConstraintSummaryV1,
) -> ProofTranscriptV1 {
    let lower_layer_claim_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_CLAIM_DOMAIN_SEPARATOR,
        &assembly.witness_bundle.lower_layer_claim.canonical_bytes(),
    );
    let lower_layer_public_inputs_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_PUBLIC_INPUTS_DOMAIN_SEPARATOR,
        &assembly
            .witness_bundle
            .lower_layer_public_inputs
            .canonical_bytes(),
    );
    let public_claim_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_PUBLIC_DOMAIN_SEPARATOR,
        &canonical_public_claim_bytes_v1(&assembly.public_claim),
    );
    let witness_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_WITNESS_DOMAIN_SEPARATOR,
        &canonical_witness_bundle_bytes_v1(&assembly.witness_bundle),
    );
    let constraint_summary_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
        &canonical_constraint_summary_bytes_v1(constraint_summary),
    );

    let mut transcript_preimage =
        Vec::with_capacity(AURA_PROOF_TRANSCRIPT_V1_DOMAIN_SEPARATOR.len() + 1 + 32 * 5);
    transcript_preimage.extend_from_slice(AURA_PROOF_TRANSCRIPT_V1_DOMAIN_SEPARATOR);
    transcript_preimage.push(PROOF_TRANSCRIPT_VERSION_V1);
    transcript_preimage.extend_from_slice(&lower_layer_claim_digest);
    transcript_preimage.extend_from_slice(&lower_layer_public_inputs_digest);
    transcript_preimage.extend_from_slice(&public_claim_digest);
    transcript_preimage.extend_from_slice(&witness_digest);
    transcript_preimage.extend_from_slice(&constraint_summary_digest);

    // This transcript is a deterministic handoff artifact for future proving work.
    // It is not a proof, not a verifier object, and not final proof serialization.
    ProofTranscriptV1 {
        transcript_version: PROOF_TRANSCRIPT_VERSION_V1,
        lower_layer_claim: assembly.witness_bundle.lower_layer_claim,
        lower_layer_public_inputs: assembly.witness_bundle.lower_layer_public_inputs,
        lower_layer_claim_digest,
        lower_layer_public_inputs_digest,
        public_claim_digest,
        witness_digest,
        constraint_summary_digest,
        checked_transition_count: constraint_summary.checked_transition_count,
        trace_state_count: constraint_summary.trace_state_count,
        lineage_hash: constraint_summary.lineage_hash,
        intent_hash: constraint_summary.intent_hash,
        storm_trace_root: assembly.witness_bundle.lower_layer_claim.trace_root,
        legacy_dcm_commitment_root: constraint_summary.recomputed_dcm_commitment_root,
        transcript_digest: sha256_bytes(&transcript_preimage),
    }
}

pub fn build_storm_encryption_binding_from_proof_transcript_v1(
    transcript: &ProofTranscriptV1,
    sender_id: [u8; HASH_LEN_V1],
    receiver_id: [u8; HASH_LEN_V1],
    session_key_id: [u8; HASH_LEN_V1],
) -> StormEncryptionBindingV1 {
    build_storm_encryption_binding_v1(
        &transcript.lower_layer_claim,
        &transcript.lower_layer_public_inputs,
        transcript.lower_layer_claim_digest,
        sender_id,
        receiver_id,
        session_key_id,
    )
}

fn canonical_public_claim_bytes_v1(public_claim: &PublicClaimV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(381);
    bytes.push(public_claim.lineage_version);
    bytes.extend_from_slice(&public_claim.lineage_flags.to_le_bytes());
    bytes.push(public_claim.dcm_commitment_kind.as_u8());
    bytes.extend_from_slice(&public_claim.dcm_commitment_root);
    bytes.push(public_claim.storm_version);
    bytes.push(public_claim.storm_modulus_id);
    bytes.extend_from_slice(&public_claim.storm_iteration_count.to_le_bytes());
    bytes.extend_from_slice(&public_claim.storm_side_a_hash);
    bytes.extend_from_slice(&public_claim.storm_side_b_hash);
    bytes.extend_from_slice(&public_claim.storm_context_hash);
    bytes.extend_from_slice(&public_claim.storm_trace_root);
    bytes.push(public_claim.subject_binding_type.as_u8());
    bytes.extend_from_slice(&public_claim.subject_id);
    bytes.push(public_claim.intent_type.as_u8());
    bytes.extend_from_slice(&public_claim.intent_hash);
    bytes.push(public_claim.freshness_mode.as_u8());
    bytes.extend_from_slice(&public_claim.freshness_nonce);
    bytes.extend_from_slice(&public_claim.freshness_reference.to_le_bytes());
    bytes.extend_from_slice(&public_claim.lineage_hash);
    bytes.extend_from_slice(&public_claim.controlled_account_id);
    extend_validity_bounds_v1(&mut bytes, &public_claim.envelope_validity_bounds);
    bytes
}

fn canonical_witness_bundle_bytes_v1(witness_bundle: &WitnessBundleV1) -> Vec<u8> {
    // These transcript-only bytes are explicit and deterministic. They are not protocol wire
    // format and do not claim to be final prover serialization.
    let trace_len = witness_bundle.layer1_execution_trace.len();
    let mut bytes = Vec::with_capacity(
        witness_bundle.lower_layer_claim.canonical_bytes().len()
            + witness_bundle
                .lower_layer_public_inputs
                .canonical_bytes()
                .len()
            + DCM_CLAIM_521_CANONICAL_BYTE_LEN_V1
            + 8
            + DCM_STATE_521_CANONICAL_BYTE_LEN_V1 * trace_len
            + 32 * 8
            + witness_bundle.lineage_preimage.len()
            + witness_bundle.intent_hash_preimage.len()
            + 128,
    );

    bytes.extend_from_slice(&witness_bundle.lower_layer_claim.canonical_bytes());
    bytes.extend_from_slice(&witness_bundle.lower_layer_public_inputs.canonical_bytes());
    bytes.extend_from_slice(&witness_bundle.legacy_lower_layer_claim.canonical_bytes());
    bytes.extend_from_slice(&(trace_len as u64).to_le_bytes());
    for state in &witness_bundle.layer1_execution_trace {
        bytes.extend_from_slice(&state.canonical_bytes());
    }

    extend_optional_hash_v1(
        &mut bytes,
        witness_bundle.layer2_witness_fields.subject_public_key,
    );
    extend_optional_hash_v1(
        &mut bytes,
        witness_bundle.layer2_witness_fields.proof_material_v1_hash,
    );
    extend_optional_hash_v1(
        &mut bytes,
        witness_bundle.layer2_witness_fields.fractal_key_v1_hash,
    );

    extend_len_prefixed_bytes_v1(&mut bytes, &witness_bundle.lineage_preimage);
    extend_len_prefixed_bytes_v1(&mut bytes, &witness_bundle.intent_hash_preimage);
    extend_authorization_envelope_bytes_v1(
        &mut bytes,
        &witness_bundle.authorization_envelope,
        &witness_bundle.lineage_preimage,
    );

    bytes
}

fn canonical_constraint_summary_bytes_v1(
    constraint_summary: &RecurrenceConstraintSummaryV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(112);
    bytes.extend_from_slice(&constraint_summary.checked_transition_count.to_le_bytes());
    bytes.extend_from_slice(&constraint_summary.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&constraint_summary.recomputed_dcm_commitment_root);
    bytes.extend_from_slice(&constraint_summary.intent_hash);
    bytes.extend_from_slice(&constraint_summary.lineage_hash);
    bytes
}

fn extend_validity_bounds_v1(
    bytes: &mut Vec<u8>,
    validity_bounds: &AuthorizationEnvelopeValidityBoundsV1,
) {
    bytes.extend_from_slice(&validity_bounds.validity_flags.to_le_bytes());
    bytes.extend_from_slice(&validity_bounds.not_before_unix_seconds.to_le_bytes());
    bytes.extend_from_slice(&validity_bounds.not_after_unix_seconds.to_le_bytes());
    bytes.extend_from_slice(&validity_bounds.not_before_batch_number.to_le_bytes());
    bytes.extend_from_slice(&validity_bounds.not_after_batch_number.to_le_bytes());
}

fn extend_optional_hash_v1(bytes: &mut Vec<u8>, value: Option<[u8; HASH_LEN_V1]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0u8; HASH_LEN_V1]);
        }
    }
}

fn extend_len_prefixed_bytes_v1(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

fn extend_authorization_envelope_bytes_v1(
    bytes: &mut Vec<u8>,
    envelope: &crate::AuthorizationEnvelopeV1,
    lineage_preimage: &[u8],
) {
    bytes.push(envelope.auth_version);
    bytes.push(envelope.auth_kind as u8);
    bytes.extend_from_slice(&envelope.controlled_account_id);
    extend_validity_bounds_v1(bytes, &envelope.envelope_validity_bounds);
    bytes.push(match envelope.lineage_transport_kind {
        AuthorizationEnvelopeLineageTransportKindV1::InlineAuthorizationLineageV1 => 0x01,
        AuthorizationEnvelopeLineageTransportKindV1::ProofMediatedLineageStatementV1 => 0x02,
    });
    bytes.extend_from_slice(&envelope.lineage_hash);
    match envelope.inline_authorization_lineage_v1 {
        Some(_) => {
            bytes.push(1);
            extend_len_prefixed_bytes_v1(bytes, lineage_preimage);
        }
        None => {
            bytes.push(0);
            extend_len_prefixed_bytes_v1(bytes, &[]);
        }
    }
}
