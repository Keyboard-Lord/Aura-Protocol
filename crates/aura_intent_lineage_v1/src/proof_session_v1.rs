// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Layer 3 proof-session packaging for Aura's canonical lower-layer claim path.
//! This module carries the accepted 521-bit pair-state claim into:
//! - deterministic transcript/session metadata
//! - the retained mock proof path
//! - the active storm-native real proof path
//! - local acceptance surfaces bound to the same canonical lower-layer claim

use core::fmt;

use crate::{
    assemble_layer3_proof_claim_v1, build_proof_transcript_from_summary_v1,
    build_storm_air_public_inputs_v1, build_storm_public_inputs_v1,
    dcm_air_public_inputs_from_claim_521_v1, build_storm_encryption_binding_from_proof_transcript_v1,
    prove_storm_air_real_v1, sha256_domain_separated, validate_recurrence_constraints_v1,
    verify_dcm_air_mock_proof_v1, verify_storm_air_real_v1, DcmAirMockProofArtifactV1,
    DcmAirMockVerifierBindingsV1, DcmAirMockVerifierErrorV1, DcmClaim521V1,
    Layer3ClaimConstructionInputV1, Layer3ClaimErrorV1, ProofClaimAssemblyV1,
    ProofTranscriptErrorV1, ProofTranscriptV1, PublicClaimV1, RecurrenceConstraintSummaryV1,
    StormAirPublicInputsV1, StormAirRealProofArtifactV1, StormAirRealProverErrorV1,
    StormAirRealVerifierErrorV1, StormClaim521V1, StormEncryptionBindingV1,
    StormPublicInputs521V1, WitnessBundleV1,
    AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_CLAIM_DOMAIN_SEPARATOR,
    AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_PUBLIC_INPUTS_DOMAIN_SEPARATOR, HASH_LEN_V1,
};

pub const PROOF_SESSION_PACKAGING_VERSION_V1: u8 = 1;
pub const AURA_PROOF_SESSION_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_PROOF_SESSION_V1";
pub const AURA_PROOF_SESSION_V1_REAL_STARK_TRANSCRIPT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_SESSION_V1_REAL_STARK_TRANSCRIPT";
pub const AURA_PROOF_SESSION_V1_REAL_STARK_SESSION_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_PROOF_SESSION_V1_REAL_STARK_SESSION";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofSessionIdV1 {
    pub bytes: [u8; HASH_LEN_V1],
}

impl ProofSessionIdV1 {
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN_V1] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofSessionMetadataV1 {
    pub packaging_version: u8,
    pub transcript_version: u8,
    pub assembly_version: u8,
    pub public_input_category_count: u16,
    pub witness_category_count: u16,
    pub checked_transition_count: u64,
    pub trace_state_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverInputBundleV1 {
    pub packaging_version: u8,
    pub transcript: ProofTranscriptV1,
    pub witness_bundle: WitnessBundleV1,
    pub constraint_summary: RecurrenceConstraintSummaryV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierInputBundleV1 {
    pub packaging_version: u8,
    pub transcript: ProofTranscriptV1,
    pub lower_layer_claim: StormClaim521V1,
    pub lower_layer_public_inputs: StormPublicInputs521V1,
    pub legacy_lower_layer_claim: DcmClaim521V1,
    pub public_claim: PublicClaimV1,
    pub constraint_summary_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofSessionPackageV1 {
    pub session_id: ProofSessionIdV1,
    pub session_metadata: ProofSessionMetadataV1,
    pub prover_input_bundle: ProverInputBundleV1,
    pub verifier_input_bundle: VerifierInputBundleV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LowerLayerRealStarkProofSessionV1 {
    pub session_package: ProofSessionPackageV1,
    pub proof_artifact: StormAirRealProofArtifactV1,
    pub proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    pub proof_bound_session_id: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSessionErrorV1 {
    ClaimAssemblyFailed(Layer3ClaimErrorV1),
    TranscriptConstructionFailed(ProofTranscriptErrorV1),
}

#[derive(Debug)]
pub enum LowerLayerRealStarkSessionErrorV1 {
    SessionPackagingFailed(ProofSessionErrorV1),
    ClaimRelationshipMismatch { field: &'static str },
    RealStarkProverRejected(StormAirRealProverErrorV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerLayerMockAcceptanceV1 {
    pub session_id: [u8; HASH_LEN_V1],
    pub lower_layer_claim: StormClaim521V1,
    pub transcript_digest: [u8; HASH_LEN_V1],
    pub legacy_dcm_commitment_root: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerLayerRealStarkAcceptanceV1 {
    pub session_id: [u8; HASH_LEN_V1],
    pub lower_layer_claim: StormClaim521V1,
    pub transcript_digest: [u8; HASH_LEN_V1],
    pub proof_binding_digest: [u8; HASH_LEN_V1],
    pub legacy_dcm_commitment_root: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSessionAcceptanceErrorV1 {
    ClaimRelationshipMismatch { field: &'static str },
    MockVerifierRejected(DcmAirMockVerifierErrorV1),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LowerLayerRealStarkAcceptanceErrorV1 {
    ClaimRelationshipMismatch {
        field: &'static str,
    },
    ProofBoundTranscriptDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ProofBoundSessionIdMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    RealStarkVerifierRejected(StormAirRealVerifierErrorV1),
}

impl fmt::Display for ProofSessionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimAssemblyFailed(error) => write!(f, "claim assembly failed: {error}"),
            Self::TranscriptConstructionFailed(error) => {
                write!(f, "transcript construction failed: {error}")
            }
        }
    }
}

impl std::error::Error for ProofSessionErrorV1 {}

impl fmt::Display for LowerLayerRealStarkSessionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionPackagingFailed(error) => write!(f, "session packaging failed: {error}"),
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::RealStarkProverRejected(error) => {
                write!(f, "real stark prover rejected session: {error}")
            }
        }
    }
}

impl std::error::Error for LowerLayerRealStarkSessionErrorV1 {}

impl fmt::Display for ProofSessionAcceptanceErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::MockVerifierRejected(error) => write!(f, "mock verifier rejected: {error}"),
        }
    }
}

impl std::error::Error for ProofSessionAcceptanceErrorV1 {}

impl fmt::Display for LowerLayerRealStarkAcceptanceErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::ProofBoundTranscriptDigestMismatch { expected, actual } => write!(
                f,
                "proof-bound transcript digest mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::ProofBoundSessionIdMismatch { expected, actual } => write!(
                f,
                "proof-bound session id mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::RealStarkVerifierRejected(error) => {
                write!(f, "real stark verifier rejected: {error}")
            }
        }
    }
}

impl std::error::Error for LowerLayerRealStarkAcceptanceErrorV1 {}

pub fn package_proof_session_v1(
    input: &Layer3ClaimConstructionInputV1,
) -> Result<ProofSessionPackageV1, ProofSessionErrorV1> {
    let assembly =
        assemble_layer3_proof_claim_v1(input).map_err(ProofSessionErrorV1::ClaimAssemblyFailed)?;
    package_proof_session_from_assembly_v1(&assembly)
}

pub fn package_proof_session_from_assembly_v1(
    assembly: &ProofClaimAssemblyV1,
) -> Result<ProofSessionPackageV1, ProofSessionErrorV1> {
    let constraint_summary = validate_recurrence_constraints_v1(assembly).map_err(|error| {
        ProofSessionErrorV1::TranscriptConstructionFailed(
            ProofTranscriptErrorV1::ConstraintValidationFailed(error),
        )
    })?;
    let transcript = build_proof_transcript_from_summary_v1(assembly, &constraint_summary);
    Ok(build_proof_session_package_v1(
        assembly,
        &constraint_summary,
        transcript,
    ))
}

fn build_proof_session_package_v1(
    assembly: &ProofClaimAssemblyV1,
    constraint_summary: &RecurrenceConstraintSummaryV1,
    transcript: ProofTranscriptV1,
) -> ProofSessionPackageV1 {
    let session_metadata = ProofSessionMetadataV1 {
        packaging_version: PROOF_SESSION_PACKAGING_VERSION_V1,
        transcript_version: transcript.transcript_version,
        assembly_version: assembly.metadata.assembly_version,
        public_input_category_count: assembly.metadata.public_input_category_count,
        witness_category_count: assembly.metadata.witness_category_count,
        checked_transition_count: constraint_summary.checked_transition_count,
        trace_state_count: constraint_summary.trace_state_count,
    };

    let session_id = ProofSessionIdV1 {
        bytes: derive_proof_session_id_v1(&transcript, &session_metadata),
    };

    ProofSessionPackageV1 {
        session_id,
        session_metadata,
        prover_input_bundle: ProverInputBundleV1 {
            packaging_version: PROOF_SESSION_PACKAGING_VERSION_V1,
            transcript,
            witness_bundle: assembly.witness_bundle.clone(),
            constraint_summary: *constraint_summary,
        },
        verifier_input_bundle: VerifierInputBundleV1 {
            packaging_version: PROOF_SESSION_PACKAGING_VERSION_V1,
            transcript,
            lower_layer_claim: assembly.witness_bundle.lower_layer_claim,
            lower_layer_public_inputs: assembly.witness_bundle.lower_layer_public_inputs,
            legacy_lower_layer_claim: assembly.witness_bundle.legacy_lower_layer_claim,
            public_claim: assembly.public_claim,
            constraint_summary_digest: transcript.constraint_summary_digest,
        },
    }
}

pub fn accept_lower_layer_mock_session_v1(
    package: &ProofSessionPackageV1,
    verifier_bindings: &DcmAirMockVerifierBindingsV1,
    proof_artifact: &DcmAirMockProofArtifactV1,
) -> Result<LowerLayerMockAcceptanceV1, ProofSessionAcceptanceErrorV1> {
    let expected_public_inputs = validate_session_package_legacy_claims_v1(package)
        .map_err(|field| ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch { field })?;
    let verifier_bundle = &package.verifier_input_bundle;
    let prover_bundle = &package.prover_input_bundle;
    if verifier_bindings.public_inputs != expected_public_inputs {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_bindings.public_inputs",
        });
    }
    if verifier_bindings.row_count != verifier_bundle.lower_layer_claim.trace_state_count() {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_bindings.row_count",
        });
    }
    if verifier_bundle.legacy_lower_layer_claim.trace_state_count()
        != verifier_bundle.lower_layer_claim.trace_state_count()
    {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.legacy_lower_layer_claim.trace_state_count",
        });
    }
    if verifier_bindings.checked_transition_count
        != verifier_bundle
            .legacy_lower_layer_claim
            .config
            .iteration_count
    {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_bindings.checked_transition_count",
        });
    }

    if verifier_bundle.public_claim.dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.public_claim.dcm_commitment_root",
        });
    }
    if verifier_bundle.transcript.legacy_dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.legacy_dcm_commitment_root",
        });
    }
    if prover_bundle
        .constraint_summary
        .recomputed_dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err(ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "prover_input_bundle.constraint_summary.recomputed_dcm_commitment_root",
        });
    }

    verify_dcm_air_mock_proof_v1(verifier_bindings, proof_artifact)
        .map_err(ProofSessionAcceptanceErrorV1::MockVerifierRejected)?;

    Ok(LowerLayerMockAcceptanceV1 {
        session_id: *package.session_id.as_bytes(),
        lower_layer_claim: verifier_bundle.lower_layer_claim,
        transcript_digest: verifier_bundle.transcript.transcript_digest,
        legacy_dcm_commitment_root: verifier_bundle.legacy_lower_layer_claim.commitment_root,
    })
}

pub fn prove_lower_layer_real_stark_session_v1(
    input: &Layer3ClaimConstructionInputV1,
) -> Result<LowerLayerRealStarkProofSessionV1, LowerLayerRealStarkSessionErrorV1> {
    let session_package = package_proof_session_v1(input)
        .map_err(LowerLayerRealStarkSessionErrorV1::SessionPackagingFailed)?;
    prove_lower_layer_real_stark_session_from_package_v1(session_package)
}

pub fn prove_lower_layer_real_stark_session_from_assembly_v1(
    assembly: &ProofClaimAssemblyV1,
) -> Result<LowerLayerRealStarkProofSessionV1, LowerLayerRealStarkSessionErrorV1> {
    let session_package = package_proof_session_from_assembly_v1(assembly)
        .map_err(LowerLayerRealStarkSessionErrorV1::SessionPackagingFailed)?;
    prove_lower_layer_real_stark_session_from_package_v1(session_package)
}

pub fn accept_lower_layer_real_stark_session_v1(
    session: &LowerLayerRealStarkProofSessionV1,
) -> Result<LowerLayerRealStarkAcceptanceV1, LowerLayerRealStarkAcceptanceErrorV1> {
    let expected_public_inputs = validate_session_package_storm_claims_v1(&session.session_package)
        .map_err(
            |field| LowerLayerRealStarkAcceptanceErrorV1::ClaimRelationshipMismatch { field },
        )?;
    let expected_proof_bound_transcript_digest = derive_real_stark_bound_transcript_digest_v1(
        &session.session_package.verifier_input_bundle.transcript,
        &session.proof_artifact,
    );
    if session.proof_bound_transcript_digest != expected_proof_bound_transcript_digest {
        return Err(
            LowerLayerRealStarkAcceptanceErrorV1::ProofBoundTranscriptDigestMismatch {
                expected: expected_proof_bound_transcript_digest,
                actual: session.proof_bound_transcript_digest,
            },
        );
    }

    let expected_proof_bound_session_id =
        derive_real_stark_bound_session_id_v1(&session.session_package, &session.proof_artifact);
    if session.proof_bound_session_id != expected_proof_bound_session_id {
        return Err(
            LowerLayerRealStarkAcceptanceErrorV1::ProofBoundSessionIdMismatch {
                expected: expected_proof_bound_session_id,
                actual: session.proof_bound_session_id,
            },
        );
    }

    verify_storm_air_real_v1(&expected_public_inputs, &session.proof_artifact)
        .map_err(LowerLayerRealStarkAcceptanceErrorV1::RealStarkVerifierRejected)?;

    Ok(LowerLayerRealStarkAcceptanceV1 {
        session_id: session.proof_bound_session_id,
        lower_layer_claim: session
            .session_package
            .verifier_input_bundle
            .lower_layer_claim,
        transcript_digest: session.proof_bound_transcript_digest,
        proof_binding_digest: session.proof_artifact.proof_binding_digest,
        legacy_dcm_commitment_root: session
            .session_package
            .verifier_input_bundle
            .legacy_lower_layer_claim
            .commitment_root,
    })
}

fn derive_proof_session_id_v1(
    transcript: &ProofTranscriptV1,
    session_metadata: &ProofSessionMetadataV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_PROOF_SESSION_V1_DOMAIN_SEPARATOR,
        &canonical_session_id_payload_v1(transcript, session_metadata),
    )
}

pub fn build_storm_encryption_binding_from_proof_session_v1(
    session_package: &ProofSessionPackageV1,
    sender_id: [u8; HASH_LEN_V1],
    receiver_id: [u8; HASH_LEN_V1],
    session_key_id: [u8; HASH_LEN_V1],
) -> StormEncryptionBindingV1 {
    build_storm_encryption_binding_from_proof_transcript_v1(
        &session_package.verifier_input_bundle.transcript,
        sender_id,
        receiver_id,
        session_key_id,
    )
}

fn canonical_session_id_payload_v1(
    transcript: &ProofTranscriptV1,
    session_metadata: &ProofSessionMetadataV1,
) -> Vec<u8> {
    // These packaging bytes are deterministic session metadata only.
    // They are not protocol wire format and do not claim to be final prover packaging.
    let mut bytes = Vec::with_capacity(1 + 1 + 1 + 2 + 2 + 8 + 8 + 32 * 3);
    bytes.push(session_metadata.packaging_version);
    bytes.push(session_metadata.transcript_version);
    bytes.push(session_metadata.assembly_version);
    bytes.extend_from_slice(&session_metadata.public_input_category_count.to_le_bytes());
    bytes.extend_from_slice(&session_metadata.witness_category_count.to_le_bytes());
    bytes.extend_from_slice(&session_metadata.checked_transition_count.to_le_bytes());
    bytes.extend_from_slice(&session_metadata.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&transcript.transcript_digest);
    bytes.extend_from_slice(&transcript.public_claim_digest);
    bytes.extend_from_slice(&transcript.constraint_summary_digest);
    bytes
}

fn prove_lower_layer_real_stark_session_from_package_v1(
    session_package: ProofSessionPackageV1,
) -> Result<LowerLayerRealStarkProofSessionV1, LowerLayerRealStarkSessionErrorV1> {
    let public_inputs = validate_session_package_storm_claims_v1(&session_package)
        .map_err(|field| LowerLayerRealStarkSessionErrorV1::ClaimRelationshipMismatch { field })?;
    let proof_artifact = prove_storm_air_real_v1(
        &session_package.verifier_input_bundle.lower_layer_claim,
        &public_inputs,
    )
    .map_err(LowerLayerRealStarkSessionErrorV1::RealStarkProverRejected)?;
    let proof_bound_transcript_digest = derive_real_stark_bound_transcript_digest_v1(
        &session_package.verifier_input_bundle.transcript,
        &proof_artifact,
    );
    let proof_bound_session_id =
        derive_real_stark_bound_session_id_v1(&session_package, &proof_artifact);

    Ok(LowerLayerRealStarkProofSessionV1 {
        session_package,
        proof_artifact,
        proof_bound_transcript_digest,
        proof_bound_session_id,
    })
}

fn validate_session_package_legacy_claims_v1(
    package: &ProofSessionPackageV1,
) -> Result<crate::DcmAirPublicInputsV1, &'static str> {
    let verifier_bundle = &package.verifier_input_bundle;
    let prover_bundle = &package.prover_input_bundle;
    let session_metadata = &package.session_metadata;

    if prover_bundle.packaging_version != PROOF_SESSION_PACKAGING_VERSION_V1 {
        return Err("prover_input_bundle.packaging_version");
    }
    if verifier_bundle.packaging_version != PROOF_SESSION_PACKAGING_VERSION_V1 {
        return Err("verifier_input_bundle.packaging_version");
    }
    if session_metadata.packaging_version != PROOF_SESSION_PACKAGING_VERSION_V1 {
        return Err("session_metadata.packaging_version");
    }
    if session_metadata.transcript_version != verifier_bundle.transcript.transcript_version {
        return Err("session_metadata.transcript_version");
    }
    if verifier_bundle.constraint_summary_digest
        != verifier_bundle.transcript.constraint_summary_digest
    {
        return Err("verifier_input_bundle.constraint_summary_digest");
    }
    if verifier_bundle.lower_layer_claim != verifier_bundle.transcript.lower_layer_claim {
        return Err("verifier_input_bundle.lower_layer_claim");
    }
    if verifier_bundle.lower_layer_public_inputs
        != verifier_bundle.transcript.lower_layer_public_inputs
    {
        return Err("verifier_input_bundle.lower_layer_public_inputs");
    }
    if verifier_bundle.lower_layer_claim != prover_bundle.witness_bundle.lower_layer_claim {
        return Err("prover_input_bundle.witness_bundle.lower_layer_claim");
    }
    if verifier_bundle.lower_layer_public_inputs
        != prover_bundle.witness_bundle.lower_layer_public_inputs
    {
        return Err("prover_input_bundle.witness_bundle.lower_layer_public_inputs");
    }
    if prover_bundle.transcript.lower_layer_claim != verifier_bundle.lower_layer_claim {
        return Err("prover_input_bundle.transcript.lower_layer_claim");
    }
    if prover_bundle.transcript.lower_layer_public_inputs
        != verifier_bundle.lower_layer_public_inputs
    {
        return Err("prover_input_bundle.transcript.lower_layer_public_inputs");
    }
    if verifier_bundle.legacy_lower_layer_claim
        != prover_bundle.witness_bundle.legacy_lower_layer_claim
    {
        return Err("prover_input_bundle.witness_bundle.legacy_lower_layer_claim");
    }

    let expected_lower_layer_claim_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_CLAIM_DOMAIN_SEPARATOR,
        &verifier_bundle.lower_layer_claim.canonical_bytes(),
    );
    if expected_lower_layer_claim_digest != verifier_bundle.transcript.lower_layer_claim_digest {
        return Err("verifier_input_bundle.transcript.lower_layer_claim_digest");
    }
    if expected_lower_layer_claim_digest != prover_bundle.transcript.lower_layer_claim_digest {
        return Err("prover_input_bundle.transcript.lower_layer_claim_digest");
    }
    let expected_lower_layer_public_inputs_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_PUBLIC_INPUTS_DOMAIN_SEPARATOR,
        &verifier_bundle.lower_layer_public_inputs.canonical_bytes(),
    );
    if expected_lower_layer_public_inputs_digest
        != verifier_bundle.transcript.lower_layer_public_inputs_digest
    {
        return Err("verifier_input_bundle.transcript.lower_layer_public_inputs_digest");
    }
    if expected_lower_layer_public_inputs_digest
        != prover_bundle.transcript.lower_layer_public_inputs_digest
    {
        return Err("prover_input_bundle.transcript.lower_layer_public_inputs_digest");
    }

    let expected_public_inputs =
        dcm_air_public_inputs_from_claim_521_v1(&verifier_bundle.legacy_lower_layer_claim);
    let expected_trace_state_count = verifier_bundle.legacy_lower_layer_claim.trace_state_count();
    let expected_transition_count = verifier_bundle
        .legacy_lower_layer_claim
        .config
        .iteration_count;

    if session_metadata.checked_transition_count != expected_transition_count {
        return Err("session_metadata.checked_transition_count");
    }
    if session_metadata.trace_state_count != expected_trace_state_count {
        return Err("session_metadata.trace_state_count");
    }
    if verifier_bundle.transcript.checked_transition_count != expected_transition_count {
        return Err("verifier_input_bundle.transcript.checked_transition_count");
    }
    if verifier_bundle.transcript.trace_state_count != expected_trace_state_count {
        return Err("verifier_input_bundle.transcript.trace_state_count");
    }
    if prover_bundle.constraint_summary.checked_transition_count != expected_transition_count {
        return Err("prover_input_bundle.constraint_summary.checked_transition_count");
    }
    if prover_bundle.constraint_summary.trace_state_count != expected_trace_state_count {
        return Err("prover_input_bundle.constraint_summary.trace_state_count");
    }
    if package.session_id.bytes
        != derive_proof_session_id_v1(&verifier_bundle.transcript, session_metadata)
    {
        return Err("session_id");
    }

    if verifier_bundle.public_claim.dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err("verifier_input_bundle.public_claim.dcm_commitment_root");
    }
    if verifier_bundle.transcript.legacy_dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err("verifier_input_bundle.transcript.legacy_dcm_commitment_root");
    }
    if prover_bundle
        .constraint_summary
        .recomputed_dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err("prover_input_bundle.constraint_summary.recomputed_dcm_commitment_root");
    }
    if verifier_bundle.public_claim.storm_version
        != verifier_bundle.lower_layer_public_inputs.version
    {
        return Err("verifier_input_bundle.public_claim.storm_version");
    }
    if verifier_bundle.public_claim.storm_modulus_id
        != verifier_bundle.lower_layer_public_inputs.modulus_id
    {
        return Err("verifier_input_bundle.public_claim.storm_modulus_id");
    }
    if verifier_bundle.public_claim.storm_iteration_count
        != verifier_bundle.lower_layer_public_inputs.iteration_count
    {
        return Err("verifier_input_bundle.public_claim.storm_iteration_count");
    }
    if verifier_bundle.public_claim.storm_side_a_hash
        != verifier_bundle.lower_layer_public_inputs.side_a_hash
    {
        return Err("verifier_input_bundle.public_claim.storm_side_a_hash");
    }
    if verifier_bundle.public_claim.storm_side_b_hash
        != verifier_bundle.lower_layer_public_inputs.side_b_hash
    {
        return Err("verifier_input_bundle.public_claim.storm_side_b_hash");
    }
    if verifier_bundle.public_claim.storm_context_hash
        != verifier_bundle.lower_layer_public_inputs.context_hash
    {
        return Err("verifier_input_bundle.public_claim.storm_context_hash");
    }
    if verifier_bundle.public_claim.storm_trace_root
        != verifier_bundle.lower_layer_public_inputs.trace_root
    {
        return Err("verifier_input_bundle.public_claim.storm_trace_root");
    }
    if verifier_bundle.transcript.storm_trace_root != verifier_bundle.lower_layer_claim.trace_root {
        return Err("verifier_input_bundle.transcript.storm_trace_root");
    }

    Ok(expected_public_inputs)
}

fn validate_session_package_storm_claims_v1(
    package: &ProofSessionPackageV1,
) -> Result<StormAirPublicInputsV1, &'static str> {
    let verifier_bundle = &package.verifier_input_bundle;
    let prover_bundle = &package.prover_input_bundle;
    let session_metadata = &package.session_metadata;

    if prover_bundle.packaging_version != PROOF_SESSION_PACKAGING_VERSION_V1 {
        return Err("prover_input_bundle.packaging_version");
    }
    if verifier_bundle.packaging_version != PROOF_SESSION_PACKAGING_VERSION_V1 {
        return Err("verifier_input_bundle.packaging_version");
    }
    if session_metadata.packaging_version != PROOF_SESSION_PACKAGING_VERSION_V1 {
        return Err("session_metadata.packaging_version");
    }
    if session_metadata.transcript_version != verifier_bundle.transcript.transcript_version {
        return Err("session_metadata.transcript_version");
    }
    if verifier_bundle.constraint_summary_digest
        != verifier_bundle.transcript.constraint_summary_digest
    {
        return Err("verifier_input_bundle.constraint_summary_digest");
    }
    if verifier_bundle.lower_layer_claim != verifier_bundle.transcript.lower_layer_claim {
        return Err("verifier_input_bundle.lower_layer_claim");
    }
    if verifier_bundle.lower_layer_public_inputs
        != verifier_bundle.transcript.lower_layer_public_inputs
    {
        return Err("verifier_input_bundle.lower_layer_public_inputs");
    }
    if verifier_bundle.lower_layer_claim != prover_bundle.witness_bundle.lower_layer_claim {
        return Err("prover_input_bundle.witness_bundle.lower_layer_claim");
    }
    if verifier_bundle.lower_layer_public_inputs
        != prover_bundle.witness_bundle.lower_layer_public_inputs
    {
        return Err("prover_input_bundle.witness_bundle.lower_layer_public_inputs");
    }
    if prover_bundle.transcript.lower_layer_claim != verifier_bundle.lower_layer_claim {
        return Err("prover_input_bundle.transcript.lower_layer_claim");
    }
    if prover_bundle.transcript.lower_layer_public_inputs
        != verifier_bundle.lower_layer_public_inputs
    {
        return Err("prover_input_bundle.transcript.lower_layer_public_inputs");
    }
    if verifier_bundle.legacy_lower_layer_claim
        != prover_bundle.witness_bundle.legacy_lower_layer_claim
    {
        return Err("prover_input_bundle.witness_bundle.legacy_lower_layer_claim");
    }

    let expected_lower_layer_claim_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_CLAIM_DOMAIN_SEPARATOR,
        &verifier_bundle.lower_layer_claim.canonical_bytes(),
    );
    if expected_lower_layer_claim_digest != verifier_bundle.transcript.lower_layer_claim_digest {
        return Err("verifier_input_bundle.transcript.lower_layer_claim_digest");
    }
    if expected_lower_layer_claim_digest != prover_bundle.transcript.lower_layer_claim_digest {
        return Err("prover_input_bundle.transcript.lower_layer_claim_digest");
    }
    let expected_lower_layer_public_inputs_digest = sha256_domain_separated(
        AURA_PROOF_TRANSCRIPT_V1_LOWER_LAYER_PUBLIC_INPUTS_DOMAIN_SEPARATOR,
        &verifier_bundle.lower_layer_public_inputs.canonical_bytes(),
    );
    if expected_lower_layer_public_inputs_digest
        != verifier_bundle.transcript.lower_layer_public_inputs_digest
    {
        return Err("verifier_input_bundle.transcript.lower_layer_public_inputs_digest");
    }
    if expected_lower_layer_public_inputs_digest
        != prover_bundle.transcript.lower_layer_public_inputs_digest
    {
        return Err("prover_input_bundle.transcript.lower_layer_public_inputs_digest");
    }

    let expected_claim_public_inputs =
        build_storm_public_inputs_v1(&verifier_bundle.lower_layer_claim);
    let expected_public_inputs =
        build_storm_air_public_inputs_v1(&verifier_bundle.lower_layer_claim);
    let expected_trace_state_count = verifier_bundle.lower_layer_claim.trace_state_count();
    let expected_transition_count = verifier_bundle.lower_layer_claim.iteration_count;

    if session_metadata.checked_transition_count != expected_transition_count {
        return Err("session_metadata.checked_transition_count");
    }
    if session_metadata.trace_state_count != expected_trace_state_count {
        return Err("session_metadata.trace_state_count");
    }
    if verifier_bundle.transcript.checked_transition_count != expected_transition_count {
        return Err("verifier_input_bundle.transcript.checked_transition_count");
    }
    if verifier_bundle.transcript.trace_state_count != expected_trace_state_count {
        return Err("verifier_input_bundle.transcript.trace_state_count");
    }
    if prover_bundle.constraint_summary.checked_transition_count != expected_transition_count {
        return Err("prover_input_bundle.constraint_summary.checked_transition_count");
    }
    if prover_bundle.constraint_summary.trace_state_count != expected_trace_state_count {
        return Err("prover_input_bundle.constraint_summary.trace_state_count");
    }
    if package.session_id.bytes
        != derive_proof_session_id_v1(&verifier_bundle.transcript, session_metadata)
    {
        return Err("session_id");
    }

    if verifier_bundle.public_claim.dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err("verifier_input_bundle.public_claim.dcm_commitment_root");
    }
    if verifier_bundle.transcript.legacy_dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err("verifier_input_bundle.transcript.legacy_dcm_commitment_root");
    }
    if prover_bundle
        .constraint_summary
        .recomputed_dcm_commitment_root
        != verifier_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err("prover_input_bundle.constraint_summary.recomputed_dcm_commitment_root");
    }
    if verifier_bundle.public_claim.storm_version
        != verifier_bundle.lower_layer_public_inputs.version
    {
        return Err("verifier_input_bundle.public_claim.storm_version");
    }
    if verifier_bundle.public_claim.storm_modulus_id
        != verifier_bundle.lower_layer_public_inputs.modulus_id
    {
        return Err("verifier_input_bundle.public_claim.storm_modulus_id");
    }
    if verifier_bundle.public_claim.storm_iteration_count
        != verifier_bundle.lower_layer_public_inputs.iteration_count
    {
        return Err("verifier_input_bundle.public_claim.storm_iteration_count");
    }
    if verifier_bundle.public_claim.storm_side_a_hash
        != verifier_bundle.lower_layer_public_inputs.side_a_hash
    {
        return Err("verifier_input_bundle.public_claim.storm_side_a_hash");
    }
    if verifier_bundle.public_claim.storm_side_b_hash
        != verifier_bundle.lower_layer_public_inputs.side_b_hash
    {
        return Err("verifier_input_bundle.public_claim.storm_side_b_hash");
    }
    if verifier_bundle.public_claim.storm_context_hash
        != verifier_bundle.lower_layer_public_inputs.context_hash
    {
        return Err("verifier_input_bundle.public_claim.storm_context_hash");
    }
    if verifier_bundle.public_claim.storm_trace_root
        != verifier_bundle.lower_layer_public_inputs.trace_root
    {
        return Err("verifier_input_bundle.public_claim.storm_trace_root");
    }
    if verifier_bundle.transcript.storm_trace_root != verifier_bundle.lower_layer_claim.trace_root {
        return Err("verifier_input_bundle.transcript.storm_trace_root");
    }
    if verifier_bundle.lower_layer_public_inputs != expected_claim_public_inputs {
        return Err("verifier_input_bundle.lower_layer_public_inputs");
    }

    Ok(expected_public_inputs)
}

fn derive_real_stark_bound_transcript_digest_v1(
    transcript: &ProofTranscriptV1,
    proof_artifact: &StormAirRealProofArtifactV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_PROOF_SESSION_V1_REAL_STARK_TRANSCRIPT_DOMAIN_SEPARATOR,
        &canonical_real_stark_transcript_binding_bytes_v1(transcript, proof_artifact),
    )
}

fn derive_real_stark_bound_session_id_v1(
    session_package: &ProofSessionPackageV1,
    proof_artifact: &StormAirRealProofArtifactV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_PROOF_SESSION_V1_REAL_STARK_SESSION_DOMAIN_SEPARATOR,
        &canonical_real_stark_session_binding_bytes_v1(session_package, proof_artifact),
    )
}

fn canonical_real_stark_transcript_binding_bytes_v1(
    transcript: &ProofTranscriptV1,
    proof_artifact: &StormAirRealProofArtifactV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HASH_LEN_V1 * 4 + 8 + 8 + 2 + 2);
    bytes.extend_from_slice(&transcript.transcript_digest);
    bytes.extend_from_slice(&transcript.lower_layer_claim_digest);
    bytes.extend_from_slice(&proof_artifact.public_input_digest);
    bytes.extend_from_slice(&proof_artifact.proof_binding_digest);
    bytes.extend_from_slice(&proof_artifact.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.internal_trace_length.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.trace_width.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.backend_constraint_count.to_le_bytes());
    bytes
}

fn canonical_real_stark_session_binding_bytes_v1(
    session_package: &ProofSessionPackageV1,
    proof_artifact: &StormAirRealProofArtifactV1,
) -> Vec<u8> {
    let proof_bound_transcript_digest = derive_real_stark_bound_transcript_digest_v1(
        &session_package.verifier_input_bundle.transcript,
        proof_artifact,
    );
    let mut bytes = Vec::with_capacity(HASH_LEN_V1 * 4);
    bytes.extend_from_slice(session_package.session_id.as_bytes());
    bytes.extend_from_slice(&proof_bound_transcript_digest);
    bytes.extend_from_slice(&proof_artifact.proof_binding_digest);
    bytes.extend_from_slice(&proof_artifact.proof_bytes_digest);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        derive_real_stark_bound_session_id_v1, derive_real_stark_bound_transcript_digest_v1,
        prove_lower_layer_real_stark_session_v1,
    };
    use crate::{
        build_storm_claim_v1, derive_storm_air_real_proof_binding_digest_v1,
        derive_storm_air_real_proof_bytes_digest_v1, run_native_layer1_layer2_bridge_521_v1,
        AuraLayer4FeePolicyKindV1, AuraLayer4IntentBodyV1, AuraLayer4OperationBodyV1,
        AuraLayer4TxKindV1, DcmConfig521V1, DcmInput521V1, FreshnessModeV1,
        Layer1Layer2BridgeFreshnessV1, Layer1Layer2BridgeIntentSourceV1,
        Layer1Layer2BridgeSubjectBindingV1, Layer3ClaimConstructionInputV1, StormContextV1,
        StormExecutionInputsV1, SubjectBindingTypeV1, ValueTransferOperationV1,
        STORM_CONTEXT_V1_VERSION,
    };

    #[test]
    fn transcript_digest_changes_when_real_proof_changes() {
        let session = prove_lower_layer_real_stark_session_v1(&canonical_input()).unwrap();
        let mut tampered_artifact = session.proof_artifact.clone();
        tampered_artifact.proof_bytes[0] ^= 0x01;
        tampered_artifact.proof_bytes_digest =
            derive_storm_air_real_proof_bytes_digest_v1(&tampered_artifact.proof_bytes);
        tampered_artifact.proof_binding_digest =
            derive_storm_air_real_proof_binding_digest_v1(&tampered_artifact);

        assert_ne!(
            session.proof_bound_transcript_digest,
            derive_real_stark_bound_transcript_digest_v1(
                &session.session_package.verifier_input_bundle.transcript,
                &tampered_artifact,
            )
        );
    }

    #[test]
    fn proof_session_id_changes_when_real_proof_changes() {
        let session = prove_lower_layer_real_stark_session_v1(&canonical_input()).unwrap();
        let mut tampered_artifact = session.proof_artifact.clone();
        tampered_artifact.proof_bytes[0] ^= 0x01;
        tampered_artifact.proof_bytes_digest =
            derive_storm_air_real_proof_bytes_digest_v1(&tampered_artifact.proof_bytes);
        tampered_artifact.proof_binding_digest =
            derive_storm_air_real_proof_binding_digest_v1(&tampered_artifact);

        assert_ne!(
            session.proof_bound_session_id,
            derive_real_stark_bound_session_id_v1(&session.session_package, &tampered_artifact)
        );
    }

    fn canonical_input() -> Layer3ClaimConstructionInputV1 {
        let config = DcmConfig521V1 { iteration_count: 5 };
        let dcm_input = DcmInput521V1::from_u64(3, 7);
        let intent = AuraLayer4IntentBodyV1 {
            intent_version: 1,
            intent_flags: 0,
            rollup_id: [0x11; 32],
            tx_kind: AuraLayer4TxKindV1::ValueTransfer,
            sender_account_id: [0x22; 32],
            sender_nonce: 7,
            validity_flags: 0x000c,
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 0,
            not_before_batch_number: 120,
            not_after_batch_number: 125,
            fee_policy_kind: AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
            max_fee_native: 500,
            client_context_commitment: [0u8; 32],
            operation_body: AuraLayer4OperationBodyV1::ValueTransfer(ValueTransferOperationV1 {
                recipient_account_id: [0x33; 32],
                amount: 2500,
            }),
        };
        let bridge = run_native_layer1_layer2_bridge_521_v1(
            &config,
            &dcm_input,
            Layer1Layer2BridgeIntentSourceV1::IntentBody(intent),
            Layer1Layer2BridgeSubjectBindingV1 {
                subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
                subject_id: [0x55; 32],
                subject_public_key: None,
            },
            Layer1Layer2BridgeFreshnessV1 {
                freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
                freshness_nonce: [0x66; 32],
                freshness_reference: 4242,
            },
        )
        .unwrap();

        let lower_layer_claim = build_storm_claim_v1(
            &StormExecutionInputsV1 {
                side_a: [0x91; 110],
                side_b: [0x19; 110],
                context_bytes_v1: StormContextV1 {
                    context_version: STORM_CONTEXT_V1_VERSION,
                    network_id: [0x77; 32],
                    intent_hash: intent.intent_hash().unwrap(),
                    freshness_nonce: [0x66; 32],
                    valid_from: intent.not_before_batch_number,
                    valid_until: intent.not_after_batch_number,
                    controller_id: [0x55; 32],
                    route_tag: [0x88; 32],
                }
                .to_bytes(),
                iteration_count: config.iteration_count,
            },
            bridge.dcm_claim.commitment_root,
            bridge.dcm_execution.trace_commitment,
        );

        Layer3ClaimConstructionInputV1::from_native_bridge_with_storm_claim(
            config,
            dcm_input,
            lower_layer_claim,
            intent,
            bridge,
        )
    }
}
