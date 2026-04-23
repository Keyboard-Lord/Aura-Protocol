//! First Layer 3 proving boundary for the frozen Layer 2 authorization-lineage object.
//!
//! This boundary proves lower-layer execution correctness through the existing real STARK path
//! and then binds one exact `NativeLayer2AuthorizationLineageObjectV1` above that lower-layer
//! proof. It does not modify the active canonical pipeline, settlement authority, or any
//! verifier-adapter surface.

use core::fmt;

use crate::{
    canonical_native_layer2_authorization_lineage_helper_hash_v1,
    dcm_air_public_inputs_from_claim_521_v1, derive_dcm_layer1_commitments_521_v1,
    prove_dcm_air_real_stark_v1, sha256_bytes, sha256_domain_separated,
    verify_dcm_air_real_stark_v1, AuraLayer4IntentBodyV1, AuraLayer4IntentHashV1Error,
    DcmAirRealStarkProofArtifactV1, DcmAirRealStarkProverErrorV1, DcmAirRealStarkVerifierErrorV1,
    DcmAirTraceV1, DcmClaim521V1, DcmCommitmentKindV1, DcmExecution521ErrorV1,
    DcmExecution521V1, DcmInput521V1, DeterministicCommitment521V1,
    DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1, IntentTypeV1, LowerHex32, LowerHex521,
    NativeLayer2AuthorizationLineageObjectV1, NativeLayer2AuthorizationLineageObjectV1Error,
    HASH_LEN_V1,
};

pub const LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1: u8 = 1;
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineagePublicClaimV1 {
    pub lower_layer_claim: DcmClaim521V1,
    pub layer2_object: NativeLayer2AuthorizationLineageObjectV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageProvingInputV1 {
    pub public_claim: Layer3AuthorizationLineagePublicClaimV1,
    pub intent_body: AuraLayer4IntentBodyV1,
}

impl Layer3AuthorizationLineageProvingInputV1 {
    pub fn new(
        lower_layer_claim: DcmClaim521V1,
        layer2_object: NativeLayer2AuthorizationLineageObjectV1,
        intent_body: AuraLayer4IntentBodyV1,
    ) -> Self {
        Self {
            public_claim: Layer3AuthorizationLineagePublicClaimV1 {
                lower_layer_claim,
                layer2_object,
            },
            intent_body,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageConstraintSummaryV1 {
    pub checked_transition_count: u64,
    pub trace_state_count: u64,
    pub recomputed_trace_commitment: [u8; HASH_LEN_V1],
    pub recomputed_dcm_commitment_root: [u8; HASH_LEN_V1],
    pub recomputed_intent_hash: [u8; HASH_LEN_V1],
    pub recomputed_lineage_commitment: DeterministicCommitment521V1,
    pub recomputed_lineage_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageProofTranscriptV1 {
    pub transcript_version: u8,
    pub public_claim_digest: [u8; HASH_LEN_V1],
    pub witness_digest: [u8; HASH_LEN_V1],
    pub constraint_summary_digest: [u8; HASH_LEN_V1],
    pub checked_transition_count: u64,
    pub trace_state_count: u64,
    pub lineage_commitment: DeterministicCommitment521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub intent_hash: [u8; HASH_LEN_V1],
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub dcm_trace_commitment: [u8; HASH_LEN_V1],
    pub transcript_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageRealStarkProofV1 {
    pub public_claim: Layer3AuthorizationLineagePublicClaimV1,
    pub intent_body: AuraLayer4IntentBodyV1,
    pub transcript: Layer3AuthorizationLineageProofTranscriptV1,
    pub proof_artifact: DcmAirRealStarkProofArtifactV1,
    pub proof_bound_transcript_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageAcceptanceV1 {
    pub lower_layer_claim: DcmClaim521V1,
    pub lineage_commitment: DeterministicCommitment521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub layer3_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    pub proof_binding_digest: [u8; HASH_LEN_V1],
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub dcm_trace_commitment: [u8; HASH_LEN_V1],
    pub intent_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer3AuthorizationLineageBoundaryErrorV1 {
    Layer1ParametersInvalid(DcmExecution521ErrorV1),
    InvalidLayer2Object(NativeLayer2AuthorizationLineageObjectV1Error),
    InvalidIntent(AuraLayer4IntentHashV1Error),
    ModeConflict {
        reason: &'static str,
    },
    ClaimRelationshipMismatch {
        field: &'static str,
    },
    CommitmentMismatch {
        field: &'static str,
        expected: DeterministicCommitment521V1,
        actual: DeterministicCommitment521V1,
    },
    HashMismatch {
        field: &'static str,
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

#[derive(Debug)]
pub enum Layer3AuthorizationLineageProverErrorV1 {
    BoundaryValidationFailed(Layer3AuthorizationLineageBoundaryErrorV1),
    RealStarkProverRejected(DcmAirRealStarkProverErrorV1),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Layer3AuthorizationLineageVerifierErrorV1 {
    BoundaryValidationFailed(Layer3AuthorizationLineageBoundaryErrorV1),
    TranscriptMismatch {
        field: &'static str,
    },
    ProofBoundTranscriptDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    RealStarkVerifierRejected(DcmAirRealStarkVerifierErrorV1),
}

impl fmt::Display for Layer3AuthorizationLineageBoundaryErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layer1ParametersInvalid(error) => {
                write!(f, "layer1 parameters invalid: {error}")
            }
            Self::InvalidLayer2Object(error) => write!(f, "invalid layer2 object: {error}"),
            Self::InvalidIntent(error) => write!(f, "invalid intent: {error}"),
            Self::ModeConflict { reason } => write!(f, "mode conflict: {reason}"),
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::CommitmentMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} mismatch: expected {}, got {}",
                LowerHex521(expected),
                LowerHex521(actual)
            ),
            Self::HashMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
        }
    }
}

impl std::error::Error for Layer3AuthorizationLineageBoundaryErrorV1 {}

impl fmt::Display for Layer3AuthorizationLineageProverErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryValidationFailed(error) => {
                write!(f, "boundary validation failed: {error}")
            }
            Self::RealStarkProverRejected(error) => {
                write!(f, "real stark prover rejected boundary: {error}")
            }
        }
    }
}

impl std::error::Error for Layer3AuthorizationLineageProverErrorV1 {}

impl fmt::Display for Layer3AuthorizationLineageVerifierErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryValidationFailed(error) => {
                write!(f, "boundary validation failed: {error}")
            }
            Self::TranscriptMismatch { field } => write!(f, "transcript mismatch: {field}"),
            Self::ProofBoundTranscriptDigestMismatch { expected, actual } => write!(
                f,
                "proof-bound transcript digest mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::RealStarkVerifierRejected(error) => {
                write!(f, "real stark verifier rejected boundary: {error}")
            }
        }
    }
}

impl std::error::Error for Layer3AuthorizationLineageVerifierErrorV1 {}

struct ValidatedLayer3AuthorizationLineageBoundaryV1 {
    execution: DcmExecution521V1,
    summary: Layer3AuthorizationLineageConstraintSummaryV1,
    intent_hash_preimage: Vec<u8>,
}

pub fn construct_layer3_authorization_lineage_proof_transcript_v1(
    input: &Layer3AuthorizationLineageProvingInputV1,
) -> Result<Layer3AuthorizationLineageProofTranscriptV1, Layer3AuthorizationLineageBoundaryErrorV1>
{
    let validated =
        validate_layer3_authorization_lineage_boundary_v1(&input.public_claim, &input.intent_body)?;
    build_layer3_authorization_lineage_proof_transcript_v1(
        &input.public_claim,
        &validated.summary,
        &validated.intent_hash_preimage,
    )
}

pub fn prove_layer3_authorization_lineage_real_stark_v1(
    input: &Layer3AuthorizationLineageProvingInputV1,
) -> Result<Layer3AuthorizationLineageRealStarkProofV1, Layer3AuthorizationLineageProverErrorV1> {
    let validated =
        validate_layer3_authorization_lineage_boundary_v1(&input.public_claim, &input.intent_body)
            .map_err(Layer3AuthorizationLineageProverErrorV1::BoundaryValidationFailed)?;

    let transcript = build_layer3_authorization_lineage_proof_transcript_v1(
        &input.public_claim,
        &validated.summary,
        &validated.intent_hash_preimage,
    )
    .map_err(Layer3AuthorizationLineageProverErrorV1::BoundaryValidationFailed)?;

    let public_inputs =
        dcm_air_public_inputs_from_claim_521_v1(&input.public_claim.lower_layer_claim);
    let trace = DcmAirTraceV1::new(validated.execution.states);
    let proof_artifact = prove_dcm_air_real_stark_v1(&public_inputs, &trace)
        .map_err(Layer3AuthorizationLineageProverErrorV1::RealStarkProverRejected)?;
    let proof_bound_transcript_digest =
        derive_layer3_authorization_lineage_bound_transcript_digest_v1(
            &transcript,
            &proof_artifact,
        );

    Ok(Layer3AuthorizationLineageRealStarkProofV1 {
        public_claim: input.public_claim.clone(),
        intent_body: input.intent_body,
        transcript,
        proof_artifact,
        proof_bound_transcript_digest,
    })
}

pub fn verify_layer3_authorization_lineage_real_stark_v1(
    proof: &Layer3AuthorizationLineageRealStarkProofV1,
) -> Result<Layer3AuthorizationLineageAcceptanceV1, Layer3AuthorizationLineageVerifierErrorV1> {
    let validated =
        validate_layer3_authorization_lineage_boundary_v1(&proof.public_claim, &proof.intent_body)
            .map_err(Layer3AuthorizationLineageVerifierErrorV1::BoundaryValidationFailed)?;

    let expected_transcript = build_layer3_authorization_lineage_proof_transcript_v1(
        &proof.public_claim,
        &validated.summary,
        &validated.intent_hash_preimage,
    )
    .map_err(Layer3AuthorizationLineageVerifierErrorV1::BoundaryValidationFailed)?;
    verify_transcript_matches_v1(&proof.transcript, &expected_transcript)?;

    let expected_proof_bound_transcript_digest =
        derive_layer3_authorization_lineage_bound_transcript_digest_v1(
            &expected_transcript,
            &proof.proof_artifact,
        );
    if proof.proof_bound_transcript_digest != expected_proof_bound_transcript_digest {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::ProofBoundTranscriptDigestMismatch {
                expected: expected_proof_bound_transcript_digest,
                actual: proof.proof_bound_transcript_digest,
            },
        );
    }

    let public_inputs =
        dcm_air_public_inputs_from_claim_521_v1(&proof.public_claim.lower_layer_claim);
    verify_dcm_air_real_stark_v1(&public_inputs, &proof.proof_artifact)
        .map_err(Layer3AuthorizationLineageVerifierErrorV1::RealStarkVerifierRejected)?;

    Ok(Layer3AuthorizationLineageAcceptanceV1 {
        lower_layer_claim: proof.public_claim.lower_layer_claim,
        lineage_commitment: validated.summary.recomputed_lineage_commitment,
        lineage_hash: validated.summary.recomputed_lineage_hash,
        layer3_transcript_digest: expected_transcript.transcript_digest,
        layer3_proof_bound_transcript_digest: expected_proof_bound_transcript_digest,
        proof_binding_digest: proof.proof_artifact.proof_binding_digest,
        dcm_commitment_root: validated.summary.recomputed_dcm_commitment_root,
        dcm_trace_commitment: validated.summary.recomputed_trace_commitment,
        intent_hash: validated.summary.recomputed_intent_hash,
    })
}

fn validate_layer3_authorization_lineage_boundary_v1(
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    intent_body: &AuraLayer4IntentBodyV1,
) -> Result<ValidatedLayer3AuthorizationLineageBoundaryV1, Layer3AuthorizationLineageBoundaryErrorV1>
{
    let recomputed_lineage_commitment =
        canonical_layer3_bound_layer2_lineage_commitment_v1(&public_claim.layer2_object)
            .map_err(Layer3AuthorizationLineageBoundaryErrorV1::InvalidLayer2Object)?;
    let recomputed_lineage_hash =
        canonical_layer3_bound_layer2_lineage_hash_v1(&public_claim.layer2_object)
        .map_err(Layer3AuthorizationLineageBoundaryErrorV1::InvalidLayer2Object)?;

    if public_claim.layer2_object.lineage.dcm_commitment_kind
        != DcmCommitmentKindV1::DcmRootCommitmentV1
    {
        return Err(Layer3AuthorizationLineageBoundaryErrorV1::ModeConflict {
            reason: "layer3_boundary_requires_native_dcm_root_commitment",
        });
    }

    if public_claim.layer2_object.lineage.intent_type != IntentTypeV1::AuraLayer4IntentHashV1 {
        return Err(Layer3AuthorizationLineageBoundaryErrorV1::ModeConflict {
            reason: "layer3_boundary_requires_aura_layer4_intent_hash_v1",
        });
    }

    let intent_hash_preimage = intent_body
        .canonical_hash_preimage()
        .map_err(Layer3AuthorizationLineageBoundaryErrorV1::InvalidIntent)?;
    let recomputed_intent_hash = sha256_bytes(&intent_hash_preimage);
    if public_claim.layer2_object.lineage.intent_hash != recomputed_intent_hash {
        return Err(Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
            field: "public_claim.layer2_object.intent_hash",
            expected: recomputed_intent_hash,
            actual: public_claim.layer2_object.lineage.intent_hash,
        });
    }

    public_claim
        .lower_layer_claim
        .config
        .validate()
        .map_err(Layer3AuthorizationLineageBoundaryErrorV1::Layer1ParametersInvalid)?;

    let dcm_input = DcmInput521V1 {
        x0: public_claim.lower_layer_claim.initial_state.x,
        y0: public_claim.lower_layer_claim.initial_state.y,
    };
    let execution = DcmExecution521V1::run(&public_claim.lower_layer_claim.config, &dcm_input)
        .map_err(Layer3AuthorizationLineageBoundaryErrorV1::Layer1ParametersInvalid)?;

    if execution.final_state != public_claim.lower_layer_claim.final_state {
        return Err(
            Layer3AuthorizationLineageBoundaryErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.lower_layer_claim.final_state",
            },
        );
    }

    if execution.trace_length != public_claim.lower_layer_claim.trace_state_count() {
        return Err(
            Layer3AuthorizationLineageBoundaryErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.lower_layer_claim.trace_state_count",
            },
        );
    }

    let recomputed_commitments =
        derive_dcm_layer1_commitments_521_v1(&public_claim.lower_layer_claim.config, &execution);

    if public_claim.lower_layer_claim.commitment_root != recomputed_commitments.dcm_commitment_root
    {
        return Err(Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
            field: "public_claim.lower_layer_claim.commitment_root",
            expected: recomputed_commitments.dcm_commitment_root,
            actual: public_claim.lower_layer_claim.commitment_root,
        });
    }

    if public_claim.layer2_object.lineage.dcm_commitment_root
        != public_claim.lower_layer_claim.commitment_root
    {
        return Err(Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
            field: "public_claim.layer2_object.dcm_commitment_root",
            expected: public_claim.lower_layer_claim.commitment_root,
            actual: public_claim.layer2_object.lineage.dcm_commitment_root,
        });
    }

    if public_claim.layer2_object.lineage.dcm_trace_commitment
        != recomputed_commitments.dcm_trace_commitment
    {
        return Err(Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
            field: "public_claim.layer2_object.dcm_trace_commitment",
            expected: recomputed_commitments.dcm_trace_commitment,
            actual: public_claim.layer2_object.lineage.dcm_trace_commitment,
        });
    }

    Ok(ValidatedLayer3AuthorizationLineageBoundaryV1 {
        execution,
        summary: Layer3AuthorizationLineageConstraintSummaryV1 {
            checked_transition_count: public_claim.lower_layer_claim.config.iteration_count,
            trace_state_count: public_claim.lower_layer_claim.trace_state_count(),
            recomputed_trace_commitment: recomputed_commitments.dcm_trace_commitment,
            recomputed_dcm_commitment_root: recomputed_commitments.dcm_commitment_root,
            recomputed_intent_hash,
            recomputed_lineage_commitment,
            recomputed_lineage_hash,
        },
        intent_hash_preimage,
    })
}

fn build_layer3_authorization_lineage_proof_transcript_v1(
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    summary: &Layer3AuthorizationLineageConstraintSummaryV1,
    intent_hash_preimage: &[u8],
) -> Result<Layer3AuthorizationLineageProofTranscriptV1, Layer3AuthorizationLineageBoundaryErrorV1>
{
    let public_claim_digest = sha256_domain_separated(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
        &canonical_layer3_authorization_lineage_public_claim_bytes_v1(public_claim)
            .map_err(Layer3AuthorizationLineageBoundaryErrorV1::InvalidLayer2Object)?,
    );
    let witness_digest = sha256_domain_separated(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR,
        &canonical_layer3_authorization_lineage_witness_bytes_v1(intent_hash_preimage),
    );
    let constraint_summary_digest = sha256_domain_separated(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
        &canonical_layer3_authorization_lineage_constraint_summary_bytes_v1(summary),
    );

    let mut transcript_preimage = Vec::with_capacity(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR.len()
            + 1
            + HASH_LEN_V1 * 3,
    );
    transcript_preimage
        .extend_from_slice(AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR);
    transcript_preimage.push(LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1);
    transcript_preimage.extend_from_slice(&public_claim_digest);
    transcript_preimage.extend_from_slice(&witness_digest);
    transcript_preimage.extend_from_slice(&constraint_summary_digest);

    Ok(Layer3AuthorizationLineageProofTranscriptV1 {
        transcript_version: LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1,
        public_claim_digest,
        witness_digest,
        constraint_summary_digest,
        checked_transition_count: summary.checked_transition_count,
        trace_state_count: summary.trace_state_count,
        lineage_commitment: summary.recomputed_lineage_commitment,
        lineage_hash: summary.recomputed_lineage_hash,
        intent_hash: summary.recomputed_intent_hash,
        dcm_commitment_root: summary.recomputed_dcm_commitment_root,
        dcm_trace_commitment: summary.recomputed_trace_commitment,
        transcript_digest: sha256_bytes(&transcript_preimage),
    })
}

fn verify_transcript_matches_v1(
    actual: &Layer3AuthorizationLineageProofTranscriptV1,
    expected: &Layer3AuthorizationLineageProofTranscriptV1,
) -> Result<(), Layer3AuthorizationLineageVerifierErrorV1> {
    if actual.transcript_version != expected.transcript_version {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "transcript_version",
            },
        );
    }
    if actual.public_claim_digest != expected.public_claim_digest {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "public_claim_digest",
            },
        );
    }
    if actual.witness_digest != expected.witness_digest {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "witness_digest",
            },
        );
    }
    if actual.constraint_summary_digest != expected.constraint_summary_digest {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "constraint_summary_digest",
            },
        );
    }
    if actual.checked_transition_count != expected.checked_transition_count {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "checked_transition_count",
            },
        );
    }
    if actual.trace_state_count != expected.trace_state_count {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "trace_state_count",
            },
        );
    }
    if actual.lineage_commitment != expected.lineage_commitment {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "lineage_commitment",
            },
        );
    }
    if actual.lineage_hash != expected.lineage_hash {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "lineage_hash",
            },
        );
    }
    if actual.intent_hash != expected.intent_hash {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "intent_hash",
            },
        );
    }
    if actual.dcm_commitment_root != expected.dcm_commitment_root {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "dcm_commitment_root",
            },
        );
    }
    if actual.dcm_trace_commitment != expected.dcm_trace_commitment {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "dcm_trace_commitment",
            },
        );
    }
    if actual.transcript_digest != expected.transcript_digest {
        return Err(
            Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
                field: "transcript_digest",
            },
        );
    }

    Ok(())
}

fn derive_layer3_authorization_lineage_bound_transcript_digest_v1(
    transcript: &Layer3AuthorizationLineageProofTranscriptV1,
    proof_artifact: &DcmAirRealStarkProofArtifactV1,
) -> [u8; HASH_LEN_V1] {
    sha256_domain_separated(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR,
        &canonical_layer3_authorization_lineage_real_stark_binding_bytes_v1(
            transcript,
            proof_artifact,
        ),
    )
}

pub(crate) fn canonical_layer3_bound_layer2_lineage_commitment_v1(
    layer2_object: &NativeLayer2AuthorizationLineageObjectV1,
) -> Result<DeterministicCommitment521V1, NativeLayer2AuthorizationLineageObjectV1Error> {
    layer2_object.validate()?;
    Ok(layer2_object.lineage_commitment)
}

pub(crate) fn canonical_layer3_bound_layer2_lineage_hash_v1(
    layer2_object: &NativeLayer2AuthorizationLineageObjectV1,
) -> Result<[u8; HASH_LEN_V1], NativeLayer2AuthorizationLineageObjectV1Error> {
    layer2_object.validate()?;
    canonical_native_layer2_authorization_lineage_helper_hash_v1(&layer2_object.lineage)
        .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)
}

pub(crate) fn canonical_layer3_authorization_lineage_public_claim_bytes_v1(
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
) -> Result<Vec<u8>, NativeLayer2AuthorizationLineageObjectV1Error> {
    let serialized_object = public_claim.layer2_object.serialized_object()?;
    let mut bytes = Vec::with_capacity(
        public_claim.lower_layer_claim.canonical_bytes().len() + serialized_object.len(),
    );
    bytes.extend_from_slice(&public_claim.lower_layer_claim.canonical_bytes());
    bytes.extend_from_slice(&serialized_object);
    Ok(bytes)
}

fn canonical_layer3_authorization_lineage_witness_bytes_v1(intent_hash_preimage: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + intent_hash_preimage.len());
    bytes.extend_from_slice(&(intent_hash_preimage.len() as u64).to_le_bytes());
    bytes.extend_from_slice(intent_hash_preimage);
    bytes
}

fn canonical_layer3_authorization_lineage_constraint_summary_bytes_v1(
    summary: &Layer3AuthorizationLineageConstraintSummaryV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        16 + (HASH_LEN_V1 * 4) + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
    );
    bytes.extend_from_slice(&summary.checked_transition_count.to_le_bytes());
    bytes.extend_from_slice(&summary.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&summary.recomputed_trace_commitment);
    bytes.extend_from_slice(&summary.recomputed_dcm_commitment_root);
    bytes.extend_from_slice(&summary.recomputed_intent_hash);
    bytes.extend_from_slice(&summary.recomputed_lineage_commitment.to_bytes());
    bytes.extend_from_slice(&summary.recomputed_lineage_hash);
    bytes
}

fn canonical_layer3_authorization_lineage_real_stark_binding_bytes_v1(
    transcript: &Layer3AuthorizationLineageProofTranscriptV1,
    proof_artifact: &DcmAirRealStarkProofArtifactV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HASH_LEN_V1 * 4 + 8 + 8 + 2 + 2);
    bytes.extend_from_slice(&transcript.transcript_digest);
    bytes.extend_from_slice(&transcript.public_claim_digest);
    bytes.extend_from_slice(&proof_artifact.public_input_digest);
    bytes.extend_from_slice(&proof_artifact.proof_binding_digest);
    bytes.extend_from_slice(&proof_artifact.trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.internal_trace_length.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.trace_width.to_le_bytes());
    bytes.extend_from_slice(&proof_artifact.backend_constraint_count.to_le_bytes());
    bytes
}
