// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Layer 3 recurrence and relationship checks for the canonical native cat-map path.
//! This module validates deterministic claim semantics only; it is not a verifier or AIR framework.

use core::fmt;

use crate::{
    advance_dcm_state_521_v1, assemble_layer3_proof_claim_v1, build_dcm_claim_521_v1,
    build_storm_public_inputs_v1, derive_dcm_layer1_commitments_521_v1,
    derive_trace_commitment_521_v1, AuthorizationEnvelopeFreshnessContextV1,
    AuthorizationEnvelopeV1Decision, DcmCommitmentKindV1, DcmExecution521ErrorV1,
    DcmExecution521V1, DcmInput521V1, DcmState521V1, DcmTraceCommitment521ErrorV1,
    FreshnessModeV1, IntentTypeV1, LowerHex32, ProofClaimAssemblyV1, SubjectBindingTypeV1,
    HASH_LEN_V1, LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1, LAYER3_PUBLIC_INPUT_CATEGORY_COUNT_V1,
    LAYER3_WITNESS_CATEGORY_COUNT_V1, LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT,
    LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH, LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH,
    LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecurrenceConstraintSummaryV1 {
    pub checked_transition_count: u64,
    pub trace_state_count: u64,
    pub recomputed_trace_commitment: [u8; HASH_LEN_V1],
    pub recomputed_dcm_commitment_root: [u8; HASH_LEN_V1],
    pub intent_hash: [u8; HASH_LEN_V1],
    pub lineage_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecurrenceConstraintDecisionV1 {
    Accept(RecurrenceConstraintSummaryV1),
    Reject(RecurrenceConstraintErrorV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecurrenceConstraintErrorV1 {
    EmptyTrace,
    Layer1ParametersInvalid(DcmExecution521ErrorV1),
    TraceLengthMismatch {
        expected: u64,
        actual: u64,
    },
    InitialStateMismatch {
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    FinalStateMismatch {
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    RecurrenceViolation {
        index: u64,
        expected: DcmState521V1,
        actual: DcmState521V1,
    },
    TraceCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    CommitmentRootMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ClaimRelationshipMismatch {
        field: &'static str,
    },
    ModeConflict {
        reason: &'static str,
    },
    MissingRequiredWitnessField {
        field: &'static str,
    },
}

impl fmt::Display for RecurrenceConstraintErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "trace must not be empty"),
            Self::Layer1ParametersInvalid(error) => {
                write!(f, "layer1 parameters invalid: {error}")
            }
            Self::TraceLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "trace length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InitialStateMismatch { expected, actual } => {
                write!(
                    f,
                    "initial state mismatch: expected {expected}, got {actual}"
                )
            }
            Self::FinalStateMismatch { expected, actual } => {
                write!(f, "final state mismatch: expected {expected}, got {actual}")
            }
            Self::RecurrenceViolation {
                index,
                expected,
                actual,
            } => write!(
                f,
                "recurrence violation at index {index}: expected {expected}, got {actual}"
            ),
            Self::TraceCommitmentMismatch { expected, actual } => write!(
                f,
                "trace commitment mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::CommitmentRootMismatch { expected, actual } => write!(
                f,
                "commitment root mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::ModeConflict { reason } => write!(f, "mode conflict: {reason}"),
            Self::MissingRequiredWitnessField { field } => {
                write!(f, "missing required witness field: {field}")
            }
        }
    }
}

impl std::error::Error for RecurrenceConstraintErrorV1 {}

pub fn evaluate_recurrence_constraints_v1(
    assembly: &ProofClaimAssemblyV1,
) -> RecurrenceConstraintDecisionV1 {
    match validate_recurrence_constraints_v1(assembly) {
        Ok(summary) => RecurrenceConstraintDecisionV1::Accept(summary),
        Err(error) => RecurrenceConstraintDecisionV1::Reject(error),
    }
}

pub fn validate_recurrence_constraints_v1(
    assembly: &ProofClaimAssemblyV1,
) -> Result<RecurrenceConstraintSummaryV1, RecurrenceConstraintErrorV1> {
    validate_metadata(assembly)?;
    assembly
        .witness_bundle
        .lower_layer_claim
        .validate()
        .map_err(|_| RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.lower_layer_claim",
        })?;
    if build_storm_public_inputs_v1(&assembly.witness_bundle.lower_layer_claim)
        != assembly.witness_bundle.lower_layer_public_inputs
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.lower_layer_public_inputs",
        });
    }
    assembly
        .witness_bundle
        .legacy_lower_layer_claim
        .config
        .validate()
        .map_err(RecurrenceConstraintErrorV1::Layer1ParametersInvalid)?;

    let trace = &assembly.witness_bundle.layer1_execution_trace;
    if trace.is_empty() {
        return Err(RecurrenceConstraintErrorV1::EmptyTrace);
    }

    let expected_trace_length = assembly
        .witness_bundle
        .legacy_lower_layer_claim
        .config
        .iteration_count
        .checked_add(1)
        .ok_or(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.legacy_lower_layer_claim.config.iteration_count_overflow",
        })?;
    let actual_trace_length = trace.len() as u64;
    if actual_trace_length != expected_trace_length {
        return Err(RecurrenceConstraintErrorV1::TraceLengthMismatch {
            expected: expected_trace_length,
            actual: actual_trace_length,
        });
    }

    if assembly
        .witness_bundle
        .legacy_lower_layer_claim
        .trace_state_count()
        != actual_trace_length
    {
        return Err(RecurrenceConstraintErrorV1::TraceLengthMismatch {
            expected: assembly
                .witness_bundle
                .legacy_lower_layer_claim
                .trace_state_count(),
            actual: actual_trace_length,
        });
    }

    if assembly.metadata.trace_state_count != actual_trace_length {
        return Err(RecurrenceConstraintErrorV1::TraceLengthMismatch {
            expected: assembly.metadata.trace_state_count,
            actual: actual_trace_length,
        });
    }

    let first_state = trace[0];
    if assembly.witness_bundle.legacy_lower_layer_claim.initial_state != first_state {
        return Err(RecurrenceConstraintErrorV1::InitialStateMismatch {
            expected: assembly.witness_bundle.legacy_lower_layer_claim.initial_state,
            actual: first_state,
        });
    }

    let last_state = *trace.last().expect("checked non-empty trace");
    if assembly.witness_bundle.legacy_lower_layer_claim.final_state != last_state {
        return Err(RecurrenceConstraintErrorV1::FinalStateMismatch {
            expected: last_state,
            actual: assembly.witness_bundle.legacy_lower_layer_claim.final_state,
        });
    }

    for (index, pair) in trace.windows(2).enumerate() {
        let expected = advance_dcm_state_521_v1(pair[0]);
        let actual = pair[1];
        if actual != expected {
            return Err(RecurrenceConstraintErrorV1::RecurrenceViolation {
                index: index as u64,
                expected,
                actual,
            });
        }
    }

    let recomputed_trace_commitment = derive_trace_commitment_521_v1(
        &assembly.witness_bundle.legacy_lower_layer_claim.config,
        &DcmInput521V1 {
            x0: assembly.witness_bundle.legacy_lower_layer_claim.initial_state.x,
            y0: assembly.witness_bundle.legacy_lower_layer_claim.initial_state.y,
        },
        trace,
    )
    .map_err(map_trace_commitment_error_v1)?;
    if assembly
        .witness_bundle
        .layer2_witness_fields
        .dcm_trace_commitment
        .is_some()
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.layer2_witness_fields.dcm_trace_commitment",
        });
    }

    let recomputed_execution = DcmExecution521V1 {
        states: trace.clone(),
        final_state: last_state,
        trace_length: actual_trace_length,
        trace_commitment: recomputed_trace_commitment,
    };
    let recomputed_commitments = derive_dcm_layer1_commitments_521_v1(
        &assembly.witness_bundle.legacy_lower_layer_claim.config,
        &recomputed_execution,
    );
    if recomputed_commitments.dcm_commitment_root != assembly.public_claim.dcm_commitment_root {
        return Err(RecurrenceConstraintErrorV1::CommitmentRootMismatch {
            expected: recomputed_commitments.dcm_commitment_root,
            actual: assembly.public_claim.dcm_commitment_root,
        });
    }
    if recomputed_commitments.dcm_commitment_root
        != assembly.witness_bundle.legacy_lower_layer_claim.commitment_root
    {
        return Err(RecurrenceConstraintErrorV1::CommitmentRootMismatch {
            expected: recomputed_commitments.dcm_commitment_root,
            actual: assembly.witness_bundle.legacy_lower_layer_claim.commitment_root,
        });
    }
    if assembly.witness_bundle.lower_layer_claim.legacy_commitment_root
        != recomputed_commitments.dcm_commitment_root
    {
        return Err(RecurrenceConstraintErrorV1::CommitmentRootMismatch {
            expected: recomputed_commitments.dcm_commitment_root,
            actual: assembly.witness_bundle.lower_layer_claim.legacy_commitment_root,
        });
    }
    if assembly.witness_bundle.lower_layer_claim.legacy_trace_commitment
        != recomputed_trace_commitment
    {
        return Err(RecurrenceConstraintErrorV1::TraceCommitmentMismatch {
            expected: recomputed_trace_commitment,
            actual: assembly.witness_bundle.lower_layer_claim.legacy_trace_commitment,
        });
    }

    let envelope = &assembly.witness_bundle.authorization_envelope;
    match envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default()) {
        AuthorizationEnvelopeV1Decision::Accept { lineage_hash } => {
            if lineage_hash != assembly.public_claim.lineage_hash {
                return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                    field: "authorization_envelope.accepted_lineage_hash",
                });
            }
        }
        AuthorizationEnvelopeV1Decision::Reject(error) => match error {
            crate::AuthorizationEnvelopeV1Error::ModeConflict { reason } => {
                return Err(RecurrenceConstraintErrorV1::ModeConflict { reason });
            }
            _ => {
                return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                    field: "authorization_envelope",
                });
            }
        },
    }

    validate_envelope_public_relationships(envelope, &assembly.public_claim)?;

    let lineage = envelope.inline_authorization_lineage_v1.ok_or(
        RecurrenceConstraintErrorV1::MissingRequiredWitnessField {
            field: "authorization_envelope.inline_authorization_lineage_v1",
        },
    )?;
    validate_native_lineage_shape(&lineage, &assembly.public_claim, &assembly.witness_bundle)?;

    let recomputed_lineage_preimage =
        lineage.canonical_preimage().map_err(|error| {
            match error {
        crate::AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyIntentType
        | crate::AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyFreshnessMode
        | crate::AuthorizationLineageV1Error::NativeDcmRootedCannotCarryProofMaterialV1Hash
        | crate::AuthorizationLineageV1Error::NativeDcmRootedCannotCarryFractalKeyV1Hash
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresZeroDcmCommitmentRoot
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityCannotCarryDcmTraceCommitment
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyIntentType
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyFreshnessMode
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresProofMaterialV1Hash
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresFractalKeyV1Hash => {
            RecurrenceConstraintErrorV1::ModeConflict {
                reason: error.reject_reason(),
            }
        }
        _ => RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.lineage_preimage",
        },
    }
        })?;
    if recomputed_lineage_preimage != assembly.witness_bundle.lineage_preimage {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.lineage_preimage",
        });
    }

    let recomputed_lineage_hash = lineage.lineage_hash().map_err(|error| match error {
        crate::AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyIntentType
        | crate::AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyFreshnessMode
        | crate::AuthorizationLineageV1Error::NativeDcmRootedCannotCarryProofMaterialV1Hash
        | crate::AuthorizationLineageV1Error::NativeDcmRootedCannotCarryFractalKeyV1Hash
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresZeroDcmCommitmentRoot
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityCannotCarryDcmTraceCommitment
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyIntentType
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyFreshnessMode
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresProofMaterialV1Hash
        | crate::AuthorizationLineageV1Error::LegacyCompatibilityRequiresFractalKeyV1Hash => {
            RecurrenceConstraintErrorV1::ModeConflict {
                reason: error.reject_reason(),
            }
        }
        _ => RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.lineage_hash",
        },
    })?;
    if recomputed_lineage_hash != assembly.public_claim.lineage_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.lineage_hash",
        });
    }

    let recomputed_intent_preimage = assembly
        .witness_bundle
        .intent_body
        .canonical_hash_preimage()
        .map_err(|_| RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.intent_hash_preimage",
        })?;
    if recomputed_intent_preimage != assembly.witness_bundle.intent_hash_preimage {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.intent_hash_preimage",
        });
    }

    let recomputed_intent_hash =
        assembly
            .witness_bundle
            .intent_body
            .intent_hash()
            .map_err(|_| RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.intent_hash",
            })?;
    if recomputed_intent_hash != assembly.public_claim.intent_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.intent_hash",
        });
    }

    let reassembled = assemble_layer3_proof_claim_v1(&crate::Layer3ClaimConstructionInputV1 {
        lower_layer_claim: assembly.witness_bundle.lower_layer_claim,
        lower_layer_public_inputs: assembly.witness_bundle.lower_layer_public_inputs,
        legacy_lower_layer_claim: build_dcm_claim_521_v1(
            &assembly.witness_bundle.legacy_lower_layer_claim.config,
            &DcmInput521V1 {
                x0: assembly.witness_bundle.legacy_lower_layer_claim.initial_state.x,
                y0: assembly.witness_bundle.legacy_lower_layer_claim.initial_state.y,
            },
            &recomputed_execution,
        ),
        dcm_execution: recomputed_execution,
        lineage,
        envelope: *envelope,
        envelope_decision: AuthorizationEnvelopeV1Decision::Accept {
            lineage_hash: recomputed_lineage_hash,
        },
        intent: assembly.witness_bundle.intent_body,
    })
    .map_err(|_| RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
        field: "layer3_claim_reassembly",
    })?;

    if reassembled.public_claim != assembly.public_claim {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim",
        });
    }
    if reassembled.metadata != assembly.metadata {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch { field: "metadata" });
    }

    Ok(RecurrenceConstraintSummaryV1 {
        checked_transition_count: actual_trace_length - 1,
        trace_state_count: actual_trace_length,
        recomputed_trace_commitment,
        recomputed_dcm_commitment_root: recomputed_commitments.dcm_commitment_root,
        intent_hash: recomputed_intent_hash,
        lineage_hash: recomputed_lineage_hash,
    })
}

fn map_trace_commitment_error_v1(
    error: DcmTraceCommitment521ErrorV1,
) -> RecurrenceConstraintErrorV1 {
    match error {
        DcmTraceCommitment521ErrorV1::IterationCountTooLarge { actual } => {
            RecurrenceConstraintErrorV1::Layer1ParametersInvalid(
                DcmExecution521ErrorV1::IterationCountTooLarge { actual },
            )
        }
        DcmTraceCommitment521ErrorV1::TraceLengthMismatch { expected, actual } => {
            RecurrenceConstraintErrorV1::TraceLengthMismatch { expected, actual }
        }
        DcmTraceCommitment521ErrorV1::InitialStateMismatch { expected, actual } => {
            RecurrenceConstraintErrorV1::InitialStateMismatch { expected, actual }
        }
        DcmTraceCommitment521ErrorV1::TransitionMismatch {
            index,
            expected,
            actual,
        } => RecurrenceConstraintErrorV1::RecurrenceViolation {
            index,
            expected,
            actual,
        },
    }
}

fn validate_metadata(assembly: &ProofClaimAssemblyV1) -> Result<(), RecurrenceConstraintErrorV1> {
    if assembly.metadata.assembly_version != LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1 {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "metadata.assembly_version",
        });
    }
    if assembly.metadata.public_input_category_count != LAYER3_PUBLIC_INPUT_CATEGORY_COUNT_V1 {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "metadata.public_input_category_count",
        });
    }
    if assembly.metadata.witness_category_count != LAYER3_WITNESS_CATEGORY_COUNT_V1 {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "metadata.witness_category_count",
        });
    }
    Ok(())
}

fn validate_public_claim_native_shape(
    public_claim: &crate::PublicClaimV1,
) -> Result<(), RecurrenceConstraintErrorV1> {
    if public_claim.dcm_commitment_kind != DcmCommitmentKindV1::DcmRootCommitmentV1 {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_dcm_commitment_kind_not_allowed",
        });
    }
    if public_claim.intent_type != IntentTypeV1::AuraLayer4IntentHashV1 {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_or_non_native_intent_type_not_allowed",
        });
    }
    if matches!(
        public_claim.freshness_mode,
        FreshnessModeV1::LegacyV1ChallengeFreshness
    ) {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_freshness_mode_not_allowed",
        });
    }
    if public_claim.lineage_flags
        & (LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH | LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH)
        != 0
    {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_compatibility_fields_not_allowed",
        });
    }
    if public_claim.lineage_flags & LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT != 0 {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_carry_dcm_trace_commitment",
        });
    }
    Ok(())
}

fn validate_storm_public_claim_relationships(
    public_claim: &crate::PublicClaimV1,
    witness_bundle: &crate::WitnessBundleV1,
) -> Result<(), RecurrenceConstraintErrorV1> {
    if public_claim.storm_version != witness_bundle.lower_layer_public_inputs.version {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_version",
        });
    }
    if public_claim.storm_modulus_id != witness_bundle.lower_layer_public_inputs.modulus_id {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_modulus_id",
        });
    }
    if public_claim.storm_iteration_count != witness_bundle.lower_layer_public_inputs.iteration_count
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_iteration_count",
        });
    }
    if public_claim.storm_side_a_hash != witness_bundle.lower_layer_public_inputs.side_a_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_side_a_hash",
        });
    }
    if public_claim.storm_side_b_hash != witness_bundle.lower_layer_public_inputs.side_b_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_side_b_hash",
        });
    }
    if public_claim.storm_context_hash != witness_bundle.lower_layer_public_inputs.context_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_context_hash",
        });
    }
    if public_claim.storm_trace_root != witness_bundle.lower_layer_public_inputs.trace_root {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.storm_trace_root",
        });
    }
    Ok(())
}

fn validate_envelope_public_relationships(
    envelope: &crate::AuthorizationEnvelopeV1,
    public_claim: &crate::PublicClaimV1,
) -> Result<(), RecurrenceConstraintErrorV1> {
    if envelope.lineage_hash != public_claim.lineage_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "authorization_envelope.lineage_hash",
        });
    }
    if envelope.controlled_account_id != public_claim.controlled_account_id {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.controlled_account_id",
        });
    }
    if envelope.envelope_validity_bounds.validity_flags
        != public_claim.envelope_validity_bounds.validity_flags
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.envelope_validity_bounds.validity_flags",
        });
    }
    if envelope.envelope_validity_bounds.not_before_unix_seconds
        != public_claim
            .envelope_validity_bounds
            .not_before_unix_seconds
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.envelope_validity_bounds.not_before_unix_seconds",
        });
    }
    if envelope.envelope_validity_bounds.not_after_unix_seconds
        != public_claim.envelope_validity_bounds.not_after_unix_seconds
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.envelope_validity_bounds.not_after_unix_seconds",
        });
    }
    if envelope.envelope_validity_bounds.not_before_batch_number
        != public_claim
            .envelope_validity_bounds
            .not_before_batch_number
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.envelope_validity_bounds.not_before_batch_number",
        });
    }
    if envelope.envelope_validity_bounds.not_after_batch_number
        != public_claim.envelope_validity_bounds.not_after_batch_number
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.envelope_validity_bounds.not_after_batch_number",
        });
    }
    Ok(())
}

fn validate_witness_field_relationships(
    lineage: &crate::AuthorizationLineageV1,
    witness_bundle: &crate::WitnessBundleV1,
) -> Result<(), RecurrenceConstraintErrorV1> {
    let actual_dcm_trace_commitment = witness_bundle.layer2_witness_fields.dcm_trace_commitment;
    if actual_dcm_trace_commitment.is_some() {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.layer2_witness_fields.dcm_trace_commitment",
        });
    }

    let expected_subject_public_key =
        if lineage.lineage_flags & LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY != 0 {
            Some(lineage.subject_public_key)
        } else {
            None
        };
    let actual_subject_public_key = witness_bundle.layer2_witness_fields.subject_public_key;
    if expected_subject_public_key.is_some() && actual_subject_public_key.is_none() {
        return Err(RecurrenceConstraintErrorV1::MissingRequiredWitnessField {
            field: "witness_bundle.layer2_witness_fields.subject_public_key",
        });
    }
    if actual_subject_public_key != expected_subject_public_key {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.layer2_witness_fields.subject_public_key",
        });
    }
    if witness_bundle
        .layer2_witness_fields
        .proof_material_v1_hash
        .is_some()
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.layer2_witness_fields.proof_material_v1_hash",
        });
    }
    if witness_bundle
        .layer2_witness_fields
        .fractal_key_v1_hash
        .is_some()
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.layer2_witness_fields.fractal_key_v1_hash",
        });
    }

    Ok(())
}

fn validate_native_lineage_shape(
    lineage: &crate::AuthorizationLineageV1,
    public_claim: &crate::PublicClaimV1,
    witness_bundle: &crate::WitnessBundleV1,
) -> Result<(), RecurrenceConstraintErrorV1> {
    validate_public_claim_native_shape(public_claim)?;
    validate_storm_public_claim_relationships(public_claim, witness_bundle)?;

    if lineage.dcm_commitment_kind != DcmCommitmentKindV1::DcmRootCommitmentV1 {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_dcm_commitment_kind_not_allowed",
        });
    }
    if lineage.intent_type != IntentTypeV1::AuraLayer4IntentHashV1 {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_or_non_native_intent_type_not_allowed",
        });
    }
    if matches!(
        lineage.freshness_mode,
        FreshnessModeV1::LegacyV1ChallengeFreshness
    ) {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_freshness_mode_not_allowed",
        });
    }
    if lineage.lineage_flags
        & (LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH | LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH)
        != 0
    {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "legacy_compatibility_fields_not_allowed",
        });
    }

    if lineage.lineage_flags & LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT != 0 {
        return Err(RecurrenceConstraintErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_carry_dcm_trace_commitment",
        });
    }
    validate_witness_field_relationships(lineage, witness_bundle)?;

    if lineage.subject_binding_type == SubjectBindingTypeV1::RawEd25519PublicKey32 {
        if lineage.lineage_flags & LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY != 0 {
            return Err(RecurrenceConstraintErrorV1::ModeConflict {
                reason: "subject_public_key_flag_forbidden_for_raw_ed25519",
            });
        }
        if witness_bundle
            .layer2_witness_fields
            .subject_public_key
            .is_some()
        {
            return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "witness_bundle.layer2_witness_fields.subject_public_key",
            });
        }
    }

    if public_claim.lineage_version != lineage.version {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.lineage_version",
        });
    }
    if public_claim.lineage_flags != lineage.lineage_flags {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.lineage_flags",
        });
    }
    if public_claim.dcm_commitment_kind != lineage.dcm_commitment_kind {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.dcm_commitment_kind",
        });
    }
    if public_claim.dcm_commitment_root != lineage.dcm_commitment_root {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.dcm_commitment_root",
        });
    }
    if public_claim.subject_binding_type != lineage.subject_binding_type {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.subject_binding_type",
        });
    }
    if public_claim.subject_id != lineage.subject_id {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.subject_id",
        });
    }
    if public_claim.intent_type != lineage.intent_type {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.intent_type",
        });
    }
    if public_claim.intent_hash != lineage.intent_hash {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.intent_hash",
        });
    }
    if public_claim.freshness_mode != lineage.freshness_mode {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.freshness_mode",
        });
    }
    if public_claim.freshness_nonce != lineage.freshness_nonce {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.freshness_nonce",
        });
    }
    if public_claim.freshness_reference != lineage.freshness_reference {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.freshness_reference",
        });
    }
    if public_claim.controlled_account_id
        != witness_bundle.authorization_envelope.controlled_account_id
    {
        return Err(RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "public_claim.controlled_account_id",
        });
    }

    Ok(())
}
