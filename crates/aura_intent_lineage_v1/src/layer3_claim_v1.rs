// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Layer 3 proof-claim assembly for the canonical native cat-map path.
//! This module constructs deterministic public/witness containers but does not build a proof.

use core::fmt;

use crate::{
    build_dcm_claim_521_v1, build_storm_public_inputs_v1, derive_dcm_commitment_root_521_v1,
    AuraLayer4IntentBodyV1,
    AuraLayer4IntentHashV1Error, AuthorizationEnvelopeV1, AuthorizationEnvelopeV1Decision,
    AuthorizationEnvelopeValidityBoundsV1, AuthorizationLineageV1, AuthorizationLineageV1Error,
    DcmClaim521V1, DcmCommitmentKindV1, DcmConfig521V1, DcmExecution521ErrorV1, DcmExecution521V1,
    DcmInput521V1, DcmState521V1, FreshnessModeV1, IntentTypeV1,
    Layer1Layer2BridgeSuccess521V1, LowerHex32, StormClaim521V1, StormPublicInputs521V1,
    SubjectBindingTypeV1, HASH_LEN_V1, LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH,
    LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH, LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY,
    VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER, VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS,
    VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER, VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS,
};

pub const LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1: u8 = 1;
pub const LAYER3_PUBLIC_INPUT_CATEGORY_COUNT_V1: u16 = 2;
pub const LAYER3_WITNESS_CATEGORY_COUNT_V1: u16 = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer3ClaimConstructionInputV1 {
    pub lower_layer_claim: StormClaim521V1,
    pub lower_layer_public_inputs: StormPublicInputs521V1,
    pub legacy_lower_layer_claim: DcmClaim521V1,
    pub dcm_execution: DcmExecution521V1,
    pub lineage: AuthorizationLineageV1,
    pub envelope: AuthorizationEnvelopeV1,
    pub envelope_decision: AuthorizationEnvelopeV1Decision,
    pub intent: AuraLayer4IntentBodyV1,
}

impl Layer3ClaimConstructionInputV1 {
    pub fn from_native_bridge_with_storm_claim(
        dcm_config: DcmConfig521V1,
        dcm_input: DcmInput521V1,
        lower_layer_claim: StormClaim521V1,
        intent: AuraLayer4IntentBodyV1,
        bridge: Layer1Layer2BridgeSuccess521V1,
    ) -> Self {
        let expected_claim = build_dcm_claim_521_v1(&dcm_config, &dcm_input, &bridge.dcm_execution);
        debug_assert_eq!(bridge.dcm_claim, expected_claim);
        Self {
            lower_layer_public_inputs: build_storm_public_inputs_v1(&lower_layer_claim),
            lower_layer_claim,
            legacy_lower_layer_claim: bridge.dcm_claim,
            dcm_execution: bridge.dcm_execution,
            lineage: bridge.lineage,
            envelope: bridge.envelope,
            envelope_decision: bridge.envelope_decision,
            intent,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicClaimV1 {
    pub lineage_version: u8,
    pub lineage_flags: u16,
    pub dcm_commitment_kind: DcmCommitmentKindV1,
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub storm_version: u8,
    pub storm_modulus_id: u8,
    pub storm_iteration_count: u64,
    pub storm_side_a_hash: [u8; HASH_LEN_V1],
    pub storm_side_b_hash: [u8; HASH_LEN_V1],
    pub storm_context_hash: [u8; HASH_LEN_V1],
    pub storm_trace_root: [u8; HASH_LEN_V1],
    pub subject_binding_type: SubjectBindingTypeV1,
    pub subject_id: [u8; HASH_LEN_V1],
    pub intent_type: IntentTypeV1,
    pub intent_hash: [u8; HASH_LEN_V1],
    pub freshness_mode: FreshnessModeV1,
    pub freshness_nonce: [u8; HASH_LEN_V1],
    pub freshness_reference: u64,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub controlled_account_id: [u8; HASH_LEN_V1],
    pub envelope_validity_bounds: AuthorizationEnvelopeValidityBoundsV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer2WitnessFieldsV1 {
    pub dcm_trace_commitment: Option<[u8; HASH_LEN_V1]>,
    pub subject_public_key: Option<[u8; HASH_LEN_V1]>,
    pub proof_material_v1_hash: Option<[u8; HASH_LEN_V1]>,
    pub fractal_key_v1_hash: Option<[u8; HASH_LEN_V1]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessBundleV1 {
    pub lower_layer_claim: StormClaim521V1,
    pub lower_layer_public_inputs: StormPublicInputs521V1,
    pub legacy_lower_layer_claim: DcmClaim521V1,
    pub layer1_execution_trace: Vec<DcmState521V1>,
    pub layer2_witness_fields: Layer2WitnessFieldsV1,
    pub lineage_preimage: Vec<u8>,
    pub intent_body: AuraLayer4IntentBodyV1,
    pub intent_hash_preimage: Vec<u8>,
    pub authorization_envelope: AuthorizationEnvelopeV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofClaimAssemblyMetadataV1 {
    pub assembly_version: u8,
    // Counts below are logical category counts, not scalar field counts.
    pub public_input_category_count: u16,
    pub witness_category_count: u16,
    pub trace_state_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofClaimAssemblyV1 {
    pub public_claim: PublicClaimV1,
    pub witness_bundle: WitnessBundleV1,
    pub metadata: ProofClaimAssemblyMetadataV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer3ClaimErrorV1 {
    EnvelopeNotAccepted,
    Layer1ParametersInvalid(DcmExecution521ErrorV1),
    MissingRequiredWitnessField {
        field: &'static str,
    },
    InvalidIntent {
        reason: &'static str,
    },
    InvalidFieldCombination {
        reason: &'static str,
    },
    ClaimRelationshipMismatch {
        field: &'static str,
    },
    ModeConflict {
        reason: &'static str,
    },
    HashMismatch {
        field: &'static str,
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    EnvelopeValidationChanged {
        actual: AuthorizationEnvelopeV1Decision,
    },
}

impl fmt::Display for Layer3ClaimErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvelopeNotAccepted => write!(f, "envelope decision must be accept"),
            Self::Layer1ParametersInvalid(error) => {
                write!(f, "layer1 parameters invalid: {error}")
            }
            Self::MissingRequiredWitnessField { field } => {
                write!(f, "missing required witness field: {field}")
            }
            Self::InvalidIntent { reason } => write!(f, "invalid intent: {reason}"),
            Self::InvalidFieldCombination { reason } => {
                write!(f, "invalid field combination: {reason}")
            }
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::ModeConflict { reason } => write!(f, "mode conflict: {reason}"),
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
            Self::EnvelopeValidationChanged { actual } => {
                write!(f, "envelope validation changed: {actual:?}")
            }
        }
    }
}

impl std::error::Error for Layer3ClaimErrorV1 {}

pub fn assemble_layer3_proof_claim_v1(
    input: &Layer3ClaimConstructionInputV1,
) -> Result<ProofClaimAssemblyV1, Layer3ClaimErrorV1> {
    let intent_hash = input.intent.intent_hash().map_err(map_intent_error)?;
    validate_storm_claim_consistency_v1(
        &input.lower_layer_claim,
        &input.lower_layer_public_inputs,
    )?;
    validate_dcm_execution_consistency_v1(&input.legacy_lower_layer_claim, &input.dcm_execution)?;

    input.lineage.validate().map_err(map_lineage_error)?;

    if input.lineage.dcm_commitment_kind != DcmCommitmentKindV1::DcmRootCommitmentV1 {
        return Err(Layer3ClaimErrorV1::ModeConflict {
            reason: "legacy_dcm_commitment_kind_not_allowed",
        });
    }

    if input.lineage.intent_type != IntentTypeV1::AuraLayer4IntentHashV1 {
        return Err(Layer3ClaimErrorV1::ModeConflict {
            reason: "legacy_or_non_native_intent_type_not_allowed",
        });
    }

    if matches!(
        input.lineage.freshness_mode,
        FreshnessModeV1::LegacyV1ChallengeFreshness
    ) {
        return Err(Layer3ClaimErrorV1::ModeConflict {
            reason: "legacy_freshness_mode_not_allowed",
        });
    }

    if input.lineage.lineage_flags
        & (LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH | LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH)
        != 0
    {
        return Err(Layer3ClaimErrorV1::ModeConflict {
            reason: "legacy_compatibility_fields_not_allowed",
        });
    }

    if input.lineage.lineage_flags & crate::LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT != 0 {
        return Err(Layer3ClaimErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_carry_dcm_trace_commitment",
        });
    }

    if input.lineage.dcm_commitment_root != input.legacy_lower_layer_claim.commitment_root {
        return Err(Layer3ClaimErrorV1::HashMismatch {
            field: "dcm_commitment_root",
            expected: input.legacy_lower_layer_claim.commitment_root,
            actual: input.lineage.dcm_commitment_root,
        });
    }

    if input.lineage.intent_hash != intent_hash {
        return Err(Layer3ClaimErrorV1::HashMismatch {
            field: "intent_hash",
            expected: intent_hash,
            actual: input.lineage.intent_hash,
        });
    }

    let lineage_hash = input.lineage.lineage_hash().map_err(map_lineage_error)?;

    if input.envelope.lineage_hash != lineage_hash {
        return Err(Layer3ClaimErrorV1::HashMismatch {
            field: "envelope.lineage_hash",
            expected: lineage_hash,
            actual: input.envelope.lineage_hash,
        });
    }

    let accept_lineage_hash = match input.envelope_decision {
        AuthorizationEnvelopeV1Decision::Accept { lineage_hash } => lineage_hash,
        AuthorizationEnvelopeV1Decision::Reject(_) => {
            return Err(Layer3ClaimErrorV1::EnvelopeNotAccepted)
        }
    };

    if accept_lineage_hash != lineage_hash {
        return Err(Layer3ClaimErrorV1::HashMismatch {
            field: "envelope_decision.lineage_hash",
            expected: lineage_hash,
            actual: accept_lineage_hash,
        });
    }

    let actual_envelope_decision = input
        .envelope
        .validate(&crate::AuthorizationEnvelopeFreshnessContextV1::default());
    if actual_envelope_decision != input.envelope_decision {
        return Err(Layer3ClaimErrorV1::EnvelopeValidationChanged {
            actual: actual_envelope_decision,
        });
    }

    let inline_lineage = input.envelope.inline_authorization_lineage_v1.ok_or(
        Layer3ClaimErrorV1::MissingRequiredWitnessField {
            field: "envelope.inline_authorization_lineage_v1",
        },
    )?;

    if inline_lineage != input.lineage {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "envelope.inline_authorization_lineage_v1",
        });
    }

    if input.envelope.controlled_account_id != input.intent.sender_account_id {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "envelope.controlled_account_id",
        });
    }

    validate_envelope_bounds_against_intent(
        &input.intent,
        &input.envelope.envelope_validity_bounds,
    )?;

    let public_claim = PublicClaimV1 {
        lineage_version: input.lineage.version,
        lineage_flags: input.lineage.lineage_flags,
        dcm_commitment_kind: input.lineage.dcm_commitment_kind,
        dcm_commitment_root: input.lineage.dcm_commitment_root,
        storm_version: input.lower_layer_public_inputs.version,
        storm_modulus_id: input.lower_layer_public_inputs.modulus_id,
        storm_iteration_count: input.lower_layer_public_inputs.iteration_count,
        storm_side_a_hash: input.lower_layer_public_inputs.side_a_hash,
        storm_side_b_hash: input.lower_layer_public_inputs.side_b_hash,
        storm_context_hash: input.lower_layer_public_inputs.context_hash,
        storm_trace_root: input.lower_layer_public_inputs.trace_root,
        subject_binding_type: input.lineage.subject_binding_type,
        subject_id: input.lineage.subject_id,
        intent_type: input.lineage.intent_type,
        intent_hash: input.lineage.intent_hash,
        freshness_mode: input.lineage.freshness_mode,
        freshness_nonce: input.lineage.freshness_nonce,
        freshness_reference: input.lineage.freshness_reference,
        lineage_hash,
        controlled_account_id: input.envelope.controlled_account_id,
        envelope_validity_bounds: input.envelope.envelope_validity_bounds,
    };

    let witness_bundle = WitnessBundleV1 {
        lower_layer_claim: input.lower_layer_claim,
        lower_layer_public_inputs: input.lower_layer_public_inputs,
        legacy_lower_layer_claim: input.legacy_lower_layer_claim,
        layer1_execution_trace: input.dcm_execution.states.clone(),
        layer2_witness_fields: build_layer2_witness_fields(&input.lineage),
        lineage_preimage: input
            .lineage
            .canonical_preimage()
            .map_err(map_lineage_error)?,
        intent_body: input.intent,
        intent_hash_preimage: input
            .intent
            .canonical_hash_preimage()
            .map_err(map_intent_error)?,
        authorization_envelope: input.envelope,
    };

    Ok(ProofClaimAssemblyV1 {
        public_claim,
        witness_bundle,
        metadata: ProofClaimAssemblyMetadataV1 {
            assembly_version: LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1,
            public_input_category_count: LAYER3_PUBLIC_INPUT_CATEGORY_COUNT_V1,
            witness_category_count: LAYER3_WITNESS_CATEGORY_COUNT_V1,
            trace_state_count: input.legacy_lower_layer_claim.trace_state_count(),
        },
    })
}

fn validate_storm_claim_consistency_v1(
    lower_layer_claim: &StormClaim521V1,
    lower_layer_public_inputs: &StormPublicInputs521V1,
) -> Result<(), Layer3ClaimErrorV1> {
    lower_layer_claim
        .validate()
        .map_err(|_| Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "lower_layer_claim",
        })?;

    let expected_public_inputs = build_storm_public_inputs_v1(lower_layer_claim);
    if &expected_public_inputs != lower_layer_public_inputs {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "lower_layer_public_inputs",
        });
    }

    Ok(())
}

fn validate_dcm_execution_consistency_v1(
    lower_layer_claim: &DcmClaim521V1,
    dcm_execution: &DcmExecution521V1,
) -> Result<(), Layer3ClaimErrorV1> {
    lower_layer_claim
        .config
        .validate()
        .map_err(Layer3ClaimErrorV1::Layer1ParametersInvalid)?;

    let first_state =
        dcm_execution
            .states
            .first()
            .ok_or(Layer3ClaimErrorV1::MissingRequiredWitnessField {
                field: "dcm_execution.states",
            })?;
    if *first_state != lower_layer_claim.initial_state {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "dcm_execution.states[0]",
        });
    }

    let actual_trace_length = dcm_execution.states.len() as u64;
    if dcm_execution.trace_length != actual_trace_length
        || lower_layer_claim.trace_state_count() != actual_trace_length
    {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "dcm_execution.trace_length",
        });
    }

    let last_state = *dcm_execution
        .states
        .last()
        .expect("checked non-empty execution trace");
    if dcm_execution.final_state != last_state || lower_layer_claim.final_state != last_state {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "dcm_execution.final_state",
        });
    }

    let expected_commitment_root =
        derive_dcm_commitment_root_521_v1(&lower_layer_claim.config, dcm_execution);
    if lower_layer_claim.commitment_root != expected_commitment_root {
        return Err(Layer3ClaimErrorV1::HashMismatch {
            field: "dcm_execution.commitment_root",
            expected: expected_commitment_root,
            actual: lower_layer_claim.commitment_root,
        });
    }

    Ok(())
}

fn build_layer2_witness_fields(lineage: &AuthorizationLineageV1) -> Layer2WitnessFieldsV1 {
    Layer2WitnessFieldsV1 {
        dcm_trace_commitment: None,
        subject_public_key: if lineage.lineage_flags & LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY != 0 {
            Some(lineage.subject_public_key)
        } else {
            None
        },
        proof_material_v1_hash: if lineage.lineage_flags & LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH
            != 0
        {
            Some(lineage.proof_material_v1_hash)
        } else {
            None
        },
        fractal_key_v1_hash: if lineage.lineage_flags & LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH != 0 {
            Some(lineage.fractal_key_v1_hash)
        } else {
            None
        },
    }
}

fn validate_envelope_bounds_against_intent(
    intent: &AuraLayer4IntentBodyV1,
    envelope_bounds: &AuthorizationEnvelopeValidityBoundsV1,
) -> Result<(), Layer3ClaimErrorV1> {
    if envelope_bounds.validity_flags != intent.validity_flags {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "envelope_validity_bounds.validity_flags",
        });
    }

    validate_not_before_u64(
        envelope_bounds.validity_flags,
        VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS,
        envelope_bounds.not_before_unix_seconds,
        intent.not_before_unix_seconds,
        "envelope_validity_bounds.not_before_unix_seconds",
    )?;
    validate_not_after_u64(
        envelope_bounds.validity_flags,
        VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS,
        envelope_bounds.not_after_unix_seconds,
        intent.not_after_unix_seconds,
        "envelope_validity_bounds.not_after_unix_seconds",
    )?;
    validate_not_before_u64(
        envelope_bounds.validity_flags,
        VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER,
        envelope_bounds.not_before_batch_number,
        intent.not_before_batch_number,
        "envelope_validity_bounds.not_before_batch_number",
    )?;
    validate_not_after_u64(
        envelope_bounds.validity_flags,
        VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER,
        envelope_bounds.not_after_batch_number,
        intent.not_after_batch_number,
        "envelope_validity_bounds.not_after_batch_number",
    )?;

    Ok(())
}

fn validate_not_before_u64(
    flags: u16,
    flag: u16,
    envelope_value: u64,
    intent_value: u64,
    reason: &'static str,
) -> Result<(), Layer3ClaimErrorV1> {
    if flags & flag != 0 && envelope_value < intent_value {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch { field: reason });
    }
    Ok(())
}

fn validate_not_after_u64(
    flags: u16,
    flag: u16,
    envelope_value: u64,
    intent_value: u64,
    reason: &'static str,
) -> Result<(), Layer3ClaimErrorV1> {
    if flags & flag != 0 && envelope_value > intent_value {
        return Err(Layer3ClaimErrorV1::ClaimRelationshipMismatch { field: reason });
    }
    Ok(())
}

fn map_intent_error(error: AuraLayer4IntentHashV1Error) -> Layer3ClaimErrorV1 {
    Layer3ClaimErrorV1::InvalidIntent {
        reason: error.reject_reason(),
    }
}

fn map_lineage_error(error: AuthorizationLineageV1Error) -> Layer3ClaimErrorV1 {
    match error {
        AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyIntentType
        | AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyFreshnessMode
        | AuthorizationLineageV1Error::NativeDcmRootedCannotCarryProofMaterialV1Hash
        | AuthorizationLineageV1Error::NativeDcmRootedCannotCarryFractalKeyV1Hash
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresZeroDcmCommitmentRoot
        | AuthorizationLineageV1Error::LegacyCompatibilityCannotCarryDcmTraceCommitment
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyIntentType
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyFreshnessMode
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresProofMaterialV1Hash
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresFractalKeyV1Hash => {
            Layer3ClaimErrorV1::ModeConflict {
                reason: error.reject_reason(),
            }
        }
        _ => Layer3ClaimErrorV1::InvalidFieldCombination {
            reason: error.reject_reason(),
        },
    }
}
