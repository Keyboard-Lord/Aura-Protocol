// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Native Layer 1 -> Layer 2 bridge for Aura's canonical cat-map runtime.
//! This module assembles native lineage and envelope artifacts but does not prove them.

use core::fmt;

use crate::{
    build_dcm_claim_521_v1, derive_dcm_commitment_root_521_v1, sha256_bytes,
    AuraLayer4IntentBodyV1, AuraLayer4IntentHashV1Error, AuthorizationEnvelopeAuthKindV1,
    AuthorizationEnvelopeFreshnessContextV1, AuthorizationEnvelopeLineageTransportKindV1,
    AuthorizationEnvelopeV1, AuthorizationEnvelopeV1Decision, AuthorizationEnvelopeV1Error,
    AuthorizationEnvelopeValidityBoundsV1, AuthorizationLineageV1, AuthorizationLineageV1Error,
    DcmClaim521V1, DcmCommitmentKindV1, DcmConfig521V1, DcmConfigV1, DcmExecution521ErrorV1,
    DcmExecution521V1, DcmExecutionErrorV1, DcmExecutionV1, DcmInput521V1, DcmInputV1,
    FreshnessModeV1, IntentTypeV1, SubjectBindingTypeV1,
    AURA_DCM_V1_COMMITMENT_ROOT_DOMAIN_SEPARATOR, AUTHORIZATION_LINEAGE_VERSION_V1, HASH_LEN_V1,
    LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT, LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer1Layer2BridgeSubjectBindingV1 {
    pub subject_binding_type: SubjectBindingTypeV1,
    pub subject_id: [u8; HASH_LEN_V1],
    pub subject_public_key: Option<[u8; HASH_LEN_V1]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer1Layer2BridgeFreshnessV1 {
    pub freshness_mode: FreshnessModeV1,
    pub freshness_nonce: [u8; HASH_LEN_V1],
    pub freshness_reference: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer1Layer2BridgeIntentSourceV1 {
    IntentBody(AuraLayer4IntentBodyV1),
    IntentHash {
        controlled_account_id: [u8; HASH_LEN_V1],
        intent_hash: [u8; HASH_LEN_V1],
        validity_bounds: AuthorizationEnvelopeValidityBoundsV1,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcmLayer1CommitmentsV1 {
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub dcm_trace_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer1Layer2BridgeSuccessV1 {
    pub dcm_execution: DcmExecutionV1,
    pub dcm_commitments: DcmLayer1CommitmentsV1,
    pub lineage: AuthorizationLineageV1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub envelope: AuthorizationEnvelopeV1,
    pub envelope_decision: AuthorizationEnvelopeV1Decision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer1Layer2BridgeSuccess521V1 {
    pub dcm_execution: DcmExecution521V1,
    pub dcm_claim: DcmClaim521V1,
    pub dcm_commitments: DcmLayer1CommitmentsV1,
    pub lineage: AuthorizationLineageV1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub envelope: AuthorizationEnvelopeV1,
    pub envelope_decision: AuthorizationEnvelopeV1Decision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer1Layer2BridgeErrorV1 {
    DcmExecution(DcmExecutionErrorV1),
    DcmExecution521(DcmExecution521ErrorV1),
    InvalidIntent { reason: &'static str },
    InvalidFieldCombination { reason: &'static str },
    ModeConflict { reason: &'static str },
    EnvelopeRejected(AuthorizationEnvelopeV1Error),
}

impl fmt::Display for Layer1Layer2BridgeErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DcmExecution(error) => write!(f, "dcm execution failed: {error}"),
            Self::DcmExecution521(error) => write!(f, "521-bit dcm execution failed: {error}"),
            Self::InvalidIntent { reason } => write!(f, "invalid intent: {reason}"),
            Self::InvalidFieldCombination { reason } => {
                write!(f, "invalid field combination: {reason}")
            }
            Self::ModeConflict { reason } => write!(f, "mode conflict: {reason}"),
            Self::EnvelopeRejected(error) => write!(f, "envelope rejected: {error}"),
        }
    }
}

impl std::error::Error for Layer1Layer2BridgeErrorV1 {}

pub fn run_native_layer1_layer2_bridge_v1(
    dcm_config: &DcmConfigV1,
    dcm_input: &DcmInputV1,
    intent_source: Layer1Layer2BridgeIntentSourceV1,
    subject_binding: Layer1Layer2BridgeSubjectBindingV1,
    freshness: Layer1Layer2BridgeFreshnessV1,
) -> Result<Layer1Layer2BridgeSuccessV1, Layer1Layer2BridgeErrorV1> {
    let dcm_execution = DcmExecutionV1::run(dcm_config, dcm_input)
        .map_err(Layer1Layer2BridgeErrorV1::DcmExecution)?;
    let dcm_commitments = derive_dcm_layer1_commitments_v1(dcm_config, &dcm_execution);
    let completed = complete_native_bridge_v1(
        dcm_commitments,
        intent_source,
        subject_binding,
        freshness,
        true,
    )?;

    Ok(Layer1Layer2BridgeSuccessV1 {
        dcm_execution,
        dcm_commitments,
        lineage: completed.lineage,
        lineage_hash: completed.lineage_hash,
        envelope: completed.envelope,
        envelope_decision: completed.envelope_decision,
    })
}

pub fn run_native_layer1_layer2_bridge_521_v1(
    dcm_config: &DcmConfig521V1,
    dcm_input: &DcmInput521V1,
    intent_source: Layer1Layer2BridgeIntentSourceV1,
    subject_binding: Layer1Layer2BridgeSubjectBindingV1,
    freshness: Layer1Layer2BridgeFreshnessV1,
) -> Result<Layer1Layer2BridgeSuccess521V1, Layer1Layer2BridgeErrorV1> {
    let dcm_execution = DcmExecution521V1::run(dcm_config, dcm_input)
        .map_err(Layer1Layer2BridgeErrorV1::DcmExecution521)?;
    let dcm_claim = build_dcm_claim_521_v1(dcm_config, dcm_input, &dcm_execution);
    let dcm_commitments = DcmLayer1CommitmentsV1 {
        dcm_commitment_root: dcm_claim.commitment_root,
        dcm_trace_commitment: dcm_execution.trace_commitment,
    };
    let completed = complete_native_bridge_v1(
        dcm_commitments,
        intent_source,
        subject_binding,
        freshness,
        false,
    )?;

    Ok(Layer1Layer2BridgeSuccess521V1 {
        dcm_execution,
        dcm_claim,
        dcm_commitments,
        lineage: completed.lineage,
        lineage_hash: completed.lineage_hash,
        envelope: completed.envelope,
        envelope_decision: completed.envelope_decision,
    })
}

pub fn derive_dcm_layer1_commitments_521_v1(
    dcm_config: &DcmConfig521V1,
    dcm_execution: &DcmExecution521V1,
) -> DcmLayer1CommitmentsV1 {
    DcmLayer1CommitmentsV1 {
        dcm_commitment_root: derive_dcm_commitment_root_521_v1(dcm_config, dcm_execution),
        dcm_trace_commitment: dcm_execution.trace_commitment,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompletedNativeBridgeArtifactsV1 {
    lineage: AuthorizationLineageV1,
    lineage_hash: [u8; HASH_LEN_V1],
    envelope: AuthorizationEnvelopeV1,
    envelope_decision: AuthorizationEnvelopeV1Decision,
}

fn complete_native_bridge_v1(
    dcm_commitments: DcmLayer1CommitmentsV1,
    intent_source: Layer1Layer2BridgeIntentSourceV1,
    subject_binding: Layer1Layer2BridgeSubjectBindingV1,
    freshness: Layer1Layer2BridgeFreshnessV1,
    include_dcm_trace_commitment: bool,
) -> Result<CompletedNativeBridgeArtifactsV1, Layer1Layer2BridgeErrorV1> {
    let resolved_intent = resolve_intent_source(intent_source)?;
    let lineage = build_native_authorization_lineage_v1(
        dcm_commitments,
        resolved_intent.intent_hash,
        subject_binding,
        freshness,
        include_dcm_trace_commitment,
    )?;
    let lineage_hash = lineage.lineage_hash().map_err(map_lineage_error)?;
    let envelope = AuthorizationEnvelopeV1 {
        auth_version: 1,
        auth_kind: AuthorizationEnvelopeAuthKindV1::AuthorizationLineageV1ExactIntent,
        controlled_account_id: resolved_intent.controlled_account_id,
        envelope_validity_bounds: resolved_intent.validity_bounds,
        lineage_transport_kind:
            AuthorizationEnvelopeLineageTransportKindV1::InlineAuthorizationLineageV1,
        lineage_hash,
        inline_authorization_lineage_v1: Some(lineage),
    };

    let envelope_decision = envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default());
    match envelope_decision {
        AuthorizationEnvelopeV1Decision::Accept { .. } => Ok(CompletedNativeBridgeArtifactsV1 {
            lineage,
            lineage_hash,
            envelope,
            envelope_decision,
        }),
        AuthorizationEnvelopeV1Decision::Reject(error) => Err(match error {
            AuthorizationEnvelopeV1Error::ModeConflict { reason } => {
                Layer1Layer2BridgeErrorV1::ModeConflict { reason }
            }
            _ => Layer1Layer2BridgeErrorV1::EnvelopeRejected(error),
        }),
    }
}

pub fn derive_dcm_layer1_commitments_v1(
    dcm_config: &DcmConfigV1,
    dcm_execution: &DcmExecutionV1,
) -> DcmLayer1CommitmentsV1 {
    let dcm_trace_commitment = dcm_execution.trace_commitment;

    // Legacy small-modulus bridge root retained for migration and toy-harness coverage only.
    // Active lower-layer bindings use `derive_dcm_layer1_commitments_521_v1`.
    let final_state_bytes = dcm_execution.final_state.canonical_bytes();
    let mut root_preimage = Vec::with_capacity(
        AURA_DCM_V1_COMMITMENT_ROOT_DOMAIN_SEPARATOR.len() + 8 * 3 + 16 + HASH_LEN_V1,
    );
    root_preimage.extend_from_slice(AURA_DCM_V1_COMMITMENT_ROOT_DOMAIN_SEPARATOR);
    root_preimage.extend_from_slice(&dcm_config.modulus.to_le_bytes());
    root_preimage.extend_from_slice(&dcm_config.iteration_count.to_le_bytes());
    root_preimage.extend_from_slice(&final_state_bytes);
    root_preimage.extend_from_slice(&dcm_execution.trace_length.to_le_bytes());
    root_preimage.extend_from_slice(&dcm_trace_commitment);

    DcmLayer1CommitmentsV1 {
        dcm_commitment_root: sha256_bytes(&root_preimage),
        dcm_trace_commitment,
    }
}

pub fn build_native_authorization_lineage_v1(
    dcm_commitments: DcmLayer1CommitmentsV1,
    intent_hash: [u8; HASH_LEN_V1],
    subject_binding: Layer1Layer2BridgeSubjectBindingV1,
    freshness: Layer1Layer2BridgeFreshnessV1,
    include_dcm_trace_commitment: bool,
) -> Result<AuthorizationLineageV1, Layer1Layer2BridgeErrorV1> {
    let mut lineage_flags = 0u16;
    let dcm_trace_commitment = if include_dcm_trace_commitment {
        lineage_flags |= LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT;
        dcm_commitments.dcm_trace_commitment
    } else {
        [0u8; HASH_LEN_V1]
    };
    let subject_public_key = match subject_binding.subject_public_key {
        Some(subject_public_key) => {
            lineage_flags |= LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY;
            subject_public_key
        }
        None => [0u8; HASH_LEN_V1],
    };

    let lineage = AuthorizationLineageV1 {
        version: AUTHORIZATION_LINEAGE_VERSION_V1,
        lineage_flags,
        dcm_commitment_kind: DcmCommitmentKindV1::DcmRootCommitmentV1,
        dcm_commitment_root: dcm_commitments.dcm_commitment_root,
        dcm_trace_commitment,
        subject_binding_type: subject_binding.subject_binding_type,
        subject_id: subject_binding.subject_id,
        subject_public_key,
        intent_type: IntentTypeV1::AuraLayer4IntentHashV1,
        intent_hash,
        freshness_mode: freshness.freshness_mode,
        freshness_nonce: freshness.freshness_nonce,
        freshness_reference: freshness.freshness_reference,
        proof_material_v1_hash: [0u8; HASH_LEN_V1],
        fractal_key_v1_hash: [0u8; HASH_LEN_V1],
    };

    lineage.validate().map_err(map_lineage_error)?;
    Ok(lineage)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedIntentSourceV1 {
    controlled_account_id: [u8; HASH_LEN_V1],
    intent_hash: [u8; HASH_LEN_V1],
    validity_bounds: AuthorizationEnvelopeValidityBoundsV1,
}

fn resolve_intent_source(
    intent_source: Layer1Layer2BridgeIntentSourceV1,
) -> Result<ResolvedIntentSourceV1, Layer1Layer2BridgeErrorV1> {
    match intent_source {
        Layer1Layer2BridgeIntentSourceV1::IntentBody(intent) => {
            let intent_hash = intent.intent_hash().map_err(map_intent_error)?;
            Ok(ResolvedIntentSourceV1 {
                controlled_account_id: intent.sender_account_id,
                intent_hash,
                validity_bounds: AuthorizationEnvelopeValidityBoundsV1 {
                    validity_flags: intent.validity_flags,
                    not_before_unix_seconds: intent.not_before_unix_seconds,
                    not_after_unix_seconds: intent.not_after_unix_seconds,
                    not_before_batch_number: intent.not_before_batch_number,
                    not_after_batch_number: intent.not_after_batch_number,
                },
            })
        }
        Layer1Layer2BridgeIntentSourceV1::IntentHash {
            controlled_account_id,
            intent_hash,
            validity_bounds,
        } => Ok(ResolvedIntentSourceV1 {
            controlled_account_id,
            intent_hash,
            validity_bounds,
        }),
    }
}

fn map_intent_error(error: AuraLayer4IntentHashV1Error) -> Layer1Layer2BridgeErrorV1 {
    Layer1Layer2BridgeErrorV1::InvalidIntent {
        reason: error.reject_reason(),
    }
}

fn map_lineage_error(error: AuthorizationLineageV1Error) -> Layer1Layer2BridgeErrorV1 {
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
            Layer1Layer2BridgeErrorV1::ModeConflict {
                reason: error.reject_reason(),
            }
        }
        _ => Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
            reason: error.reject_reason(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_dcm_layer1_commitments_521_v1, run_native_layer1_layer2_bridge_521_v1,
        Layer1Layer2BridgeFreshnessV1, Layer1Layer2BridgeIntentSourceV1,
        Layer1Layer2BridgeSubjectBindingV1,
    };
    use crate::{
        derive_dcm_commitment_root_521_v1, AuraLayer4FeePolicyKindV1, AuraLayer4IntentBodyV1,
        AuraLayer4OperationBodyV1, AuraLayer4TxKindV1, AuthorizationEnvelopeV1Decision,
        DcmConfig521V1, DcmExecution521V1, DcmInput521V1, FieldElement521V1, FreshnessModeV1,
        SubjectBindingTypeV1, ValueTransferOperationV1, FIELD_ELEMENT_521_BYTE_LEN_V1,
        FIELD_MODULUS_521_V1,
    };

    #[test]
    fn derive_dcm_layer1_commitments_521_matches_manual_root_rebuild() {
        let config = canonical_config_521();
        let input = canonical_input_521();
        let execution = DcmExecution521V1::run(&config, &input).unwrap();
        let commitments = derive_dcm_layer1_commitments_521_v1(&config, &execution);
        assert_eq!(
            commitments.dcm_commitment_root,
            derive_dcm_commitment_root_521_v1(&config, &execution)
        );
    }

    #[test]
    fn native_521_bridge_embeds_derived_commitments() {
        let result = run_native_layer1_layer2_bridge_521_v1(
            &canonical_config_521(),
            &canonical_input_521(),
            Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
            canonical_subject_binding(),
            canonical_freshness(),
        )
        .unwrap();

        let expected_commitments =
            derive_dcm_layer1_commitments_521_v1(&canonical_config_521(), &result.dcm_execution);

        assert_eq!(result.dcm_commitments, expected_commitments);
        assert_eq!(
            result.envelope_decision,
            AuthorizationEnvelopeV1Decision::Accept {
                lineage_hash: result.lineage_hash,
            }
        );
    }

    fn canonical_config_521() -> DcmConfig521V1 {
        DcmConfig521V1 { iteration_count: 2 }
    }

    fn canonical_input_521() -> DcmInput521V1 {
        DcmInput521V1 {
            x0: max_minus_one_521(),
            y0: small_value_521(1),
        }
    }

    fn canonical_intent() -> AuraLayer4IntentBodyV1 {
        AuraLayer4IntentBodyV1 {
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
        }
    }

    fn canonical_subject_binding() -> Layer1Layer2BridgeSubjectBindingV1 {
        Layer1Layer2BridgeSubjectBindingV1 {
            subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            subject_id: [0x55; 32],
            subject_public_key: None,
        }
    }

    fn canonical_freshness() -> Layer1Layer2BridgeFreshnessV1 {
        Layer1Layer2BridgeFreshnessV1 {
            freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
            freshness_nonce: [0x66; 32],
            freshness_reference: 4242,
        }
    }

    fn max_minus_one_521() -> FieldElement521V1 {
        let mut bytes = FIELD_MODULUS_521_V1;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }

    fn small_value_521(value: u8) -> FieldElement521V1 {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
        FieldElement521V1::from_bytes(bytes).unwrap()
    }
}
