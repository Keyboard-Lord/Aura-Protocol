use super::authorization::{
    validate_authorization_intent_envelope_v1, AuthorizationFreshnessBindingTypeV1,
    AuthorizationIntentEnvelopeV1, AuthorizationIntentTypeV1, AuthorizationIntentVersionV1,
    AuthorizationLineageBindingV1, AuthorizationSubjectBindingTypeV1,
};
use super::proof::{
    validate_stark_proof_envelope_v1, DcmClaimWireV1, StarkProofEnvelopeV1, StarkProofVersionV1,
};
use super::settlement::{
    validate_solana_settlement_request_v1, SolanaCommitmentConfigV1, SolanaSettlementRequestWireV1,
    SolanaSettlementVersionV1,
};
use super::submission::{
    build_submit_proof_request_wire_v1, BuildSubmitProofRequestWireRequestV1,
    SubmitProofRequestWireV1,
};
use crate::{AuraSdkErrorV1, legacy::PreparedSubmitProofV1};
use serde::{Deserialize, Serialize};

/// ```compile_fail
/// use aura_sdk_v1::{legacy::BuildSettlementPipelineFromPreparedProofRequestV1, legacy::PreparedSubmitProofV1};
///
/// let prepared: PreparedSubmitProofV1 = todo!();
/// let _ = BuildSettlementPipelineFromPreparedProofRequestV1 {
///     prepared_submit_proof: prepared,
///     program_id_base58: String::from("11111111111111111111111111111111"),
///     submitter_pubkey_base58: String::from("11111111111111111111111111111111"),
///     challenge_pubkey_base58: String::from("11111111111111111111111111111111"),
///     intent_id_hex: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
///     proof_session_id_hex: String::from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
///     initial_state_hex: String::from("11"),
///     final_state_hex: String::from("22"),
///     commitment_root_hex: String::from("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
///     solana_rpc_url: Some(String::from("https://rpc.aura.invalid")),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildSettlementPipelineFromPreparedProofRequestV1 {
    pub prepared_submit_proof: PreparedSubmitProofV1,
    pub program_id_base58: String,
    pub submitter_pubkey_base58: String,
    pub challenge_pubkey_base58: String,
    pub intent_id_hex: String,
    pub proof_session_id_hex: String,
    pub iteration_count: u64,
    pub initial_state_hex: String,
    pub final_state_hex: String,
    pub commitment_root_hex: String,
    pub solana_rpc_url: Option<String>,
    pub commitment_config: SolanaCommitmentConfigV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPipelineFromPreparedProofV1 {
    pub submit_proof_request_wire: SubmitProofRequestWireV1,
    pub authorization_intent_envelope: AuthorizationIntentEnvelopeV1,
    pub stark_proof_envelope: StarkProofEnvelopeV1,
    pub solana_settlement_request_wire: SolanaSettlementRequestWireV1,
}

pub fn build_settlement_pipeline_from_prepared_proof_v1(
    request: BuildSettlementPipelineFromPreparedProofRequestV1,
) -> Result<SettlementPipelineFromPreparedProofV1, AuraSdkErrorV1> {
    let intent_id_hex = request.intent_id_hex.clone();

    let submit_proof_request_wire =
        build_submit_proof_request_wire_v1(BuildSubmitProofRequestWireRequestV1 {
            prepared_submit_proof: request.prepared_submit_proof,
            program_id_base58: request.program_id_base58,
            submitter_pubkey_base58: request.submitter_pubkey_base58,
            challenge_pubkey_base58: request.challenge_pubkey_base58,
        })?;

    let authorization_intent_envelope =
        validate_authorization_intent_envelope_v1(AuthorizationIntentEnvelopeV1 {
            intent_version: AuthorizationIntentVersionV1::V1,
            intent_id_hex,
            authorization_lineage: AuthorizationLineageBindingV1 {
                subject_binding_type: AuthorizationSubjectBindingTypeV1::SubmitterPubkeyBase58,
                subject_binding: submit_proof_request_wire.submitter_pubkey_base58.clone(),
                intent_type: AuthorizationIntentTypeV1::OpaqueIntentHash32,
                intent_commitment_hex: request.intent_id_hex,
                freshness_binding_type: AuthorizationFreshnessBindingTypeV1::ChallengePubkeyBase58,
                freshness_binding: submit_proof_request_wire.challenge_pubkey_base58.clone(),
            },
            submit_proof_request: submit_proof_request_wire.clone(),
        })?;

    let stark_proof_envelope = validate_stark_proof_envelope_v1(StarkProofEnvelopeV1 {
        proof_version: StarkProofVersionV1::V1,
        proof_session_id_hex: request.proof_session_id_hex,
        dcm_claim: DcmClaimWireV1 {
            iteration_count: request.iteration_count,
            initial_state: request.initial_state_hex,
            final_state: request.final_state_hex,
            commitment_root: request.commitment_root_hex,
        },
        authorization_intent: authorization_intent_envelope.clone(),
    })?;

    let solana_settlement_request_wire =
        validate_solana_settlement_request_v1(SolanaSettlementRequestWireV1 {
            settlement_version: SolanaSettlementVersionV1::V1,
            solana_rpc_url: request.solana_rpc_url,
            commitment_config: request.commitment_config,
            stark_proof_envelope: stark_proof_envelope.clone(),
        })?;

    Ok(SettlementPipelineFromPreparedProofV1 {
        submit_proof_request_wire,
        authorization_intent_envelope,
        stark_proof_envelope,
        solana_settlement_request_wire,
    })
}
