use super::proof::{
    validate_stark_proof_envelope_v1, GenerateStarkProofEnvelopeV1, StarkProofEnvelopeV1,
};
use crate::{AuraSdkErrorV1};
use super::{generate_stark_proof_envelope_v1};
use serde::{Deserialize, Deserializer, Serialize};

/// ```compile_fail
/// use aura_sdk_v1::legacy::{
///     GenerateAuthorizationIntentV1, GenerateSolanaSettlementRequestV1,
///     GenerateStarkProofEnvelopeV1, GenerateSubmitProofRequestV1,
///     SolanaCommitmentConfigV1,
/// };
///
/// let _ = GenerateSolanaSettlementRequestV1 {
///     commitment_config: SolanaCommitmentConfigV1::Confirmed,
///     stark_proof_envelope: GenerateStarkProofEnvelopeV1 {
///         proof_session_id_hex: String::from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
///         iteration_count: 5,
///         initial_state_hex: String::from("11"),
///         final_state_hex: String::from("22"),
///         commitment_root_hex: String::from("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
///         authorization_intent: GenerateAuthorizationIntentV1 {
///             intent_id_hex: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
///             submit_proof_request: GenerateSubmitProofRequestV1 {
///                 program_id_base58: String::from("11111111111111111111111111111111"),
///                 submitter_pubkey_base58: String::from("11111111111111111111111111111111"),
///                 challenge_pubkey_base58: String::from("11111111111111111111111111111111"),
///                 proof_hash_hex: String::from("0000000000000000000000000000000000000000000000000000000000000000"),
///             },
///         },
///     },
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateSolanaSettlementRequestV1 {
    pub solana_rpc_url: Option<String>,
    pub commitment_config: SolanaCommitmentConfigV1,
    pub stark_proof_envelope: GenerateStarkProofEnvelopeV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SolanaSettlementVersionV1 {
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SolanaCommitmentConfigV1 {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaSettlementRequestWireV1 {
    pub settlement_version: SolanaSettlementVersionV1,
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub solana_rpc_url: Option<String>,
    pub commitment_config: SolanaCommitmentConfigV1,
    pub stark_proof_envelope: StarkProofEnvelopeV1,
}

pub fn generate_solana_settlement_request_v1(
    request: GenerateSolanaSettlementRequestV1,
) -> Result<SolanaSettlementRequestWireV1, AuraSdkErrorV1> {
    let solana_rpc_url = normalize_solana_rpc_url_v1(request.solana_rpc_url)?;
    let stark_proof_envelope = generate_stark_proof_envelope_v1(request.stark_proof_envelope)?;

    validate_solana_settlement_request_v1(SolanaSettlementRequestWireV1 {
        settlement_version: SolanaSettlementVersionV1::V1,
        solana_rpc_url,
        commitment_config: request.commitment_config,
        stark_proof_envelope,
    })
}

pub fn validate_solana_settlement_request_v1(
    payload: SolanaSettlementRequestWireV1,
) -> Result<SolanaSettlementRequestWireV1, AuraSdkErrorV1> {
    let solana_rpc_url = normalize_solana_rpc_url_v1(payload.solana_rpc_url)?;
    let stark_proof_envelope = validate_stark_proof_envelope_v1(payload.stark_proof_envelope)?;

    Ok(SolanaSettlementRequestWireV1 {
        settlement_version: payload.settlement_version,
        solana_rpc_url,
        commitment_config: payload.commitment_config,
        stark_proof_envelope,
    })
}

fn normalize_solana_rpc_url_v1(
    solana_rpc_url: Option<String>,
) -> Result<Option<String>, AuraSdkErrorV1> {
    match solana_rpc_url {
        Some(url) => {
            if url.is_empty() {
                return Err(invalid_settlement_field(
                    "solana_rpc_url",
                    "must not be empty when present",
                ));
            }
            if let Some((index, _)) = url.char_indices().find(|(_, value)| value.is_whitespace()) {
                return Err(invalid_settlement_field(
                    "solana_rpc_url",
                    format!("contains whitespace at index {index}"),
                ));
            }
            Ok(Some(url))
        }
        None => Ok(None),
    }
}

fn invalid_settlement_field(field: &'static str, reason: impl Into<String>) -> AuraSdkErrorV1 {
    AuraSdkErrorV1::SettlementFieldInvalid {
        field,
        reason: reason.into(),
    }
}

fn deserialize_explicit_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}
