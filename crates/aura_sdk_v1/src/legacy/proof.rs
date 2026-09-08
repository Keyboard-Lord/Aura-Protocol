use super::authorization::{
    validate_authorization_intent_envelope_v1, AuthorizationIntentEnvelopeV1,
    GenerateAuthorizationIntentV1,
};
#[allow(unused_imports)]
pub use super::settlement::{
    generate_solana_settlement_request_v1, validate_solana_settlement_request_v1,
    GenerateSolanaSettlementRequestV1, SolanaCommitmentConfigV1, SolanaSettlementRequestWireV1,
    SolanaSettlementVersionV1,
};
use crate::udot::normalize_udot_hash;
use crate::{AuraSdkErrorV1};
use super::{generate_authorization_intent_v1};
use aura_intent_lineage_v1::{
    DcmConfig521V1, DcmState521V1, FieldElement521V1, DCM_STATE_521_CANONICAL_BYTE_LEN_V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1,
};
use serde::{Deserialize, Serialize};

/// ```compile_fail
/// use aura_sdk_v1::legacy::{
///     GenerateAuthorizationIntentV1, GenerateStarkProofEnvelopeV1,
///     GenerateSubmitProofRequestV1,
/// };
///
/// let _ = GenerateStarkProofEnvelopeV1 {
///     proof_session_id_hex: String::from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
///     iteration_count: 5,
///     initial_state_hex: String::from("11"),
///     final_state_hex: String::from("22"),
///     authorization_intent: GenerateAuthorizationIntentV1 {
///         intent_id_hex: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
///         submit_proof_request: GenerateSubmitProofRequestV1 {
///             program_id_base58: String::from("11111111111111111111111111111111"),
///             submitter_pubkey_base58: String::from("11111111111111111111111111111111"),
///             challenge_pubkey_base58: String::from("11111111111111111111111111111111"),
///             proof_hash_hex: String::from("0000000000000000000000000000000000000000000000000000000000000000"),
///         },
///     },
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateStarkProofEnvelopeV1 {
    pub proof_session_id_hex: String,
    pub iteration_count: u64,
    pub initial_state_hex: String,
    pub final_state_hex: String,
    pub commitment_root_hex: String,
    pub authorization_intent: GenerateAuthorizationIntentV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StarkProofVersionV1 {
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcmClaimWireV1 {
    pub iteration_count: u64,
    pub initial_state: String,
    pub final_state: String,
    pub commitment_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StarkProofEnvelopeV1 {
    pub proof_version: StarkProofVersionV1,
    pub proof_session_id_hex: String,
    pub dcm_claim: DcmClaimWireV1,
    pub authorization_intent: AuthorizationIntentEnvelopeV1,
}

pub fn generate_stark_proof_envelope_v1(
    request: GenerateStarkProofEnvelopeV1,
) -> Result<StarkProofEnvelopeV1, AuraSdkErrorV1> {
    let proof_session_id_hex = normalize_udot_hash(&request.proof_session_id_hex)?.to_string();
    let dcm_claim = validate_dcm_claim_wire_v1(DcmClaimWireV1 {
        iteration_count: request.iteration_count,
        initial_state: request.initial_state_hex,
        final_state: request.final_state_hex,
        commitment_root: request.commitment_root_hex,
    })?;
    let authorization_intent = generate_authorization_intent_v1(request.authorization_intent)?;

    validate_stark_proof_envelope_v1(StarkProofEnvelopeV1 {
        proof_version: StarkProofVersionV1::V1,
        proof_session_id_hex,
        dcm_claim,
        authorization_intent,
    })
}

pub fn validate_stark_proof_envelope_v1(
    payload: StarkProofEnvelopeV1,
) -> Result<StarkProofEnvelopeV1, AuraSdkErrorV1> {
    let proof_session_id_hex = normalize_udot_hash(&payload.proof_session_id_hex)?.to_string();
    let dcm_claim = validate_dcm_claim_wire_v1(payload.dcm_claim)?;
    let authorization_intent =
        validate_authorization_intent_envelope_v1(payload.authorization_intent)?;

    Ok(StarkProofEnvelopeV1 {
        proof_version: payload.proof_version,
        proof_session_id_hex,
        dcm_claim,
        authorization_intent,
    })
}

fn validate_dcm_claim_wire_v1(payload: DcmClaimWireV1) -> Result<DcmClaimWireV1, AuraSdkErrorV1> {
    DcmConfig521V1 {
        iteration_count: payload.iteration_count,
    }
    .validate()
    .map_err(|error| invalid_proof_field("dcm_claim.iteration_count", error.to_string()))?;

    Ok(DcmClaimWireV1 {
        iteration_count: payload.iteration_count,
        initial_state: normalize_dcm_state_hex(&payload.initial_state, "dcm_claim.initial_state")?,
        final_state: normalize_dcm_state_hex(&payload.final_state, "dcm_claim.final_state")?,
        commitment_root: normalize_udot_hash(&payload.commitment_root)?.to_string(),
    })
}

fn normalize_dcm_state_hex(input: &str, field: &'static str) -> Result<String, AuraSdkErrorV1> {
    let decoded = decode_fixed_hex_bytes(input, DCM_STATE_521_CANONICAL_BYTE_LEN_V1, field)?;
    let (x_slice, y_slice) = decoded.split_at(FIELD_ELEMENT_521_BYTE_LEN_V1);

    let mut x_bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    x_bytes.copy_from_slice(x_slice);
    let mut y_bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    y_bytes.copy_from_slice(y_slice);

    let x = FieldElement521V1::from_bytes(x_bytes)
        .map_err(|error| invalid_proof_field(field, error.to_string()))?;
    let y = FieldElement521V1::from_bytes(y_bytes)
        .map_err(|error| invalid_proof_field(field, error.to_string()))?;

    Ok(encode_hex_lower(&DcmState521V1 { x, y }.canonical_bytes()))
}

fn decode_fixed_hex_bytes(
    input: &str,
    expected_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, AuraSdkErrorV1> {
    let char_count = input.chars().count();
    let expected_chars = expected_bytes * 2;

    if char_count != expected_chars {
        return Err(invalid_proof_field(
            field,
            format!("expected {expected_chars} hex characters, got {char_count}"),
        ));
    }

    let chars = input.chars().collect::<Vec<_>>();
    let mut output = Vec::with_capacity(expected_bytes);

    for (index, value) in chars.iter().enumerate() {
        if value.is_whitespace() {
            return Err(invalid_proof_field(
                field,
                format!("invalid whitespace at index {index}"),
            ));
        }
    }

    for (index, chunk) in chars.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0]).ok_or_else(|| {
            invalid_proof_field(
                field,
                format!("invalid hex character at index {}", index * 2),
            )
        })?;
        let low = decode_hex_nibble(chunk[1]).ok_or_else(|| {
            invalid_proof_field(
                field,
                format!("invalid hex character at index {}", index * 2 + 1),
            )
        })?;
        output.push((high << 4) | low);
    }

    let canonical = encode_hex_lower(&output);
    if input != canonical {
        return Err(invalid_proof_field(
            field,
            format!("expected canonical lowercase hex {canonical}, got {input}"),
        ));
    }

    Ok(output)
}

fn decode_hex_nibble(value: char) -> Option<u8> {
    match value {
        '0'..='9' => Some(value as u8 - b'0'),
        'a'..='f' => Some(value as u8 - b'a' + 10),
        'A'..='F' => Some(value as u8 - b'A' + 10),
        _ => None,
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn invalid_proof_field(field: &'static str, reason: impl Into<String>) -> AuraSdkErrorV1 {
    AuraSdkErrorV1::ProofEnvelopeFieldInvalid {
        field,
        reason: reason.into(),
    }
}
