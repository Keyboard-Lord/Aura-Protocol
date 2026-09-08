use crate::{generate_wallet_visual_v1, validate_wallet_visual_v1, AuraSdkErrorV1, PreparedSubmitProofV1};
use crate::udot::normalize_udot_hash;
use serde::{Deserialize, Serialize};

/// ```no_run
/// use aura_sdk_v1::legacy::GenerateSubmitProofRequestV1;
///
/// let _ = GenerateSubmitProofRequestV1 {
///     program_id_base58: String::from("11111111111111111111111111111111"),
///     submitter_pubkey_base58: String::from("11111111111111111111111111111111"),
///     challenge_pubkey_base58: String::from("11111111111111111111111111111111"),
///     proof_hash_hex: String::from("0000000000000000000000000000000000000000000000000000000000000000"),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateSubmitProofRequestV1 {
    pub program_id_base58: String,
    pub submitter_pubkey_base58: String,
    pub challenge_pubkey_base58: String,
    pub proof_hash_hex: String,
}

/// ```no_run
/// use aura_sdk_v1::{legacy::BuildSubmitProofRequestWireRequestV1, PreparedSubmitProofV1};
///
/// let prepared: PreparedSubmitProofV1 = todo!();
/// let _ = BuildSubmitProofRequestWireRequestV1 {
///     prepared_submit_proof: prepared,
///     program_id_base58: String::from("11111111111111111111111111111111"),
///     submitter_pubkey_base58: String::from("11111111111111111111111111111111"),
///     challenge_pubkey_base58: String::from("11111111111111111111111111111111"),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildSubmitProofRequestWireRequestV1 {
    pub prepared_submit_proof: PreparedSubmitProofV1,
    pub program_id_base58: String,
    pub submitter_pubkey_base58: String,
    pub challenge_pubkey_base58: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitProofRequestWireV1 {
    pub program_id_base58: String,
    pub submitter_pubkey_base58: String,
    pub challenge_pubkey_base58: String,
    pub proof_hash_hex: String,
    pub wallet_visual_v1: String,
}

pub fn generate_submit_proof_request_v1(
    request: GenerateSubmitProofRequestV1,
) -> Result<SubmitProofRequestWireV1, AuraSdkErrorV1> {
    let proof_hash_hex = normalize_udot_hash(&request.proof_hash_hex)?.to_string();
    let wallet_visual_v1 = generate_wallet_visual_v1(&proof_hash_hex)?;
    validate_submit_proof_request_wire_v1(SubmitProofRequestWireV1 {
        program_id_base58: request.program_id_base58,
        submitter_pubkey_base58: request.submitter_pubkey_base58,
        challenge_pubkey_base58: request.challenge_pubkey_base58,
        proof_hash_hex,
        wallet_visual_v1,
    })
}

pub fn build_submit_proof_request_wire_v1(
    request: BuildSubmitProofRequestWireRequestV1,
) -> Result<SubmitProofRequestWireV1, AuraSdkErrorV1> {
    generate_submit_proof_request_v1(GenerateSubmitProofRequestV1 {
        program_id_base58: request.program_id_base58,
        submitter_pubkey_base58: request.submitter_pubkey_base58,
        challenge_pubkey_base58: request.challenge_pubkey_base58,
        proof_hash_hex: encode_hex_lower_v1(&request.prepared_submit_proof.proof_hash),
    })
}

pub fn validate_submit_proof_request_wire_v1(
    payload: SubmitProofRequestWireV1,
) -> Result<SubmitProofRequestWireV1, AuraSdkErrorV1> {
    let proof_hash_hex = normalize_udot_hash(&payload.proof_hash_hex)?.to_string();
    let wallet_visual_v1 = validate_wallet_visual_v1(&proof_hash_hex, &payload.wallet_visual_v1)?;

    Ok(SubmitProofRequestWireV1 {
        program_id_base58: payload.program_id_base58,
        submitter_pubkey_base58: payload.submitter_pubkey_base58,
        challenge_pubkey_base58: payload.challenge_pubkey_base58,
        proof_hash_hex,
        wallet_visual_v1,
    })
}

fn encode_hex_lower_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}
