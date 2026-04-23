//! Rust client for the frozen Aura v1 `submit_proof` path.

use aura_sdk_v1::{
    validate_solana_settlement_request_v1, validate_wallet_visual_v1, AuraSdkErrorV1,
};
use core::fmt;
use solana_client::{client_error::ClientError, rpc_client::RpcClient};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_program, sysvar,
    transaction::Transaction,
};
use std::str::FromStr;

pub use aura_sdk_v1::{
    SolanaCommitmentConfigV1, SolanaSettlementRequestWireV1, SolanaSettlementVersionV1,
    SubmitProofRequestWireV1,
};

const PROOF_RECORD_SEED_V1: &[u8] = b"proof-record";
const SUBMIT_PROOF_TAG_V1: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSubmitProofInstructionV1 {
    pub proof_record_address: Pubkey,
    pub instruction: Instruction,
}

#[derive(Debug)]
pub struct PreparedSubmitProofTransactionV1 {
    pub proof_record_address: Pubkey,
    pub transaction: Transaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitProofSubmissionV1 {
    pub proof_record_address: Pubkey,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedSubmitProofRequestWireV1 {
    canonical_request: SubmitProofRequestWireV1,
    program_id: Pubkey,
    submitter: Pubkey,
    challenge: Pubkey,
    proof_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedSolanaSettlementRequestWireV1 {
    canonical_request: SolanaSettlementRequestWireV1,
    submit_request: ValidatedSubmitProofRequestWireV1,
}

#[derive(Debug)]
pub enum AuraSubmissionClientErrorV1 {
    Rpc(ClientError),
    InvalidPubkeyEncoding {
        field: &'static str,
        value: String,
    },
    InvalidProofHashHex {
        reason: String,
    },
    InvalidWalletVisual(AuraSdkErrorV1),
    InvalidSettlementEnvelope(AuraSdkErrorV1),
    SubmitterPubkeyMismatch {
        expected_submitter_pubkey_base58: String,
        actual_submitter_pubkey_base58: String,
    },
}

impl fmt::Display for AuraSubmissionClientErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(error) => write!(f, "rpc client error: {error}"),
            Self::InvalidPubkeyEncoding { field, value } => {
                write!(f, "invalid {field}: {value}")
            }
            Self::InvalidProofHashHex { reason } => write!(f, "invalid proof_hash_hex: {reason}"),
            Self::InvalidWalletVisual(error) => write!(f, "invalid wallet_visual_v1: {error}"),
            Self::InvalidSettlementEnvelope(error) => {
                write!(f, "invalid settlement request: {error}")
            }
            Self::SubmitterPubkeyMismatch {
                expected_submitter_pubkey_base58,
                actual_submitter_pubkey_base58,
            } => write!(
                f,
                "submitter keypair pubkey {actual_submitter_pubkey_base58} does not match request submitter_pubkey_base58 {expected_submitter_pubkey_base58}"
            ),
        }
    }
}

impl std::error::Error for AuraSubmissionClientErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(error) => Some(error),
            Self::InvalidWalletVisual(error) => Some(error),
            Self::InvalidSettlementEnvelope(error) => Some(error),
            Self::InvalidPubkeyEncoding { .. }
            | Self::InvalidProofHashHex { .. }
            | Self::SubmitterPubkeyMismatch { .. } => None,
        }
    }
}

impl From<ClientError> for AuraSubmissionClientErrorV1 {
    fn from(error: ClientError) -> Self {
        Self::Rpc(error)
    }
}

impl From<AuraSdkErrorV1> for AuraSubmissionClientErrorV1 {
    fn from(error: AuraSdkErrorV1) -> Self {
        Self::InvalidWalletVisual(error)
    }
}

pub fn derive_proof_record_address_v1(
    program_id: &Pubkey,
    challenge: &Pubkey,
    submitter: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[PROOF_RECORD_SEED_V1, challenge.as_ref(), submitter.as_ref()],
        program_id,
    )
}

pub fn prepare_submit_proof_instruction_v1(
    program_id: Pubkey,
    submitter: Pubkey,
    challenge: Pubkey,
    proof_hash: [u8; 32],
) -> PreparedSubmitProofInstructionV1 {
    let (proof_record_address, _) =
        derive_proof_record_address_v1(&program_id, &challenge, &submitter);

    let mut data = Vec::with_capacity(33);
    data.push(SUBMIT_PROOF_TAG_V1);
    data.extend_from_slice(&proof_hash);

    PreparedSubmitProofInstructionV1 {
        proof_record_address,
        instruction: Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(submitter, true),
                AccountMeta::new(challenge, false),
                AccountMeta::new(proof_record_address, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(sysvar::clock::id(), false),
            ],
            data,
        },
    }
}

pub fn parse_submit_proof_request_wire_v1(
    payload: SubmitProofRequestWireV1,
) -> Result<SubmitProofRequestWireV1, AuraSubmissionClientErrorV1> {
    Ok(validate_submit_proof_request_wire_v1(payload)?.canonical_request)
}

pub fn parse_solana_settlement_request_wire_v1(
    payload: SolanaSettlementRequestWireV1,
) -> Result<SolanaSettlementRequestWireV1, AuraSubmissionClientErrorV1> {
    Ok(validate_solana_settlement_request_wire_v1(payload)?.canonical_request)
}

pub fn prepare_submit_proof_instruction_from_wire_v1(
    payload: SubmitProofRequestWireV1,
) -> Result<PreparedSubmitProofInstructionV1, AuraSubmissionClientErrorV1> {
    let validated = validate_submit_proof_request_wire_v1(payload)?;

    Ok(prepare_submit_proof_instruction_v1(
        validated.program_id,
        validated.submitter,
        validated.challenge,
        validated.proof_hash,
    ))
}

pub fn prepare_submit_proof_instruction_from_settlement_wire_v1(
    payload: SolanaSettlementRequestWireV1,
) -> Result<PreparedSubmitProofInstructionV1, AuraSubmissionClientErrorV1> {
    let validated = validate_solana_settlement_request_wire_v1(payload)?;

    Ok(prepare_submit_proof_instruction_v1(
        validated.submit_request.program_id,
        validated.submit_request.submitter,
        validated.submit_request.challenge,
        validated.submit_request.proof_hash,
    ))
}

pub fn prepare_submit_proof_transaction_v1(
    submitter: &Keypair,
    program_id: Pubkey,
    challenge: Pubkey,
    proof_hash: [u8; 32],
    recent_blockhash: Hash,
) -> PreparedSubmitProofTransactionV1 {
    let prepared_instruction =
        prepare_submit_proof_instruction_v1(program_id, submitter.pubkey(), challenge, proof_hash);

    PreparedSubmitProofTransactionV1 {
        proof_record_address: prepared_instruction.proof_record_address,
        transaction: Transaction::new_signed_with_payer(
            &[prepared_instruction.instruction],
            Some(&submitter.pubkey()),
            &[submitter],
            recent_blockhash,
        ),
    }
}

pub fn prepare_submit_proof_transaction_from_wire_v1(
    submitter: &Keypair,
    payload: SubmitProofRequestWireV1,
    recent_blockhash: Hash,
) -> Result<PreparedSubmitProofTransactionV1, AuraSubmissionClientErrorV1> {
    let validated = validate_submit_proof_request_wire_v1(payload)?;
    ensure_submitter_keypair_matches_v1(submitter, &validated)?;

    Ok(prepare_submit_proof_transaction_v1(
        submitter,
        validated.program_id,
        validated.challenge,
        validated.proof_hash,
        recent_blockhash,
    ))
}

pub fn prepare_submit_proof_transaction_from_settlement_wire_v1(
    submitter: &Keypair,
    payload: SolanaSettlementRequestWireV1,
    recent_blockhash: Hash,
) -> Result<PreparedSubmitProofTransactionV1, AuraSubmissionClientErrorV1> {
    let validated = validate_solana_settlement_request_wire_v1(payload)?;
    ensure_submitter_keypair_matches_v1(submitter, &validated.submit_request)?;

    Ok(prepare_submit_proof_transaction_v1(
        submitter,
        validated.submit_request.program_id,
        validated.submit_request.challenge,
        validated.submit_request.proof_hash,
        recent_blockhash,
    ))
}

pub fn submit_proof_v1(
    rpc_client: &RpcClient,
    submitter: &Keypair,
    program_id: Pubkey,
    challenge: Pubkey,
    proof_hash: [u8; 32],
) -> Result<SubmitProofSubmissionV1, AuraSubmissionClientErrorV1> {
    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    let prepared_transaction = prepare_submit_proof_transaction_v1(
        submitter,
        program_id,
        challenge,
        proof_hash,
        recent_blockhash,
    );
    let signature = rpc_client.send_and_confirm_transaction(&prepared_transaction.transaction)?;

    Ok(SubmitProofSubmissionV1 {
        proof_record_address: prepared_transaction.proof_record_address,
        signature,
    })
}

pub fn submit_proof_from_wire_v1(
    rpc_client: &RpcClient,
    submitter: &Keypair,
    payload: SubmitProofRequestWireV1,
) -> Result<SubmitProofSubmissionV1, AuraSubmissionClientErrorV1> {
    let validated = validate_submit_proof_request_wire_v1(payload)?;
    ensure_submitter_keypair_matches_v1(submitter, &validated)?;

    submit_proof_v1(
        rpc_client,
        submitter,
        validated.program_id,
        validated.challenge,
        validated.proof_hash,
    )
}

pub fn submit_proof_from_settlement_wire_v1(
    rpc_client: &RpcClient,
    submitter: &Keypair,
    payload: SolanaSettlementRequestWireV1,
) -> Result<SubmitProofSubmissionV1, AuraSubmissionClientErrorV1> {
    let validated = validate_solana_settlement_request_wire_v1(payload)?;
    ensure_submitter_keypair_matches_v1(submitter, &validated.submit_request)?;

    submit_proof_v1(
        rpc_client,
        submitter,
        validated.submit_request.program_id,
        validated.submit_request.challenge,
        validated.submit_request.proof_hash,
    )
}

fn validate_submit_proof_request_wire_v1(
    payload: SubmitProofRequestWireV1,
) -> Result<ValidatedSubmitProofRequestWireV1, AuraSubmissionClientErrorV1> {
    let program_id = parse_pubkey_base58_v1("program_id_base58", &payload.program_id_base58)?;
    let submitter =
        parse_pubkey_base58_v1("submitter_pubkey_base58", &payload.submitter_pubkey_base58)?;
    let challenge =
        parse_pubkey_base58_v1("challenge_pubkey_base58", &payload.challenge_pubkey_base58)?;
    let proof_hash = decode_hex_32_v1(&payload.proof_hash_hex)?;
    let proof_hash_hex = encode_hex_lower_v1(&proof_hash);
    let wallet_visual_v1 = validate_wallet_visual_v1(&proof_hash_hex, &payload.wallet_visual_v1)
        .map_err(AuraSubmissionClientErrorV1::InvalidWalletVisual)?;

    Ok(ValidatedSubmitProofRequestWireV1 {
        canonical_request: SubmitProofRequestWireV1 {
            program_id_base58: program_id.to_string(),
            submitter_pubkey_base58: submitter.to_string(),
            challenge_pubkey_base58: challenge.to_string(),
            proof_hash_hex: proof_hash_hex.clone(),
            wallet_visual_v1,
        },
        program_id,
        submitter,
        challenge,
        proof_hash,
    })
}

fn validate_solana_settlement_request_wire_v1(
    payload: SolanaSettlementRequestWireV1,
) -> Result<ValidatedSolanaSettlementRequestWireV1, AuraSubmissionClientErrorV1> {
    let canonical_request = validate_solana_settlement_request_v1(payload)
        .map_err(AuraSubmissionClientErrorV1::InvalidSettlementEnvelope)?;
    let submit_request = validate_submit_proof_request_wire_v1(
        canonical_request
            .stark_proof_envelope
            .authorization_intent
            .submit_proof_request
            .clone(),
    )?;

    Ok(ValidatedSolanaSettlementRequestWireV1 {
        canonical_request,
        submit_request,
    })
}

fn ensure_submitter_keypair_matches_v1(
    submitter: &Keypair,
    request: &ValidatedSubmitProofRequestWireV1,
) -> Result<(), AuraSubmissionClientErrorV1> {
    let actual_submitter_pubkey_base58 = submitter.pubkey().to_string();
    let expected_submitter_pubkey_base58 = &request.canonical_request.submitter_pubkey_base58;

    if actual_submitter_pubkey_base58 != *expected_submitter_pubkey_base58 {
        return Err(AuraSubmissionClientErrorV1::SubmitterPubkeyMismatch {
            expected_submitter_pubkey_base58: expected_submitter_pubkey_base58.clone(),
            actual_submitter_pubkey_base58,
        });
    }

    Ok(())
}

fn parse_pubkey_base58_v1(
    field: &'static str,
    value: &str,
) -> Result<Pubkey, AuraSubmissionClientErrorV1> {
    Pubkey::from_str(value).map_err(|_| AuraSubmissionClientErrorV1::InvalidPubkeyEncoding {
        field,
        value: value.to_owned(),
    })
}

fn decode_hex_32_v1(input: &str) -> Result<[u8; 32], AuraSubmissionClientErrorV1> {
    if input.len() != 64 {
        return Err(AuraSubmissionClientErrorV1::InvalidProofHashHex {
            reason: format!("expected 64 hex characters, got {}", input.len()),
        });
    }

    let mut output = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble_v1(pair[0])?;
        let low = decode_nibble_v1(pair[1])?;
        output[index] = (high << 4) | low;
    }

    Ok(output)
}

fn decode_nibble_v1(value: u8) -> Result<u8, AuraSubmissionClientErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AuraSubmissionClientErrorV1::InvalidProofHashHex {
            reason: "contains a non-hex character".to_owned(),
        }),
    }
}

fn encode_hex_lower_v1(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
