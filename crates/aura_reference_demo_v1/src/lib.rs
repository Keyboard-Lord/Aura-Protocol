use aura_sdk_v1::{prepare_submit_proof_flow_v1, AuraSdkErrorV1, PreparedSubmitProofV1};
use aura_submission_client_v1::{
    prepare_submit_proof_instruction_v1, prepare_submit_proof_transaction_v1,
    PreparedSubmitProofInstructionV1, PreparedSubmitProofTransactionV1,
};
use core::fmt;
use solana_sdk::{
    hash::Hash, pubkey::Pubkey, signature::Signer, signer::keypair::keypair_from_seed,
};

const SAMPLE_PROOF_BLOB_BYTES_V1: &[u8] = b"proof-blob-v1\n";
const SAMPLE_PUBLIC_INPUTS_BYTES_V1: &[u8] = b"public-inputs-v1\n";
const SAMPLE_VERIFICATION_KEY_BYTES_V1: &[u8] = b"verification-key-v1\n";
const SAMPLE_SUBMITTER_SEED_V1: [u8; 32] = [0x11; 32];
const SAMPLE_CHALLENGE_PUBKEY_BYTES_V1: [u8; 32] = [0x22; 32];
const SAMPLE_PROGRAM_ID_BYTES_V1: [u8; 32] = [0x33; 32];
const SAMPLE_RECENT_BLOCKHASH_BYTES_V1: [u8; 32] = [0x44; 32];

#[derive(Debug)]
pub struct ReferenceDemoArtifactsV1 {
    pub prepared: PreparedSubmitProofV1,
    pub program_id: Pubkey,
    pub submitter_pubkey: Pubkey,
    pub challenge_pubkey: Pubkey,
    pub recent_blockhash: Hash,
    pub prepared_instruction: PreparedSubmitProofInstructionV1,
    pub prepared_transaction: PreparedSubmitProofTransactionV1,
}

#[derive(Debug)]
pub enum AuraReferenceDemoErrorV1 {
    DeterministicKeypair(String),
    Sdk(AuraSdkErrorV1),
}

impl fmt::Display for AuraReferenceDemoErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeterministicKeypair(error) => {
                write!(f, "failed to build deterministic demo keypair: {error}")
            }
            Self::Sdk(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuraReferenceDemoErrorV1 {}

impl From<AuraSdkErrorV1> for AuraReferenceDemoErrorV1 {
    fn from(error: AuraSdkErrorV1) -> Self {
        Self::Sdk(error)
    }
}

pub fn run_reference_demo_v1() -> Result<ReferenceDemoArtifactsV1, AuraReferenceDemoErrorV1> {
    let submitter = keypair_from_seed(&SAMPLE_SUBMITTER_SEED_V1)
        .map_err(|error| AuraReferenceDemoErrorV1::DeterministicKeypair(error.to_string()))?;
    let submitter_pubkey = submitter.pubkey();
    let challenge_pubkey = Pubkey::new_from_array(SAMPLE_CHALLENGE_PUBKEY_BYTES_V1);
    let program_id = Pubkey::new_from_array(SAMPLE_PROGRAM_ID_BYTES_V1);
    let recent_blockhash = Hash::new_from_array(SAMPLE_RECENT_BLOCKHASH_BYTES_V1);

    let prepared = prepare_submit_proof_flow_v1(
        submitter_pubkey.to_bytes(),
        challenge_pubkey.to_bytes(),
        SAMPLE_PROOF_BLOB_BYTES_V1,
        SAMPLE_PUBLIC_INPUTS_BYTES_V1,
        SAMPLE_VERIFICATION_KEY_BYTES_V1,
    )?;

    let prepared_instruction = prepare_submit_proof_instruction_v1(
        program_id,
        submitter_pubkey,
        challenge_pubkey,
        prepared.proof_hash,
    );
    let prepared_transaction = prepare_submit_proof_transaction_v1(
        &submitter,
        program_id,
        challenge_pubkey,
        prepared.proof_hash,
        recent_blockhash,
    );

    Ok(ReferenceDemoArtifactsV1 {
        prepared,
        program_id,
        submitter_pubkey,
        challenge_pubkey,
        recent_blockhash,
        prepared_instruction,
        prepared_transaction,
    })
}

pub fn render_reference_demo_report_v1(artifacts: &ReferenceDemoArtifactsV1) -> String {
    let instruction = &artifacts.prepared_instruction.instruction;
    let transaction = &artifacts.prepared_transaction.transaction;
    let signature = transaction.signatures[0];
    let fractal_key = &artifacts.prepared.fractal_key;

    let mut report = String::new();
    report.push_str("Aura v1 Reference Demo\n");
    report.push_str("sample: built-in-v1\n");
    report.push('\n');
    report.push_str("off_chain_preparation\n");
    report.push_str(&format!(
        "proof_blob_hash: {}\n",
        encode_hex_lower(&artifacts.prepared.proof_material.proof_blob_hash)
    ));
    report.push_str(&format!(
        "public_inputs_hash: {}\n",
        encode_hex_lower(&artifacts.prepared.proof_material.public_inputs_hash)
    ));
    report.push_str(&format!(
        "verification_key_hash: {}\n",
        encode_hex_lower(&artifacts.prepared.proof_material.verification_key_hash)
    ));
    report.push_str(&format!(
        "proof_material_type: 0x{:04x}\n",
        artifacts.prepared.proof_material.proof_material_type
    ));
    report.push_str(&format!(
        "proof_material_hash: {}\n",
        encode_hex_lower(&artifacts.prepared.proof_material_hash)
    ));
    report.push_str(&format!(
        "fractal_key_version: {}\n",
        fractal_key.fractal_key_version
    ));
    report.push_str(&format!(
        "fractal_component_count: {}\n",
        fractal_key.component_count
    ));
    report.push_str(&format!(
        "fractal_component_1_subject_binding: {}\n",
        encode_hex_lower(&fractal_key.components[0].payload32)
    ));
    report.push_str(&format!(
        "fractal_component_2_challenge_binding: {}\n",
        encode_hex_lower(&fractal_key.components[1].payload32)
    ));
    report.push_str(&format!(
        "fractal_component_3_proof_material_hash: {}\n",
        encode_hex_lower(&fractal_key.components[2].payload32)
    ));
    report.push_str(&format!(
        "proof_hash: {}\n",
        encode_hex_lower(&artifacts.prepared.proof_hash)
    ));
    report.push('\n');
    report.push_str("transaction_assembly\n");
    report.push_str(&format!("program_id: {}\n", artifacts.program_id));
    report.push_str(&format!(
        "submitter_pubkey: {}\n",
        artifacts.submitter_pubkey
    ));
    report.push_str(&format!(
        "challenge_pubkey: {}\n",
        artifacts.challenge_pubkey
    ));
    report.push_str(&format!(
        "proof_record_pda: {}\n",
        artifacts.prepared_instruction.proof_record_address
    ));
    report.push_str(&format!(
        "recent_blockhash: {}\n",
        artifacts.recent_blockhash
    ));
    report.push_str(&format!(
        "instruction_data: {}\n",
        encode_hex_lower(&instruction.data)
    ));

    for (index, account) in instruction.accounts.iter().enumerate() {
        report.push_str(&format!(
            "account_{}: {} {}\n",
            index + 1,
            account.pubkey,
            format_account_flags(account.is_signer, account.is_writable)
        ));
    }

    report.push_str(&format!(
        "transaction_payer: {}\n",
        transaction.message.account_keys[0]
    ));
    report.push_str(&format!("transaction_signature: {signature}\n"));
    report
}

fn format_account_flags(is_signer: bool, is_writable: bool) -> &'static str {
    match (is_signer, is_writable) {
        (true, true) => "signer writable",
        (true, false) => "signer readonly",
        (false, true) => "writable",
        (false, false) => "readonly",
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
