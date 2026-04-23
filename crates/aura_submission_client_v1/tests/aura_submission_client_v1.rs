use aura_protocol::{process_instruction, ChallengeAccount, ProofRecord};
use aura_sdk_v1::{
    generate_solana_settlement_request_v1, generate_submit_proof_request_v1,
    proof_hash_hex_from_wallet_visual_v1, GenerateAuthorizationIntentV1,
    GenerateSolanaSettlementRequestV1, GenerateStarkProofEnvelopeV1, GenerateSubmitProofRequestV1,
    SolanaCommitmentConfigV1, SolanaSettlementRequestWireV1, SubmitProofRequestWireV1,
};
use aura_submission_client_v1::{
    derive_proof_record_address_v1, parse_solana_settlement_request_wire_v1,
    parse_submit_proof_request_wire_v1, prepare_submit_proof_instruction_from_settlement_wire_v1,
    prepare_submit_proof_instruction_from_wire_v1,
};
use serde_json::json;
use solana_program_test::{processor, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program, sysvar,
    transaction::Transaction,
};

const PROTOCOL_VERSION: u8 = 1;
const CHALLENGE_TTL_SECONDS: i64 = 60;
const INTENT_ID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROOF_SESSION_ID_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROOF_HASH_HEX: &str = "30701f142e89ace16515b1e32d18dba996e3adaa15cc1e5b42fded287506c7db";
const COMMITMENT_ROOT_HEX: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct Harness {
    context: ProgramTestContext,
    program_id: Pubkey,
    authority: Keypair,
    subject: Keypair,
}

impl Harness {
    async fn new() -> Self {
        let program_id = Pubkey::new_unique();
        let authority = Keypair::new();
        let subject = Keypair::new();

        let mut program_test =
            ProgramTest::new("aura_protocol", program_id, processor!(process_instruction));
        program_test.prefer_bpf(false);
        for key in [authority.pubkey(), subject.pubkey()] {
            program_test.add_account(key, funded_system_account(10_000_000));
        }

        let mut context = program_test.start_with_context().await;
        context.last_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

        Self {
            context,
            program_id,
            authority,
            subject,
        }
    }

    fn protocol_config_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"protocol-config"], &self.program_id)
    }

    fn challenge_pda(&self, nonce: [u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"challenge", self.subject.pubkey().as_ref(), nonce.as_ref()],
            &self.program_id,
        )
    }

    async fn current_clock(&mut self) -> Clock {
        self.context
            .banks_client
            .get_sysvar::<Clock>()
            .await
            .unwrap()
    }

    async fn refresh_blockhash(&mut self) {
        self.context.last_blockhash = self
            .context
            .banks_client
            .get_latest_blockhash()
            .await
            .unwrap();
    }

    async fn process_instruction(
        &mut self,
        instruction: Instruction,
        signers: &[&Keypair],
    ) -> Result<(), BanksClientError> {
        let mut all_signers: Vec<&dyn Signer> = vec![&self.context.payer];
        all_signers.extend(signers.iter().map(|signer| *signer as &dyn Signer));

        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&self.context.payer.pubkey()),
            &all_signers,
            self.context.last_blockhash,
        );
        let result = self
            .context
            .banks_client
            .process_transaction(transaction)
            .await;
        self.refresh_blockhash().await;
        result
    }

    async fn initialize_protocol(&mut self) -> Result<(), BanksClientError> {
        let (protocol_config, _) = self.protocol_config_pda();
        let authority = clone_keypair(&self.authority);
        let instruction = initialize_protocol_instruction(
            self.program_id,
            self.context.payer.pubkey(),
            authority.pubkey(),
            protocol_config,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        );
        self.process_instruction(instruction, &[&authority]).await
    }

    async fn issue_challenge(
        &mut self,
        nonce: [u8; 32],
        challenge: Pubkey,
    ) -> Result<(), BanksClientError> {
        let (protocol_config, _) = self.protocol_config_pda();
        let authority = clone_keypair(&self.authority);
        let instruction = issue_challenge_instruction(
            self.program_id,
            self.context.payer.pubkey(),
            authority.pubkey(),
            protocol_config,
            self.subject.pubkey(),
            challenge,
            nonce,
        );
        self.process_instruction(instruction, &[&authority]).await
    }

    async fn get_challenge(&mut self, address: Pubkey) -> ChallengeAccount {
        let account = self
            .context
            .banks_client
            .get_account(address)
            .await
            .unwrap()
            .unwrap();
        ChallengeAccount::unpack(&account.data).unwrap()
    }

    async fn get_proof_record(&mut self, address: Pubkey) -> ProofRecord {
        let account = self
            .context
            .banks_client
            .get_account(address)
            .await
            .unwrap()
            .unwrap();
        ProofRecord::unpack(&account.data).unwrap()
    }
}

fn funded_system_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::from_bytes(&keypair.to_bytes()).unwrap()
}

fn initialize_protocol_instruction(
    program_id: Pubkey,
    payer: Pubkey,
    authority: Pubkey,
    protocol_config: Pubkey,
    protocol_version: u8,
    challenge_ttl_seconds: i64,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(0);
    data.push(protocol_version);
    data.extend_from_slice(&challenge_ttl_seconds.to_le_bytes());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(protocol_config, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn issue_challenge_instruction(
    program_id: Pubkey,
    payer: Pubkey,
    authority: Pubkey,
    protocol_config: Pubkey,
    subject: Pubkey,
    challenge: Pubkey,
    nonce: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(33);
    data.push(1);
    data.extend_from_slice(&nonce);

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new_readonly(subject, false),
            AccountMeta::new(challenge, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
        data,
    }
}

fn canonical_state_hex(x_low: u8, y_low: u8) -> String {
    let mut bytes = vec![0u8; 132];
    bytes[65] = x_low;
    bytes[131] = y_low;
    encode_hex_lower(&bytes)
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

fn decode_hex_32_v1(input: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble_v1(pair[0]) << 4) | decode_nibble_v1(pair[1]);
    }
    bytes
}

fn decode_nibble_v1(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}

fn sample_submit_proof_request_wire_v1(
    program_id: Pubkey,
    submitter: Pubkey,
    challenge: Pubkey,
) -> SubmitProofRequestWireV1 {
    generate_submit_proof_request_v1(GenerateSubmitProofRequestV1 {
        program_id_base58: program_id.to_string(),
        submitter_pubkey_base58: submitter.to_string(),
        challenge_pubkey_base58: challenge.to_string(),
        proof_hash_hex: PROOF_HASH_HEX.to_owned(),
    })
    .unwrap()
}

fn sample_settlement_request_wire_v1(
    program_id: Pubkey,
    submitter: Pubkey,
    challenge: Pubkey,
) -> SolanaSettlementRequestWireV1 {
    generate_solana_settlement_request_v1(GenerateSolanaSettlementRequestV1 {
        solana_rpc_url: Some("https://rpc.aura.invalid".to_owned()),
        commitment_config: SolanaCommitmentConfigV1::Confirmed,
        stark_proof_envelope: GenerateStarkProofEnvelopeV1 {
            proof_session_id_hex: PROOF_SESSION_ID_HEX.to_owned(),
            iteration_count: 5,
            initial_state_hex: canonical_state_hex(0x11, 0x22),
            final_state_hex: canonical_state_hex(0x33, 0x44),
            commitment_root_hex: COMMITMENT_ROOT_HEX.to_owned(),
            authorization_intent: GenerateAuthorizationIntentV1 {
                intent_id_hex: INTENT_ID_HEX.to_owned(),
                submit_proof_request: GenerateSubmitProofRequestV1 {
                    program_id_base58: program_id.to_string(),
                    submitter_pubkey_base58: submitter.to_string(),
                    challenge_pubkey_base58: challenge.to_string(),
                    proof_hash_hex: PROOF_HASH_HEX.to_owned(),
                },
            },
        },
    })
    .unwrap()
}

#[test]
fn submit_proof_request_wire_round_trips_the_canonical_wallet_surface() {
    let request = sample_submit_proof_request_wire_v1(
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    );
    let canonical = parse_submit_proof_request_wire_v1(request.clone()).unwrap();

    assert_eq!(canonical, request);
    assert_eq!(
        proof_hash_hex_from_wallet_visual_v1(&canonical.wallet_visual_v1).unwrap(),
        canonical.proof_hash_hex
    );
}

#[test]
fn submit_proof_request_wire_rejects_alternate_wallet_peer_fields() {
    let request = sample_submit_proof_request_wire_v1(
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    );

    let seal_line_error = serde_json::from_value::<SubmitProofRequestWireV1>(json!({
        "program_id_base58": request.program_id_base58,
        "submitter_pubkey_base58": request.submitter_pubkey_base58,
        "challenge_pubkey_base58": request.challenge_pubkey_base58,
        "proof_hash_hex": request.proof_hash_hex,
        "wallet_visual_v1": request.wallet_visual_v1,
        "seal_line": "forbidden"
    }))
    .unwrap_err();
    assert!(seal_line_error.to_string().contains("unknown field `seal_line`"));

    assert!(serde_json::from_value::<SubmitProofRequestWireV1>(json!({
        "program_id_base58": request.program_id_base58,
        "submitter_pubkey_base58": request.submitter_pubkey_base58,
        "challenge_pubkey_base58": request.challenge_pubkey_base58,
        "proof_hash_hex": request.proof_hash_hex,
        "wallet_visual_v1": request.wallet_visual_v1,
        "udot_bundle": {"seal_line": "forbidden"}
    }))
    .unwrap_err()
    .to_string()
    .contains("unknown field `udot_bundle`"));
}

#[test]
fn submit_proof_request_wire_rejects_wallet_visual_mismatch() {
    let mut request = sample_submit_proof_request_wire_v1(
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    );
    request.wallet_visual_v1 = request.wallet_visual_v1.replacen('○', "◌", 1);

    let error = parse_submit_proof_request_wire_v1(request).unwrap_err();
    assert!(error.to_string().contains("wallet_visual_v1"));
}

#[test]
fn prepare_submit_proof_instruction_from_wire_preserves_proof_hash_bytes() {
    let program_id = Pubkey::new_unique();
    let submitter = Pubkey::new_unique();
    let challenge = Pubkey::new_unique();
    let request = sample_submit_proof_request_wire_v1(program_id, submitter, challenge);
    let prepared = prepare_submit_proof_instruction_from_wire_v1(request.clone()).unwrap();

    assert_eq!(
        encode_hex_lower(&prepared.instruction.data),
        format!("02{}", request.proof_hash_hex)
    );
    assert_eq!(prepared.instruction.program_id, program_id);
    assert_eq!(prepared.instruction.accounts[0].pubkey, submitter);
    assert_eq!(prepared.instruction.accounts[1].pubkey, challenge);
}

#[test]
fn settlement_wire_produces_the_same_submit_instruction_boundary() {
    let program_id = Pubkey::new_unique();
    let submitter = Pubkey::new_unique();
    let challenge = Pubkey::new_unique();
    let request = sample_submit_proof_request_wire_v1(program_id, submitter, challenge);
    let settlement = sample_settlement_request_wire_v1(program_id, submitter, challenge);

    let from_request = prepare_submit_proof_instruction_from_wire_v1(request).unwrap();
    let from_settlement = prepare_submit_proof_instruction_from_settlement_wire_v1(settlement).unwrap();

    assert_eq!(from_request, from_settlement);
    assert_eq!(
        parse_solana_settlement_request_wire_v1(sample_settlement_request_wire_v1(
            program_id,
            submitter,
            challenge,
        ))
        .unwrap()
        .stark_proof_envelope
        .authorization_intent
        .submit_proof_request
        .proof_hash_hex,
        PROOF_HASH_HEX
    );
}

#[tokio::test]
async fn canonical_wallet_surface_submits_successfully_against_program_test() {
    let mut harness = Harness::new().await;
    harness.initialize_protocol().await.unwrap();

    let nonce = [7u8; 32];
    let (challenge, _) = harness.challenge_pda(nonce);
    harness.issue_challenge(nonce, challenge).await.unwrap();

    let challenge_account = harness.get_challenge(challenge).await;
    assert_eq!(challenge_account.subject, harness.subject.pubkey());
    assert!(!challenge_account.used);
    assert!(challenge_account.expires_at > harness.current_clock().await.unix_timestamp);

    let request =
        sample_submit_proof_request_wire_v1(harness.program_id, harness.subject.pubkey(), challenge);
    let prepared = prepare_submit_proof_instruction_from_wire_v1(request.clone()).unwrap();
    let submitter = clone_keypair(&harness.subject);

    harness
        .process_instruction(prepared.instruction, &[&submitter])
        .await
        .unwrap();

    let (expected_proof_record, expected_bump) =
        derive_proof_record_address_v1(&harness.program_id, &challenge, &harness.subject.pubkey());
    let proof_record = harness.get_proof_record(prepared.proof_record_address).await;

    assert_eq!(prepared.proof_record_address, expected_proof_record);
    assert_eq!(proof_record.bump, expected_bump);
    assert_eq!(proof_record.challenge, challenge);
    assert_eq!(proof_record.submitter, harness.subject.pubkey());
    assert_eq!(proof_record.proof_hash, decode_hex_32_v1(&request.proof_hash_hex));
    assert!(proof_record.accepted);
}
