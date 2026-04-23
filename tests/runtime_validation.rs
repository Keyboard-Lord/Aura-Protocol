use aura_protocol::{
    process_instruction, AuraError, AuraInstruction, ChallengeAccount, ProofRecord, ProtocolConfig,
};
use solana_program::program_error::ProgramError;
use solana_program_test::{processor, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program, sysvar,
    transaction::{Transaction, TransactionError},
};
use std::sync::Once;

const ACCOUNT_TYPE_PROTOCOL_CONFIG: u8 = 1;
const ACCOUNT_TYPE_CHALLENGE: u8 = 2;
const ACCOUNT_TYPE_PROOF_RECORD: u8 = 3;
const SCHEMA_VERSION: u8 = 1;
const RESERVED_LEN: usize = 5;
const PROTOCOL_VERSION: u8 = 1;
const CHALLENGE_TTL_SECONDS: i64 = 60;

static INIT_TEST_ENV: Once = Once::new();

fn init_test_env() {
    INIT_TEST_ENV.call_once(|| {
        std::env::set_var("RUST_LOG", "warn,tarpc::client=error,tarpc::server=error");
    });
}

struct Harness {
    context: ProgramTestContext,
    program_id: Pubkey,
    authority: Keypair,
    subject: Keypair,
    wrong_authority: Keypair,
    wrong_submitter: Keypair,
}

impl Harness {
    async fn new() -> Self {
        init_test_env();

        let program_id = Pubkey::new_unique();
        let authority = Keypair::new();
        let subject = Keypair::new();
        let wrong_authority = Keypair::new();
        let wrong_submitter = Keypair::new();

        let mut program_test =
            ProgramTest::new("aura_protocol", program_id, processor!(process_instruction));
        program_test.prefer_bpf(false);
        for key in [
            authority.pubkey(),
            subject.pubkey(),
            wrong_authority.pubkey(),
            wrong_submitter.pubkey(),
        ] {
            program_test.add_account(key, funded_system_account(10_000_000));
        }

        let mut context = program_test.start_with_context().await;
        context.last_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

        Self {
            context,
            program_id,
            authority,
            subject,
            wrong_authority,
            wrong_submitter,
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

    fn proof_pda(&self, challenge: Pubkey, submitter: Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"proof-record", challenge.as_ref(), submitter.as_ref()],
            &self.program_id,
        )
    }

    async fn refresh_blockhash(&mut self) {
        self.context.last_blockhash = self
            .context
            .banks_client
            .get_latest_blockhash()
            .await
            .unwrap();
    }

    async fn current_clock(&mut self) -> Clock {
        self.context
            .banks_client
            .get_sysvar::<Clock>()
            .await
            .unwrap()
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

    async fn initialize_protocol(
        &mut self,
        protocol_config: Pubkey,
        protocol_version: u8,
        challenge_ttl_seconds: i64,
    ) -> Result<(), BanksClientError> {
        let authority = clone_keypair(&self.authority);
        let instruction = initialize_protocol_instruction(
            self.program_id,
            self.context.payer.pubkey(),
            authority.pubkey(),
            protocol_config,
            protocol_version,
            challenge_ttl_seconds,
        );
        self.process_instruction(instruction, &[&authority]).await
    }

    async fn issue_challenge(
        &mut self,
        authority: &Keypair,
        nonce: [u8; 32],
        challenge: Pubkey,
    ) -> Result<(), BanksClientError> {
        let (protocol_config, _) = self.protocol_config_pda();
        let instruction = issue_challenge_instruction(
            self.program_id,
            self.context.payer.pubkey(),
            authority.pubkey(),
            protocol_config,
            self.subject.pubkey(),
            challenge,
            nonce,
        );
        self.process_instruction(instruction, &[authority]).await
    }

    async fn submit_proof(
        &mut self,
        submitter: &Keypair,
        challenge: Pubkey,
        proof_record: Pubkey,
        proof_hash: [u8; 32],
    ) -> Result<(), BanksClientError> {
        let instruction = submit_proof_instruction(
            self.program_id,
            submitter.pubkey(),
            challenge,
            proof_record,
            proof_hash,
        );
        self.process_instruction(instruction, &[submitter]).await
    }

    async fn get_account(&mut self, address: Pubkey) -> Option<Account> {
        self.context
            .banks_client
            .get_account(address)
            .await
            .unwrap()
    }

    async fn get_protocol_config(&mut self, address: Pubkey) -> ProtocolConfig {
        let account = self.get_account(address).await.unwrap();
        ProtocolConfig::unpack(&account.data).unwrap()
    }

    async fn get_challenge(&mut self, address: Pubkey) -> ChallengeAccount {
        let account = self.get_account(address).await.unwrap();
        ChallengeAccount::unpack(&account.data).unwrap()
    }

    async fn get_proof_record(&mut self, address: Pubkey) -> ProofRecord {
        let account = self.get_account(address).await.unwrap();
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

fn submit_proof_instruction(
    program_id: Pubkey,
    submitter: Pubkey,
    challenge: Pubkey,
    proof_record: Pubkey,
    proof_hash: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(33);
    data.push(2);
    data.extend_from_slice(&proof_hash);

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(submitter, true),
            AccountMeta::new(challenge, false),
            AccountMeta::new(proof_record, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
        data,
    }
}

fn assert_custom_error(error: BanksClientError, expected: AuraError) {
    let transaction_error = match error {
        BanksClientError::TransactionError(err) => err,
        BanksClientError::SimulationError { err, .. } => err,
        other => panic!("unexpected banks client error: {other:?}"),
    };

    match transaction_error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => {
            assert_eq!(code, expected as u32);
        }
        other => panic!("unexpected transaction error: {other:?}"),
    }
}

fn assert_program_error(error: ProgramError, expected: AuraError) {
    assert_eq!(error, ProgramError::Custom(expected as u32));
}

#[test]
fn instruction_unpack_rejects_unknown_tag() {
    let error = AuraInstruction::unpack(&[9]).unwrap_err();
    assert_program_error(error, AuraError::InvalidInstructionData);
}

#[test]
fn instruction_unpack_rejects_non_canonical_lengths() {
    let cases: &[&[u8]] = &[
        &[],
        &[0],
        &[0, PROTOCOL_VERSION],
        &[0, PROTOCOL_VERSION, 0, 0, 0, 0, 0, 0, 0],
        &[0, PROTOCOL_VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[1],
        &[1; 32],
        &[1; 34],
        &[2],
        &[2; 32],
        &[2; 34],
    ];

    for case in cases {
        let error = AuraInstruction::unpack(case).unwrap_err();
        assert_program_error(error, AuraError::InvalidInstructionData);
    }
}

#[tokio::test]
async fn initialize_protocol_success() {
    let mut harness = Harness::new().await;
    let (protocol_config_address, protocol_config_bump) = harness.protocol_config_pda();

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();

    let account = harness.get_account(protocol_config_address).await.unwrap();
    assert_eq!(account.owner, harness.program_id);
    assert_eq!(account.data.len(), ProtocolConfig::LEN);

    let protocol_config = harness.get_protocol_config(protocol_config_address).await;
    assert_eq!(protocol_config.account_type, ACCOUNT_TYPE_PROTOCOL_CONFIG);
    assert_eq!(protocol_config.schema_version, SCHEMA_VERSION);
    assert_eq!(protocol_config.bump, protocol_config_bump);
    assert_eq!(protocol_config.reserved, [0; RESERVED_LEN]);
    assert_eq!(protocol_config.authority, harness.authority.pubkey());
    assert_eq!(protocol_config.protocol_version, PROTOCOL_VERSION);
    assert_eq!(protocol_config.challenge_ttl_seconds, CHALLENGE_TTL_SECONDS);
}

#[tokio::test]
async fn issue_challenge_success() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let nonce = [7; 32];
    let (challenge_address, challenge_bump) = harness.challenge_pda(nonce);
    let mut clock = harness.current_clock().await;
    clock.unix_timestamp = 1_700_000_000;
    harness.context.set_sysvar(&clock);

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();

    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();

    let account = harness.get_account(challenge_address).await.unwrap();
    assert_eq!(account.owner, harness.program_id);
    assert_eq!(account.data.len(), ChallengeAccount::LEN);

    let challenge = harness.get_challenge(challenge_address).await;
    assert_eq!(challenge.account_type, ACCOUNT_TYPE_CHALLENGE);
    assert_eq!(challenge.schema_version, SCHEMA_VERSION);
    assert_eq!(challenge.bump, challenge_bump);
    assert_eq!(challenge.reserved, [0; RESERVED_LEN]);
    assert_eq!(challenge.subject, harness.subject.pubkey());
    assert_eq!(challenge.nonce, nonce);
    assert_eq!(challenge.created_at, clock.unix_timestamp);
    assert_eq!(
        challenge.expires_at,
        clock.unix_timestamp + CHALLENGE_TTL_SECONDS
    );
    assert!(!challenge.used);
}

#[tokio::test]
async fn submit_proof_success() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let subject = clone_keypair(&harness.subject);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let nonce = [11; 32];
    let proof_hash = [19; 32];
    let (challenge_address, challenge_bump) = harness.challenge_pda(nonce);
    let (proof_record_address, proof_record_bump) =
        harness.proof_pda(challenge_address, harness.subject.pubkey());

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();
    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();
    let mut clock = harness.current_clock().await;
    clock.unix_timestamp = 1_700_000_100;
    harness.context.set_sysvar(&clock);

    harness
        .submit_proof(
            &subject,
            challenge_address,
            proof_record_address,
            proof_hash,
        )
        .await
        .unwrap();

    let challenge = harness.get_challenge(challenge_address).await;
    assert_eq!(challenge.account_type, ACCOUNT_TYPE_CHALLENGE);
    assert_eq!(challenge.schema_version, SCHEMA_VERSION);
    assert_eq!(challenge.bump, challenge_bump);
    assert_eq!(challenge.reserved, [0; RESERVED_LEN]);
    assert_eq!(challenge.subject, harness.subject.pubkey());
    assert_eq!(challenge.nonce, nonce);
    assert!(challenge.used);

    let proof_account = harness.get_account(proof_record_address).await.unwrap();
    assert_eq!(proof_account.owner, harness.program_id);
    assert_eq!(proof_account.data.len(), ProofRecord::LEN);

    let proof_record = harness.get_proof_record(proof_record_address).await;
    assert_eq!(proof_record.account_type, ACCOUNT_TYPE_PROOF_RECORD);
    assert_eq!(proof_record.schema_version, SCHEMA_VERSION);
    assert_eq!(proof_record.bump, proof_record_bump);
    assert_eq!(proof_record.reserved, [0; RESERVED_LEN]);
    assert_eq!(proof_record.challenge, challenge_address);
    assert_eq!(proof_record.submitter, harness.subject.pubkey());
    assert_eq!(proof_record.proof_hash, proof_hash);
    assert_eq!(proof_record.submitted_at, clock.unix_timestamp);
    assert!(proof_record.accepted);
}

#[tokio::test]
async fn wrong_pda_rejections() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let subject = clone_keypair(&harness.subject);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let wrong_protocol_config =
        Pubkey::find_program_address(&[b"protocol-config-wrong"], &harness.program_id).0;

    let error = harness
        .initialize_protocol(
            wrong_protocol_config,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::InvalidPda);
    assert!(harness.get_account(wrong_protocol_config).await.is_none());

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();

    let nonce = [23; 32];
    let wrong_nonce = [24; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);
    let (wrong_challenge_address, _) = harness.challenge_pda(wrong_nonce);
    let error = harness
        .issue_challenge(&authority, nonce, wrong_challenge_address)
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::InvalidPda);
    assert!(harness.get_account(challenge_address).await.is_none());
    assert!(harness.get_account(wrong_challenge_address).await.is_none());

    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();

    let wrong_proof_record = harness
        .proof_pda(challenge_address, harness.wrong_submitter.pubkey())
        .0;
    let error = harness
        .submit_proof(&subject, challenge_address, wrong_proof_record, [25; 32])
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::InvalidPda);

    let challenge = harness.get_challenge(challenge_address).await;
    assert!(!challenge.used);
    assert!(harness.get_account(wrong_proof_record).await.is_none());
}

#[tokio::test]
async fn wrong_authority_fails() {
    let mut harness = Harness::new().await;
    let wrong_authority = clone_keypair(&harness.wrong_authority);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let nonce = [31; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();

    let error = harness
        .issue_challenge(&wrong_authority, nonce, challenge_address)
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::InvalidAuthority);
    assert!(harness.get_account(challenge_address).await.is_none());
}

#[tokio::test]
async fn expired_challenge_fails() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let subject = clone_keypair(&harness.subject);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let nonce = [37; 32];
    let proof_hash = [38; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);
    let (proof_record_address, _) = harness.proof_pda(challenge_address, harness.subject.pubkey());

    harness
        .initialize_protocol(protocol_config_address, PROTOCOL_VERSION, 1)
        .await
        .unwrap();
    let mut clock = harness.current_clock().await;
    clock.unix_timestamp = 1_700_000_200;
    harness.context.set_sysvar(&clock);
    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();

    let challenge = harness.get_challenge(challenge_address).await;
    // ProgramTestContext::set_sysvar provides deterministic local time control
    // for the expiration path without changing program logic.
    clock.unix_timestamp = challenge.expires_at + 1;
    harness.context.set_sysvar(&clock);

    let error = harness
        .submit_proof(
            &subject,
            challenge_address,
            proof_record_address,
            proof_hash,
        )
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::ChallengeExpired);

    let challenge = harness.get_challenge(challenge_address).await;
    assert!(!challenge.used);
    assert!(harness.get_account(proof_record_address).await.is_none());
}

#[tokio::test]
async fn reused_challenge_fails() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let subject = clone_keypair(&harness.subject);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let nonce = [41; 32];
    let proof_hash = [42; 32];
    let replay_attempt_hash = [43; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);
    let (proof_record_address, proof_record_bump) =
        harness.proof_pda(challenge_address, harness.subject.pubkey());

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();
    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();
    harness
        .submit_proof(
            &subject,
            challenge_address,
            proof_record_address,
            proof_hash,
        )
        .await
        .unwrap();

    let error = harness
        .submit_proof(
            &subject,
            challenge_address,
            proof_record_address,
            replay_attempt_hash,
        )
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::ChallengeAlreadyUsed);

    let challenge = harness.get_challenge(challenge_address).await;
    assert!(challenge.used);

    let proof_record = harness.get_proof_record(proof_record_address).await;
    assert_eq!(proof_record.bump, proof_record_bump);
    assert_eq!(proof_record.proof_hash, proof_hash);
    assert!(proof_record.accepted);
}

#[tokio::test]
async fn wrong_submitter_fails() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let wrong_submitter = clone_keypair(&harness.wrong_submitter);
    let (protocol_config_address, _) = harness.protocol_config_pda();
    let nonce = [47; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);
    let (proof_record_address, _) =
        harness.proof_pda(challenge_address, harness.wrong_submitter.pubkey());

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();
    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();

    let error = harness
        .submit_proof(
            &wrong_submitter,
            challenge_address,
            proof_record_address,
            [48; 32],
        )
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::InvalidSubmitter);

    let challenge = harness.get_challenge(challenge_address).await;
    assert!(!challenge.used);
    assert!(harness.get_account(proof_record_address).await.is_none());
}

#[tokio::test]
async fn extra_accounts_fail_closed_for_every_instruction() {
    let mut harness = Harness::new().await;
    let authority = clone_keypair(&harness.authority);
    let subject = clone_keypair(&harness.subject);
    let extra_account = Pubkey::new_unique();
    let (protocol_config_address, _) = harness.protocol_config_pda();

    let mut initialize = initialize_protocol_instruction(
        harness.program_id,
        harness.context.payer.pubkey(),
        authority.pubkey(),
        protocol_config_address,
        PROTOCOL_VERSION,
        CHALLENGE_TTL_SECONDS,
    );
    initialize
        .accounts
        .push(AccountMeta::new_readonly(extra_account, false));
    let error = harness
        .process_instruction(initialize, &[&authority])
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::UnexpectedAccounts);
    assert!(harness.get_account(protocol_config_address).await.is_none());

    harness
        .initialize_protocol(
            protocol_config_address,
            PROTOCOL_VERSION,
            CHALLENGE_TTL_SECONDS,
        )
        .await
        .unwrap();

    let nonce = [57; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);
    let mut issue = issue_challenge_instruction(
        harness.program_id,
        harness.context.payer.pubkey(),
        authority.pubkey(),
        protocol_config_address,
        harness.subject.pubkey(),
        challenge_address,
        nonce,
    );
    issue
        .accounts
        .push(AccountMeta::new_readonly(extra_account, false));
    let error = harness
        .process_instruction(issue, &[&authority])
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::UnexpectedAccounts);
    assert!(harness.get_account(challenge_address).await.is_none());

    harness
        .issue_challenge(&authority, nonce, challenge_address)
        .await
        .unwrap();

    let (proof_record_address, _) = harness.proof_pda(challenge_address, harness.subject.pubkey());
    let mut submit = submit_proof_instruction(
        harness.program_id,
        subject.pubkey(),
        challenge_address,
        proof_record_address,
        [58; 32],
    );
    submit
        .accounts
        .push(AccountMeta::new_readonly(extra_account, false));
    let error = harness
        .process_instruction(submit, &[&subject])
        .await
        .unwrap_err();
    assert_custom_error(error, AuraError::UnexpectedAccounts);
    assert!(!harness.get_challenge(challenge_address).await.used);
    assert!(harness.get_account(proof_record_address).await.is_none());
}
