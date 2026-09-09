use aura_fractal_key_integration_v1::legacy::prepare_submit_proof_v1;
use aura_protocol::{process_instruction, ChallengeAccount, ProofRecord};
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
use std::sync::Once;

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
}

impl Harness {
    async fn new() -> Self {
        init_test_env();

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

    fn proof_pda(&self, challenge: Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[
                b"proof-record",
                challenge.as_ref(),
                self.subject.pubkey().as_ref(),
            ],
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

    async fn submit_proof(
        &mut self,
        challenge: Pubkey,
        proof_record: Pubkey,
        proof_hash: [u8; 32],
    ) -> Result<(), BanksClientError> {
        let subject = clone_keypair(&self.subject);
        let instruction = submit_proof_instruction(
            self.program_id,
            subject.pubkey(),
            challenge,
            proof_record,
            proof_hash,
        );
        self.process_instruction(instruction, &[&subject]).await
    }

    async fn get_account(&mut self, address: Pubkey) -> Account {
        self.context
            .banks_client
            .get_account(address)
            .await
            .unwrap()
            .unwrap()
    }

    async fn get_challenge(&mut self, address: Pubkey) -> ChallengeAccount {
        let account = self.get_account(address).await;
        ChallengeAccount::unpack(&account.data).unwrap()
    }

    async fn get_proof_record(&mut self, address: Pubkey) -> ProofRecord {
        let account = self.get_account(address).await;
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

#[tokio::test]
async fn fractal_key_integration_submit_proof_end_to_end() {
    let mut harness = Harness::new().await;
    let nonce = [0x44; 32];
    let proof_material_hash = [0x55; 32];
    let (challenge_address, _) = harness.challenge_pda(nonce);
    let (proof_record_address, _) = harness.proof_pda(challenge_address);

    harness.initialize_protocol().await.unwrap();

    let mut clock = harness.current_clock().await;
    clock.unix_timestamp = 1_700_200_000;
    harness.context.set_sysvar(&clock);

    harness
        .issue_challenge(nonce, challenge_address)
        .await
        .unwrap();

    let mut submit_clock = harness.current_clock().await;
    submit_clock.unix_timestamp = 1_700_200_030;
    harness.context.set_sysvar(&submit_clock);

    let preparation = prepare_submit_proof_v1(
        harness.subject.pubkey().to_bytes(),
        challenge_address.to_bytes(),
        proof_material_hash,
    )
    .unwrap();
    assert_eq!(preparation.fractal_key.proof_hash(), preparation.proof_hash);
    assert_eq!(preparation.fractal_key.fractal_key_version, 1);
    assert_eq!(preparation.fractal_key.component_count, 3);
    assert_eq!(preparation.fractal_key.components[0].component_type, 0x0001);
    assert_eq!(preparation.fractal_key.components[1].component_type, 0x0002);
    assert_eq!(preparation.fractal_key.components[2].component_type, 0x0003);
    assert_eq!(
        preparation.fractal_key.components[0].payload32,
        harness.subject.pubkey().to_bytes()
    );
    assert_eq!(
        preparation.fractal_key.components[1].payload32,
        challenge_address.to_bytes()
    );
    assert_eq!(
        preparation.fractal_key.components[2].payload32,
        proof_material_hash
    );

    harness
        .submit_proof(
            challenge_address,
            proof_record_address,
            preparation.proof_hash,
        )
        .await
        .unwrap();

    let challenge = harness.get_challenge(challenge_address).await;
    assert!(challenge.used);

    let proof_record = harness.get_proof_record(proof_record_address).await;
    assert_eq!(proof_record.challenge, challenge_address);
    assert_eq!(proof_record.submitter, harness.subject.pubkey());
    assert_eq!(proof_record.proof_hash, preparation.proof_hash);
    assert!(proof_record.accepted);
}
