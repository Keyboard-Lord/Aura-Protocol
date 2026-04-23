//! Frozen Aura v1 Solana MVP.
//!
//! Within the repository-wide Aura architecture, this crate implements only a
//! narrow Layer 4 state-recording slice. It does not implement the DCM core,
//! Layer 2 DCM-rooted authorization lineage, or the Layer 3 STARK proving
//! layer.

use core::convert::TryInto;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction, system_program,
    sysvar::{clock::Clock, rent::Rent, Sysvar},
};

const CONFIG_SEED: &[u8] = b"protocol-config";
const CHALLENGE_SEED: &[u8] = b"challenge";
const PROOF_SEED: &[u8] = b"proof-record";

const SCHEMA_VERSION: u8 = 1;
const ACCOUNT_TYPE_PROTOCOL_CONFIG: u8 = 1;
const ACCOUNT_TYPE_CHALLENGE: u8 = 2;
const ACCOUNT_TYPE_PROOF_RECORD: u8 = 3;

const U8_BYTES: usize = 1;
const PUBKEY_BYTES: usize = 32;
const I64_BYTES: usize = 8;
const BOOL_BYTES: usize = 1;

const ACCOUNT_TYPE_OFFSET: usize = 0;
const SCHEMA_VERSION_OFFSET: usize = ACCOUNT_TYPE_OFFSET + U8_BYTES;
const BUMP_OFFSET: usize = SCHEMA_VERSION_OFFSET + U8_BYTES;
const RESERVED_OFFSET: usize = BUMP_OFFSET + U8_BYTES;
const RESERVED_LEN: usize = 5;
const HEADER_LEN: usize = RESERVED_OFFSET + RESERVED_LEN;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    instruction_data: &[u8],
) -> ProgramResult {
    match AuraInstruction::unpack(instruction_data)? {
        AuraInstruction::InitializeProtocol {
            protocol_version,
            challenge_ttl_seconds,
        } => process_initialize_protocol(
            program_id,
            accounts,
            protocol_version,
            challenge_ttl_seconds,
        ),
        AuraInstruction::IssueChallenge { nonce } => {
            process_issue_challenge(program_id, accounts, nonce)
        }
        AuraInstruction::SubmitProof { proof_hash } => {
            process_submit_proof(program_id, accounts, proof_hash)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    pub account_type: u8,
    pub schema_version: u8,
    pub bump: u8,
    pub reserved: [u8; RESERVED_LEN],
    pub authority: Pubkey,
    pub protocol_version: u8,
    pub challenge_ttl_seconds: i64,
}

impl ProtocolConfig {
    const AUTHORITY_OFFSET: usize = HEADER_LEN;
    const PROTOCOL_VERSION_OFFSET: usize = Self::AUTHORITY_OFFSET + PUBKEY_BYTES;
    const CHALLENGE_TTL_SECONDS_OFFSET: usize = Self::PROTOCOL_VERSION_OFFSET + U8_BYTES;
    pub const LEN: usize = Self::CHALLENGE_TTL_SECONDS_OFFSET + I64_BYTES;

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != Self::LEN {
            return Err(AuraError::InvalidAccountData.into());
        }

        let (account_type, schema_version, bump, reserved) =
            unpack_header(input, ACCOUNT_TYPE_PROTOCOL_CONFIG)?;
        let authority = Pubkey::new_from_array(
            input[Self::AUTHORITY_OFFSET..Self::AUTHORITY_OFFSET + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let protocol_version = input[Self::PROTOCOL_VERSION_OFFSET];
        let challenge_ttl_seconds = i64::from_le_bytes(
            input[Self::CHALLENGE_TTL_SECONDS_OFFSET
                ..Self::CHALLENGE_TTL_SECONDS_OFFSET + I64_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );

        Ok(Self {
            account_type,
            schema_version,
            bump,
            reserved,
            authority,
            protocol_version,
            challenge_ttl_seconds,
        })
    }

    pub fn pack(&self, output: &mut [u8]) -> ProgramResult {
        if output.len() != Self::LEN {
            return Err(AuraError::InvalidAccountData.into());
        }

        pack_header(
            output,
            self.account_type,
            self.schema_version,
            self.bump,
            &self.reserved,
            ACCOUNT_TYPE_PROTOCOL_CONFIG,
        )?;
        output[Self::AUTHORITY_OFFSET..Self::AUTHORITY_OFFSET + PUBKEY_BYTES]
            .copy_from_slice(self.authority.as_ref());
        output[Self::PROTOCOL_VERSION_OFFSET] = self.protocol_version;
        output[Self::CHALLENGE_TTL_SECONDS_OFFSET..Self::CHALLENGE_TTL_SECONDS_OFFSET + I64_BYTES]
            .copy_from_slice(&self.challenge_ttl_seconds.to_le_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeAccount {
    pub account_type: u8,
    pub schema_version: u8,
    pub bump: u8,
    pub reserved: [u8; RESERVED_LEN],
    pub subject: Pubkey,
    pub nonce: [u8; 32],
    pub created_at: i64,
    pub expires_at: i64,
    pub used: bool,
}

impl ChallengeAccount {
    const SUBJECT_OFFSET: usize = HEADER_LEN;
    const NONCE_OFFSET: usize = Self::SUBJECT_OFFSET + PUBKEY_BYTES;
    const CREATED_AT_OFFSET: usize = Self::NONCE_OFFSET + 32;
    const EXPIRES_AT_OFFSET: usize = Self::CREATED_AT_OFFSET + I64_BYTES;
    const USED_OFFSET: usize = Self::EXPIRES_AT_OFFSET + I64_BYTES;
    pub const LEN: usize = Self::USED_OFFSET + BOOL_BYTES;

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != Self::LEN {
            return Err(AuraError::InvalidAccountData.into());
        }

        let (account_type, schema_version, bump, reserved) =
            unpack_header(input, ACCOUNT_TYPE_CHALLENGE)?;
        let subject = Pubkey::new_from_array(
            input[Self::SUBJECT_OFFSET..Self::SUBJECT_OFFSET + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let nonce = input[Self::NONCE_OFFSET..Self::NONCE_OFFSET + 32]
            .try_into()
            .map_err(|_| AuraError::InvalidAccountData)?;
        let created_at = i64::from_le_bytes(
            input[Self::CREATED_AT_OFFSET..Self::CREATED_AT_OFFSET + I64_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let expires_at = i64::from_le_bytes(
            input[Self::EXPIRES_AT_OFFSET..Self::EXPIRES_AT_OFFSET + I64_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let used = unpack_bool(input[Self::USED_OFFSET])?;

        Ok(Self {
            account_type,
            schema_version,
            bump,
            reserved,
            subject,
            nonce,
            created_at,
            expires_at,
            used,
        })
    }

    pub fn pack(&self, output: &mut [u8]) -> ProgramResult {
        if output.len() != Self::LEN {
            return Err(AuraError::InvalidAccountData.into());
        }

        pack_header(
            output,
            self.account_type,
            self.schema_version,
            self.bump,
            &self.reserved,
            ACCOUNT_TYPE_CHALLENGE,
        )?;
        output[Self::SUBJECT_OFFSET..Self::SUBJECT_OFFSET + PUBKEY_BYTES]
            .copy_from_slice(self.subject.as_ref());
        output[Self::NONCE_OFFSET..Self::NONCE_OFFSET + 32].copy_from_slice(&self.nonce);
        output[Self::CREATED_AT_OFFSET..Self::CREATED_AT_OFFSET + I64_BYTES]
            .copy_from_slice(&self.created_at.to_le_bytes());
        output[Self::EXPIRES_AT_OFFSET..Self::EXPIRES_AT_OFFSET + I64_BYTES]
            .copy_from_slice(&self.expires_at.to_le_bytes());
        output[Self::USED_OFFSET] = pack_bool(self.used);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofRecord {
    pub account_type: u8,
    pub schema_version: u8,
    pub bump: u8,
    pub reserved: [u8; RESERVED_LEN],
    pub challenge: Pubkey,
    pub submitter: Pubkey,
    pub proof_hash: [u8; 32],
    pub submitted_at: i64,
    pub accepted: bool,
}

impl ProofRecord {
    const CHALLENGE_OFFSET: usize = HEADER_LEN;
    const SUBMITTER_OFFSET: usize = Self::CHALLENGE_OFFSET + PUBKEY_BYTES;
    const PROOF_HASH_OFFSET: usize = Self::SUBMITTER_OFFSET + PUBKEY_BYTES;
    const SUBMITTED_AT_OFFSET: usize = Self::PROOF_HASH_OFFSET + 32;
    const ACCEPTED_OFFSET: usize = Self::SUBMITTED_AT_OFFSET + I64_BYTES;
    pub const LEN: usize = Self::ACCEPTED_OFFSET + BOOL_BYTES;

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != Self::LEN {
            return Err(AuraError::InvalidAccountData.into());
        }

        let (account_type, schema_version, bump, reserved) =
            unpack_header(input, ACCOUNT_TYPE_PROOF_RECORD)?;
        let challenge = Pubkey::new_from_array(
            input[Self::CHALLENGE_OFFSET..Self::CHALLENGE_OFFSET + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let submitter = Pubkey::new_from_array(
            input[Self::SUBMITTER_OFFSET..Self::SUBMITTER_OFFSET + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let proof_hash = input[Self::PROOF_HASH_OFFSET..Self::PROOF_HASH_OFFSET + 32]
            .try_into()
            .map_err(|_| AuraError::InvalidAccountData)?;
        let submitted_at = i64::from_le_bytes(
            input[Self::SUBMITTED_AT_OFFSET..Self::SUBMITTED_AT_OFFSET + I64_BYTES]
                .try_into()
                .map_err(|_| AuraError::InvalidAccountData)?,
        );
        let accepted = unpack_bool(input[Self::ACCEPTED_OFFSET])?;

        Ok(Self {
            account_type,
            schema_version,
            bump,
            reserved,
            challenge,
            submitter,
            proof_hash,
            submitted_at,
            accepted,
        })
    }

    pub fn pack(&self, output: &mut [u8]) -> ProgramResult {
        if output.len() != Self::LEN {
            return Err(AuraError::InvalidAccountData.into());
        }

        pack_header(
            output,
            self.account_type,
            self.schema_version,
            self.bump,
            &self.reserved,
            ACCOUNT_TYPE_PROOF_RECORD,
        )?;
        output[Self::CHALLENGE_OFFSET..Self::CHALLENGE_OFFSET + PUBKEY_BYTES]
            .copy_from_slice(self.challenge.as_ref());
        output[Self::SUBMITTER_OFFSET..Self::SUBMITTER_OFFSET + PUBKEY_BYTES]
            .copy_from_slice(self.submitter.as_ref());
        output[Self::PROOF_HASH_OFFSET..Self::PROOF_HASH_OFFSET + 32]
            .copy_from_slice(&self.proof_hash);
        output[Self::SUBMITTED_AT_OFFSET..Self::SUBMITTED_AT_OFFSET + I64_BYTES]
            .copy_from_slice(&self.submitted_at.to_le_bytes());
        output[Self::ACCEPTED_OFFSET] = pack_bool(self.accepted);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuraInstruction {
    InitializeProtocol {
        protocol_version: u8,
        challenge_ttl_seconds: i64,
    },
    IssueChallenge {
        nonce: [u8; 32],
    },
    SubmitProof {
        proof_hash: [u8; 32],
    },
}

impl AuraInstruction {
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = input
            .split_first()
            .ok_or::<ProgramError>(AuraError::InvalidInstructionData.into())?;

        match tag {
            0 => {
                if rest.len() != 9 {
                    return Err(AuraError::InvalidInstructionData.into());
                }

                let protocol_version = rest[0];
                let challenge_ttl_seconds = i64::from_le_bytes(
                    rest[1..9]
                        .try_into()
                        .map_err(|_| AuraError::InvalidInstructionData)?,
                );

                Ok(Self::InitializeProtocol {
                    protocol_version,
                    challenge_ttl_seconds,
                })
            }
            1 => {
                if rest.len() != 32 {
                    return Err(AuraError::InvalidInstructionData.into());
                }

                Ok(Self::IssueChallenge {
                    nonce: rest
                        .try_into()
                        .map_err(|_| AuraError::InvalidInstructionData)?,
                })
            }
            2 => {
                if rest.len() != 32 {
                    return Err(AuraError::InvalidInstructionData.into());
                }

                Ok(Self::SubmitProof {
                    proof_hash: rest
                        .try_into()
                        .map_err(|_| AuraError::InvalidInstructionData)?,
                })
            }
            _ => Err(AuraError::InvalidInstructionData.into()),
        }
    }
}

#[repr(u32)]
pub enum AuraError {
    InvalidInstructionData = 0,
    InvalidAccountData = 1,
    MissingRequiredSignature = 2,
    InvalidAccountOwner = 3,
    InvalidSystemProgram = 4,
    InvalidClockSysvar = 5,
    InvalidPda = 6,
    AccountAlreadyInitialized = 7,
    InvalidAuthority = 8,
    ArithmeticOverflow = 9,
    ChallengeExpired = 10,
    ChallengeAlreadyUsed = 11,
    InvalidSubmitter = 12,
    InvalidChallengeTtl = 13,
    UnexpectedAccounts = 14,
    AccountNotRentExempt = 15,
    InvalidAccountState = 16,
    AccountNotWritable = 17,
    InvalidAccountType = 18,
    InvalidSchemaVersion = 19,
    InvalidReservedBytes = 20,
    InvalidBump = 21,
}

impl From<AuraError> for ProgramError {
    fn from(error: AuraError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

fn process_initialize_protocol(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    protocol_version: u8,
    challenge_ttl_seconds: i64,
) -> ProgramResult {
    if challenge_ttl_seconds <= 0 {
        return Err(AuraError::InvalidChallengeTtl.into());
    }

    let account_info_iter = &mut accounts.iter();
    let payer_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let protocol_config_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    assert_no_remaining_accounts(account_info_iter)?;

    assert_signer(payer_info)?;
    assert_signer(authority_info)?;
    assert_writable(payer_info)?;
    assert_writable(protocol_config_info)?;
    assert_system_program(system_program_info)?;

    let (expected_config_key, config_bump) =
        Pubkey::find_program_address(&[CONFIG_SEED], program_id);
    if protocol_config_info.key != &expected_config_key {
        return Err(AuraError::InvalidPda.into());
    }

    assert_uninitialized_pda(protocol_config_info)?;

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(ProtocolConfig::LEN);
    let config_bump_seed = [config_bump];

    invoke_signed(
        &system_instruction::create_account(
            payer_info.key,
            protocol_config_info.key,
            lamports,
            ProtocolConfig::LEN as u64,
            program_id,
        ),
        &[
            payer_info.clone(),
            protocol_config_info.clone(),
            system_program_info.clone(),
        ],
        &[&[CONFIG_SEED, &config_bump_seed]],
    )?;

    if protocol_config_info.owner != program_id {
        return Err(AuraError::InvalidAccountOwner.into());
    }
    if protocol_config_info.data_len() != ProtocolConfig::LEN {
        return Err(AuraError::InvalidAccountData.into());
    }
    if !rent.is_exempt(protocol_config_info.lamports(), ProtocolConfig::LEN) {
        return Err(AuraError::AccountNotRentExempt.into());
    }

    let config = ProtocolConfig {
        account_type: ACCOUNT_TYPE_PROTOCOL_CONFIG,
        schema_version: SCHEMA_VERSION,
        bump: config_bump,
        reserved: [0; RESERVED_LEN],
        authority: *authority_info.key,
        protocol_version,
        challenge_ttl_seconds,
    };

    let data = &mut *protocol_config_info.try_borrow_mut_data()?;
    config.pack(data)
}

fn process_issue_challenge(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    nonce: [u8; 32],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let protocol_config_info = next_account_info(account_info_iter)?;
    let subject_info = next_account_info(account_info_iter)?;
    let challenge_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let clock_sysvar_info = next_account_info(account_info_iter)?;
    assert_no_remaining_accounts(account_info_iter)?;

    assert_signer(payer_info)?;
    assert_signer(authority_info)?;
    assert_writable(payer_info)?;
    assert_writable(challenge_info)?;
    assert_system_program(system_program_info)?;
    assert_clock_sysvar(clock_sysvar_info)?;
    assert_program_account(protocol_config_info, program_id, ProtocolConfig::LEN)?;

    let protocol_config = {
        let data = protocol_config_info.try_borrow_data()?;
        ProtocolConfig::unpack(&data)?
    };
    assert_protocol_config_pda_and_bump(program_id, protocol_config_info.key, &protocol_config)?;
    if protocol_config.authority != *authority_info.key {
        return Err(AuraError::InvalidAuthority.into());
    }
    if protocol_config.challenge_ttl_seconds <= 0 {
        return Err(AuraError::InvalidChallengeTtl.into());
    }

    let (expected_challenge_key, challenge_bump) = Pubkey::find_program_address(
        &[CHALLENGE_SEED, subject_info.key.as_ref(), nonce.as_ref()],
        program_id,
    );
    if challenge_info.key != &expected_challenge_key {
        return Err(AuraError::InvalidPda.into());
    }

    assert_uninitialized_pda(challenge_info)?;

    let clock = Clock::from_account_info(clock_sysvar_info)?;
    let created_at = clock.unix_timestamp;
    let expires_at = created_at
        .checked_add(protocol_config.challenge_ttl_seconds)
        .ok_or::<ProgramError>(AuraError::ArithmeticOverflow.into())?;

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(ChallengeAccount::LEN);
    let challenge_bump_seed = [challenge_bump];

    invoke_signed(
        &system_instruction::create_account(
            payer_info.key,
            challenge_info.key,
            lamports,
            ChallengeAccount::LEN as u64,
            program_id,
        ),
        &[
            payer_info.clone(),
            challenge_info.clone(),
            system_program_info.clone(),
        ],
        &[&[
            CHALLENGE_SEED,
            subject_info.key.as_ref(),
            nonce.as_ref(),
            &challenge_bump_seed,
        ]],
    )?;

    if challenge_info.owner != program_id {
        return Err(AuraError::InvalidAccountOwner.into());
    }
    if challenge_info.data_len() != ChallengeAccount::LEN {
        return Err(AuraError::InvalidAccountData.into());
    }
    if !rent.is_exempt(challenge_info.lamports(), ChallengeAccount::LEN) {
        return Err(AuraError::AccountNotRentExempt.into());
    }

    let challenge = ChallengeAccount {
        account_type: ACCOUNT_TYPE_CHALLENGE,
        schema_version: SCHEMA_VERSION,
        bump: challenge_bump,
        reserved: [0; RESERVED_LEN],
        subject: *subject_info.key,
        nonce,
        created_at,
        expires_at,
        used: false,
    };

    let data = &mut *challenge_info.try_borrow_mut_data()?;
    challenge.pack(data)
}

fn process_submit_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    proof_hash: [u8; 32],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let submitter_info = next_account_info(account_info_iter)?;
    let challenge_info = next_account_info(account_info_iter)?;
    let proof_record_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let clock_sysvar_info = next_account_info(account_info_iter)?;
    assert_no_remaining_accounts(account_info_iter)?;

    assert_signer(submitter_info)?;
    assert_writable(submitter_info)?;
    assert_writable(challenge_info)?;
    assert_writable(proof_record_info)?;
    assert_system_program(system_program_info)?;
    assert_clock_sysvar(clock_sysvar_info)?;
    assert_program_account(challenge_info, program_id, ChallengeAccount::LEN)?;

    let challenge_state = {
        let data = challenge_info.try_borrow_data()?;
        ChallengeAccount::unpack(&data)?
    };

    assert_challenge_pda_and_bump(program_id, challenge_info.key, &challenge_state)?;

    if challenge_state.subject != *submitter_info.key {
        return Err(AuraError::InvalidSubmitter.into());
    }
    if challenge_state.created_at > challenge_state.expires_at {
        return Err(AuraError::InvalidAccountState.into());
    }
    if challenge_state.used {
        return Err(AuraError::ChallengeAlreadyUsed.into());
    }

    let clock = Clock::from_account_info(clock_sysvar_info)?;
    if clock.unix_timestamp > challenge_state.expires_at {
        return Err(AuraError::ChallengeExpired.into());
    }

    let (expected_proof_key, proof_bump) = Pubkey::find_program_address(
        &[
            PROOF_SEED,
            challenge_info.key.as_ref(),
            submitter_info.key.as_ref(),
        ],
        program_id,
    );
    if proof_record_info.key != &expected_proof_key {
        return Err(AuraError::InvalidPda.into());
    }

    assert_uninitialized_pda(proof_record_info)?;

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(ProofRecord::LEN);
    let proof_bump_seed = [proof_bump];

    invoke_signed(
        &system_instruction::create_account(
            submitter_info.key,
            proof_record_info.key,
            lamports,
            ProofRecord::LEN as u64,
            program_id,
        ),
        &[
            submitter_info.clone(),
            proof_record_info.clone(),
            system_program_info.clone(),
        ],
        &[&[
            PROOF_SEED,
            challenge_info.key.as_ref(),
            submitter_info.key.as_ref(),
            &proof_bump_seed,
        ]],
    )?;

    if proof_record_info.owner != program_id {
        return Err(AuraError::InvalidAccountOwner.into());
    }
    if proof_record_info.data_len() != ProofRecord::LEN {
        return Err(AuraError::InvalidAccountData.into());
    }
    if !rent.is_exempt(proof_record_info.lamports(), ProofRecord::LEN) {
        return Err(AuraError::AccountNotRentExempt.into());
    }

    let updated_challenge = ChallengeAccount {
        used: true,
        ..challenge_state
    };
    {
        let data = &mut *challenge_info.try_borrow_mut_data()?;
        updated_challenge.pack(data)?;
    }

    let proof_record = ProofRecord {
        account_type: ACCOUNT_TYPE_PROOF_RECORD,
        schema_version: SCHEMA_VERSION,
        bump: proof_bump,
        reserved: [0; RESERVED_LEN],
        challenge: *challenge_info.key,
        submitter: *submitter_info.key,
        proof_hash,
        submitted_at: clock.unix_timestamp,
        accepted: true,
    };
    assert_proof_record_pda_and_bump(
        program_id,
        proof_record_info.key,
        challenge_info.key,
        submitter_info.key,
        &proof_record,
    )?;
    {
        let data = &mut *proof_record_info.try_borrow_mut_data()?;
        proof_record.pack(data)?;
    }

    Ok(())
}

fn unpack_header(
    input: &[u8],
    expected_account_type: u8,
) -> Result<(u8, u8, u8, [u8; RESERVED_LEN]), ProgramError> {
    if input.len() < HEADER_LEN {
        return Err(AuraError::InvalidAccountData.into());
    }

    let account_type = input[ACCOUNT_TYPE_OFFSET];
    if account_type != expected_account_type {
        return Err(AuraError::InvalidAccountType.into());
    }

    let schema_version = input[SCHEMA_VERSION_OFFSET];
    if schema_version != SCHEMA_VERSION {
        return Err(AuraError::InvalidSchemaVersion.into());
    }

    // `unpack_header` validates only structural header bytes. Callers must
    // validate `bump` against the canonical PDA derivation for the account.
    let bump = input[BUMP_OFFSET];
    let reserved: [u8; RESERVED_LEN] = input[RESERVED_OFFSET..HEADER_LEN]
        .try_into()
        .map_err(|_| AuraError::InvalidAccountData)?;
    if !is_all_zero(&reserved) {
        return Err(AuraError::InvalidReservedBytes.into());
    }

    Ok((account_type, schema_version, bump, reserved))
}

fn pack_header(
    output: &mut [u8],
    account_type: u8,
    schema_version: u8,
    bump: u8,
    reserved: &[u8; RESERVED_LEN],
    expected_account_type: u8,
) -> ProgramResult {
    if output.len() < HEADER_LEN {
        return Err(AuraError::InvalidAccountData.into());
    }
    if account_type != expected_account_type {
        return Err(AuraError::InvalidAccountType.into());
    }
    if schema_version != SCHEMA_VERSION {
        return Err(AuraError::InvalidSchemaVersion.into());
    }
    if !is_all_zero(reserved) {
        return Err(AuraError::InvalidReservedBytes.into());
    }

    output[ACCOUNT_TYPE_OFFSET] = account_type;
    output[SCHEMA_VERSION_OFFSET] = schema_version;
    output[BUMP_OFFSET] = bump;
    output[RESERVED_OFFSET..HEADER_LEN].copy_from_slice(reserved);
    Ok(())
}

fn assert_protocol_config_pda_and_bump(
    program_id: &Pubkey,
    account_key: &Pubkey,
    protocol_config: &ProtocolConfig,
) -> ProgramResult {
    let (expected_key, expected_bump) = Pubkey::find_program_address(&[CONFIG_SEED], program_id);
    if account_key != &expected_key {
        return Err(AuraError::InvalidPda.into());
    }
    if protocol_config.bump != expected_bump {
        return Err(AuraError::InvalidBump.into());
    }
    Ok(())
}

fn assert_challenge_pda_and_bump(
    program_id: &Pubkey,
    account_key: &Pubkey,
    challenge: &ChallengeAccount,
) -> ProgramResult {
    let (expected_key, expected_bump) = Pubkey::find_program_address(
        &[
            CHALLENGE_SEED,
            challenge.subject.as_ref(),
            challenge.nonce.as_ref(),
        ],
        program_id,
    );
    if account_key != &expected_key {
        return Err(AuraError::InvalidPda.into());
    }
    if challenge.bump != expected_bump {
        return Err(AuraError::InvalidBump.into());
    }
    Ok(())
}

fn assert_proof_record_pda_and_bump(
    program_id: &Pubkey,
    account_key: &Pubkey,
    challenge_key: &Pubkey,
    submitter_key: &Pubkey,
    proof_record: &ProofRecord,
) -> ProgramResult {
    let (expected_key, expected_bump) = Pubkey::find_program_address(
        &[PROOF_SEED, challenge_key.as_ref(), submitter_key.as_ref()],
        program_id,
    );
    if account_key != &expected_key {
        return Err(AuraError::InvalidPda.into());
    }
    if proof_record.bump != expected_bump {
        return Err(AuraError::InvalidBump.into());
    }
    Ok(())
}

fn assert_signer(account_info: &AccountInfo<'_>) -> ProgramResult {
    if !account_info.is_signer {
        return Err(AuraError::MissingRequiredSignature.into());
    }
    Ok(())
}

fn assert_writable(account_info: &AccountInfo<'_>) -> ProgramResult {
    if !account_info.is_writable {
        return Err(AuraError::AccountNotWritable.into());
    }
    Ok(())
}

fn assert_program_account(
    account_info: &AccountInfo<'_>,
    program_id: &Pubkey,
    expected_len: usize,
) -> ProgramResult {
    if account_info.owner != program_id {
        return Err(AuraError::InvalidAccountOwner.into());
    }
    if account_info.executable {
        return Err(AuraError::InvalidAccountOwner.into());
    }
    if account_info.data_len() != expected_len {
        return Err(AuraError::InvalidAccountData.into());
    }
    Ok(())
}

fn assert_system_program(account_info: &AccountInfo<'_>) -> ProgramResult {
    if !system_program::check_id(account_info.key) {
        return Err(AuraError::InvalidSystemProgram.into());
    }
    Ok(())
}

fn assert_clock_sysvar(account_info: &AccountInfo<'_>) -> ProgramResult {
    if !solana_program::sysvar::clock::check_id(account_info.key) {
        return Err(AuraError::InvalidClockSysvar.into());
    }
    Ok(())
}

fn assert_uninitialized_pda(account_info: &AccountInfo<'_>) -> ProgramResult {
    if account_info.owner != &system_program::ID {
        return Err(AuraError::AccountAlreadyInitialized.into());
    }
    if account_info.executable {
        return Err(AuraError::AccountAlreadyInitialized.into());
    }
    if account_info.lamports() != 0 {
        return Err(AuraError::AccountAlreadyInitialized.into());
    }
    if !account_info.data_is_empty() {
        return Err(AuraError::AccountAlreadyInitialized.into());
    }
    Ok(())
}

fn assert_no_remaining_accounts(
    iter: &mut core::slice::Iter<'_, AccountInfo<'_>>,
) -> ProgramResult {
    if iter.next().is_some() {
        return Err(AuraError::UnexpectedAccounts.into());
    }
    Ok(())
}

fn unpack_bool(value: u8) -> Result<bool, ProgramError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AuraError::InvalidAccountData.into()),
    }
}

fn pack_bool(value: bool) -> u8 {
    if value {
        1
    } else {
        0
    }
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
