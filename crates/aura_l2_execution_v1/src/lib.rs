//! Deterministic Aura L2 local execution engine for the first proving-chain milestone.
//!
//! This crate implements the smallest complete local state machine needed by the
//! frozen Aura authority stack:
//!
//! - account-based state
//! - balances and nonces
//! - one canonical transaction family: transfer
//! - deterministic batch execution
//! - deterministic commitments required by the transition-binding contract
//!
//! This crate does not implement:
//!
//! - generalized intents
//! - authorization-lineage validation
//! - smart contracts
//! - non-zero fees
//! - Solana settlement
//! - a cryptographic STARK

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

mod token_transaction_v1;

pub use token_transaction_v1::*;

pub const HASH_LEN_V1: usize = 32;
pub const ZERO32_V1: [u8; HASH_LEN_V1] = [0u8; HASH_LEN_V1];

pub const EXECUTION_MODEL_VERSION_V1: u32 = 1;
pub const BATCH_VERSION_V1: u32 = 1;
pub const TRANSFER_TX_VERSION_V1: u32 = 1;
pub const TRANSITION_BINDING_VERSION_V1: u32 = 1;
pub const EXECUTION_OUTCOME_STATUS_APPLIED_V1: u8 = 1;
pub const ZERO_FEE_PER_TRANSFER_V1: u64 = 0;

pub const AURA_L2_LOCAL_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_ACCOUNT_LEAF_V1";
pub const AURA_L2_LOCAL_STATE_ROOT_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_STATE_ROOT_V1";
pub const AURA_L2_LOCAL_STATE_EMPTY_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_STATE_EMPTY_V1";
pub const AURA_L2_LOCAL_TRANSFER_TX_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_TRANSFER_TX_V1";
pub const AURA_L2_LOCAL_TOUCHED_ACCOUNTS_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_TOUCHED_ACCOUNTS_V1";
pub const AURA_L2_LOCAL_TRANSFER_RESULT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_TRANSFER_RESULT_V1";
pub const AURA_L2_LOCAL_SYSTEM_CONFIG_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_SYSTEM_CONFIG_V1";
pub const AURA_L2_LOCAL_FEE_PARAMETERS_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_FEE_PARAMETERS_V1";
pub const AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_V1";
pub const AURA_L2_LOCAL_EXECUTION_CONSTANTS_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_EXECUTION_CONSTANTS_V1";
pub const AURA_L2_LOCAL_FEE_SUMMARY_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_FEE_SUMMARY_V1";

pub const D_TX_ENTRY_V1: &[u8] = b"AURA_L2_TX_ENTRY_V1";
pub const D_TX_LIST_V1: &[u8] = b"AURA_L2_TX_LIST_V1";
pub const D_OUTCOME_V1: &[u8] = b"AURA_L2_EXECUTION_OUTCOME_V1";
pub const D_OUTCOME_LIST_V1: &[u8] = b"AURA_L2_OUTCOME_LIST_V1";
pub const D_CONTEXT_V1: &[u8] = b"AURA_L2_BATCH_CONTEXT_V1";

pub fn sha256_bytes(bytes: &[u8]) -> [u8; HASH_LEN_V1] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalAccountV1 {
    pub account_id: [u8; HASH_LEN_V1],
    pub balance: u64,
    pub nonce: u64,
}

impl LocalAccountV1 {
    pub fn canonical_bytes(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[..32].copy_from_slice(&self.account_id);
        bytes[32..40].copy_from_slice(&self.balance.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    pub fn leaf_hash(&self) -> [u8; HASH_LEN_V1] {
        let mut preimage =
            Vec::with_capacity(AURA_L2_LOCAL_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1.len() + 48);
        preimage.extend_from_slice(AURA_L2_LOCAL_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1);
        preimage.extend_from_slice(&self.canonical_bytes());
        sha256_bytes(&preimage)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalStateV1 {
    accounts: BTreeMap<[u8; HASH_LEN_V1], LocalAccountV1>,
}

impl LocalStateV1 {
    pub fn new<I>(accounts: I) -> Result<Self, LocalExecutionErrorV1>
    where
        I: IntoIterator<Item = LocalAccountV1>,
    {
        let mut map = BTreeMap::new();
        for account in accounts {
            if map.insert(account.account_id, account).is_some() {
                return Err(LocalExecutionErrorV1::DuplicateAccountId {
                    account_id: account.account_id,
                });
            }
        }
        Ok(Self { accounts: map })
    }

    pub fn account(&self, account_id: &[u8; HASH_LEN_V1]) -> Option<&LocalAccountV1> {
        self.accounts.get(account_id)
    }

    pub fn ordered_accounts(&self) -> Vec<LocalAccountV1> {
        self.accounts.values().copied().collect()
    }

    pub fn state_root(&self) -> [u8; HASH_LEN_V1] {
        if self.accounts.is_empty() {
            return sha256_bytes(AURA_L2_LOCAL_STATE_EMPTY_DOMAIN_SEPARATOR_V1);
        }

        let mut preimage = Vec::with_capacity(
            AURA_L2_LOCAL_STATE_ROOT_DOMAIN_SEPARATOR_V1.len()
                + 8
                + (self.accounts.len() * HASH_LEN_V1),
        );
        preimage.extend_from_slice(AURA_L2_LOCAL_STATE_ROOT_DOMAIN_SEPARATOR_V1);
        preimage.extend_from_slice(&(self.accounts.len() as u64).to_le_bytes());
        for account in self.accounts.values() {
            preimage.extend_from_slice(&account.leaf_hash());
        }
        sha256_bytes(&preimage)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferTransactionV1 {
    pub tx_version: u32,
    pub sender_account_id: [u8; HASH_LEN_V1],
    pub recipient_account_id: [u8; HASH_LEN_V1],
    pub sender_nonce: u64,
    pub amount: u64,
}

impl TransferTransactionV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(AURA_L2_LOCAL_TRANSFER_TX_DOMAIN_SEPARATOR_V1.len() + 84);
        bytes.extend_from_slice(AURA_L2_LOCAL_TRANSFER_TX_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&self.tx_version.to_le_bytes());
        bytes.extend_from_slice(&self.sender_account_id);
        bytes.extend_from_slice(&self.recipient_account_id);
        bytes.extend_from_slice(&self.sender_nonce.to_le_bytes());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchExecutionRequestV1 {
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; HASH_LEN_V1],
    pub transactions: Vec<TransferTransactionV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalExecutionConfigV1 {
    pub rollup_id: [u8; HASH_LEN_V1],
    pub execution_model_version: u32,
    pub batch_version: u32,
}

impl LocalExecutionConfigV1 {
    pub fn new(rollup_id: [u8; HASH_LEN_V1]) -> Self {
        Self {
            rollup_id,
            execution_model_version: EXECUTION_MODEL_VERSION_V1,
            batch_version: BATCH_VERSION_V1,
        }
    }

    pub fn system_config_commitment(&self) -> [u8; HASH_LEN_V1] {
        let mut bytes =
            Vec::with_capacity(AURA_L2_LOCAL_SYSTEM_CONFIG_DOMAIN_SEPARATOR_V1.len() + 40);
        bytes.extend_from_slice(AURA_L2_LOCAL_SYSTEM_CONFIG_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&self.rollup_id);
        bytes.extend_from_slice(&self.execution_model_version.to_le_bytes());
        bytes.extend_from_slice(&self.batch_version.to_le_bytes());
        sha256_bytes(&bytes)
    }

    pub fn fee_parameters_commitment(&self) -> [u8; HASH_LEN_V1] {
        let mut bytes =
            Vec::with_capacity(AURA_L2_LOCAL_FEE_PARAMETERS_DOMAIN_SEPARATOR_V1.len() + 8);
        bytes.extend_from_slice(AURA_L2_LOCAL_FEE_PARAMETERS_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&ZERO_FEE_PER_TRANSFER_V1.to_le_bytes());
        sha256_bytes(&bytes)
    }

    pub fn validity_reference_commitment(&self) -> [u8; HASH_LEN_V1] {
        let mut bytes =
            Vec::with_capacity(AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_DOMAIN_SEPARATOR_V1.len() + 1);
        bytes.extend_from_slice(AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_DOMAIN_SEPARATOR_V1);
        bytes.push(0);
        sha256_bytes(&bytes)
    }

    pub fn execution_constants_commitment(&self) -> [u8; HASH_LEN_V1] {
        let mut bytes =
            Vec::with_capacity(AURA_L2_LOCAL_EXECUTION_CONSTANTS_DOMAIN_SEPARATOR_V1.len() + 9);
        bytes.extend_from_slice(AURA_L2_LOCAL_EXECUTION_CONSTANTS_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&TRANSFER_TX_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&TRANSITION_BINDING_VERSION_V1.to_le_bytes());
        bytes.push(EXECUTION_OUTCOME_STATUS_APPLIED_V1);
        sha256_bytes(&bytes)
    }

    pub fn batch_context(&self) -> LocalBatchContextV1 {
        LocalBatchContextV1::new(
            self.system_config_commitment(),
            self.fee_parameters_commitment(),
            self.validity_reference_commitment(),
            self.execution_constants_commitment(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalBatchContextV1 {
    pub system_config_commitment: [u8; HASH_LEN_V1],
    pub fee_parameters_commitment: [u8; HASH_LEN_V1],
    pub validity_reference_commitment: [u8; HASH_LEN_V1],
    pub execution_constants_commitment: [u8; HASH_LEN_V1],
}

impl LocalBatchContextV1 {
    pub fn new(
        system_config_commitment: [u8; HASH_LEN_V1],
        fee_parameters_commitment: [u8; HASH_LEN_V1],
        validity_reference_commitment: [u8; HASH_LEN_V1],
        execution_constants_commitment: [u8; HASH_LEN_V1],
    ) -> Self {
        Self {
            system_config_commitment,
            fee_parameters_commitment,
            validity_reference_commitment,
            execution_constants_commitment,
        }
    }

    pub fn context_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(D_CONTEXT_V1.len() + 4 + (HASH_LEN_V1 * 4));
        bytes.extend_from_slice(D_CONTEXT_V1);
        bytes.extend_from_slice(&TRANSITION_BINDING_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&self.system_config_commitment);
        bytes.extend_from_slice(&self.fee_parameters_commitment);
        bytes.extend_from_slice(&self.validity_reference_commitment);
        bytes.extend_from_slice(&self.execution_constants_commitment);
        bytes
    }

    pub fn batch_context_commitment(&self) -> [u8; HASH_LEN_V1] {
        sha256_bytes(&self.context_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalFeeSummaryV1 {
    pub tx_count: u64,
    pub total_fee_charged: u64,
}

impl LocalFeeSummaryV1 {
    pub fn new(tx_count: u64) -> Self {
        Self {
            tx_count,
            total_fee_charged: 0,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            AURA_L2_LOCAL_FEE_SUMMARY_DOMAIN_SEPARATOR_V1.len() + 4 + 8 + 8 + 32,
        );
        bytes.extend_from_slice(AURA_L2_LOCAL_FEE_SUMMARY_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&self.tx_count.to_le_bytes());
        bytes.extend_from_slice(&self.total_fee_charged.to_le_bytes());
        bytes.extend_from_slice(&ZERO32_V1);
        bytes
    }

    pub fn commitment(&self) -> [u8; HASH_LEN_V1] {
        sha256_bytes(&self.canonical_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionOutcomeV1 {
    pub tx_index: u64,
    pub sender_account_id: [u8; HASH_LEN_V1],
    pub consumed_nonce: u64,
    pub fee_charged: u64,
    pub touched_accounts_commitment: [u8; HASH_LEN_V1],
    pub operation_result_commitment: [u8; HASH_LEN_V1],
    pub status: u8,
}

impl ExecutionOutcomeV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(D_OUTCOME_V1.len() + 8 + 32 + 8 + 8 + 32 + 32 + 1);
        bytes.extend_from_slice(D_OUTCOME_V1);
        bytes.extend_from_slice(&self.tx_index.to_le_bytes());
        bytes.extend_from_slice(&self.sender_account_id);
        bytes.extend_from_slice(&self.consumed_nonce.to_le_bytes());
        bytes.extend_from_slice(&self.fee_charged.to_le_bytes());
        bytes.extend_from_slice(&self.touched_accounts_commitment);
        bytes.extend_from_slice(&self.operation_result_commitment);
        bytes.push(self.status);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedTransferStepV1 {
    pub tx_index: u64,
    pub sender_account_id: [u8; HASH_LEN_V1],
    pub recipient_account_id: [u8; HASH_LEN_V1],
    pub sender_nonce_before: u64,
    pub sender_nonce_after: u64,
    pub sender_balance_before: u64,
    pub sender_balance_after: u64,
    pub recipient_balance_before: u64,
    pub recipient_balance_after: u64,
    pub amount: u64,
    pub fee_charged: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutedBatchV1 {
    pub config: LocalExecutionConfigV1,
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; HASH_LEN_V1],
    pub tx_count: u64,
    pub pre_state: LocalStateV1,
    pub post_state: LocalStateV1,
    pub pre_state_root: [u8; HASH_LEN_V1],
    pub post_state_root: [u8; HASH_LEN_V1],
    pub transactions: Vec<TransferTransactionV1>,
    pub transaction_bytes: Vec<Vec<u8>>,
    pub transactions_commitment: [u8; HASH_LEN_V1],
    pub outcomes: Vec<ExecutionOutcomeV1>,
    pub outcome_bytes: Vec<Vec<u8>>,
    pub outcomes_commitment: [u8; HASH_LEN_V1],
    pub batch_context: LocalBatchContextV1,
    pub context_bytes: Vec<u8>,
    pub batch_context_commitment: [u8; HASH_LEN_V1],
    pub fee_summary: LocalFeeSummaryV1,
    pub fee_summary_bytes: Vec<u8>,
    pub fee_summary_commitment: [u8; HASH_LEN_V1],
    pub applied_steps: Vec<AppliedTransferStepV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalExecutionErrorV1 {
    DuplicateAccountId {
        account_id: [u8; HASH_LEN_V1],
    },
    TxCountOverflow,
    UnsupportedTxVersion {
        expected: u32,
        actual: u32,
    },
    ZeroAmount {
        tx_index: u64,
    },
    SelfTransfer {
        tx_index: u64,
        account_id: [u8; HASH_LEN_V1],
    },
    MissingSender {
        tx_index: u64,
        account_id: [u8; HASH_LEN_V1],
    },
    MissingRecipient {
        tx_index: u64,
        account_id: [u8; HASH_LEN_V1],
    },
    NonceMismatch {
        tx_index: u64,
        expected: u64,
        actual: u64,
    },
    InsufficientBalance {
        tx_index: u64,
        available: u64,
        required: u64,
    },
    RecipientBalanceOverflow {
        tx_index: u64,
    },
}

impl fmt::Display for LocalExecutionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAccountId { account_id } => {
                write!(f, "duplicate account id: {}", LowerHex32(account_id))
            }
            Self::TxCountOverflow => write!(f, "transaction count overflow"),
            Self::UnsupportedTxVersion { expected, actual } => write!(
                f,
                "unsupported tx version: expected {expected}, got {actual}"
            ),
            Self::ZeroAmount { tx_index } => write!(f, "zero amount at tx index {tx_index}"),
            Self::SelfTransfer { tx_index, account_id } => write!(
                f,
                "self transfer at tx index {tx_index} for account {}",
                LowerHex32(account_id)
            ),
            Self::MissingSender {
                tx_index,
                account_id,
            } => write!(
                f,
                "missing sender at tx index {tx_index}: {}",
                LowerHex32(account_id)
            ),
            Self::MissingRecipient {
                tx_index,
                account_id,
            } => write!(
                f,
                "missing recipient at tx index {tx_index}: {}",
                LowerHex32(account_id)
            ),
            Self::NonceMismatch {
                tx_index,
                expected,
                actual,
            } => write!(
                f,
                "nonce mismatch at tx index {tx_index}: expected {expected}, got {actual}"
            ),
            Self::InsufficientBalance {
                tx_index,
                available,
                required,
            } => write!(
                f,
                "insufficient balance at tx index {tx_index}: available {available}, required {required}"
            ),
            Self::RecipientBalanceOverflow { tx_index } => {
                write!(f, "recipient balance overflow at tx index {tx_index}")
            }
        }
    }
}

impl std::error::Error for LocalExecutionErrorV1 {}

pub fn execute_transfer_batch_v1(
    pre_state: &LocalStateV1,
    config: &LocalExecutionConfigV1,
    request: &BatchExecutionRequestV1,
) -> Result<ExecutedBatchV1, LocalExecutionErrorV1> {
    let tx_count = u64::try_from(request.transactions.len())
        .map_err(|_| LocalExecutionErrorV1::TxCountOverflow)?;
    let pre_state_root = pre_state.state_root();
    let transaction_bytes: Vec<Vec<u8>> = request
        .transactions
        .iter()
        .map(TransferTransactionV1::canonical_bytes)
        .collect();
    let transactions_commitment = derive_transactions_commitment_v1(&transaction_bytes);

    let batch_context = config.batch_context();
    let context_bytes = batch_context.context_bytes();
    let batch_context_commitment = batch_context.batch_context_commitment();

    let fee_summary = LocalFeeSummaryV1::new(tx_count);
    let fee_summary_bytes = fee_summary.canonical_bytes();
    let fee_summary_commitment = fee_summary.commitment();

    let mut effective_state = pre_state.clone();
    let mut outcomes = Vec::with_capacity(request.transactions.len());
    let mut applied_steps = Vec::with_capacity(request.transactions.len());

    for (index, tx) in request.transactions.iter().enumerate() {
        let tx_index = index as u64;
        if tx.tx_version != TRANSFER_TX_VERSION_V1 {
            return Err(LocalExecutionErrorV1::UnsupportedTxVersion {
                expected: TRANSFER_TX_VERSION_V1,
                actual: tx.tx_version,
            });
        }
        if tx.amount == 0 {
            return Err(LocalExecutionErrorV1::ZeroAmount { tx_index });
        }
        if tx.sender_account_id == tx.recipient_account_id {
            return Err(LocalExecutionErrorV1::SelfTransfer {
                tx_index,
                account_id: tx.sender_account_id,
            });
        }

        let sender_before = *effective_state.accounts.get(&tx.sender_account_id).ok_or(
            LocalExecutionErrorV1::MissingSender {
                tx_index,
                account_id: tx.sender_account_id,
            },
        )?;
        let recipient_before = *effective_state
            .accounts
            .get(&tx.recipient_account_id)
            .ok_or(LocalExecutionErrorV1::MissingRecipient {
                tx_index,
                account_id: tx.recipient_account_id,
            })?;

        if sender_before.nonce != tx.sender_nonce {
            return Err(LocalExecutionErrorV1::NonceMismatch {
                tx_index,
                expected: sender_before.nonce,
                actual: tx.sender_nonce,
            });
        }

        let required = tx.amount;
        if sender_before.balance < required {
            return Err(LocalExecutionErrorV1::InsufficientBalance {
                tx_index,
                available: sender_before.balance,
                required,
            });
        }

        let recipient_after_balance = recipient_before
            .balance
            .checked_add(tx.amount)
            .ok_or(LocalExecutionErrorV1::RecipientBalanceOverflow { tx_index })?;
        let sender_after_balance = sender_before.balance - tx.amount;

        let sender_after = LocalAccountV1 {
            account_id: sender_before.account_id,
            balance: sender_after_balance,
            nonce: sender_before.nonce + 1,
        };
        let recipient_after = LocalAccountV1 {
            account_id: recipient_before.account_id,
            balance: recipient_after_balance,
            nonce: recipient_before.nonce,
        };

        effective_state
            .accounts
            .insert(sender_after.account_id, sender_after);
        effective_state
            .accounts
            .insert(recipient_after.account_id, recipient_after);

        let touched_accounts_commitment =
            derive_touched_accounts_commitment_v1(&tx.sender_account_id, &tx.recipient_account_id);
        let operation_result_commitment = derive_transfer_result_commitment_v1(
            tx.amount,
            sender_before.balance,
            sender_after.balance,
            recipient_before.balance,
            recipient_after.balance,
        );
        outcomes.push(ExecutionOutcomeV1 {
            tx_index,
            sender_account_id: tx.sender_account_id,
            consumed_nonce: sender_before.nonce,
            fee_charged: ZERO_FEE_PER_TRANSFER_V1,
            touched_accounts_commitment,
            operation_result_commitment,
            status: EXECUTION_OUTCOME_STATUS_APPLIED_V1,
        });
        applied_steps.push(AppliedTransferStepV1 {
            tx_index,
            sender_account_id: tx.sender_account_id,
            recipient_account_id: tx.recipient_account_id,
            sender_nonce_before: sender_before.nonce,
            sender_nonce_after: sender_after.nonce,
            sender_balance_before: sender_before.balance,
            sender_balance_after: sender_after.balance,
            recipient_balance_before: recipient_before.balance,
            recipient_balance_after: recipient_after.balance,
            amount: tx.amount,
            fee_charged: ZERO_FEE_PER_TRANSFER_V1,
        });
    }

    let post_state_root = effective_state.state_root();
    let outcome_bytes: Vec<Vec<u8>> = outcomes
        .iter()
        .map(ExecutionOutcomeV1::canonical_bytes)
        .collect();
    let outcomes_commitment = derive_outcomes_commitment_v1(&outcome_bytes);

    Ok(ExecutedBatchV1 {
        config: *config,
        batch_number: request.batch_number,
        parent_batch_commitment: request.parent_batch_commitment,
        tx_count,
        pre_state: pre_state.clone(),
        post_state: effective_state,
        pre_state_root,
        post_state_root,
        transactions: request.transactions.clone(),
        transaction_bytes,
        transactions_commitment,
        outcomes,
        outcome_bytes,
        outcomes_commitment,
        batch_context,
        context_bytes,
        batch_context_commitment,
        fee_summary,
        fee_summary_bytes,
        fee_summary_commitment,
        applied_steps,
    })
}

pub fn derive_touched_accounts_commitment_v1(
    sender_account_id: &[u8; HASH_LEN_V1],
    recipient_account_id: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut bytes =
        Vec::with_capacity(AURA_L2_LOCAL_TOUCHED_ACCOUNTS_DOMAIN_SEPARATOR_V1.len() + 64);
    bytes.extend_from_slice(AURA_L2_LOCAL_TOUCHED_ACCOUNTS_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(sender_account_id);
    bytes.extend_from_slice(recipient_account_id);
    sha256_bytes(&bytes)
}

pub fn derive_transfer_result_commitment_v1(
    amount: u64,
    sender_balance_before: u64,
    sender_balance_after: u64,
    recipient_balance_before: u64,
    recipient_balance_after: u64,
) -> [u8; HASH_LEN_V1] {
    let mut bytes =
        Vec::with_capacity(AURA_L2_LOCAL_TRANSFER_RESULT_DOMAIN_SEPARATOR_V1.len() + 40);
    bytes.extend_from_slice(AURA_L2_LOCAL_TRANSFER_RESULT_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&amount.to_le_bytes());
    bytes.extend_from_slice(&sender_balance_before.to_le_bytes());
    bytes.extend_from_slice(&sender_balance_after.to_le_bytes());
    bytes.extend_from_slice(&recipient_balance_before.to_le_bytes());
    bytes.extend_from_slice(&recipient_balance_after.to_le_bytes());
    sha256_bytes(&bytes)
}

pub fn derive_transactions_commitment_v1(transaction_bytes: &[Vec<u8>]) -> [u8; HASH_LEN_V1] {
    let mut preimage =
        Vec::with_capacity(D_TX_LIST_V1.len() + 8 + (transaction_bytes.len() * HASH_LEN_V1));
    preimage.extend_from_slice(D_TX_LIST_V1);
    preimage.extend_from_slice(&(transaction_bytes.len() as u64).to_le_bytes());
    for (index, tx_bytes) in transaction_bytes.iter().enumerate() {
        let mut entry_preimage = Vec::with_capacity(D_TX_ENTRY_V1.len() + 8 + 8 + tx_bytes.len());
        entry_preimage.extend_from_slice(D_TX_ENTRY_V1);
        entry_preimage.extend_from_slice(&(index as u64).to_le_bytes());
        entry_preimage.extend_from_slice(&(tx_bytes.len() as u64).to_le_bytes());
        entry_preimage.extend_from_slice(tx_bytes);
        preimage.extend_from_slice(&sha256_bytes(&entry_preimage));
    }
    sha256_bytes(&preimage)
}

pub fn derive_outcomes_commitment_v1(outcome_bytes: &[Vec<u8>]) -> [u8; HASH_LEN_V1] {
    let mut preimage =
        Vec::with_capacity(D_OUTCOME_LIST_V1.len() + 8 + (outcome_bytes.len() * HASH_LEN_V1));
    preimage.extend_from_slice(D_OUTCOME_LIST_V1);
    preimage.extend_from_slice(&(outcome_bytes.len() as u64).to_le_bytes());
    for bytes in outcome_bytes {
        preimage.extend_from_slice(&sha256_bytes(bytes));
    }
    sha256_bytes(&preimage)
}

pub struct LowerHex32<'a>(pub &'a [u8; HASH_LEN_V1]);

impl fmt::Display for LowerHex32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        execute_transfer_batch_v1, BatchExecutionRequestV1, LocalAccountV1, LocalExecutionConfigV1,
        LocalExecutionErrorV1, LocalStateV1, TransferTransactionV1,
        EXECUTION_OUTCOME_STATUS_APPLIED_V1, TRANSFER_TX_VERSION_V1, ZERO32_V1,
    };

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn genesis_state() -> LocalStateV1 {
        LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 1_000,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x22),
                balance: 250,
                nonce: 0,
            },
        ])
        .unwrap()
    }

    fn config() -> LocalExecutionConfigV1 {
        LocalExecutionConfigV1::new(id(0xAA))
    }

    #[test]
    fn deterministic_execution_produces_stable_post_state() {
        let state = genesis_state();
        let request = BatchExecutionRequestV1 {
            batch_number: 0,
            parent_batch_commitment: ZERO32_V1,
            transactions: vec![TransferTransactionV1 {
                tx_version: TRANSFER_TX_VERSION_V1,
                sender_account_id: id(0x11),
                recipient_account_id: id(0x22),
                sender_nonce: 0,
                amount: 150,
            }],
        };

        let first = execute_transfer_batch_v1(&state, &config(), &request).unwrap();
        let second = execute_transfer_batch_v1(&state, &config(), &request).unwrap();

        assert_eq!(first.post_state_root, second.post_state_root);
        assert_eq!(
            first.transactions_commitment,
            second.transactions_commitment
        );
        assert_eq!(first.outcomes_commitment, second.outcomes_commitment);
        assert_eq!(
            first.batch_context_commitment,
            second.batch_context_commitment
        );
    }

    #[test]
    fn valid_transfer_updates_balances_and_nonce() {
        let state = genesis_state();
        let result = execute_transfer_batch_v1(
            &state,
            &config(),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 400,
                }],
            },
        )
        .unwrap();

        let sender = result.post_state.account(&id(0x11)).unwrap();
        let recipient = result.post_state.account(&id(0x22)).unwrap();
        assert_eq!(sender.balance, 600);
        assert_eq!(sender.nonce, 1);
        assert_eq!(recipient.balance, 650);
        assert_eq!(recipient.nonce, 0);
        assert_eq!(result.outcomes.len(), 1);
        assert_eq!(
            result.outcomes[0].status,
            EXECUTION_OUTCOME_STATUS_APPLIED_V1
        );
    }

    #[test]
    fn invalid_nonce_rejects() {
        let state = genesis_state();
        let error = execute_transfer_batch_v1(
            &state,
            &config(),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 7,
                    amount: 1,
                }],
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            LocalExecutionErrorV1::NonceMismatch {
                tx_index: 0,
                expected: 0,
                actual: 7,
            }
        );
    }

    #[test]
    fn insufficient_balance_rejects() {
        let state = genesis_state();
        let error = execute_transfer_batch_v1(
            &state,
            &config(),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 10_000,
                }],
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            LocalExecutionErrorV1::InsufficientBalance {
                tx_index: 0,
                available: 1_000,
                required: 10_000,
            }
        );
    }

    #[test]
    fn zero_amount_rejects() {
        let state = genesis_state();
        let error = execute_transfer_batch_v1(
            &state,
            &config(),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 0,
                }],
            },
        )
        .unwrap_err();

        assert_eq!(error, LocalExecutionErrorV1::ZeroAmount { tx_index: 0 });
    }

    #[test]
    fn self_transfer_rejects() {
        let state = genesis_state();
        let error = execute_transfer_batch_v1(
            &state,
            &config(),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x11),
                    sender_nonce: 0,
                    amount: 1,
                }],
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            LocalExecutionErrorV1::SelfTransfer {
                tx_index: 0,
                account_id: id(0x11),
            }
        );
    }

    #[test]
    fn recipient_balance_overflow_rejects() {
        let state = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 10,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x22),
                balance: u64::MAX,
                nonce: 0,
            },
        ])
        .unwrap();

        let error = execute_transfer_batch_v1(
            &state,
            &config(),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 1,
                }],
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            LocalExecutionErrorV1::RecipientBalanceOverflow { tx_index: 0 }
        );
    }

    #[test]
    fn duplicate_account_ids_reject_during_state_construction() {
        let error = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 1,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 2,
                nonce: 1,
            },
        ])
        .unwrap_err();

        assert_eq!(
            error,
            LocalExecutionErrorV1::DuplicateAccountId {
                account_id: id(0x11),
            }
        );
    }
}
