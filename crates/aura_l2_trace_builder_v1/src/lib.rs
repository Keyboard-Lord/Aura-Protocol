//! Deterministic Aura L2 trace and witness builder for the first local proving chain.
//!
//! The trace and witness structures in this crate are real and deterministic.
//! They prepare the exact execution data that both the current mock prover and the
//! STARK-ready scaffold consume.
//!
//! Current status:
//!
//! - concrete trace layout: implemented
//! - AIR expectation checks: implemented as deterministic host checks
//! - real STARK proof generation: implemented in the prover/verifier crates against this frozen
//!   trace and witness boundary

use core::fmt;

use aura_l2_execution_v1::{
    execute_transfer_batch_v1, sha256_bytes, AppliedTransferStepV1, BatchExecutionRequestV1,
    ExecutedBatchV1, ExecutionOutcomeV1, LocalAccountV1, LocalBatchContextV1,
    LocalExecutionConfigV1, LocalExecutionErrorV1, LocalFeeSummaryV1, LocalStateV1,
    TransferTransactionV1, HASH_LEN_V1, ZERO_FEE_PER_TRANSFER_V1,
};
use aura_l2_public_input_v1::{
    PublicInputSchemaErrorV1, TransitionEnvelopeV1, PUBLIC_INPUT_SCHEMA_LEN_V1,
};

pub const AURA_L2_LOCAL_TRACE_ROW_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_TRACE_ROW_V1";
pub const AURA_L2_LOCAL_TRACE_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_LOCAL_TRACE_DIGEST_V1";
pub const AURA_L2_LOCAL_WITNESS_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_WITNESS_DIGEST_V1";
pub const AURA_L2_LOCAL_STARK_TRACE_LAYOUT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_STARK_TRACE_LAYOUT_V1";
pub const AURA_L2_LOCAL_STARK_TRACE_LAYOUT_ROW_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_STARK_TRACE_LAYOUT_ROW_V1";

pub const LOCAL_STARK_TRACE_LAYOUT_VERSION_V1: u32 = 1;
pub const LOCAL_STARK_TRACE_COLUMN_COUNT_V1: u64 = 17;
pub const LOCAL_STARK_TRACE_INITIALIZATION_ROW_COUNT_V1: u64 = 0;
pub const LOCAL_STARK_TRACE_FINALIZATION_ROW_COUNT_V1: u64 = 0;
pub const LOCAL_STARK_TRACE_PADDING_ROW_COUNT_V1: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalStarkTraceColumnV1 {
    TxIndex,
    SenderAccountIdLimb0,
    SenderAccountIdLimb1,
    SenderAccountIdLimb2,
    SenderAccountIdLimb3,
    RecipientAccountIdLimb0,
    RecipientAccountIdLimb1,
    RecipientAccountIdLimb2,
    RecipientAccountIdLimb3,
    Amount,
    FeeCharged,
    SenderNonceBefore,
    SenderNonceAfter,
    SenderBalanceBefore,
    SenderBalanceAfter,
    RecipientBalanceBefore,
    RecipientBalanceAfter,
}

impl LocalStarkTraceColumnV1 {
    pub const ALL: [Self; LOCAL_STARK_TRACE_COLUMN_COUNT_V1 as usize] = [
        Self::TxIndex,
        Self::SenderAccountIdLimb0,
        Self::SenderAccountIdLimb1,
        Self::SenderAccountIdLimb2,
        Self::SenderAccountIdLimb3,
        Self::RecipientAccountIdLimb0,
        Self::RecipientAccountIdLimb1,
        Self::RecipientAccountIdLimb2,
        Self::RecipientAccountIdLimb3,
        Self::Amount,
        Self::FeeCharged,
        Self::SenderNonceBefore,
        Self::SenderNonceAfter,
        Self::SenderBalanceBefore,
        Self::SenderBalanceAfter,
        Self::RecipientBalanceBefore,
        Self::RecipientBalanceAfter,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TxIndex => "tx_index",
            Self::SenderAccountIdLimb0 => "sender_account_id_limb_0",
            Self::SenderAccountIdLimb1 => "sender_account_id_limb_1",
            Self::SenderAccountIdLimb2 => "sender_account_id_limb_2",
            Self::SenderAccountIdLimb3 => "sender_account_id_limb_3",
            Self::RecipientAccountIdLimb0 => "recipient_account_id_limb_0",
            Self::RecipientAccountIdLimb1 => "recipient_account_id_limb_1",
            Self::RecipientAccountIdLimb2 => "recipient_account_id_limb_2",
            Self::RecipientAccountIdLimb3 => "recipient_account_id_limb_3",
            Self::Amount => "amount",
            Self::FeeCharged => "fee_charged",
            Self::SenderNonceBefore => "sender_nonce_before",
            Self::SenderNonceAfter => "sender_nonce_after",
            Self::SenderBalanceBefore => "sender_balance_before",
            Self::SenderBalanceAfter => "sender_balance_after",
            Self::RecipientBalanceBefore => "recipient_balance_before",
            Self::RecipientBalanceAfter => "recipient_balance_after",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferTraceRowV1 {
    pub tx_index: u64,
    pub sender_account_id: [u8; HASH_LEN_V1],
    pub recipient_account_id: [u8; HASH_LEN_V1],
    pub amount: u64,
    pub fee_charged: u64,
    pub sender_nonce_before: u64,
    pub sender_nonce_after: u64,
    pub sender_balance_before: u64,
    pub sender_balance_after: u64,
    pub recipient_balance_before: u64,
    pub recipient_balance_after: u64,
}

impl TransferTraceRowV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AURA_L2_LOCAL_TRACE_ROW_DOMAIN_SEPARATOR_V1.len() + 120);
        bytes.extend_from_slice(AURA_L2_LOCAL_TRACE_ROW_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&self.tx_index.to_le_bytes());
        bytes.extend_from_slice(&self.sender_account_id);
        bytes.extend_from_slice(&self.recipient_account_id);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.fee_charged.to_le_bytes());
        bytes.extend_from_slice(&self.sender_nonce_before.to_le_bytes());
        bytes.extend_from_slice(&self.sender_nonce_after.to_le_bytes());
        bytes.extend_from_slice(&self.sender_balance_before.to_le_bytes());
        bytes.extend_from_slice(&self.sender_balance_after.to_le_bytes());
        bytes.extend_from_slice(&self.recipient_balance_before.to_le_bytes());
        bytes.extend_from_slice(&self.recipient_balance_after.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalStarkTraceRowV1 {
    pub tx_index: u64,
    pub sender_account_id_limbs: [u64; 4],
    pub recipient_account_id_limbs: [u64; 4],
    pub amount: u64,
    pub fee_charged: u64,
    pub sender_nonce_before: u64,
    pub sender_nonce_after: u64,
    pub sender_balance_before: u64,
    pub sender_balance_after: u64,
    pub recipient_balance_before: u64,
    pub recipient_balance_after: u64,
}

impl LocalStarkTraceRowV1 {
    pub fn from_transfer_trace_row(row: &TransferTraceRowV1) -> Self {
        Self {
            tx_index: row.tx_index,
            sender_account_id_limbs: split_u64_limbs_le_v1(&row.sender_account_id),
            recipient_account_id_limbs: split_u64_limbs_le_v1(&row.recipient_account_id),
            amount: row.amount,
            fee_charged: row.fee_charged,
            sender_nonce_before: row.sender_nonce_before,
            sender_nonce_after: row.sender_nonce_after,
            sender_balance_before: row.sender_balance_before,
            sender_balance_after: row.sender_balance_after,
            recipient_balance_before: row.recipient_balance_before,
            recipient_balance_after: row.recipient_balance_after,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            AURA_L2_LOCAL_STARK_TRACE_LAYOUT_ROW_DOMAIN_SEPARATOR_V1.len() + 8 * 17,
        );
        bytes.extend_from_slice(AURA_L2_LOCAL_STARK_TRACE_LAYOUT_ROW_DOMAIN_SEPARATOR_V1);
        bytes.extend_from_slice(&self.tx_index.to_le_bytes());
        for limb in self.sender_account_id_limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        for limb in self.recipient_account_id_limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.fee_charged.to_le_bytes());
        bytes.extend_from_slice(&self.sender_nonce_before.to_le_bytes());
        bytes.extend_from_slice(&self.sender_nonce_after.to_le_bytes());
        bytes.extend_from_slice(&self.sender_balance_before.to_le_bytes());
        bytes.extend_from_slice(&self.sender_balance_after.to_le_bytes());
        bytes.extend_from_slice(&self.recipient_balance_before.to_le_bytes());
        bytes.extend_from_slice(&self.recipient_balance_after.to_le_bytes());
        bytes
    }

    pub fn value_for_column(&self, column: LocalStarkTraceColumnV1) -> u64 {
        match column {
            LocalStarkTraceColumnV1::TxIndex => self.tx_index,
            LocalStarkTraceColumnV1::SenderAccountIdLimb0 => self.sender_account_id_limbs[0],
            LocalStarkTraceColumnV1::SenderAccountIdLimb1 => self.sender_account_id_limbs[1],
            LocalStarkTraceColumnV1::SenderAccountIdLimb2 => self.sender_account_id_limbs[2],
            LocalStarkTraceColumnV1::SenderAccountIdLimb3 => self.sender_account_id_limbs[3],
            LocalStarkTraceColumnV1::RecipientAccountIdLimb0 => self.recipient_account_id_limbs[0],
            LocalStarkTraceColumnV1::RecipientAccountIdLimb1 => self.recipient_account_id_limbs[1],
            LocalStarkTraceColumnV1::RecipientAccountIdLimb2 => self.recipient_account_id_limbs[2],
            LocalStarkTraceColumnV1::RecipientAccountIdLimb3 => self.recipient_account_id_limbs[3],
            LocalStarkTraceColumnV1::Amount => self.amount,
            LocalStarkTraceColumnV1::FeeCharged => self.fee_charged,
            LocalStarkTraceColumnV1::SenderNonceBefore => self.sender_nonce_before,
            LocalStarkTraceColumnV1::SenderNonceAfter => self.sender_nonce_after,
            LocalStarkTraceColumnV1::SenderBalanceBefore => self.sender_balance_before,
            LocalStarkTraceColumnV1::SenderBalanceAfter => self.sender_balance_after,
            LocalStarkTraceColumnV1::RecipientBalanceBefore => self.recipient_balance_before,
            LocalStarkTraceColumnV1::RecipientBalanceAfter => self.recipient_balance_after,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalStarkTransactionWitnessRowV1 {
    pub tx_index: u64,
    pub sender_account_id_limbs: [u64; 4],
    pub recipient_account_id_limbs: [u64; 4],
    pub sender_nonce: u64,
    pub amount: u64,
}

impl LocalStarkTransactionWitnessRowV1 {
    pub fn from_transaction(tx_index: u64, tx: &TransferTransactionV1) -> Self {
        Self {
            tx_index,
            sender_account_id_limbs: split_u64_limbs_le_v1(&tx.sender_account_id),
            recipient_account_id_limbs: split_u64_limbs_le_v1(&tx.recipient_account_id),
            sender_nonce: tx.sender_nonce,
            amount: tx.amount,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalStarkTraceLayoutV1 {
    pub layout_version: u32,
    pub row_count: u64,
    pub rows: Vec<LocalStarkTraceRowV1>,
}

impl LocalStarkTraceLayoutV1 {
    pub fn from_transfer_rows(rows: &[TransferTraceRowV1]) -> Self {
        Self {
            layout_version: LOCAL_STARK_TRACE_LAYOUT_VERSION_V1,
            row_count: rows.len() as u64,
            rows: rows
                .iter()
                .map(LocalStarkTraceRowV1::from_transfer_trace_row)
                .collect(),
        }
    }

    pub fn column_count(&self) -> u64 {
        LOCAL_STARK_TRACE_COLUMN_COUNT_V1
    }

    pub fn initialization_row_count(&self) -> u64 {
        LOCAL_STARK_TRACE_INITIALIZATION_ROW_COUNT_V1
    }

    pub fn transaction_row_count(&self) -> u64 {
        self.row_count
    }

    pub fn finalization_row_count(&self) -> u64 {
        LOCAL_STARK_TRACE_FINALIZATION_ROW_COUNT_V1
    }

    pub fn padding_row_count(&self) -> u64 {
        LOCAL_STARK_TRACE_PADDING_ROW_COUNT_V1
    }

    pub fn total_row_count(&self) -> u64 {
        self.initialization_row_count()
            + self.transaction_row_count()
            + self.finalization_row_count()
            + self.padding_row_count()
    }

    pub fn column_values(&self, column: LocalStarkTraceColumnV1) -> Vec<u64> {
        self.rows
            .iter()
            .map(|row| row.value_for_column(column))
            .collect()
    }

    pub fn layout_digest(&self) -> [u8; HASH_LEN_V1] {
        derive_trace_layout_digest_v1(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceWitnessBundleV1 {
    pub config: LocalExecutionConfigV1,
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; HASH_LEN_V1],
    pub public_inputs: TransitionEnvelopeV1,
    pub public_inputs_bytes: [u8; PUBLIC_INPUT_SCHEMA_LEN_V1],
    pub pre_state_accounts: Vec<LocalAccountV1>,
    pub post_state_accounts: Vec<LocalAccountV1>,
    pub transactions: Vec<TransferTransactionV1>,
    pub transaction_bytes: Vec<Vec<u8>>,
    pub outcomes: Vec<ExecutionOutcomeV1>,
    pub outcome_bytes: Vec<Vec<u8>>,
    pub batch_context: LocalBatchContextV1,
    pub context_bytes: Vec<u8>,
    pub fee_summary: LocalFeeSummaryV1,
    pub fee_summary_bytes: Vec<u8>,
    pub trace_rows: Vec<TransferTraceRowV1>,
    pub stark_trace_layout: LocalStarkTraceLayoutV1,
    pub transaction_witness_rows: Vec<LocalStarkTransactionWitnessRowV1>,
    pub trace_digest: [u8; HASH_LEN_V1],
    pub trace_layout_digest: [u8; HASH_LEN_V1],
    pub witness_digest: [u8; HASH_LEN_V1],
}

#[derive(Debug)]
pub enum TraceBuilderErrorV1 {
    PublicInputError(PublicInputSchemaErrorV1),
    ExecutionError(LocalExecutionErrorV1),
    StateMismatch {
        field: &'static str,
    },
    TransactionBytesMismatch {
        tx_index: u64,
    },
    OutcomeMismatch {
        tx_index: u64,
    },
    ContextMismatch,
    FeeSummaryMismatch,
    TraceRowMismatch {
        tx_index: u64,
    },
    TraceLayoutMismatch {
        row_index: u64,
        field: &'static str,
    },
    TraceDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    TraceLayoutDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    WitnessDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    AirConstraintViolation {
        constraint: &'static str,
        tx_index: Option<u64>,
    },
    PublicInputBytesMismatch,
}

impl fmt::Display for TraceBuilderErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicInputError(error) => write!(f, "public input error: {error}"),
            Self::ExecutionError(error) => write!(f, "execution error: {error}"),
            Self::StateMismatch { field } => write!(f, "state mismatch in {field}"),
            Self::TransactionBytesMismatch { tx_index } => {
                write!(f, "transaction bytes mismatch at tx index {tx_index}")
            }
            Self::OutcomeMismatch { tx_index } => {
                write!(f, "outcome mismatch at tx index {tx_index}")
            }
            Self::ContextMismatch => write!(f, "batch context mismatch"),
            Self::FeeSummaryMismatch => write!(f, "fee summary mismatch"),
            Self::TraceRowMismatch { tx_index } => {
                write!(f, "trace row mismatch at tx index {tx_index}")
            }
            Self::TraceLayoutMismatch { row_index, field } => {
                write!(f, "trace layout mismatch at tx index {row_index}: {field}")
            }
            Self::TraceDigestMismatch { .. } => write!(f, "trace digest mismatch"),
            Self::TraceLayoutDigestMismatch { .. } => write!(f, "trace layout digest mismatch"),
            Self::WitnessDigestMismatch { .. } => write!(f, "witness digest mismatch"),
            Self::AirConstraintViolation {
                constraint,
                tx_index,
            } => {
                if let Some(tx_index) = tx_index {
                    write!(
                        f,
                        "air constraint violation at tx index {tx_index}: {constraint}"
                    )
                } else {
                    write!(f, "air constraint violation: {constraint}")
                }
            }
            Self::PublicInputBytesMismatch => write!(f, "public input bytes mismatch"),
        }
    }
}

impl std::error::Error for TraceBuilderErrorV1 {}

impl From<PublicInputSchemaErrorV1> for TraceBuilderErrorV1 {
    fn from(value: PublicInputSchemaErrorV1) -> Self {
        Self::PublicInputError(value)
    }
}

impl From<LocalExecutionErrorV1> for TraceBuilderErrorV1 {
    fn from(value: LocalExecutionErrorV1) -> Self {
        Self::ExecutionError(value)
    }
}

pub fn build_trace_witness_bundle_v1(
    executed: &ExecutedBatchV1,
) -> Result<TraceWitnessBundleV1, TraceBuilderErrorV1> {
    let public_inputs = TransitionEnvelopeV1::from_executed_batch(executed);
    public_inputs.ensure_matches_executed_batch(executed)?;
    let public_inputs_bytes = public_inputs.encode_bytes();
    let trace_rows = trace_rows_from_steps_v1(&executed.applied_steps);
    let stark_trace_layout = LocalStarkTraceLayoutV1::from_transfer_rows(&trace_rows);
    let transaction_witness_rows =
        transaction_witness_rows_from_transactions_v1(&executed.transactions);
    let trace_digest = derive_trace_digest_v1(&trace_rows);
    let trace_layout_digest = derive_trace_layout_digest_v1(&stark_trace_layout);

    let mut bundle = TraceWitnessBundleV1 {
        config: executed.config,
        batch_number: executed.batch_number,
        parent_batch_commitment: executed.parent_batch_commitment,
        public_inputs,
        public_inputs_bytes,
        pre_state_accounts: executed.pre_state.ordered_accounts(),
        post_state_accounts: executed.post_state.ordered_accounts(),
        transactions: executed.transactions.clone(),
        transaction_bytes: executed.transaction_bytes.clone(),
        outcomes: executed.outcomes.clone(),
        outcome_bytes: executed.outcome_bytes.clone(),
        batch_context: executed.batch_context,
        context_bytes: executed.context_bytes.clone(),
        fee_summary: executed.fee_summary,
        fee_summary_bytes: executed.fee_summary_bytes.clone(),
        trace_rows,
        stark_trace_layout,
        transaction_witness_rows,
        trace_digest,
        trace_layout_digest,
        witness_digest: [0u8; HASH_LEN_V1],
    };
    bundle.witness_digest = derive_witness_digest_v1(&bundle);
    validate_trace_witness_bundle_v1(&bundle)?;
    Ok(bundle)
}

pub fn validate_trace_witness_bundle_v1(
    bundle: &TraceWitnessBundleV1,
) -> Result<(), TraceBuilderErrorV1> {
    let decoded = TransitionEnvelopeV1::decode_exact(&bundle.public_inputs_bytes)?;
    if decoded != bundle.public_inputs {
        return Err(TraceBuilderErrorV1::PublicInputBytesMismatch);
    }

    let pre_state = LocalStateV1::new(bundle.pre_state_accounts.iter().copied())?;
    let request = BatchExecutionRequestV1 {
        batch_number: bundle.batch_number,
        parent_batch_commitment: bundle.parent_batch_commitment,
        transactions: bundle.transactions.clone(),
    };
    let executed = execute_transfer_batch_v1(&pre_state, &bundle.config, &request)?;
    bundle
        .public_inputs
        .ensure_matches_executed_batch(&executed)?;

    if executed.post_state.ordered_accounts() != bundle.post_state_accounts {
        return Err(TraceBuilderErrorV1::StateMismatch {
            field: "post_state",
        });
    }
    if executed.pre_state.ordered_accounts() != bundle.pre_state_accounts {
        return Err(TraceBuilderErrorV1::StateMismatch { field: "pre_state" });
    }
    for (index, (expected, actual)) in executed
        .transaction_bytes
        .iter()
        .zip(bundle.transaction_bytes.iter())
        .enumerate()
    {
        if expected != actual {
            return Err(TraceBuilderErrorV1::TransactionBytesMismatch {
                tx_index: index as u64,
            });
        }
    }
    if executed.transaction_bytes.len() != bundle.transaction_bytes.len() {
        return Err(TraceBuilderErrorV1::StateMismatch {
            field: "transaction_bytes_len",
        });
    }
    for (index, (expected, actual)) in executed
        .outcomes
        .iter()
        .zip(bundle.outcomes.iter())
        .enumerate()
    {
        if expected != actual {
            return Err(TraceBuilderErrorV1::OutcomeMismatch {
                tx_index: index as u64,
            });
        }
    }
    if executed.outcomes.len() != bundle.outcomes.len() {
        return Err(TraceBuilderErrorV1::StateMismatch {
            field: "outcomes_len",
        });
    }
    if executed.outcome_bytes != bundle.outcome_bytes {
        return Err(TraceBuilderErrorV1::StateMismatch {
            field: "outcome_bytes",
        });
    }
    if executed.batch_context != bundle.batch_context
        || executed.context_bytes != bundle.context_bytes
    {
        return Err(TraceBuilderErrorV1::ContextMismatch);
    }
    if executed.fee_summary != bundle.fee_summary
        || executed.fee_summary_bytes != bundle.fee_summary_bytes
    {
        return Err(TraceBuilderErrorV1::FeeSummaryMismatch);
    }
    let expected_rows = trace_rows_from_steps_v1(&executed.applied_steps);
    for (index, (expected, actual)) in expected_rows
        .iter()
        .zip(bundle.trace_rows.iter())
        .enumerate()
    {
        if expected != actual {
            return Err(TraceBuilderErrorV1::TraceRowMismatch {
                tx_index: index as u64,
            });
        }
    }
    if expected_rows.len() != bundle.trace_rows.len() {
        return Err(TraceBuilderErrorV1::StateMismatch {
            field: "trace_rows_len",
        });
    }

    validate_trace_layout_alignment_v1(&bundle.trace_rows, &bundle.stark_trace_layout)?;
    validate_transaction_witness_alignment_v1(
        &bundle.transactions,
        &bundle.trace_rows,
        &bundle.transaction_witness_rows,
    )?;
    validate_air_expectations_v1(bundle)?;

    let expected_trace_digest = derive_trace_digest_v1(&bundle.trace_rows);
    if bundle.trace_digest != expected_trace_digest {
        return Err(TraceBuilderErrorV1::TraceDigestMismatch {
            expected: expected_trace_digest,
            actual: bundle.trace_digest,
        });
    }
    let expected_trace_layout_digest = derive_trace_layout_digest_v1(&bundle.stark_trace_layout);
    if bundle.trace_layout_digest != expected_trace_layout_digest {
        return Err(TraceBuilderErrorV1::TraceLayoutDigestMismatch {
            expected: expected_trace_layout_digest,
            actual: bundle.trace_layout_digest,
        });
    }
    let expected_witness_digest = derive_witness_digest_v1(bundle);
    if bundle.witness_digest != expected_witness_digest {
        return Err(TraceBuilderErrorV1::WitnessDigestMismatch {
            expected: expected_witness_digest,
            actual: bundle.witness_digest,
        });
    }
    Ok(())
}

pub fn validate_air_expectations_v1(
    bundle: &TraceWitnessBundleV1,
) -> Result<(), TraceBuilderErrorV1> {
    if bundle.trace_rows.len() as u64 != bundle.public_inputs.tx_count {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "row_count_equals_public_tx_count",
            tx_index: None,
        });
    }
    if bundle.stark_trace_layout.row_count != bundle.public_inputs.tx_count {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "layout_row_count_equals_public_tx_count",
            tx_index: None,
        });
    }
    if bundle.trace_rows.len() != bundle.transactions.len() {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "row_count_equals_transaction_count",
            tx_index: None,
        });
    }
    if bundle.trace_rows.len() != bundle.transaction_witness_rows.len() {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "row_count_equals_transaction_witness_count",
            tx_index: None,
        });
    }
    if bundle.trace_rows.len() != bundle.outcomes.len() {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "row_count_equals_outcome_count",
            tx_index: None,
        });
    }

    for (index, row) in bundle.trace_rows.iter().enumerate() {
        let tx_index = index as u64;
        let tx = &bundle.transactions[index];
        let tx_witness = &bundle.transaction_witness_rows[index];
        let outcome = &bundle.outcomes[index];

        if row.tx_index != tx_index {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "tx_index_matches_row_position",
                tx_index: Some(tx_index),
            });
        }
        if row.tx_index != outcome.tx_index {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "outcome_tx_index_matches_row",
                tx_index: Some(tx_index),
            });
        }
        if tx_witness.tx_index != tx_index {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_tx_index_matches_row",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_account_id != tx.sender_account_id
            || row.recipient_account_id != tx.recipient_account_id
        {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_accounts_match_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if row.amount != tx.amount {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_amount_matches_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_account_id != limbs_to_account_id_v1(&tx_witness.sender_account_id_limbs)
            || row.recipient_account_id
                != limbs_to_account_id_v1(&tx_witness.recipient_account_id_limbs)
        {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_accounts_match_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if row.amount != tx_witness.amount {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_amount_matches_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_nonce_before != tx.sender_nonce {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_nonce_matches_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_nonce_before != tx_witness.sender_nonce {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_nonce_matches_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_account_id == row.recipient_account_id {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "sender_and_recipient_distinct",
                tx_index: Some(tx_index),
            });
        }
        if row.amount == 0 {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "amount_non_zero",
                tx_index: Some(tx_index),
            });
        }
        if row.fee_charged != ZERO_FEE_PER_TRANSFER_V1
            || outcome.fee_charged != ZERO_FEE_PER_TRANSFER_V1
        {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "fee_charged_zero",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_nonce_after != row.sender_nonce_before + 1 {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "sender_nonce_progression",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_balance_before < row.amount {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "sender_balance_covers_amount",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_balance_after + row.amount != row.sender_balance_before {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "sender_balance_update",
                tx_index: Some(tx_index),
            });
        }
        if row.recipient_balance_before + row.amount != row.recipient_balance_after {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "recipient_balance_update",
                tx_index: Some(tx_index),
            });
        }
        if row.sender_balance_before + row.recipient_balance_before
            != row.sender_balance_after + row.recipient_balance_after
        {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "pairwise_balance_conservation",
                tx_index: Some(tx_index),
            });
        }
        if outcome.sender_account_id != row.sender_account_id {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "outcome_sender_matches_row",
                tx_index: Some(tx_index),
            });
        }
        if outcome.consumed_nonce != row.sender_nonce_before {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "outcome_consumed_nonce_matches_row",
                tx_index: Some(tx_index),
            });
        }
    }

    Ok(())
}

pub fn validate_trace_layout_alignment_v1(
    rows: &[TransferTraceRowV1],
    layout: &LocalStarkTraceLayoutV1,
) -> Result<(), TraceBuilderErrorV1> {
    if layout.layout_version != LOCAL_STARK_TRACE_LAYOUT_VERSION_V1 {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "layout_version",
        });
    }
    if layout.row_count != rows.len() as u64 {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "row_count",
        });
    }
    if layout.column_count() != LOCAL_STARK_TRACE_COLUMN_COUNT_V1 {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "column_count",
        });
    }
    if layout.rows.len() != rows.len() {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "row_vector_length",
        });
    }
    if layout.initialization_row_count() != LOCAL_STARK_TRACE_INITIALIZATION_ROW_COUNT_V1 {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "initialization_row_count",
        });
    }
    if layout.finalization_row_count() != LOCAL_STARK_TRACE_FINALIZATION_ROW_COUNT_V1 {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "finalization_row_count",
        });
    }
    if layout.padding_row_count() != LOCAL_STARK_TRACE_PADDING_ROW_COUNT_V1 {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "padding_row_count",
        });
    }
    if layout.total_row_count() != layout.row_count {
        return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
            row_index: 0,
            field: "total_row_count",
        });
    }

    for (index, (row, layout_row)) in rows.iter().zip(layout.rows.iter()).enumerate() {
        let expected = LocalStarkTraceRowV1::from_transfer_trace_row(row);
        if expected != *layout_row {
            return Err(TraceBuilderErrorV1::TraceLayoutMismatch {
                row_index: index as u64,
                field: "row_values",
            });
        }
    }
    Ok(())
}

pub fn trace_rows_from_steps_v1(steps: &[AppliedTransferStepV1]) -> Vec<TransferTraceRowV1> {
    steps
        .iter()
        .map(|step| TransferTraceRowV1 {
            tx_index: step.tx_index,
            sender_account_id: step.sender_account_id,
            recipient_account_id: step.recipient_account_id,
            amount: step.amount,
            fee_charged: step.fee_charged,
            sender_nonce_before: step.sender_nonce_before,
            sender_nonce_after: step.sender_nonce_after,
            sender_balance_before: step.sender_balance_before,
            sender_balance_after: step.sender_balance_after,
            recipient_balance_before: step.recipient_balance_before,
            recipient_balance_after: step.recipient_balance_after,
        })
        .collect()
}

pub fn transaction_witness_rows_from_transactions_v1(
    transactions: &[TransferTransactionV1],
) -> Vec<LocalStarkTransactionWitnessRowV1> {
    transactions
        .iter()
        .enumerate()
        .map(|(index, tx)| LocalStarkTransactionWitnessRowV1::from_transaction(index as u64, tx))
        .collect()
}

pub fn validate_transaction_witness_alignment_v1(
    transactions: &[TransferTransactionV1],
    rows: &[TransferTraceRowV1],
    witness_rows: &[LocalStarkTransactionWitnessRowV1],
) -> Result<(), TraceBuilderErrorV1> {
    if transactions.len() != witness_rows.len() {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "transaction_count_equals_transaction_witness_count",
            tx_index: None,
        });
    }
    if rows.len() != witness_rows.len() {
        return Err(TraceBuilderErrorV1::AirConstraintViolation {
            constraint: "trace_row_count_equals_transaction_witness_count",
            tx_index: None,
        });
    }

    for (index, ((tx, row), witness_row)) in transactions
        .iter()
        .zip(rows.iter())
        .zip(witness_rows.iter())
        .enumerate()
    {
        let tx_index = index as u64;
        if witness_row.tx_index != tx_index {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_index_matches_transaction_position",
                tx_index: Some(tx_index),
            });
        }
        if witness_row.sender_account_id_limbs != split_u64_limbs_le_v1(&tx.sender_account_id)
            || witness_row.recipient_account_id_limbs
                != split_u64_limbs_le_v1(&tx.recipient_account_id)
        {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_accounts_match_transaction",
                tx_index: Some(tx_index),
            });
        }
        if witness_row.amount != tx.amount {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_amount_matches_transaction",
                tx_index: Some(tx_index),
            });
        }
        if witness_row.sender_nonce != tx.sender_nonce {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_nonce_matches_transaction",
                tx_index: Some(tx_index),
            });
        }
        if witness_row.sender_account_id_limbs != split_u64_limbs_le_v1(&row.sender_account_id)
            || witness_row.recipient_account_id_limbs
                != split_u64_limbs_le_v1(&row.recipient_account_id)
        {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_accounts_match_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if witness_row.amount != row.amount {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_amount_matches_trace_row",
                tx_index: Some(tx_index),
            });
        }
        if witness_row.sender_nonce != row.sender_nonce_before {
            return Err(TraceBuilderErrorV1::AirConstraintViolation {
                constraint: "transaction_witness_nonce_matches_trace_row",
                tx_index: Some(tx_index),
            });
        }
    }

    Ok(())
}

pub fn derive_trace_digest_v1(rows: &[TransferTraceRowV1]) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_L2_LOCAL_TRACE_DIGEST_DOMAIN_SEPARATOR_V1.len() + 8 + rows.len() * 128,
    );
    preimage.extend_from_slice(AURA_L2_LOCAL_TRACE_DIGEST_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        preimage.extend_from_slice(&row.canonical_bytes());
    }
    sha256_bytes(&preimage)
}

pub fn derive_trace_layout_digest_v1(layout: &LocalStarkTraceLayoutV1) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_L2_LOCAL_STARK_TRACE_LAYOUT_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 8
            + 8
            + layout.rows.len()
                * (AURA_L2_LOCAL_STARK_TRACE_LAYOUT_ROW_DOMAIN_SEPARATOR_V1.len() + 8 * 17),
    );
    preimage.extend_from_slice(AURA_L2_LOCAL_STARK_TRACE_LAYOUT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&layout.layout_version.to_le_bytes());
    preimage.extend_from_slice(&layout.row_count.to_le_bytes());
    preimage.extend_from_slice(&LOCAL_STARK_TRACE_COLUMN_COUNT_V1.to_le_bytes());
    for row in &layout.rows {
        preimage.extend_from_slice(&row.canonical_bytes());
    }
    sha256_bytes(&preimage)
}

pub fn derive_witness_digest_v1(bundle: &TraceWitnessBundleV1) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(AURA_L2_LOCAL_WITNESS_DIGEST_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&bundle.public_inputs_bytes);
    preimage.extend_from_slice(&(bundle.pre_state_accounts.len() as u64).to_le_bytes());
    for account in &bundle.pre_state_accounts {
        preimage.extend_from_slice(&account.canonical_bytes());
    }
    preimage.extend_from_slice(&(bundle.post_state_accounts.len() as u64).to_le_bytes());
    for account in &bundle.post_state_accounts {
        preimage.extend_from_slice(&account.canonical_bytes());
    }
    preimage.extend_from_slice(&(bundle.transaction_bytes.len() as u64).to_le_bytes());
    for tx_bytes in &bundle.transaction_bytes {
        preimage.extend_from_slice(&(tx_bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(tx_bytes);
    }
    preimage.extend_from_slice(&(bundle.outcome_bytes.len() as u64).to_le_bytes());
    for outcome_bytes in &bundle.outcome_bytes {
        preimage.extend_from_slice(&(outcome_bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(outcome_bytes);
    }
    preimage.extend_from_slice(&(bundle.context_bytes.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&bundle.context_bytes);
    preimage.extend_from_slice(&(bundle.fee_summary_bytes.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&bundle.fee_summary_bytes);
    preimage.extend_from_slice(&bundle.trace_digest);
    preimage.extend_from_slice(&bundle.trace_layout_digest);
    sha256_bytes(&preimage)
}

pub fn split_u64_limbs_le_v1(bytes: &[u8; HASH_LEN_V1]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        let end = start + 8;
        *limb = u64::from_le_bytes(bytes[start..end].try_into().expect("exact slice"));
    }
    limbs
}

pub fn limbs_to_account_id_v1(limbs: &[u64; 4]) -> [u8; HASH_LEN_V1] {
    let mut bytes = [0u8; HASH_LEN_V1];
    for (index, limb) in limbs.iter().enumerate() {
        let start = index * 8;
        let end = start + 8;
        bytes[start..end].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use aura_l2_execution_v1::{
        execute_transfer_batch_v1, BatchExecutionRequestV1, LocalAccountV1, LocalExecutionConfigV1,
        LocalStateV1, TransferTransactionV1, TRANSFER_TX_VERSION_V1, ZERO32_V1,
    };

    use super::{
        build_trace_witness_bundle_v1, trace_rows_from_steps_v1,
        transaction_witness_rows_from_transactions_v1, validate_air_expectations_v1,
        validate_trace_witness_bundle_v1, LocalStarkTraceColumnV1, LocalStarkTraceLayoutV1,
        LocalStarkTraceRowV1, LocalStarkTransactionWitnessRowV1, LOCAL_STARK_TRACE_COLUMN_COUNT_V1,
        LOCAL_STARK_TRACE_FINALIZATION_ROW_COUNT_V1, LOCAL_STARK_TRACE_INITIALIZATION_ROW_COUNT_V1,
        LOCAL_STARK_TRACE_PADDING_ROW_COUNT_V1,
    };

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn canonical_bundle() -> super::TraceWitnessBundleV1 {
        let state = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(1),
                balance: 100,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(2),
                balance: 5,
                nonce: 0,
            },
        ])
        .unwrap();
        let executed = execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(id(9)),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(1),
                    recipient_account_id: id(2),
                    sender_nonce: 0,
                    amount: 10,
                }],
            },
        )
        .unwrap();
        build_trace_witness_bundle_v1(&executed).unwrap()
    }

    fn two_transfer_bundle() -> super::TraceWitnessBundleV1 {
        let state = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(1),
                balance: 100,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(2),
                balance: 30,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(3),
                balance: 1,
                nonce: 0,
            },
        ])
        .unwrap();
        let executed = execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(id(9)),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![
                    TransferTransactionV1 {
                        tx_version: TRANSFER_TX_VERSION_V1,
                        sender_account_id: id(1),
                        recipient_account_id: id(2),
                        sender_nonce: 0,
                        amount: 10,
                    },
                    TransferTransactionV1 {
                        tx_version: TRANSFER_TX_VERSION_V1,
                        sender_account_id: id(2),
                        recipient_account_id: id(3),
                        sender_nonce: 0,
                        amount: 7,
                    },
                ],
            },
        )
        .unwrap();
        build_trace_witness_bundle_v1(&executed).unwrap()
    }

    #[test]
    fn trace_bundle_is_deterministic_for_same_execution() {
        let first = canonical_bundle();
        let second = canonical_bundle();
        assert_eq!(first.trace_digest, second.trace_digest);
        assert_eq!(first.trace_layout_digest, second.trace_layout_digest);
        assert_eq!(first.witness_digest, second.witness_digest);
    }

    #[test]
    fn trace_bundle_remains_identical_across_twelve_rebuilds() {
        let baseline = canonical_bundle();
        for _ in 0..12 {
            let rebuilt = canonical_bundle();
            assert_eq!(rebuilt.public_inputs_bytes, baseline.public_inputs_bytes);
            assert_eq!(rebuilt.trace_rows, baseline.trace_rows);
            assert_eq!(rebuilt.stark_trace_layout, baseline.stark_trace_layout);
            assert_eq!(
                rebuilt.transaction_witness_rows,
                baseline.transaction_witness_rows
            );
            assert_eq!(rebuilt.trace_digest, baseline.trace_digest);
            assert_eq!(rebuilt.trace_layout_digest, baseline.trace_layout_digest);
            assert_eq!(rebuilt.witness_digest, baseline.witness_digest);
        }
    }

    #[test]
    fn execution_result_equals_trace_derived_result_for_canonical_case() {
        let bundle = two_transfer_bundle();
        let pre_state = LocalStateV1::new(bundle.pre_state_accounts.iter().copied()).unwrap();
        let executed = execute_transfer_batch_v1(
            &pre_state,
            &bundle.config,
            &BatchExecutionRequestV1 {
                batch_number: bundle.batch_number,
                parent_batch_commitment: bundle.parent_batch_commitment,
                transactions: bundle.transactions.clone(),
            },
        )
        .unwrap();

        assert_eq!(
            trace_rows_from_steps_v1(&executed.applied_steps),
            bundle.trace_rows
        );
        assert_eq!(executed.outcomes, bundle.outcomes);
        assert_eq!(executed.outcome_bytes, bundle.outcome_bytes);
        assert_eq!(
            executed.post_state.ordered_accounts(),
            bundle.post_state_accounts
        );
        assert_eq!(
            LocalStarkTraceLayoutV1::from_transfer_rows(&bundle.trace_rows),
            bundle.stark_trace_layout
        );
        assert_eq!(
            transaction_witness_rows_from_transactions_v1(&executed.transactions),
            bundle.transaction_witness_rows
        );
    }

    #[test]
    fn trace_layout_is_stable_for_canonical_case() {
        let bundle = canonical_bundle();
        assert_eq!(bundle.stark_trace_layout.row_count, 1);
        assert_eq!(
            bundle.stark_trace_layout.total_row_count(),
            bundle.stark_trace_layout.row_count
        );
        assert_eq!(
            bundle.stark_trace_layout.column_count(),
            LOCAL_STARK_TRACE_COLUMN_COUNT_V1
        );
        let sender_limb_0 = bundle
            .stark_trace_layout
            .column_values(LocalStarkTraceColumnV1::SenderAccountIdLimb0)[0];
        let recipient_limb_0 = bundle
            .stark_trace_layout
            .column_values(LocalStarkTraceColumnV1::RecipientAccountIdLimb0)[0];
        assert_eq!(sender_limb_0, 0x0101010101010101);
        assert_eq!(recipient_limb_0, 0x0202020202020202);
    }

    #[test]
    fn transaction_witness_alignment_is_stable_for_canonical_case() {
        let bundle = canonical_bundle();

        assert_eq!(bundle.transaction_witness_rows.len(), 1);
        assert_eq!(
            bundle.transaction_witness_rows[0],
            LocalStarkTransactionWitnessRowV1 {
                tx_index: 0,
                sender_account_id_limbs: [0x0101010101010101; 4],
                recipient_account_id_limbs: [0x0202020202020202; 4],
                sender_nonce: 0,
                amount: 10,
            }
        );
    }

    #[test]
    fn trace_layout_has_no_initialization_finalization_or_padding_rows() {
        let bundle = canonical_bundle();
        assert_eq!(
            bundle.stark_trace_layout.initialization_row_count(),
            LOCAL_STARK_TRACE_INITIALIZATION_ROW_COUNT_V1
        );
        assert_eq!(
            bundle.stark_trace_layout.finalization_row_count(),
            LOCAL_STARK_TRACE_FINALIZATION_ROW_COUNT_V1
        );
        assert_eq!(
            bundle.stark_trace_layout.padding_row_count(),
            LOCAL_STARK_TRACE_PADDING_ROW_COUNT_V1
        );
        assert_eq!(
            bundle.stark_trace_layout.total_row_count(),
            bundle.stark_trace_layout.row_count
        );
    }

    #[test]
    fn canonical_row_generation_is_exact_for_two_transfer_batch() {
        let bundle = two_transfer_bundle();
        assert_eq!(bundle.trace_rows.len(), 2);
        assert_eq!(bundle.stark_trace_layout.rows.len(), 2);
        assert_eq!(bundle.transaction_witness_rows.len(), 2);

        assert_eq!(
            bundle.stark_trace_layout.rows[0],
            LocalStarkTraceRowV1 {
                tx_index: 0,
                sender_account_id_limbs: [0x0101010101010101; 4],
                recipient_account_id_limbs: [0x0202020202020202; 4],
                amount: 10,
                fee_charged: 0,
                sender_nonce_before: 0,
                sender_nonce_after: 1,
                sender_balance_before: 100,
                sender_balance_after: 90,
                recipient_balance_before: 30,
                recipient_balance_after: 40,
            }
        );
        assert_eq!(
            bundle.stark_trace_layout.rows[1],
            LocalStarkTraceRowV1 {
                tx_index: 1,
                sender_account_id_limbs: [0x0202020202020202; 4],
                recipient_account_id_limbs: [0x0303030303030303; 4],
                amount: 7,
                fee_charged: 0,
                sender_nonce_before: 0,
                sender_nonce_after: 1,
                sender_balance_before: 40,
                sender_balance_after: 33,
                recipient_balance_before: 1,
                recipient_balance_after: 8,
            }
        );
        assert_eq!(
            bundle.transaction_witness_rows[0],
            LocalStarkTransactionWitnessRowV1 {
                tx_index: 0,
                sender_account_id_limbs: [0x0101010101010101; 4],
                recipient_account_id_limbs: [0x0202020202020202; 4],
                sender_nonce: 0,
                amount: 10,
            }
        );
        assert_eq!(
            bundle.transaction_witness_rows[1],
            LocalStarkTransactionWitnessRowV1 {
                tx_index: 1,
                sender_account_id_limbs: [0x0202020202020202; 4],
                recipient_account_id_limbs: [0x0303030303030303; 4],
                sender_nonce: 0,
                amount: 7,
            }
        );
    }

    #[test]
    fn tampered_trace_row_rejects() {
        let mut bundle = canonical_bundle();
        bundle.trace_rows[0].sender_balance_after += 1;
        assert!(validate_trace_witness_bundle_v1(&bundle).is_err());
    }

    #[test]
    fn malformed_public_input_bytes_reject_bundle_validation() {
        let mut bundle = canonical_bundle();
        bundle.public_inputs_bytes[0] ^= 0x01;
        assert!(validate_trace_witness_bundle_v1(&bundle).is_err());
    }

    #[test]
    fn air_expectations_reject_tampered_nonce_progression() {
        let mut bundle = canonical_bundle();
        bundle.trace_rows[0].sender_nonce_after += 1;
        bundle.stark_trace_layout.rows[0].sender_nonce_after += 1;
        assert!(validate_air_expectations_v1(&bundle).is_err());
    }

    #[test]
    fn air_expectations_reject_sender_recipient_equality() {
        let mut bundle = canonical_bundle();
        bundle.trace_rows[0].recipient_account_id = bundle.trace_rows[0].sender_account_id;
        bundle.stark_trace_layout.rows[0].recipient_account_id_limbs =
            bundle.stark_trace_layout.rows[0].sender_account_id_limbs;
        assert!(validate_air_expectations_v1(&bundle).is_err());
    }

    #[test]
    fn air_expectations_reject_tampered_transaction_witness_row() {
        let mut bundle = canonical_bundle();
        bundle.transaction_witness_rows[0].amount += 1;
        assert!(validate_air_expectations_v1(&bundle).is_err());
        assert!(validate_trace_witness_bundle_v1(&bundle).is_err());
    }
}
