use core::fmt;
use std::convert::TryInto;

use aura_l2_execution_v1::{
    execute_transfer_batch_v1, BatchExecutionRequestV1, ExecutedBatchV1, LocalAccountV1,
    LocalExecutionConfigV1, LocalExecutionErrorV1, LocalStateV1, TransferTransactionV1,
    HASH_LEN_V1,
};
use aura_l2_trace_builder_v1::{
    build_trace_witness_bundle_v1, LocalStarkTraceRowV1, LocalStarkTransactionWitnessRowV1,
    TraceBuilderErrorV1, TraceWitnessBundleV1,
};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions,
    Prover, ProverError, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree, VerifierError,
};

use crate::{prepare_proof_inputs_v1, PreparedProofInputsV1};

pub const LOCAL_STARK_BACKEND_WINTERFELL_V1: u32 = 1;
pub const LOCAL_STARK_BACKEND_PROOF_ENVELOPE_VERSION_V1: u32 = 1;
pub const AURA_L2_LOCAL_WINTERFELL_STARK_PROOF_ENVELOPE_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_L2_LOCAL_WINTERFELL_STARK_PROOF_ENVELOPE_V1";

const WINTERFELL_TRACE_WIDTH_V1: usize = 38;
const WINTERFELL_MIN_TRACE_LENGTH_V1: usize = 8;

const COL_TX_INDEX: usize = 0;
const COL_SENDER_LIMB_0: usize = 1;
const COL_SENDER_LIMB_1: usize = 2;
const COL_SENDER_LIMB_2: usize = 3;
const COL_SENDER_LIMB_3: usize = 4;
const COL_RECIPIENT_LIMB_0: usize = 5;
const COL_RECIPIENT_LIMB_1: usize = 6;
const COL_RECIPIENT_LIMB_2: usize = 7;
const COL_RECIPIENT_LIMB_3: usize = 8;
const COL_AMOUNT: usize = 9;
const COL_FEE: usize = 10;
const COL_SENDER_NONCE_BEFORE: usize = 11;
const COL_SENDER_NONCE_AFTER: usize = 12;
const COL_SENDER_BALANCE_BEFORE: usize = 13;
const COL_SENDER_BALANCE_AFTER: usize = 14;
const COL_RECIPIENT_BALANCE_BEFORE: usize = 15;
const COL_RECIPIENT_BALANCE_AFTER: usize = 16;
const COL_ACTIVE: usize = 17;
const COL_AMOUNT_INVERSE: usize = 18;
const COL_DISTINCT_SELECTOR_0: usize = 19;
const COL_DISTINCT_SELECTOR_1: usize = 20;
const COL_DISTINCT_SELECTOR_2: usize = 21;
const COL_DISTINCT_SELECTOR_3: usize = 22;
const COL_DISTINCT_INVERSE_0: usize = 23;
const COL_DISTINCT_INVERSE_1: usize = 24;
const COL_DISTINCT_INVERSE_2: usize = 25;
const COL_DISTINCT_INVERSE_3: usize = 26;
const COL_TX_WITNESS_INDEX: usize = 27;
const COL_TX_WITNESS_SENDER_LIMB_0: usize = 28;
const COL_TX_WITNESS_SENDER_LIMB_1: usize = 29;
const COL_TX_WITNESS_SENDER_LIMB_2: usize = 30;
const COL_TX_WITNESS_SENDER_LIMB_3: usize = 31;
const COL_TX_WITNESS_RECIPIENT_LIMB_0: usize = 32;
const COL_TX_WITNESS_RECIPIENT_LIMB_1: usize = 33;
const COL_TX_WITNESS_RECIPIENT_LIMB_2: usize = 34;
const COL_TX_WITNESS_RECIPIENT_LIMB_3: usize = 35;
const COL_TX_WITNESS_AMOUNT: usize = 36;
const COL_TX_WITNESS_SENDER_NONCE: usize = 37;

const FREEZE_COLUMN_INDICES_V1: [usize; 17] = [
    COL_TX_INDEX,
    COL_SENDER_LIMB_0,
    COL_SENDER_LIMB_1,
    COL_SENDER_LIMB_2,
    COL_SENDER_LIMB_3,
    COL_RECIPIENT_LIMB_0,
    COL_RECIPIENT_LIMB_1,
    COL_RECIPIENT_LIMB_2,
    COL_RECIPIENT_LIMB_3,
    COL_AMOUNT,
    COL_FEE,
    COL_SENDER_NONCE_BEFORE,
    COL_SENDER_NONCE_AFTER,
    COL_SENDER_BALANCE_BEFORE,
    COL_SENDER_BALANCE_AFTER,
    COL_RECIPIENT_BALANCE_BEFORE,
    COL_RECIPIENT_BALANCE_AFTER,
];

const DISTINCT_SELECTOR_COLUMN_INDICES_V1: [usize; 4] = [
    COL_DISTINCT_SELECTOR_0,
    COL_DISTINCT_SELECTOR_1,
    COL_DISTINCT_SELECTOR_2,
    COL_DISTINCT_SELECTOR_3,
];

const DISTINCT_INVERSE_COLUMN_INDICES_V1: [usize; 4] = [
    COL_DISTINCT_INVERSE_0,
    COL_DISTINCT_INVERSE_1,
    COL_DISTINCT_INVERSE_2,
    COL_DISTINCT_INVERSE_3,
];

const SENDER_LIMB_COLUMN_INDICES_V1: [usize; 4] = [
    COL_SENDER_LIMB_0,
    COL_SENDER_LIMB_1,
    COL_SENDER_LIMB_2,
    COL_SENDER_LIMB_3,
];

const RECIPIENT_LIMB_COLUMN_INDICES_V1: [usize; 4] = [
    COL_RECIPIENT_LIMB_0,
    COL_RECIPIENT_LIMB_1,
    COL_RECIPIENT_LIMB_2,
    COL_RECIPIENT_LIMB_3,
];

const TX_WITNESS_SENDER_LIMB_COLUMN_INDICES_V1: [usize; 4] = [
    COL_TX_WITNESS_SENDER_LIMB_0,
    COL_TX_WITNESS_SENDER_LIMB_1,
    COL_TX_WITNESS_SENDER_LIMB_2,
    COL_TX_WITNESS_SENDER_LIMB_3,
];

const TX_WITNESS_RECIPIENT_LIMB_COLUMN_INDICES_V1: [usize; 4] = [
    COL_TX_WITNESS_RECIPIENT_LIMB_0,
    COL_TX_WITNESS_RECIPIENT_LIMB_1,
    COL_TX_WITNESS_RECIPIENT_LIMB_2,
    COL_TX_WITNESS_RECIPIENT_LIMB_3,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinterfellStarkPublicInputsV1 {
    pub tx_count: u64,
    pub public_inputs_hash: [u8; HASH_LEN_V1],
    pub trace_digest: [u8; HASH_LEN_V1],
    pub trace_layout_digest: [u8; HASH_LEN_V1],
}

impl ToElements<BaseElement> for WinterfellStarkPublicInputsV1 {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(1 + HASH_LEN_V1 * 3);
        elements.push(BaseElement::new(self.tx_count as u128));
        for byte in self.public_inputs_hash {
            elements.push(BaseElement::new(byte as u128));
        }
        for byte in self.trace_digest {
            elements.push(BaseElement::new(byte as u128));
        }
        for byte in self.trace_layout_digest {
            elements.push(BaseElement::new(byte as u128));
        }
        elements
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinterfellStarkProofEnvelopeV1 {
    pub envelope_version: u32,
    pub backend_kind: u32,
    pub rollup_id: [u8; HASH_LEN_V1],
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; HASH_LEN_V1],
    pub pre_state_accounts: Vec<LocalAccountV1>,
    pub transactions: Vec<TransferTransactionV1>,
    pub winterfell_proof_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum StarkBackendErrorV1 {
    TraceBuilder(TraceBuilderErrorV1),
    Execution(LocalExecutionErrorV1),
    UnsupportedTraceLength { tx_count: u64 },
    InvalidInternalTraceWitness { field: &'static str },
    ProofEnvelopeDecode { field: &'static str },
    ProofEnvelopeVersionMismatch { expected: u32, actual: u32 },
    ProofEnvelopeBackendMismatch { expected: u32, actual: u32 },
    PublicInputBytesMismatch,
    PreparedInputMismatch { field: &'static str },
    WinterfellProver(ProverError),
    WinterfellProofDecode(String),
    WinterfellVerifier(String),
}

impl fmt::Display for StarkBackendErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceBuilder(error) => write!(f, "trace builder error: {error}"),
            Self::Execution(error) => write!(f, "execution reconstruction error: {error}"),
            Self::UnsupportedTraceLength { tx_count } => {
                write!(
                    f,
                    "unsupported trace length derived from tx_count {tx_count}"
                )
            }
            Self::InvalidInternalTraceWitness { field } => {
                write!(f, "invalid internal trace witness: {field}")
            }
            Self::ProofEnvelopeDecode { field } => {
                write!(f, "stark proof envelope decode error: {field}")
            }
            Self::ProofEnvelopeVersionMismatch { expected, actual } => write!(
                f,
                "stark proof envelope version mismatch: expected {expected}, got {actual}"
            ),
            Self::ProofEnvelopeBackendMismatch { expected, actual } => write!(
                f,
                "stark proof envelope backend mismatch: expected {expected}, got {actual}"
            ),
            Self::PublicInputBytesMismatch => write!(f, "public input bytes mismatch"),
            Self::PreparedInputMismatch { field } => {
                write!(f, "prepared input mismatch: {field}")
            }
            Self::WinterfellProver(error) => write!(f, "winterfell prover error: {error}"),
            Self::WinterfellProofDecode(error) => {
                write!(f, "winterfell proof decode error: {error}")
            }
            Self::WinterfellVerifier(error) => {
                write!(f, "winterfell verifier error: {error}")
            }
        }
    }
}

impl std::error::Error for StarkBackendErrorV1 {}

impl From<TraceBuilderErrorV1> for StarkBackendErrorV1 {
    fn from(value: TraceBuilderErrorV1) -> Self {
        Self::TraceBuilder(value)
    }
}

impl From<LocalExecutionErrorV1> for StarkBackendErrorV1 {
    fn from(value: LocalExecutionErrorV1) -> Self {
        Self::Execution(value)
    }
}

pub fn derive_winterfell_public_inputs_v1(
    prepared: &PreparedProofInputsV1,
) -> WinterfellStarkPublicInputsV1 {
    WinterfellStarkPublicInputsV1 {
        tx_count: prepared.witness_bundle.public_inputs.tx_count,
        public_inputs_hash: prepared.public_inputs_hash,
        trace_digest: prepared.trace_digest,
        trace_layout_digest: prepared.trace_layout_digest,
    }
}

pub fn prove_with_winterfell_backend_v1(
    prepared: &PreparedProofInputsV1,
) -> Result<Vec<u8>, StarkBackendErrorV1> {
    let trace = build_winterfell_trace_v1(&prepared.witness_bundle)?;
    let pub_inputs = derive_winterfell_public_inputs_v1(prepared);
    let prover = WinterfellLocalProverV1::new(default_winterfell_proof_options_v1(), pub_inputs);
    let proof = prover
        .prove(trace)
        .map_err(StarkBackendErrorV1::WinterfellProver)?;

    let envelope = WinterfellStarkProofEnvelopeV1 {
        envelope_version: LOCAL_STARK_BACKEND_PROOF_ENVELOPE_VERSION_V1,
        backend_kind: LOCAL_STARK_BACKEND_WINTERFELL_V1,
        rollup_id: prepared.witness_bundle.config.rollup_id,
        batch_number: prepared.witness_bundle.batch_number,
        parent_batch_commitment: prepared.witness_bundle.parent_batch_commitment,
        pre_state_accounts: prepared.witness_bundle.pre_state_accounts.clone(),
        transactions: prepared.witness_bundle.transactions.clone(),
        winterfell_proof_bytes: proof.to_bytes(),
    };

    Ok(encode_winterfell_stark_proof_envelope_v1(&envelope))
}

pub fn verify_with_winterfell_backend_v1(
    public_inputs_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<PreparedProofInputsV1, StarkBackendErrorV1> {
    let envelope = decode_winterfell_stark_proof_envelope_v1(proof_bytes)?;
    let executed = reconstruct_executed_batch_from_winterfell_envelope_v1(&envelope)?;
    let bundle = build_trace_witness_bundle_v1(&executed)?;
    if bundle.public_inputs_bytes.as_slice() != public_inputs_bytes {
        return Err(StarkBackendErrorV1::PublicInputBytesMismatch);
    }

    let prepared = prepare_proof_inputs_v1(&bundle).map_err(|error| match error {
        crate::LocalProverErrorV1::TraceBuilder(trace_error) => {
            StarkBackendErrorV1::TraceBuilder(trace_error)
        }
        crate::LocalProverErrorV1::StarkBackend(error) => error,
    })?;

    let winterfell_pub_inputs = derive_winterfell_public_inputs_v1(&prepared);
    let winterfell_proof = Proof::from_bytes(&envelope.winterfell_proof_bytes)
        .map_err(|error| StarkBackendErrorV1::WinterfellProofDecode(error.to_string()))?;
    let acceptable = AcceptableOptions::MinConjecturedSecurity(95);

    verify::<
        WinterfellLocalAirV1,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(winterfell_proof, winterfell_pub_inputs, &acceptable)
    .map_err(|error: VerifierError| StarkBackendErrorV1::WinterfellVerifier(error.to_string()))?;

    Ok(prepared)
}

pub fn encode_winterfell_stark_proof_envelope_v1(
    envelope: &WinterfellStarkProofEnvelopeV1,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(AURA_L2_LOCAL_WINTERFELL_STARK_PROOF_ENVELOPE_V1_DOMAIN_SEPARATOR);
    bytes.extend_from_slice(&envelope.envelope_version.to_le_bytes());
    bytes.extend_from_slice(&envelope.backend_kind.to_le_bytes());
    bytes.extend_from_slice(&envelope.rollup_id);
    bytes.extend_from_slice(&envelope.batch_number.to_le_bytes());
    bytes.extend_from_slice(&envelope.parent_batch_commitment);
    bytes.extend_from_slice(&(envelope.pre_state_accounts.len() as u64).to_le_bytes());
    for account in &envelope.pre_state_accounts {
        bytes.extend_from_slice(&account.canonical_bytes());
    }
    bytes.extend_from_slice(&(envelope.transactions.len() as u64).to_le_bytes());
    for tx in &envelope.transactions {
        bytes.extend_from_slice(&encode_transfer_for_winterfell_envelope_v1(tx));
    }
    bytes.extend_from_slice(&(envelope.winterfell_proof_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&envelope.winterfell_proof_bytes);
    bytes
}

pub fn decode_winterfell_stark_proof_envelope_v1(
    bytes: &[u8],
) -> Result<WinterfellStarkProofEnvelopeV1, StarkBackendErrorV1> {
    let mut reader = StarkEnvelopeReaderV1::new(bytes);
    reader.expect_bytes(
        AURA_L2_LOCAL_WINTERFELL_STARK_PROOF_ENVELOPE_V1_DOMAIN_SEPARATOR,
        "domain_separator",
    )?;

    let envelope_version = reader.read_u32("envelope_version")?;
    if envelope_version != LOCAL_STARK_BACKEND_PROOF_ENVELOPE_VERSION_V1 {
        return Err(StarkBackendErrorV1::ProofEnvelopeVersionMismatch {
            expected: LOCAL_STARK_BACKEND_PROOF_ENVELOPE_VERSION_V1,
            actual: envelope_version,
        });
    }

    let backend_kind = reader.read_u32("backend_kind")?;
    if backend_kind != LOCAL_STARK_BACKEND_WINTERFELL_V1 {
        return Err(StarkBackendErrorV1::ProofEnvelopeBackendMismatch {
            expected: LOCAL_STARK_BACKEND_WINTERFELL_V1,
            actual: backend_kind,
        });
    }

    let rollup_id = reader.read_hash("rollup_id")?;
    let batch_number = reader.read_u64("batch_number")?;
    let parent_batch_commitment = reader.read_hash("parent_batch_commitment")?;

    let pre_state_count = reader.read_u64("pre_state_count")? as usize;
    let mut pre_state_accounts = Vec::with_capacity(pre_state_count);
    for _ in 0..pre_state_count {
        let account_bytes = reader.read_exact(48, "pre_state_account")?;
        pre_state_accounts.push(decode_account_from_bytes_v1(account_bytes)?);
    }

    let tx_count = reader.read_u64("tx_count")? as usize;
    let mut transactions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let tx_bytes = reader.read_exact(84, "transaction")?;
        transactions.push(decode_transfer_from_bytes_v1(tx_bytes)?);
    }

    let proof_len = reader.read_u64("winterfell_proof_len")? as usize;
    let winterfell_proof_bytes = reader
        .read_exact(proof_len, "winterfell_proof_bytes")?
        .to_vec();

    if !reader.is_empty() {
        return Err(StarkBackendErrorV1::ProofEnvelopeDecode {
            field: "trailing_bytes",
        });
    }

    Ok(WinterfellStarkProofEnvelopeV1 {
        envelope_version,
        backend_kind,
        rollup_id,
        batch_number,
        parent_batch_commitment,
        pre_state_accounts,
        transactions,
        winterfell_proof_bytes,
    })
}

pub fn reconstruct_executed_batch_from_winterfell_envelope_v1(
    envelope: &WinterfellStarkProofEnvelopeV1,
) -> Result<ExecutedBatchV1, StarkBackendErrorV1> {
    let pre_state = LocalStateV1::new(envelope.pre_state_accounts.clone())?;
    let config = LocalExecutionConfigV1::new(envelope.rollup_id);
    let request = BatchExecutionRequestV1 {
        batch_number: envelope.batch_number,
        parent_batch_commitment: envelope.parent_batch_commitment,
        transactions: envelope.transactions.clone(),
    };
    Ok(execute_transfer_batch_v1(&pre_state, &config, &request)?)
}

fn default_winterfell_proof_options_v1() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn derive_internal_trace_length_v1(tx_count: u64) -> Result<usize, StarkBackendErrorV1> {
    let active_rows: usize = tx_count
        .try_into()
        .map_err(|_| StarkBackendErrorV1::UnsupportedTraceLength { tx_count })?;
    Ok(active_rows
        .max(1)
        .next_power_of_two()
        .max(WINTERFELL_MIN_TRACE_LENGTH_V1))
}

fn build_winterfell_trace_v1(
    bundle: &TraceWitnessBundleV1,
) -> Result<TraceTable<BaseElement>, StarkBackendErrorV1> {
    let active_row_count = bundle.stark_trace_layout.rows.len();
    let trace_length = derive_internal_trace_length_v1(bundle.public_inputs.tx_count)?;
    let mut trace = TraceTable::new(WINTERFELL_TRACE_WIDTH_V1, trace_length);

    if active_row_count == 0 {
        for row_index in 0..trace_length {
            set_zero_row_v1(&mut trace, row_index);
        }
        return Ok(trace);
    }

    for (row_index, (row, tx_witness_row)) in bundle
        .stark_trace_layout
        .rows
        .iter()
        .zip(bundle.transaction_witness_rows.iter())
        .enumerate()
    {
        set_active_row_v1(&mut trace, row_index, row, tx_witness_row)?;
    }

    let last_active = bundle
        .stark_trace_layout
        .rows
        .last()
        .expect("active_row_count > 0");
    let last_tx_witness = bundle
        .transaction_witness_rows
        .last()
        .expect("active_row_count > 0");
    for row_index in active_row_count..trace_length {
        set_padding_row_v1(&mut trace, row_index, last_active, last_tx_witness)?;
    }

    Ok(trace)
}

fn set_zero_row_v1(trace: &mut TraceTable<BaseElement>, row_index: usize) {
    for column in 0..WINTERFELL_TRACE_WIDTH_V1 {
        trace.set(column, row_index, BaseElement::ZERO);
    }
}

fn set_active_row_v1(
    trace: &mut TraceTable<BaseElement>,
    row_index: usize,
    row: &LocalStarkTraceRowV1,
    tx_witness_row: &LocalStarkTransactionWitnessRowV1,
) -> Result<(), StarkBackendErrorV1> {
    let values = internal_row_values_from_stark_layout_row_v1(row, tx_witness_row, true)?;
    for (column, value) in values.into_iter().enumerate() {
        trace.set(column, row_index, value);
    }
    Ok(())
}

fn set_padding_row_v1(
    trace: &mut TraceTable<BaseElement>,
    row_index: usize,
    last_active: &LocalStarkTraceRowV1,
    last_tx_witness: &LocalStarkTransactionWitnessRowV1,
) -> Result<(), StarkBackendErrorV1> {
    let values = internal_row_values_from_stark_layout_row_v1(last_active, last_tx_witness, false)?;
    for (column, value) in values.into_iter().enumerate() {
        trace.set(column, row_index, value);
    }
    Ok(())
}

fn internal_row_values_from_stark_layout_row_v1(
    row: &LocalStarkTraceRowV1,
    tx_witness_row: &LocalStarkTransactionWitnessRowV1,
    active: bool,
) -> Result<[BaseElement; WINTERFELL_TRACE_WIDTH_V1], StarkBackendErrorV1> {
    let mut values = [BaseElement::ZERO; WINTERFELL_TRACE_WIDTH_V1];
    values[COL_TX_INDEX] = base_from_u64_v1(row.tx_index);
    values[COL_SENDER_LIMB_0] = base_from_u64_v1(row.sender_account_id_limbs[0]);
    values[COL_SENDER_LIMB_1] = base_from_u64_v1(row.sender_account_id_limbs[1]);
    values[COL_SENDER_LIMB_2] = base_from_u64_v1(row.sender_account_id_limbs[2]);
    values[COL_SENDER_LIMB_3] = base_from_u64_v1(row.sender_account_id_limbs[3]);
    values[COL_RECIPIENT_LIMB_0] = base_from_u64_v1(row.recipient_account_id_limbs[0]);
    values[COL_RECIPIENT_LIMB_1] = base_from_u64_v1(row.recipient_account_id_limbs[1]);
    values[COL_RECIPIENT_LIMB_2] = base_from_u64_v1(row.recipient_account_id_limbs[2]);
    values[COL_RECIPIENT_LIMB_3] = base_from_u64_v1(row.recipient_account_id_limbs[3]);
    values[COL_AMOUNT] = base_from_u64_v1(row.amount);
    values[COL_FEE] = base_from_u64_v1(row.fee_charged);
    values[COL_SENDER_NONCE_BEFORE] = base_from_u64_v1(row.sender_nonce_before);
    values[COL_SENDER_NONCE_AFTER] = base_from_u64_v1(row.sender_nonce_after);
    values[COL_SENDER_BALANCE_BEFORE] = base_from_u64_v1(row.sender_balance_before);
    values[COL_SENDER_BALANCE_AFTER] = base_from_u64_v1(row.sender_balance_after);
    values[COL_RECIPIENT_BALANCE_BEFORE] = base_from_u64_v1(row.recipient_balance_before);
    values[COL_RECIPIENT_BALANCE_AFTER] = base_from_u64_v1(row.recipient_balance_after);
    values[COL_ACTIVE] = if active {
        BaseElement::ONE
    } else {
        BaseElement::ZERO
    };
    values[COL_TX_WITNESS_INDEX] = base_from_u64_v1(tx_witness_row.tx_index);
    for (column, limb) in TX_WITNESS_SENDER_LIMB_COLUMN_INDICES_V1
        .into_iter()
        .zip(tx_witness_row.sender_account_id_limbs)
    {
        values[column] = base_from_u64_v1(limb);
    }
    for (column, limb) in TX_WITNESS_RECIPIENT_LIMB_COLUMN_INDICES_V1
        .into_iter()
        .zip(tx_witness_row.recipient_account_id_limbs)
    {
        values[column] = base_from_u64_v1(limb);
    }
    values[COL_TX_WITNESS_AMOUNT] = base_from_u64_v1(tx_witness_row.amount);
    values[COL_TX_WITNESS_SENDER_NONCE] = base_from_u64_v1(tx_witness_row.sender_nonce);
    if active {
        values[COL_AMOUNT_INVERSE] = if row.amount != 0 {
            base_from_u64_v1(row.amount).inv()
        } else {
            BaseElement::ZERO
        };

        let (selectors, inverses) = derive_distinct_account_witness_v1(
            &row.sender_account_id_limbs,
            &row.recipient_account_id_limbs,
        )?;
        for (column, value) in DISTINCT_SELECTOR_COLUMN_INDICES_V1
            .into_iter()
            .zip(selectors)
        {
            values[column] = value;
        }
        for (column, value) in DISTINCT_INVERSE_COLUMN_INDICES_V1.into_iter().zip(inverses) {
            values[column] = value;
        }
    } else {
        values[COL_AMOUNT_INVERSE] = BaseElement::ZERO;
        for column in DISTINCT_SELECTOR_COLUMN_INDICES_V1 {
            values[column] = BaseElement::ZERO;
        }
        for column in DISTINCT_INVERSE_COLUMN_INDICES_V1 {
            values[column] = BaseElement::ZERO;
        }
    }

    Ok(values)
}

fn base_from_u64_v1(value: u64) -> BaseElement {
    BaseElement::new(value as u128)
}

fn derive_distinct_account_witness_v1(
    sender_limbs: &[u64; 4],
    recipient_limbs: &[u64; 4],
) -> Result<([BaseElement; 4], [BaseElement; 4]), StarkBackendErrorV1> {
    let mut selectors = [BaseElement::ZERO; 4];
    let mut inverses = [BaseElement::ZERO; 4];

    for index in 0..4 {
        let sender = base_from_u64_v1(sender_limbs[index]);
        let recipient = base_from_u64_v1(recipient_limbs[index]);
        let delta = sender - recipient;
        if delta != BaseElement::ZERO {
            selectors[index] = BaseElement::ONE;
            inverses[index] = delta.inv();
            return Ok((selectors, inverses));
        }
    }

    Err(StarkBackendErrorV1::InvalidInternalTraceWitness {
        field: "sender_recipient_distinctness",
    })
}

fn encode_transfer_for_winterfell_envelope_v1(tx: &TransferTransactionV1) -> [u8; 84] {
    let mut bytes = [0u8; 84];
    bytes[0..4].copy_from_slice(&tx.tx_version.to_le_bytes());
    bytes[4..36].copy_from_slice(&tx.sender_account_id);
    bytes[36..68].copy_from_slice(&tx.recipient_account_id);
    bytes[68..76].copy_from_slice(&tx.sender_nonce.to_le_bytes());
    bytes[76..84].copy_from_slice(&tx.amount.to_le_bytes());
    bytes
}

fn decode_account_from_bytes_v1(bytes: &[u8]) -> Result<LocalAccountV1, StarkBackendErrorV1> {
    if bytes.len() != 48 {
        return Err(StarkBackendErrorV1::ProofEnvelopeDecode {
            field: "account_length",
        });
    }
    let mut account_id = [0u8; HASH_LEN_V1];
    account_id.copy_from_slice(&bytes[0..32]);
    let balance = u64::from_le_bytes(bytes[32..40].try_into().expect("exact slice"));
    let nonce = u64::from_le_bytes(bytes[40..48].try_into().expect("exact slice"));
    Ok(LocalAccountV1 {
        account_id,
        balance,
        nonce,
    })
}

fn decode_transfer_from_bytes_v1(
    bytes: &[u8],
) -> Result<TransferTransactionV1, StarkBackendErrorV1> {
    if bytes.len() != 84 {
        return Err(StarkBackendErrorV1::ProofEnvelopeDecode {
            field: "transaction_length",
        });
    }
    let tx_version = u32::from_le_bytes(bytes[0..4].try_into().expect("exact slice"));
    let mut sender_account_id = [0u8; HASH_LEN_V1];
    sender_account_id.copy_from_slice(&bytes[4..36]);
    let mut recipient_account_id = [0u8; HASH_LEN_V1];
    recipient_account_id.copy_from_slice(&bytes[36..68]);
    let sender_nonce = u64::from_le_bytes(bytes[68..76].try_into().expect("exact slice"));
    let amount = u64::from_le_bytes(bytes[76..84].try_into().expect("exact slice"));
    Ok(TransferTransactionV1 {
        tx_version,
        sender_account_id,
        recipient_account_id,
        sender_nonce,
        amount,
    })
}

struct StarkEnvelopeReaderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StarkEnvelopeReaderV1<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_bytes(
        &mut self,
        expected: &[u8],
        field: &'static str,
    ) -> Result<(), StarkBackendErrorV1> {
        let actual = self.read_exact(expected.len(), field)?;
        if actual != expected {
            return Err(StarkBackendErrorV1::ProofEnvelopeDecode { field });
        }
        Ok(())
    }

    fn read_exact(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<&'a [u8], StarkBackendErrorV1> {
        let end = self.offset.saturating_add(len);
        if end > self.bytes.len() {
            return Err(StarkBackendErrorV1::ProofEnvelopeDecode { field });
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, StarkBackendErrorV1> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("exact slice")))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, StarkBackendErrorV1> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("exact slice")))
    }

    fn read_hash(&mut self, field: &'static str) -> Result<[u8; HASH_LEN_V1], StarkBackendErrorV1> {
        let bytes = self.read_exact(HASH_LEN_V1, field)?;
        let mut out = [0u8; HASH_LEN_V1];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone)]
struct WinterfellLocalAirV1 {
    context: AirContext<BaseElement>,
    has_transactions: BaseElement,
    tx_count: u64,
    trace_length: usize,
}

impl Air for WinterfellLocalAirV1 {
    type BaseField = BaseElement;
    type PublicInputs = WinterfellStarkPublicInputsV1;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), WINTERFELL_TRACE_WIDTH_V1);
        let trace_length = trace_info.length();
        let expected_trace_length =
            derive_internal_trace_length_v1(pub_inputs.tx_count).expect("supported trace length");
        assert_eq!(trace_length, expected_trace_length);

        let mut degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(3),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(3),
            TransitionConstraintDegree::new(3),
            TransitionConstraintDegree::new(3),
            TransitionConstraintDegree::new(3),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        degrees.extend(
            FREEZE_COLUMN_INDICES_V1
                .iter()
                .map(|_| TransitionConstraintDegree::new(2)),
        );

        let num_assertions = if pub_inputs.tx_count == 0 {
            2
        } else {
            let mut count = 2usize;
            if pub_inputs.tx_count > 1 {
                count += 2;
            }
            if (pub_inputs.tx_count as usize) < trace_length {
                count += 1;
            }
            count
        };

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            has_transactions: if pub_inputs.tx_count == 0 {
                BaseElement::ZERO
            } else {
                BaseElement::ONE
            },
            tx_count: pub_inputs.tx_count,
            trace_length,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let active = current[COL_ACTIVE];
        let next_active = next[COL_ACTIVE];
        let one = E::ONE;
        let has_transactions = E::from(self.has_transactions);

        result[0] = active * (active - one);
        result[1] = next_active * (next_active - one);
        result[2] = next_active * (one - active);
        result[3] = current[COL_FEE];
        result[4] =
            current[COL_SENDER_NONCE_AFTER] - current[COL_SENDER_NONCE_BEFORE] - has_transactions;
        result[5] = current[COL_SENDER_BALANCE_AFTER] + current[COL_AMOUNT]
            - current[COL_SENDER_BALANCE_BEFORE];
        result[6] = current[COL_RECIPIENT_BALANCE_BEFORE] + current[COL_AMOUNT]
            - current[COL_RECIPIENT_BALANCE_AFTER];
        result[7] = (current[COL_SENDER_BALANCE_BEFORE] + current[COL_RECIPIENT_BALANCE_BEFORE])
            - (current[COL_SENDER_BALANCE_AFTER] + current[COL_RECIPIENT_BALANCE_AFTER]);
        result[8] = active * (current[COL_AMOUNT] * current[COL_AMOUNT_INVERSE] - one);
        result[9] = next[COL_TX_INDEX] - current[COL_TX_INDEX] - next_active;

        let distinct_selector_sum = current[COL_DISTINCT_SELECTOR_0]
            + current[COL_DISTINCT_SELECTOR_1]
            + current[COL_DISTINCT_SELECTOR_2]
            + current[COL_DISTINCT_SELECTOR_3];
        result[10] = active * (distinct_selector_sum - one);

        for (offset, ((selector_column, inverse_column), (sender_column, recipient_column))) in
            DISTINCT_SELECTOR_COLUMN_INDICES_V1
                .iter()
                .zip(DISTINCT_INVERSE_COLUMN_INDICES_V1.iter())
                .zip(
                    SENDER_LIMB_COLUMN_INDICES_V1
                        .iter()
                        .zip(RECIPIENT_LIMB_COLUMN_INDICES_V1.iter()),
                )
                .enumerate()
        {
            let limb_delta = current[*sender_column] - current[*recipient_column];
            result[11 + offset] =
                active * (limb_delta * current[*inverse_column] - current[*selector_column]);
        }

        result[15] = current[COL_TX_INDEX] - current[COL_TX_WITNESS_INDEX];
        for (offset, (row_column, witness_column)) in SENDER_LIMB_COLUMN_INDICES_V1
            .iter()
            .zip(TX_WITNESS_SENDER_LIMB_COLUMN_INDICES_V1.iter())
            .enumerate()
        {
            result[16 + offset] = current[*row_column] - current[*witness_column];
        }
        for (offset, (row_column, witness_column)) in RECIPIENT_LIMB_COLUMN_INDICES_V1
            .iter()
            .zip(TX_WITNESS_RECIPIENT_LIMB_COLUMN_INDICES_V1.iter())
            .enumerate()
        {
            result[20 + offset] = current[*row_column] - current[*witness_column];
        }
        result[24] = current[COL_AMOUNT] - current[COL_TX_WITNESS_AMOUNT];
        result[25] = current[COL_SENDER_NONCE_BEFORE] - current[COL_TX_WITNESS_SENDER_NONCE];

        let freeze_factor = one - next_active;
        for (offset, column) in FREEZE_COLUMN_INDICES_V1.iter().enumerate() {
            result[26 + offset] = freeze_factor * (next[*column] - current[*column]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = vec![Assertion::single(COL_TX_INDEX, 0, BaseElement::ZERO)];

        if self.tx_count == 0 {
            assertions.push(Assertion::single(COL_ACTIVE, 0, BaseElement::ZERO));
            return assertions;
        }

        assertions.push(Assertion::single(COL_ACTIVE, 0, BaseElement::ONE));

        let last_active = self.tx_count as usize - 1;
        if last_active != 0 {
            assertions.push(Assertion::single(
                COL_TX_INDEX,
                last_active,
                BaseElement::new((self.tx_count - 1) as u128),
            ));
            assertions.push(Assertion::single(COL_ACTIVE, last_active, BaseElement::ONE));
        }

        if last_active + 1 < self.trace_length {
            assertions.push(Assertion::single(
                COL_ACTIVE,
                last_active + 1,
                BaseElement::ZERO,
            ));
        }

        assertions
    }
}

struct WinterfellLocalProverV1 {
    options: ProofOptions,
    public_inputs: WinterfellStarkPublicInputsV1,
}

impl WinterfellLocalProverV1 {
    fn new(options: ProofOptions, public_inputs: WinterfellStarkPublicInputsV1) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for WinterfellLocalProverV1 {
    type BaseField = BaseElement;
    type Air = WinterfellLocalAirV1;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> WinterfellStarkPublicInputsV1 {
        self.public_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

#[cfg(test)]
mod tests {
    use aura_l2_execution_v1::{
        execute_transfer_batch_v1, BatchExecutionRequestV1, LocalAccountV1, LocalExecutionConfigV1,
        LocalStateV1, TransferTransactionV1, TRANSFER_TX_VERSION_V1, ZERO32_V1,
    };
    use aura_l2_trace_builder_v1::{
        build_trace_witness_bundle_v1, LocalStarkTraceRowV1, LocalStarkTransactionWitnessRowV1,
    };
    use winterfell::Trace;

    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn prepared_for_transactions(
        transactions: Vec<TransferTransactionV1>,
        accounts: [LocalAccountV1; 3],
    ) -> PreparedProofInputsV1 {
        let state = LocalStateV1::new(accounts).unwrap();
        let executed = execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(id(0xAA)),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions,
            },
        )
        .unwrap();
        let bundle = build_trace_witness_bundle_v1(&executed).unwrap();
        prepare_proof_inputs_v1(&bundle).unwrap()
    }

    fn canonical_prepared() -> PreparedProofInputsV1 {
        prepared_for_transactions(
            vec![TransferTransactionV1 {
                tx_version: TRANSFER_TX_VERSION_V1,
                sender_account_id: id(0x11),
                recipient_account_id: id(0x22),
                sender_nonce: 0,
                amount: 10,
            }],
            [
                LocalAccountV1 {
                    account_id: id(0x11),
                    balance: 80,
                    nonce: 0,
                },
                LocalAccountV1 {
                    account_id: id(0x22),
                    balance: 5,
                    nonce: 0,
                },
                LocalAccountV1 {
                    account_id: id(0x33),
                    balance: 1,
                    nonce: 0,
                },
            ],
        )
    }

    fn two_transfer_prepared() -> PreparedProofInputsV1 {
        prepared_for_transactions(
            vec![
                TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 10,
                },
                TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x22),
                    recipient_account_id: id(0x33),
                    sender_nonce: 0,
                    amount: 7,
                },
            ],
            [
                LocalAccountV1 {
                    account_id: id(0x11),
                    balance: 80,
                    nonce: 0,
                },
                LocalAccountV1 {
                    account_id: id(0x22),
                    balance: 12,
                    nonce: 0,
                },
                LocalAccountV1 {
                    account_id: id(0x33),
                    balance: 1,
                    nonce: 0,
                },
            ],
        )
    }

    #[test]
    fn distinct_account_witness_selects_first_non_equal_limb() {
        let row = LocalStarkTraceRowV1 {
            tx_index: 0,
            sender_account_id_limbs: [7, 9, 11, 13],
            recipient_account_id_limbs: [7, 5, 11, 13],
            amount: 3,
            fee_charged: 0,
            sender_nonce_before: 0,
            sender_nonce_after: 1,
            sender_balance_before: 10,
            sender_balance_after: 7,
            recipient_balance_before: 4,
            recipient_balance_after: 7,
        };
        let tx_witness = LocalStarkTransactionWitnessRowV1 {
            tx_index: 0,
            sender_account_id_limbs: [7, 9, 11, 13],
            recipient_account_id_limbs: [7, 5, 11, 13],
            sender_nonce: 0,
            amount: 3,
        };

        let values = internal_row_values_from_stark_layout_row_v1(&row, &tx_witness, true).unwrap();

        assert_eq!(values[COL_DISTINCT_SELECTOR_0], BaseElement::ZERO);
        assert_eq!(values[COL_DISTINCT_SELECTOR_1], BaseElement::ONE);
        assert_eq!(values[COL_DISTINCT_SELECTOR_2], BaseElement::ZERO);
        assert_eq!(values[COL_DISTINCT_SELECTOR_3], BaseElement::ZERO);
        assert_eq!(
            values[COL_DISTINCT_INVERSE_1],
            (base_from_u64_v1(9) - base_from_u64_v1(5)).inv()
        );
        assert_eq!(values[COL_AMOUNT_INVERSE], base_from_u64_v1(3).inv());
        assert_eq!(values[COL_TX_WITNESS_AMOUNT], base_from_u64_v1(3));
    }

    #[test]
    fn winterfell_backend_roundtrip_handles_two_transfer_batch() {
        let prepared = two_transfer_prepared();
        let proof_bytes = prove_with_winterfell_backend_v1(&prepared).unwrap();
        let verified = verify_with_winterfell_backend_v1(
            &prepared.witness_bundle.public_inputs_bytes,
            &proof_bytes,
        )
        .unwrap();

        assert_eq!(verified.public_inputs_hash, prepared.public_inputs_hash);
        assert_eq!(verified.trace_digest, prepared.trace_digest);
        assert_eq!(verified.trace_layout_digest, prepared.trace_layout_digest);
    }

    #[test]
    fn malformed_internal_trace_is_rejected_by_winterfell_verification() {
        let prepared = canonical_prepared();
        let pub_inputs = derive_winterfell_public_inputs_v1(&prepared);
        let prover =
            WinterfellLocalProverV1::new(default_winterfell_proof_options_v1(), pub_inputs.clone());
        let mut trace = build_winterfell_trace_v1(&prepared.witness_bundle).unwrap();

        let sender_limb = trace.get(COL_SENDER_LIMB_0, 0);
        trace.set(COL_RECIPIENT_LIMB_0, 0, sender_limb);

        let proof = prover.prove(trace).unwrap();
        let acceptable = AcceptableOptions::MinConjecturedSecurity(95);
        let error = verify::<
            WinterfellLocalAirV1,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
            MerkleTree<Blake3_256<BaseElement>>,
        >(proof, pub_inputs, &acceptable)
        .unwrap_err();

        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn malformed_transaction_witness_is_rejected_by_winterfell_verification() {
        let prepared = canonical_prepared();
        let pub_inputs = derive_winterfell_public_inputs_v1(&prepared);
        let prover =
            WinterfellLocalProverV1::new(default_winterfell_proof_options_v1(), pub_inputs.clone());
        let mut trace = build_winterfell_trace_v1(&prepared.witness_bundle).unwrap();

        trace.set(COL_TX_WITNESS_AMOUNT, 0, base_from_u64_v1(11));

        let proof = prover.prove(trace).unwrap();
        let acceptable = AcceptableOptions::MinConjecturedSecurity(95);
        let error = verify::<
            WinterfellLocalAirV1,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
            MerkleTree<Blake3_256<BaseElement>>,
        >(proof, pub_inputs, &acceptable)
        .unwrap_err();

        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn air_declares_exact_constraint_count() {
        let prepared = canonical_prepared();
        let trace = build_winterfell_trace_v1(&prepared.witness_bundle).unwrap();
        let air = WinterfellLocalAirV1::new(
            trace.info().clone(),
            derive_winterfell_public_inputs_v1(&prepared),
            default_winterfell_proof_options_v1(),
        );

        assert_eq!(air.context().num_transition_constraints(), 43);
    }

    #[test]
    fn padding_rows_use_deterministic_helper_sentinels() {
        let prepared = canonical_prepared();
        let trace = build_winterfell_trace_v1(&prepared.witness_bundle).unwrap();

        assert_eq!(trace.length(), 8);
        assert_eq!(trace.get(COL_ACTIVE, 0), BaseElement::ONE);
        assert_eq!(trace.get(COL_ACTIVE, 1), BaseElement::ZERO);

        assert_eq!(trace.get(COL_AMOUNT, 1), trace.get(COL_AMOUNT, 0));
        assert_eq!(trace.get(COL_AMOUNT_INVERSE, 1), BaseElement::ZERO);
        assert_eq!(
            trace.get(COL_TX_WITNESS_AMOUNT, 1),
            trace.get(COL_TX_WITNESS_AMOUNT, 0)
        );
        assert_eq!(
            trace.get(COL_TX_WITNESS_SENDER_NONCE, 1),
            trace.get(COL_TX_WITNESS_SENDER_NONCE, 0)
        );
        for column in DISTINCT_SELECTOR_COLUMN_INDICES_V1 {
            assert_eq!(trace.get(column, 1), BaseElement::ZERO);
        }
        for column in DISTINCT_INVERSE_COLUMN_INDICES_V1 {
            assert_eq!(trace.get(column, 1), BaseElement::ZERO);
        }
    }

    #[test]
    fn proof_envelope_rejects_trailing_bytes() {
        let prepared = canonical_prepared();
        let mut proof_bytes = prove_with_winterfell_backend_v1(&prepared).unwrap();
        proof_bytes.push(0xAA);

        let error = decode_winterfell_stark_proof_envelope_v1(&proof_bytes).unwrap_err();
        assert!(matches!(
            error,
            StarkBackendErrorV1::ProofEnvelopeDecode {
                field: "trailing_bytes"
            }
        ));
    }

    #[test]
    #[ignore = "diagnostic: run with winter-prover debug assertions forced on to measure one-transfer degree collapse"]
    fn debug_diagnostic_one_transfer_backend_case() {
        let prepared = canonical_prepared();
        let proof_bytes = prove_with_winterfell_backend_v1(&prepared).unwrap();
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    #[ignore = "diagnostic: run with winter-prover debug assertions forced on to compare two-transfer behavior after reformulation"]
    fn debug_diagnostic_two_transfer_backend_case() {
        let prepared = two_transfer_prepared();
        let proof_bytes = prove_with_winterfell_backend_v1(&prepared).unwrap();
        assert!(!proof_bytes.is_empty());
    }
}
