//! Aura SDK v0 for the active transfer-only local proving foundation.
//!
//! This SDK is a thin developer-facing wrapper over the currently operational
//! local-chain stack:
//!
//! - deterministic transfer-only execution
//! - frozen 284-byte public-input derivation
//! - explicit mock proof generation
//! - explicit real Winterfell-backed STARK proof generation
//! - proof verification
//! - local settlement acceptance
//! - canonical proof-vector loading, reproduction, and stored-proof verification
//!
//! This is a thin Rust compatibility wrapper over Aura's active local proving
//! foundation. It is not the canonical end-to-end authority path; that path is
//! the versioned `run-canonical-pipeline` request/report flow exposed through
//! `aura_l2_local_chain_v0` and consumed by the TypeScript parity layer.
//!
//! The SDK does not change protocol meaning. It wraps the existing crates so a
//! developer can drive the full chain flow from one surface. For repository
//! navigation, see `AURA_ENGINEERING_START_HERE_V1.md` and
//! `AURA_ACTIVE_SYSTEM_MAP_V1.md` at the repo root.
//!
//! ```no_run
//! use aura_sdk_v0::{
//!     run_flow_v0, BatchBuilderV0, GenesisBuilderV0, ProofSystemV0, ZERO32_V0,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rollup_id = [0xAA; 32];
//! let state = GenesisBuilderV0::new()
//!     .account([0x11; 32], 90, 0)
//!     .account([0x22; 32], 10, 0)
//!     .build_state()?;
//!
//! let batch = BatchBuilderV0::new(0)
//!     .with_parent_batch_commitment(ZERO32_V0)
//!     .transfer([0x11; 32], [0x22; 32], 0, 9)
//!     .build();
//!
//! let completed = run_flow_v0(&state, rollup_id, &batch, ProofSystemV0::Stark)?;
//! assert_eq!(completed.accepted_transition.batch_number, 0);
//! # Ok(())
//! # }
//! ```

use core::fmt;
use std::{fs, path::Path};

use aura_l2_execution_v1::{
    execute_transfer_batch_v1, BatchExecutionRequestV1, ExecutedBatchV1, LocalAccountV1,
    LocalExecutionErrorV1, LocalStateV1, TransferTransactionV1, HASH_LEN_V1,
    TRANSFER_TX_VERSION_V1, ZERO32_V1,
};
use aura_l2_local_chain_v0::{
    encode_hex, load_proof_vector_from_path, run_proof_vector_from_path, run_scenario_from_paths,
    run_scenario_from_paths_with_proof_system, verify_proof_vector_from_path, LocalChainErrorV1,
    ProofSystemSelectionV1,
};
use aura_l2_local_settlement_v1::{
    accept_transition_v1, LocalSettlementErrorV1, LocalSettlementStateV1,
};
use aura_l2_prover_v1::{
    prove_executed_batch_with_mock_prover_v1, prove_executed_batch_with_stark_prover_v1,
    LocalProverErrorV1,
};
use aura_l2_public_input_v1::PublicInputSchemaErrorV1;
use aura_l2_verifier_v1::{
    verify_mock_proof_artifact_v1, verify_proof_artifact_v1, LocalVerifierErrorV1,
};
use serde::Deserialize;

pub const HASH_LEN_V0: usize = HASH_LEN_V1;
pub const PUBLIC_INPUT_SCHEMA_LEN_V0: usize = aura_l2_public_input_v1::PUBLIC_INPUT_SCHEMA_LEN_V1;
pub const TRANSFER_TX_VERSION_V0: u32 = TRANSFER_TX_VERSION_V1;
pub const ZERO32_V0: [u8; HASH_LEN_V0] = ZERO32_V1;
const GENESIS_FIXTURE_NAME_V0: &str = "genesis_state";

pub use aura_l2_execution_v1::{
    AppliedTransferStepV1 as AppliedTransferStepV0, ExecutionOutcomeV1 as ExecutionOutcomeV0,
    LocalBatchContextV1 as BatchContextV0, LocalExecutionConfigV1 as ExecutionConfigV0,
    LocalFeeSummaryV1 as FeeSummaryV0,
};
pub use aura_l2_local_chain_v0::ScenarioReportV1 as ScenarioReportV0;
pub use aura_l2_local_chain_v0::ScenarioResultV1 as ScenarioResultV0;
pub use aura_l2_local_chain_v0::{
    ProofVectorCanonicalStarkArtifactV1 as ProofVectorCanonicalStarkArtifactV0,
    ProofVectorExpectedOutcomeV1 as ProofVectorExpectedOutcomeV0,
    ProofVectorExpectedPublicInputsV1 as ProofVectorExpectedPublicInputsV0,
    ProofVectorExpectedTransitionV1 as ProofVectorExpectedTransitionV0,
    ProofVectorFixtureV1 as ProofVectorFixtureV0, ProofVectorGenesisV1 as ProofVectorGenesisV0,
    ProofVectorReportV1 as ProofVectorReportV0,
    ProofVectorTamperTargetV1 as ProofVectorTamperTargetV0,
    ProofVectorTamperV1 as ProofVectorTamperV0,
};
pub use aura_l2_local_settlement_v1::AcceptedTransitionV1 as AcceptedTransitionV0;
pub use aura_l2_prover_v1::{
    LocalMockProofArtifactV1 as MockProofArtifactV0, LocalProofArtifactV1 as ProofArtifactV0,
    LocalStarkProofArtifactV1 as StarkProofArtifactV0,
};
pub use aura_l2_public_input_v1::{
    TransitionClaimV1 as TransitionClaimV0, TransitionEnvelopeV1 as PublicInputsV0,
};
pub use aura_l2_verifier_v1::VerifiedTransitionV1 as VerifiedTransitionV0;

pub type AccountV0 = LocalAccountV1;
pub type StateV0 = LocalStateV1;
pub type TransferTxV0 = TransferTransactionV1;
pub type BatchV0 = BatchExecutionRequestV1;
pub type TransitionV0 = ExecutedBatchV1;
pub type ExecutionResultV0 = ExecutedBatchV1;
pub type PublicInputBytesV0 = [u8; PUBLIC_INPUT_SCHEMA_LEN_V0];
pub type SettlementStateV0 = LocalSettlementStateV1;
pub type NextStateV0 = LocalSettlementStateV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSystemV0 {
    Mock,
    Stark,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedGenesisV0 {
    pub fixture_name: String,
    pub rollup_id: [u8; HASH_LEN_V0],
    pub state: StateV0,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionArtifactsV0 {
    pub executed_batch: TransitionV0,
    pub public_inputs: PublicInputsV0,
    pub public_input_bytes: PublicInputBytesV0,
    pub transition_claim: TransitionClaimV0,
    pub transition_binding_hash: [u8; HASH_LEN_V0],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedFlowV0 {
    pub proof_system: ProofSystemV0,
    pub transition: TransitionArtifactsV0,
    pub proof_artifact: ProofArtifactV0,
    pub verified_transition: VerifiedTransitionV0,
    pub accepted_transition: AcceptedTransitionV0,
    pub next_state: NextStateV0,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenesisBuilderV0 {
    accounts: Vec<AccountV0>,
}

impl GenesisBuilderV0 {
    pub fn new() -> Self {
        Self {
            accounts: Vec::new(),
        }
    }

    pub fn account(mut self, account_id: [u8; HASH_LEN_V0], balance: u64, nonce: u64) -> Self {
        self.accounts.push(AccountV0 {
            account_id,
            balance,
            nonce,
        });
        self
    }

    pub fn push_account(
        &mut self,
        account_id: [u8; HASH_LEN_V0],
        balance: u64,
        nonce: u64,
    ) -> &mut Self {
        self.accounts.push(AccountV0 {
            account_id,
            balance,
            nonce,
        });
        self
    }

    pub fn build_state(self) -> Result<StateV0, AuraSdkErrorV0> {
        StateV0::new(self.accounts).map_err(AuraSdkErrorV0::Execution)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchBuilderV0 {
    batch_number: u64,
    parent_batch_commitment: [u8; HASH_LEN_V0],
    transactions: Vec<TransferTxV0>,
}

impl BatchBuilderV0 {
    pub fn new(batch_number: u64) -> Self {
        Self {
            batch_number,
            parent_batch_commitment: ZERO32_V0,
            transactions: Vec::new(),
        }
    }

    pub fn with_parent_batch_commitment(
        mut self,
        parent_batch_commitment: [u8; HASH_LEN_V0],
    ) -> Self {
        self.parent_batch_commitment = parent_batch_commitment;
        self
    }

    pub fn transfer(
        mut self,
        sender_account_id: [u8; HASH_LEN_V0],
        recipient_account_id: [u8; HASH_LEN_V0],
        sender_nonce: u64,
        amount: u64,
    ) -> Self {
        self.transactions.push(transfer_tx_v0(
            sender_account_id,
            recipient_account_id,
            sender_nonce,
            amount,
        ));
        self
    }

    pub fn push_transfer(&mut self, tx: TransferTxV0) -> &mut Self {
        self.transactions.push(tx);
        self
    }

    pub fn build(self) -> BatchV0 {
        BatchV0 {
            batch_number: self.batch_number,
            parent_batch_commitment: self.parent_batch_commitment,
            transactions: self.transactions,
        }
    }
}

#[derive(Debug)]
pub enum AuraSdkErrorV0 {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidGenesisFixture(String),
    Execution(LocalExecutionErrorV1),
    PublicInputSchema(PublicInputSchemaErrorV1),
    Prover(LocalProverErrorV1),
    Verifier(LocalVerifierErrorV1),
    Settlement(LocalSettlementErrorV1),
    LocalChain(LocalChainErrorV1),
}

impl fmt::Display for AuraSdkErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::InvalidGenesisFixture(error) => write!(f, "invalid genesis fixture: {error}"),
            Self::Execution(error) => write!(f, "execution error: {error}"),
            Self::PublicInputSchema(error) => write!(f, "public input schema error: {error}"),
            Self::Prover(error) => write!(f, "prover error: {error}"),
            Self::Verifier(error) => write!(f, "verifier error: {error}"),
            Self::Settlement(error) => write!(f, "settlement error: {error}"),
            Self::LocalChain(error) => write!(f, "local chain error: {error}"),
        }
    }
}

impl std::error::Error for AuraSdkErrorV0 {}

impl From<std::io::Error> for AuraSdkErrorV0 {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for AuraSdkErrorV0 {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<LocalExecutionErrorV1> for AuraSdkErrorV0 {
    fn from(value: LocalExecutionErrorV1) -> Self {
        Self::Execution(value)
    }
}

impl From<PublicInputSchemaErrorV1> for AuraSdkErrorV0 {
    fn from(value: PublicInputSchemaErrorV1) -> Self {
        Self::PublicInputSchema(value)
    }
}

impl From<LocalProverErrorV1> for AuraSdkErrorV0 {
    fn from(value: LocalProverErrorV1) -> Self {
        Self::Prover(value)
    }
}

impl From<LocalVerifierErrorV1> for AuraSdkErrorV0 {
    fn from(value: LocalVerifierErrorV1) -> Self {
        Self::Verifier(value)
    }
}

impl From<LocalSettlementErrorV1> for AuraSdkErrorV0 {
    fn from(value: LocalSettlementErrorV1) -> Self {
        Self::Settlement(value)
    }
}

impl From<LocalChainErrorV1> for AuraSdkErrorV0 {
    fn from(value: LocalChainErrorV1) -> Self {
        Self::LocalChain(value)
    }
}

#[derive(Deserialize)]
struct GenesisFixtureFileV0 {
    fixture_name: String,
    rollup_id_hex: String,
    accounts: Vec<GenesisAccountFixtureV0>,
}

#[derive(Deserialize)]
struct GenesisAccountFixtureV0 {
    account_id_hex: String,
    balance: u64,
    nonce: u64,
}

pub fn transfer_tx_v0(
    sender_account_id: [u8; HASH_LEN_V0],
    recipient_account_id: [u8; HASH_LEN_V0],
    sender_nonce: u64,
    amount: u64,
) -> TransferTxV0 {
    TransferTxV0 {
        tx_version: TRANSFER_TX_VERSION_V0,
        sender_account_id,
        recipient_account_id,
        sender_nonce,
        amount,
    }
}

pub fn execution_config_v0(rollup_id: [u8; HASH_LEN_V0]) -> ExecutionConfigV0 {
    ExecutionConfigV0::new(rollup_id)
}

pub fn state_from_accounts_v0<I>(accounts: I) -> Result<StateV0, AuraSdkErrorV0>
where
    I: IntoIterator<Item = AccountV0>,
{
    StateV0::new(accounts).map_err(AuraSdkErrorV0::Execution)
}

pub fn load_genesis_fixture_v0<P: AsRef<Path>>(path: P) -> Result<LoadedGenesisV0, AuraSdkErrorV0> {
    let bytes = fs::read(path)?;
    let fixture: GenesisFixtureFileV0 = serde_json::from_slice(&bytes)?;
    validate_genesis_fixture_file_v0(&fixture)?;
    let rollup_id = decode_hex_32_v0_with_label(&fixture.rollup_id_hex, "genesis.rollup_id_hex")?;
    let accounts = fixture
        .accounts
        .into_iter()
        .map(|account| {
            Ok(AccountV0 {
                account_id: decode_hex_32_v0_with_label(
                    &account.account_id_hex,
                    "genesis.accounts[].account_id_hex",
                )?,
                balance: account.balance,
                nonce: account.nonce,
            })
        })
        .collect::<Result<Vec<_>, AuraSdkErrorV0>>()?;
    let state = state_from_accounts_v0(accounts)?;
    Ok(LoadedGenesisV0 {
        fixture_name: fixture.fixture_name,
        rollup_id,
        state,
    })
}

pub fn new_settlement_state_v0(
    rollup_id: [u8; HASH_LEN_V0],
    genesis_state: &StateV0,
) -> SettlementStateV0 {
    SettlementStateV0::new(rollup_id, genesis_state.state_root())
}

pub fn execute_batch_v0(
    pre_state: &StateV0,
    rollup_id: [u8; HASH_LEN_V0],
    batch: &BatchV0,
) -> Result<TransitionV0, AuraSdkErrorV0> {
    let config = execution_config_v0(rollup_id);
    execute_transfer_batch_v1(pre_state, &config, batch).map_err(AuraSdkErrorV0::Execution)
}

pub fn derive_transition_artifacts_v0(executed: &TransitionV0) -> TransitionArtifactsV0 {
    let public_inputs = PublicInputsV0::from_executed_batch(executed);
    let public_input_bytes = public_inputs.encode_bytes();
    let transition_claim = public_inputs.claim();
    let transition_binding_hash = public_inputs.transition_binding_hash_v1();
    TransitionArtifactsV0 {
        executed_batch: executed.clone(),
        public_inputs,
        public_input_bytes,
        transition_claim,
        transition_binding_hash,
    }
}

pub fn export_public_inputs_v0(executed: &TransitionV0) -> PublicInputsV0 {
    PublicInputsV0::from_executed_batch(executed)
}

pub fn export_public_input_bytes_v0(executed: &TransitionV0) -> PublicInputBytesV0 {
    export_public_inputs_v0(executed).encode_bytes()
}

pub fn prove_mock_v0(executed: &TransitionV0) -> Result<MockProofArtifactV0, AuraSdkErrorV0> {
    prove_executed_batch_with_mock_prover_v1(executed).map_err(AuraSdkErrorV0::Prover)
}

pub fn prove_stark_v0(executed: &TransitionV0) -> Result<StarkProofArtifactV0, AuraSdkErrorV0> {
    prove_executed_batch_with_stark_prover_v1(executed).map_err(AuraSdkErrorV0::Prover)
}

pub fn prove_v0(
    executed: &TransitionV0,
    proof_system: ProofSystemV0,
) -> Result<ProofArtifactV0, AuraSdkErrorV0> {
    match proof_system {
        ProofSystemV0::Mock => Ok(ProofArtifactV0::Mock(prove_mock_v0(executed)?)),
        ProofSystemV0::Stark => Ok(ProofArtifactV0::Stark(prove_stark_v0(executed)?)),
    }
}

pub fn verify_mock_v0(
    public_inputs_bytes: &[u8],
    proof_artifact: &MockProofArtifactV0,
) -> Result<VerifiedTransitionV0, AuraSdkErrorV0> {
    verify_mock_proof_artifact_v1(public_inputs_bytes, proof_artifact)
        .map_err(AuraSdkErrorV0::Verifier)
}

pub fn verify_stark_v0(
    public_inputs_bytes: &[u8],
    proof_artifact: &StarkProofArtifactV0,
) -> Result<VerifiedTransitionV0, AuraSdkErrorV0> {
    verify_proof_artifact_v1(
        public_inputs_bytes,
        &ProofArtifactV0::Stark(proof_artifact.clone()),
    )
    .map_err(AuraSdkErrorV0::Verifier)
}

pub fn verify_proof_v0(
    public_inputs_bytes: &[u8],
    proof_artifact: &ProofArtifactV0,
) -> Result<VerifiedTransitionV0, AuraSdkErrorV0> {
    verify_proof_artifact_v1(public_inputs_bytes, proof_artifact).map_err(AuraSdkErrorV0::Verifier)
}

pub fn accept_transition_v0(
    settlement_state: &mut SettlementStateV0,
    public_inputs_bytes: &[u8],
    proof_artifact: &ProofArtifactV0,
) -> Result<AcceptedTransitionV0, AuraSdkErrorV0> {
    accept_transition_v1(settlement_state, public_inputs_bytes, proof_artifact)
        .map_err(AuraSdkErrorV0::Settlement)
}

pub fn run_flow_v0(
    pre_state: &StateV0,
    rollup_id: [u8; HASH_LEN_V0],
    batch: &BatchV0,
    proof_system: ProofSystemV0,
) -> Result<CompletedFlowV0, AuraSdkErrorV0> {
    let executed = execute_batch_v0(pre_state, rollup_id, batch)?;
    let transition = derive_transition_artifacts_v0(&executed);
    let proof_artifact = prove_v0(&executed, proof_system)?;
    let verified_transition = verify_proof_v0(&transition.public_input_bytes, &proof_artifact)?;
    let mut next_state = new_settlement_state_v0(rollup_id, pre_state);
    let accepted_transition = accept_transition_v0(
        &mut next_state,
        &transition.public_input_bytes,
        &proof_artifact,
    )?;
    Ok(CompletedFlowV0 {
        proof_system,
        transition,
        proof_artifact,
        verified_transition,
        accepted_transition,
        next_state,
    })
}

pub fn run_fixture_scenario_v0<P: AsRef<Path>, Q: AsRef<Path>>(
    genesis_path: P,
    scenario_path: Q,
) -> Result<ScenarioReportV0, AuraSdkErrorV0> {
    run_scenario_from_paths(genesis_path, scenario_path).map_err(AuraSdkErrorV0::LocalChain)
}

pub fn run_fixture_scenario_with_proof_system_v0<P: AsRef<Path>, Q: AsRef<Path>>(
    genesis_path: P,
    scenario_path: Q,
    proof_system: ProofSystemV0,
) -> Result<ScenarioReportV0, AuraSdkErrorV0> {
    run_scenario_from_paths_with_proof_system(
        genesis_path,
        scenario_path,
        proof_system_selection_v1(proof_system),
    )
    .map_err(AuraSdkErrorV0::LocalChain)
}

pub fn encode_hex_v0(bytes: &[u8]) -> String {
    encode_hex(bytes)
}

pub fn load_proof_vector_v0<P: AsRef<Path>>(
    path: P,
) -> Result<ProofVectorFixtureV0, AuraSdkErrorV0> {
    load_proof_vector_from_path(path).map_err(AuraSdkErrorV0::LocalChain)
}

pub fn run_proof_vector_v0<P: AsRef<Path>>(path: P) -> Result<ProofVectorReportV0, AuraSdkErrorV0> {
    run_proof_vector_from_path(path).map_err(AuraSdkErrorV0::LocalChain)
}

pub fn verify_proof_vector_v0<P: AsRef<Path>>(
    path: P,
) -> Result<ProofVectorReportV0, AuraSdkErrorV0> {
    verify_proof_vector_from_path(path).map_err(AuraSdkErrorV0::LocalChain)
}

fn proof_system_selection_v1(proof_system: ProofSystemV0) -> ProofSystemSelectionV1 {
    match proof_system {
        ProofSystemV0::Mock => ProofSystemSelectionV1::Mock,
        ProofSystemV0::Stark => ProofSystemSelectionV1::Stark,
    }
}

fn decode_hex_32_v0_with_label(
    value: &str,
    field: &'static str,
) -> Result<[u8; HASH_LEN_V0], AuraSdkErrorV0> {
    if value.len() != HASH_LEN_V0 * 2 {
        return Err(AuraSdkErrorV0::InvalidGenesisFixture(format!(
            "{field} must contain {} hex chars, got {}",
            HASH_LEN_V0 * 2,
            value.len()
        )));
    }
    let bytes = value.as_bytes();
    let mut out = [0u8; HASH_LEN_V0];
    for i in 0..HASH_LEN_V0 {
        out[i] = (decode_hex_nibble_v0(bytes[i * 2], field)? << 4)
            | decode_hex_nibble_v0(bytes[i * 2 + 1], field)?;
    }
    Ok(out)
}

fn decode_hex_nibble_v0(value: u8, field: &'static str) -> Result<u8, AuraSdkErrorV0> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AuraSdkErrorV0::InvalidGenesisFixture(format!(
            "{field} contains invalid hex nibble: {}",
            value as char
        ))),
    }
}

fn validate_genesis_fixture_file_v0(fixture: &GenesisFixtureFileV0) -> Result<(), AuraSdkErrorV0> {
    if fixture.fixture_name.trim().is_empty() {
        return Err(AuraSdkErrorV0::InvalidGenesisFixture(
            "fixture_name must not be empty".to_string(),
        ));
    }
    if fixture.fixture_name != GENESIS_FIXTURE_NAME_V0 {
        return Err(AuraSdkErrorV0::InvalidGenesisFixture(format!(
            "unexpected genesis fixture name: {}",
            fixture.fixture_name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use aura_l2_local_chain_v0::{
        run_scenario_from_paths_with_proof_system, ProofSystemSelectionV1,
    };
    use aura_l2_public_input_v1::TransitionEnvelopeV1;
    use serde_json::Value;

    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn canonical_state() -> StateV0 {
        GenesisBuilderV0::new()
            .account(id(0x11), 90, 0)
            .account(id(0x22), 10, 0)
            .build_state()
            .unwrap()
    }

    fn canonical_batch() -> BatchV0 {
        BatchBuilderV0::new(0)
            .with_parent_batch_commitment(ZERO32_V0)
            .transfer(id(0x11), id(0x22), 0, 9)
            .build()
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn write_temp_json(name: &str, value: &Value) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aura_sdk_v0_{name}_{}_{}.json",
            std::process::id(),
            nanos
        ));
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    #[test]
    fn sdk_end_to_end_mock_flow_accepts() {
        let completed = run_flow_v0(
            &canonical_state(),
            id(0xAA),
            &canonical_batch(),
            ProofSystemV0::Mock,
        )
        .unwrap();

        assert_eq!(completed.accepted_transition.batch_number, 0);
        assert_eq!(
            completed.next_state.current_state_root,
            completed.accepted_transition.new_state_root
        );
        assert_eq!(
            completed.transition.public_input_bytes.len(),
            PUBLIC_INPUT_SCHEMA_LEN_V0
        );
    }

    #[test]
    fn sdk_end_to_end_real_stark_flow_accepts() {
        let completed = run_flow_v0(
            &canonical_state(),
            id(0xAA),
            &canonical_batch(),
            ProofSystemV0::Stark,
        )
        .unwrap();

        assert_eq!(completed.accepted_transition.batch_number, 0);
        assert_eq!(
            completed.verified_transition.transition_binding_hash,
            completed.transition.transition_binding_hash
        );
    }

    #[test]
    fn sdk_tampered_real_stark_proof_rejects() {
        let state = canonical_state();
        let executed = execute_batch_v0(&state, id(0xAA), &canonical_batch()).unwrap();
        let public_input_bytes = export_public_input_bytes_v0(&executed);
        let mut proof = prove_stark_v0(&executed).unwrap();
        proof.proof_binding_digest[0] ^= 0x01;

        let error = verify_stark_v0(&public_input_bytes, &proof).unwrap_err();
        assert!(matches!(error, AuraSdkErrorV0::Verifier(_)));
    }

    #[test]
    fn sdk_accepted_transition_flow_advances_state() {
        let state = canonical_state();
        let executed = execute_batch_v0(&state, id(0xAA), &canonical_batch()).unwrap();
        let transition = derive_transition_artifacts_v0(&executed);
        let proof = prove_v0(&executed, ProofSystemV0::Mock).unwrap();
        let mut settlement = new_settlement_state_v0(id(0xAA), &state);
        let accepted =
            accept_transition_v0(&mut settlement, &transition.public_input_bytes, &proof).unwrap();

        assert_eq!(accepted.new_state_root, settlement.current_state_root);
        assert_eq!(settlement.expected_batch_number, 1);
    }

    #[test]
    fn sdk_api_matches_existing_local_chain_behavior() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let scenario = root.join("fixtures/l2_local_v1/accepted_transition_example.json");

        let via_sdk =
            run_fixture_scenario_with_proof_system_v0(&genesis, &scenario, ProofSystemV0::Stark)
                .unwrap();
        let via_local_chain = run_scenario_from_paths_with_proof_system(
            &genesis,
            &scenario,
            ProofSystemSelectionV1::Stark,
        )
        .unwrap();

        assert_eq!(via_sdk, via_local_chain);
    }

    #[test]
    fn sdk_public_input_derivation_has_no_semantic_drift() {
        let state = canonical_state();
        let executed = execute_batch_v0(&state, id(0xAA), &canonical_batch()).unwrap();
        let derived = derive_transition_artifacts_v0(&executed);
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed);

        assert_eq!(derived.public_inputs, envelope);
        assert_eq!(derived.public_input_bytes, envelope.encode_bytes());
        assert_eq!(
            derived.transition_binding_hash,
            envelope.transition_binding_hash_v1()
        );
    }

    #[test]
    fn sdk_loads_proof_vector_fixture() {
        let root = repo_root();
        let fixture = load_proof_vector_v0(
            root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
        )
        .unwrap();

        assert_eq!(fixture.proof_system, ProofSystemSelectionV1::Stark);
        assert_eq!(fixture.expected_public_inputs.public_input_bytes.len(), 284);
        assert_eq!(fixture.expected_result, ScenarioResultV0::Accepted);
    }

    #[test]
    fn sdk_rejects_empty_genesis_fixture_name() {
        let root = repo_root();
        let source = root.join("fixtures/l2_local_v1/genesis_state.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["fixture_name"] = Value::from("");
        let temp = write_temp_json("invalid_sdk_genesis_name", &parsed);
        let error = load_genesis_fixture_v0(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, AuraSdkErrorV0::InvalidGenesisFixture(_)));
    }

    #[test]
    fn sdk_runs_proof_vector_reproducibly() {
        let root = repo_root();
        let report = run_proof_vector_v0(
            root.join("fixtures/l2_proof_vectors_v1/multi_transfer_proof.json"),
        )
        .unwrap();

        assert_eq!(report.proof_system, ProofSystemSelectionV1::Stark);
        assert_eq!(report.actual_result, ScenarioResultV0::Accepted);
    }

    #[test]
    fn sdk_verifies_stored_proof_vector() {
        let root = repo_root();
        let report = verify_proof_vector_v0(
            root.join("fixtures/l2_proof_vectors_v1/small_trace_edge_case.json"),
        )
        .unwrap();

        assert_eq!(report.proof_system, ProofSystemSelectionV1::Stark);
        assert_eq!(report.actual_result, ScenarioResultV0::Accepted);
    }

    #[test]
    fn sdk_rejects_tampered_proof_vector() {
        let root = repo_root();
        let report = verify_proof_vector_v0(
            root.join("fixtures/l2_proof_vectors_v1/tampered_proof_case.json"),
        )
        .unwrap();

        assert_eq!(report.actual_result, ScenarioResultV0::VerificationRejected);
    }

    #[test]
    fn sdk_rejects_malformed_proof_vector_fixture() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["proof_system"] = Value::from("MOCK");
        let temp = write_temp_json("invalid_proof_vector", &parsed);
        let error = load_proof_vector_v0(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, AuraSdkErrorV0::LocalChain(_)));
    }

    #[test]
    fn sdk_real_stark_flow_remains_identical_across_twelve_runs() {
        let baseline = run_flow_v0(
            &canonical_state(),
            id(0xAA),
            &canonical_batch(),
            ProofSystemV0::Stark,
        )
        .unwrap();

        for _ in 0..12 {
            let run = run_flow_v0(
                &canonical_state(),
                id(0xAA),
                &canonical_batch(),
                ProofSystemV0::Stark,
            )
            .unwrap();
            assert_eq!(run.transition, baseline.transition);
            assert_eq!(run.proof_artifact, baseline.proof_artifact);
            assert_eq!(run.verified_transition, baseline.verified_transition);
            assert_eq!(run.accepted_transition, baseline.accepted_transition);
            assert_eq!(run.next_state, baseline.next_state);
        }
    }

    #[test]
    fn sdk_all_canonical_proof_vectors_remain_loadable_and_runnable() {
        let root = repo_root();
        for fixture in [
            "minimal_single_transfer_proof.json",
            "multi_transfer_proof.json",
            "small_trace_edge_case.json",
            "tampered_proof_case.json",
        ] {
            let path = root.join("fixtures/l2_proof_vectors_v1").join(fixture);
            let loaded = load_proof_vector_v0(&path).unwrap();
            let run = run_proof_vector_v0(&path).unwrap();
            let verify = verify_proof_vector_v0(&path).unwrap();

            assert_eq!(loaded.proof_system, ProofSystemSelectionV1::Stark);
            assert_eq!(run.expected_result, loaded.expected_result);
            assert_eq!(verify.expected_result, loaded.expected_result);
        }
    }
}
