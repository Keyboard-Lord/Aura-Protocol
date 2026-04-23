//! Aura L2 local prover for the first complete proving-chain milestone.
//!
//! Current status:
//!
//! - the witness and trace are real
//! - the public-input binding is real
//! - the mock proof artifact is real and MUST be described as mock
//! - the STARK prover path is real and Winterfell-backed for the current transfer-only local chain
//!
//! The proving boundary is explicit:
//!
//! - `MockProverV1` produces the current honest proof artifact
//! - `StarkProverV1` produces a real STARK proof bound to the same frozen public-input surface
//! - the full frozen witness and commitment semantics are still enforced by the existing host-side
//!   witness validator; the STARK backend currently covers the algebraic trace relation

use core::fmt;

use aura_l2_execution_v1::{sha256_bytes, ExecutedBatchV1, HASH_LEN_V1};
use aura_l2_trace_builder_v1::{
    build_trace_witness_bundle_v1, derive_witness_digest_v1, validate_trace_witness_bundle_v1,
    TraceBuilderErrorV1, TraceWitnessBundleV1,
};

mod winterfell_backend_v1;

pub use winterfell_backend_v1::*;

pub const LOCAL_PROVER_KIND_MOCK_V1: u32 = 1;
pub const LOCAL_PROVER_KIND_STARK_V1: u32 = 2;

pub const LOCAL_MOCK_PROOF_VERSION_V1: u32 = 1;
pub const LOCAL_STARK_PROOF_VERSION_V1: u32 = 1;

pub const AURA_L2_LOCAL_MOCK_PROOF_BINDING_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_MOCK_PROOF_BINDING_V1";
pub const AURA_L2_LOCAL_STARK_REQUEST_BINDING_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_STARK_REQUEST_BINDING_V1";
pub const AURA_L2_LOCAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_LOCAL_STARK_PROOF_BINDING_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalProofSystemKindV1 {
    Mock,
    Stark,
}

impl LocalProofSystemKindV1 {
    pub fn prover_kind(self) -> u32 {
        match self {
            Self::Mock => LOCAL_PROVER_KIND_MOCK_V1,
            Self::Stark => LOCAL_PROVER_KIND_STARK_V1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedProofInputsV1 {
    pub public_inputs_hash: [u8; HASH_LEN_V1],
    pub trace_digest: [u8; HASH_LEN_V1],
    pub trace_layout_digest: [u8; HASH_LEN_V1],
    pub witness_digest: [u8; HASH_LEN_V1],
    pub witness_bundle: TraceWitnessBundleV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalMockProofArtifactV1 {
    pub prover_kind: u32,
    pub proof_version: u32,
    pub public_inputs_hash: [u8; HASH_LEN_V1],
    pub trace_digest: [u8; HASH_LEN_V1],
    pub trace_layout_digest: [u8; HASH_LEN_V1],
    pub witness_digest: [u8; HASH_LEN_V1],
    pub proof_binding_digest: [u8; HASH_LEN_V1],
    pub witness_bundle: TraceWitnessBundleV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkProofRequestV1 {
    pub prover_kind: u32,
    pub proof_version: u32,
    pub public_inputs_hash: [u8; HASH_LEN_V1],
    pub trace_digest: [u8; HASH_LEN_V1],
    pub trace_layout_digest: [u8; HASH_LEN_V1],
    pub witness_digest: [u8; HASH_LEN_V1],
    pub request_binding_digest: [u8; HASH_LEN_V1],
    pub witness_bundle: TraceWitnessBundleV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalStarkProofArtifactV1 {
    pub prover_kind: u32,
    pub proof_version: u32,
    pub public_inputs_hash: [u8; HASH_LEN_V1],
    pub trace_digest: [u8; HASH_LEN_V1],
    pub trace_layout_digest: [u8; HASH_LEN_V1],
    pub proof_bytes: Vec<u8>,
    pub proof_binding_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalProofArtifactV1 {
    Mock(LocalMockProofArtifactV1),
    Stark(LocalStarkProofArtifactV1),
}

#[derive(Debug)]
pub enum LocalProverErrorV1 {
    TraceBuilder(TraceBuilderErrorV1),
    StarkBackend(StarkBackendErrorV1),
}

impl fmt::Display for LocalProverErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceBuilder(error) => write!(f, "trace builder error: {error}"),
            Self::StarkBackend(error) => write!(f, "stark backend error: {error}"),
        }
    }
}

impl std::error::Error for LocalProverErrorV1 {}

impl From<TraceBuilderErrorV1> for LocalProverErrorV1 {
    fn from(value: TraceBuilderErrorV1) -> Self {
        Self::TraceBuilder(value)
    }
}

impl From<StarkBackendErrorV1> for LocalProverErrorV1 {
    fn from(value: StarkBackendErrorV1) -> Self {
        Self::StarkBackend(value)
    }
}

pub trait LocalProverBackendV1 {
    fn proof_system_kind(&self) -> LocalProofSystemKindV1;

    fn prepare_proof_inputs(
        &self,
        bundle: &TraceWitnessBundleV1,
    ) -> Result<PreparedProofInputsV1, LocalProverErrorV1> {
        prepare_proof_inputs_v1(bundle)
    }

    fn prove_prepared(
        &self,
        prepared: &PreparedProofInputsV1,
    ) -> Result<LocalProofArtifactV1, LocalProverErrorV1>;

    fn prove_trace_witness_bundle(
        &self,
        bundle: &TraceWitnessBundleV1,
    ) -> Result<LocalProofArtifactV1, LocalProverErrorV1> {
        let prepared = self.prepare_proof_inputs(bundle)?;
        self.prove_prepared(&prepared)
    }

    fn prove_executed_batch(
        &self,
        executed: &ExecutedBatchV1,
    ) -> Result<LocalProofArtifactV1, LocalProverErrorV1> {
        let bundle = build_trace_witness_bundle_v1(executed)?;
        self.prove_trace_witness_bundle(&bundle)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MockProverV1;

impl MockProverV1 {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_trace_witness_bundle(
        &self,
        bundle: &TraceWitnessBundleV1,
    ) -> Result<LocalMockProofArtifactV1, LocalProverErrorV1> {
        let prepared = self.prepare_proof_inputs(bundle)?;
        Ok(self.materialize_mock_artifact(&prepared))
    }

    pub fn prove_executed_batch(
        &self,
        executed: &ExecutedBatchV1,
    ) -> Result<LocalMockProofArtifactV1, LocalProverErrorV1> {
        let bundle = build_trace_witness_bundle_v1(executed)?;
        self.prove_trace_witness_bundle(&bundle)
    }

    pub fn materialize_mock_artifact(
        &self,
        prepared: &PreparedProofInputsV1,
    ) -> LocalMockProofArtifactV1 {
        let proof_binding_digest = derive_mock_proof_binding_digest_v1(
            LOCAL_MOCK_PROOF_VERSION_V1,
            &prepared.public_inputs_hash,
            &prepared.trace_digest,
            &prepared.trace_layout_digest,
            &prepared.witness_digest,
        );

        LocalMockProofArtifactV1 {
            prover_kind: LOCAL_PROVER_KIND_MOCK_V1,
            proof_version: LOCAL_MOCK_PROOF_VERSION_V1,
            public_inputs_hash: prepared.public_inputs_hash,
            trace_digest: prepared.trace_digest,
            trace_layout_digest: prepared.trace_layout_digest,
            witness_digest: prepared.witness_digest,
            proof_binding_digest,
            witness_bundle: prepared.witness_bundle.clone(),
        }
    }
}

impl LocalProverBackendV1 for MockProverV1 {
    fn proof_system_kind(&self) -> LocalProofSystemKindV1 {
        LocalProofSystemKindV1::Mock
    }

    fn prove_prepared(
        &self,
        prepared: &PreparedProofInputsV1,
    ) -> Result<LocalProofArtifactV1, LocalProverErrorV1> {
        Ok(LocalProofArtifactV1::Mock(
            self.materialize_mock_artifact(prepared),
        ))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StarkProverV1;

impl StarkProverV1 {
    pub fn new() -> Self {
        Self
    }

    pub fn prepare_stark_request(
        &self,
        bundle: &TraceWitnessBundleV1,
    ) -> Result<StarkProofRequestV1, LocalProverErrorV1> {
        let prepared = self.prepare_proof_inputs(bundle)?;
        Ok(self.prepare_stark_request_from_prepared(&prepared))
    }

    pub fn prepare_stark_request_from_prepared(
        &self,
        prepared: &PreparedProofInputsV1,
    ) -> StarkProofRequestV1 {
        let request_binding_digest = derive_stark_request_binding_digest_v1(
            LOCAL_STARK_PROOF_VERSION_V1,
            &prepared.public_inputs_hash,
            &prepared.trace_digest,
            &prepared.trace_layout_digest,
            &prepared.witness_digest,
        );

        StarkProofRequestV1 {
            prover_kind: LOCAL_PROVER_KIND_STARK_V1,
            proof_version: LOCAL_STARK_PROOF_VERSION_V1,
            public_inputs_hash: prepared.public_inputs_hash,
            trace_digest: prepared.trace_digest,
            trace_layout_digest: prepared.trace_layout_digest,
            witness_digest: prepared.witness_digest,
            request_binding_digest,
            witness_bundle: prepared.witness_bundle.clone(),
        }
    }

    pub fn materialize_stark_artifact_from_backend_output(
        &self,
        request: &StarkProofRequestV1,
        proof_bytes: &[u8],
    ) -> LocalStarkProofArtifactV1 {
        let proof_binding_digest = derive_stark_proof_binding_digest_v1(
            request.proof_version,
            &request.public_inputs_hash,
            &request.trace_digest,
            &request.trace_layout_digest,
            proof_bytes,
        );

        LocalStarkProofArtifactV1 {
            prover_kind: LOCAL_PROVER_KIND_STARK_V1,
            proof_version: request.proof_version,
            public_inputs_hash: request.public_inputs_hash,
            trace_digest: request.trace_digest,
            trace_layout_digest: request.trace_layout_digest,
            proof_bytes: proof_bytes.to_vec(),
            proof_binding_digest,
        }
    }
}

impl LocalProverBackendV1 for StarkProverV1 {
    fn proof_system_kind(&self) -> LocalProofSystemKindV1 {
        LocalProofSystemKindV1::Stark
    }

    fn prove_prepared(
        &self,
        prepared: &PreparedProofInputsV1,
    ) -> Result<LocalProofArtifactV1, LocalProverErrorV1> {
        let request = self.prepare_stark_request_from_prepared(prepared);
        let proof_bytes = prove_with_winterfell_backend_v1(prepared)?;
        Ok(LocalProofArtifactV1::Stark(
            self.materialize_stark_artifact_from_backend_output(&request, &proof_bytes),
        ))
    }
}

pub fn prepare_proof_inputs_v1(
    bundle: &TraceWitnessBundleV1,
) -> Result<PreparedProofInputsV1, LocalProverErrorV1> {
    validate_trace_witness_bundle_v1(bundle)?;

    Ok(PreparedProofInputsV1 {
        public_inputs_hash: sha256_bytes(&bundle.public_inputs_bytes),
        trace_digest: bundle.trace_digest,
        trace_layout_digest: bundle.trace_layout_digest,
        witness_digest: derive_witness_digest_v1(bundle),
        witness_bundle: bundle.clone(),
    })
}

pub fn prove_executed_batch_with_mock_prover_v1(
    executed: &ExecutedBatchV1,
) -> Result<LocalMockProofArtifactV1, LocalProverErrorV1> {
    MockProverV1::new().prove_executed_batch(executed)
}

pub fn prove_trace_witness_bundle_with_mock_prover_v1(
    bundle: &TraceWitnessBundleV1,
) -> Result<LocalMockProofArtifactV1, LocalProverErrorV1> {
    MockProverV1::new().prove_trace_witness_bundle(bundle)
}

pub fn prove_executed_batch_with_stark_prover_v1(
    executed: &ExecutedBatchV1,
) -> Result<LocalStarkProofArtifactV1, LocalProverErrorV1> {
    StarkProverV1::new()
        .prove_executed_batch(executed)
        .map(|artifact| match artifact {
            LocalProofArtifactV1::Stark(stark) => stark,
            LocalProofArtifactV1::Mock(_) => unreachable!("stark prover returned mock artifact"),
        })
}

pub fn derive_mock_proof_binding_digest_v1(
    proof_version: u32,
    public_inputs_hash: &[u8; HASH_LEN_V1],
    trace_digest: &[u8; HASH_LEN_V1],
    trace_layout_digest: &[u8; HASH_LEN_V1],
    witness_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_L2_LOCAL_MOCK_PROOF_BINDING_DOMAIN_SEPARATOR_V1.len() + 4 + 32 + 32 + 32 + 32,
    );
    preimage.extend_from_slice(AURA_L2_LOCAL_MOCK_PROOF_BINDING_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&proof_version.to_le_bytes());
    preimage.extend_from_slice(public_inputs_hash);
    preimage.extend_from_slice(trace_digest);
    preimage.extend_from_slice(trace_layout_digest);
    preimage.extend_from_slice(witness_digest);
    sha256_bytes(&preimage)
}

pub fn derive_stark_request_binding_digest_v1(
    proof_version: u32,
    public_inputs_hash: &[u8; HASH_LEN_V1],
    trace_digest: &[u8; HASH_LEN_V1],
    trace_layout_digest: &[u8; HASH_LEN_V1],
    witness_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_L2_LOCAL_STARK_REQUEST_BINDING_DOMAIN_SEPARATOR_V1.len() + 4 + 32 + 32 + 32 + 32,
    );
    preimage.extend_from_slice(AURA_L2_LOCAL_STARK_REQUEST_BINDING_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&proof_version.to_le_bytes());
    preimage.extend_from_slice(public_inputs_hash);
    preimage.extend_from_slice(trace_digest);
    preimage.extend_from_slice(trace_layout_digest);
    preimage.extend_from_slice(witness_digest);
    sha256_bytes(&preimage)
}

pub fn derive_stark_proof_binding_digest_v1(
    proof_version: u32,
    public_inputs_hash: &[u8; HASH_LEN_V1],
    trace_digest: &[u8; HASH_LEN_V1],
    trace_layout_digest: &[u8; HASH_LEN_V1],
    proof_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let proof_bytes_hash = sha256_bytes(proof_bytes);
    let mut preimage = Vec::with_capacity(
        AURA_L2_LOCAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR_V1.len() + 4 + 32 + 32 + 32 + 32,
    );
    preimage.extend_from_slice(AURA_L2_LOCAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&proof_version.to_le_bytes());
    preimage.extend_from_slice(public_inputs_hash);
    preimage.extend_from_slice(trace_digest);
    preimage.extend_from_slice(trace_layout_digest);
    preimage.extend_from_slice(&proof_bytes_hash);
    sha256_bytes(&preimage)
}

#[cfg(test)]
mod tests {
    use super::{
        prepare_proof_inputs_v1, prove_executed_batch_with_mock_prover_v1,
        prove_executed_batch_with_stark_prover_v1, prove_trace_witness_bundle_with_mock_prover_v1,
        LocalProofArtifactV1, LocalProverBackendV1, MockProverV1, StarkProverV1,
        LOCAL_MOCK_PROOF_VERSION_V1, LOCAL_PROVER_KIND_MOCK_V1, LOCAL_PROVER_KIND_STARK_V1,
        LOCAL_STARK_PROOF_VERSION_V1,
    };
    use aura_l2_execution_v1::{
        execute_transfer_batch_v1, BatchExecutionRequestV1, LocalAccountV1, LocalExecutionConfigV1,
        LocalStateV1, TransferTransactionV1, TRANSFER_TX_VERSION_V1, ZERO32_V1,
    };

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn canonical_executed_batch() -> aura_l2_execution_v1::ExecutedBatchV1 {
        let state = LocalStateV1::new([
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
        ])
        .unwrap();
        execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(id(0xAA)),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 10,
                }],
            },
        )
        .unwrap()
    }

    #[test]
    fn mock_and_stark_interfaces_prepare_identical_inputs() {
        let executed = canonical_executed_batch();
        let bundle = aura_l2_trace_builder_v1::build_trace_witness_bundle_v1(&executed).unwrap();

        let mock_prepared = MockProverV1::new().prepare_proof_inputs(&bundle).unwrap();
        let stark_prepared = StarkProverV1::new().prepare_proof_inputs(&bundle).unwrap();

        assert_eq!(mock_prepared, stark_prepared);
        assert_eq!(mock_prepared.witness_bundle.public_inputs_bytes.len(), 284);
    }

    #[test]
    fn mock_wrapper_and_struct_paths_match() {
        let executed = canonical_executed_batch();
        let bundle = aura_l2_trace_builder_v1::build_trace_witness_bundle_v1(&executed).unwrap();

        let from_wrapper = prove_executed_batch_with_mock_prover_v1(&executed).unwrap();
        let from_bundle_wrapper = prove_trace_witness_bundle_with_mock_prover_v1(&bundle).unwrap();
        let from_struct = MockProverV1::new().prove_executed_batch(&executed).unwrap();

        assert_eq!(from_wrapper, from_bundle_wrapper);
        assert_eq!(from_wrapper, from_struct);
        assert_eq!(from_struct.prover_kind, LOCAL_PROVER_KIND_MOCK_V1);
        assert_eq!(from_struct.proof_version, LOCAL_MOCK_PROOF_VERSION_V1);
    }

    #[test]
    fn stark_request_matches_prepared_inputs() {
        let executed = canonical_executed_batch();
        let bundle = aura_l2_trace_builder_v1::build_trace_witness_bundle_v1(&executed).unwrap();
        let prepared = prepare_proof_inputs_v1(&bundle).unwrap();
        let request = StarkProverV1::new().prepare_stark_request(&bundle).unwrap();

        assert_eq!(request.prover_kind, LOCAL_PROVER_KIND_STARK_V1);
        assert_eq!(request.proof_version, LOCAL_STARK_PROOF_VERSION_V1);
        assert_eq!(request.public_inputs_hash, prepared.public_inputs_hash);
        assert_eq!(request.trace_digest, prepared.trace_digest);
        assert_eq!(request.trace_layout_digest, prepared.trace_layout_digest);
        assert_eq!(request.witness_digest, prepared.witness_digest);
        assert_eq!(request.witness_bundle, prepared.witness_bundle);
    }

    #[test]
    fn stark_prover_generates_non_empty_proof_artifact() {
        let executed = canonical_executed_batch();
        let proof = prove_executed_batch_with_stark_prover_v1(&executed).unwrap();
        assert_eq!(proof.prover_kind, LOCAL_PROVER_KIND_STARK_V1);
        assert_eq!(proof.proof_version, LOCAL_STARK_PROOF_VERSION_V1);
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn mock_trait_dispatch_preserves_artifact_kind() {
        let executed = canonical_executed_batch();
        let artifact =
            LocalProverBackendV1::prove_executed_batch(&MockProverV1::new(), &executed).unwrap();
        match artifact {
            LocalProofArtifactV1::Mock(mock) => {
                assert_eq!(mock.prover_kind, LOCAL_PROVER_KIND_MOCK_V1);
            }
            LocalProofArtifactV1::Stark(_) => panic!("unexpected stark artifact"),
        }
    }

    #[test]
    fn stark_trait_dispatch_preserves_artifact_kind() {
        let executed = canonical_executed_batch();
        let artifact =
            LocalProverBackendV1::prove_executed_batch(&StarkProverV1::new(), &executed).unwrap();
        match artifact {
            LocalProofArtifactV1::Stark(stark) => {
                assert_eq!(stark.prover_kind, LOCAL_PROVER_KIND_STARK_V1);
                assert!(!stark.proof_bytes.is_empty());
            }
            LocalProofArtifactV1::Mock(_) => panic!("unexpected mock artifact"),
        }
    }

    #[test]
    fn stark_prover_rejects_malformed_trace_bundle() {
        let executed = canonical_executed_batch();
        let mut bundle =
            aura_l2_trace_builder_v1::build_trace_witness_bundle_v1(&executed).unwrap();
        bundle.trace_rows[0].recipient_balance_after += 1;
        bundle.stark_trace_layout.rows[0].recipient_balance_after += 1;

        let error =
            LocalProverBackendV1::prove_trace_witness_bundle(&StarkProverV1::new(), &bundle)
                .unwrap_err();
        assert!(matches!(error, super::LocalProverErrorV1::TraceBuilder(_)));
    }

    #[test]
    fn stark_prover_rejects_malformed_public_input_binding() {
        let executed = canonical_executed_batch();
        let mut bundle =
            aura_l2_trace_builder_v1::build_trace_witness_bundle_v1(&executed).unwrap();
        bundle.public_inputs_bytes[0] ^= 0x01;

        let error = StarkProverV1::new()
            .prepare_proof_inputs(&bundle)
            .unwrap_err();
        assert!(matches!(error, super::LocalProverErrorV1::TraceBuilder(_)));
    }
}
