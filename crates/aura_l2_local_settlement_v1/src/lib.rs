//! Aura L2 local settlement engine for the first complete proving-chain milestone.
//!
//! This crate is not Solana settlement. It is the local acceptance engine that:
//!
//! - enforces linear batch lineage
//! - binds acceptance to the exact 284-byte public-input schema
//! - depends on explicit proof verification
//! - advances the local settled state root only on success
//!
//! Current accepted proof modes are mock and real STARK.
//! This remains local settlement only; no part of this crate is Solana settlement.

use core::fmt;
use std::collections::BTreeSet;

use aura_l2_execution_v1::{HASH_LEN_V1, ZERO32_V1};
use aura_l2_prover_v1::{LocalMockProofArtifactV1, LocalProofArtifactV1};
use aura_l2_public_input_v1::{PublicInputSchemaErrorV1, TransitionEnvelopeV1};
use aura_l2_verifier_v1::{verify_proof_artifact_v1, LocalVerifierErrorV1};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSettlementStateV1 {
    pub rollup_id: [u8; HASH_LEN_V1],
    pub expected_batch_number: u64,
    pub current_state_root: [u8; HASH_LEN_V1],
    pub head_transition_binding_hash: [u8; HASH_LEN_V1],
    pub accepted_batch_numbers: BTreeSet<u64>,
    pub accepted_transition_hashes: BTreeSet<[u8; HASH_LEN_V1]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedTransitionV1 {
    pub batch_number: u64,
    pub transition_binding_hash: [u8; HASH_LEN_V1],
    pub new_state_root: [u8; HASH_LEN_V1],
}

#[derive(Debug)]
pub enum LocalSettlementErrorV1 {
    PublicInputSchema(PublicInputSchemaErrorV1),
    RollupIdMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    BatchNumberMismatch {
        expected: u64,
        actual: u64,
    },
    DuplicateBatchNumber {
        batch_number: u64,
    },
    DuplicateTransitionHash {
        transition_binding_hash: [u8; HASH_LEN_V1],
    },
    GenesisParentMismatch {
        actual: [u8; HASH_LEN_V1],
    },
    ParentBatchCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    PreStateRootMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    VerificationFailed(LocalVerifierErrorV1),
}

impl fmt::Display for LocalSettlementErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicInputSchema(error) => write!(f, "public input schema error: {error}"),
            Self::RollupIdMismatch { .. } => write!(f, "rollup id mismatch"),
            Self::BatchNumberMismatch { expected, actual } => {
                write!(
                    f,
                    "batch number mismatch: expected {expected}, got {actual}"
                )
            }
            Self::DuplicateBatchNumber { batch_number } => {
                write!(f, "duplicate batch number {batch_number}")
            }
            Self::DuplicateTransitionHash { .. } => write!(f, "duplicate transition hash"),
            Self::GenesisParentMismatch { .. } => write!(f, "genesis parent mismatch"),
            Self::ParentBatchCommitmentMismatch { .. } => {
                write!(f, "parent batch commitment mismatch")
            }
            Self::PreStateRootMismatch { .. } => write!(f, "pre-state root mismatch"),
            Self::VerificationFailed(error) => write!(f, "verification failed: {error}"),
        }
    }
}

impl std::error::Error for LocalSettlementErrorV1 {}

impl From<PublicInputSchemaErrorV1> for LocalSettlementErrorV1 {
    fn from(value: PublicInputSchemaErrorV1) -> Self {
        Self::PublicInputSchema(value)
    }
}

impl LocalSettlementStateV1 {
    pub fn new(rollup_id: [u8; HASH_LEN_V1], genesis_state_root: [u8; HASH_LEN_V1]) -> Self {
        Self {
            rollup_id,
            expected_batch_number: 0,
            current_state_root: genesis_state_root,
            head_transition_binding_hash: ZERO32_V1,
            accepted_batch_numbers: BTreeSet::new(),
            accepted_transition_hashes: BTreeSet::new(),
        }
    }
}

pub fn accept_transition_v1(
    settlement_state: &mut LocalSettlementStateV1,
    public_inputs_bytes: &[u8],
    proof_artifact: &LocalProofArtifactV1,
) -> Result<AcceptedTransitionV1, LocalSettlementErrorV1> {
    let envelope = TransitionEnvelopeV1::decode_exact(public_inputs_bytes)?;

    if envelope.rollup_id != settlement_state.rollup_id {
        return Err(LocalSettlementErrorV1::RollupIdMismatch {
            expected: settlement_state.rollup_id,
            actual: envelope.rollup_id,
        });
    }
    if envelope.batch_number != settlement_state.expected_batch_number {
        return Err(LocalSettlementErrorV1::BatchNumberMismatch {
            expected: settlement_state.expected_batch_number,
            actual: envelope.batch_number,
        });
    }
    if settlement_state
        .accepted_batch_numbers
        .contains(&envelope.batch_number)
    {
        return Err(LocalSettlementErrorV1::DuplicateBatchNumber {
            batch_number: envelope.batch_number,
        });
    }
    if envelope.batch_number == 0 {
        if envelope.parent_batch_commitment != ZERO32_V1 {
            return Err(LocalSettlementErrorV1::GenesisParentMismatch {
                actual: envelope.parent_batch_commitment,
            });
        }
    } else if envelope.parent_batch_commitment != settlement_state.head_transition_binding_hash {
        return Err(LocalSettlementErrorV1::ParentBatchCommitmentMismatch {
            expected: settlement_state.head_transition_binding_hash,
            actual: envelope.parent_batch_commitment,
        });
    }
    if envelope.pre_state_root != settlement_state.current_state_root {
        return Err(LocalSettlementErrorV1::PreStateRootMismatch {
            expected: settlement_state.current_state_root,
            actual: envelope.pre_state_root,
        });
    }

    let verified = verify_proof_artifact_v1(public_inputs_bytes, proof_artifact)
        .map_err(LocalSettlementErrorV1::VerificationFailed)?;

    let transition_binding_hash = verified.transition_binding_hash;
    if settlement_state
        .accepted_transition_hashes
        .contains(&transition_binding_hash)
    {
        return Err(LocalSettlementErrorV1::DuplicateTransitionHash {
            transition_binding_hash,
        });
    }

    settlement_state
        .accepted_batch_numbers
        .insert(envelope.batch_number);
    settlement_state
        .accepted_transition_hashes
        .insert(transition_binding_hash);
    settlement_state.current_state_root = envelope.post_state_root;
    settlement_state.head_transition_binding_hash = transition_binding_hash;
    settlement_state.expected_batch_number += 1;

    Ok(AcceptedTransitionV1 {
        batch_number: envelope.batch_number,
        transition_binding_hash,
        new_state_root: envelope.post_state_root,
    })
}

pub fn accept_mock_transition_v1(
    settlement_state: &mut LocalSettlementStateV1,
    public_inputs_bytes: &[u8],
    proof_artifact: &LocalMockProofArtifactV1,
) -> Result<AcceptedTransitionV1, LocalSettlementErrorV1> {
    accept_transition_v1(
        settlement_state,
        public_inputs_bytes,
        &LocalProofArtifactV1::Mock(proof_artifact.clone()),
    )
}

#[cfg(test)]
mod tests {
    use aura_l2_execution_v1::{
        execute_transfer_batch_v1, BatchExecutionRequestV1, LocalAccountV1, LocalExecutionConfigV1,
        LocalStateV1, TransferTransactionV1, TRANSFER_TX_VERSION_V1, ZERO32_V1,
    };
    use aura_l2_prover_v1::{
        prove_executed_batch_with_mock_prover_v1, prove_executed_batch_with_stark_prover_v1,
        LocalProofArtifactV1,
    };
    use aura_l2_public_input_v1::TransitionEnvelopeV1;
    use aura_l2_trace_builder_v1::{build_trace_witness_bundle_v1, validate_air_expectations_v1};
    use aura_l2_verifier_v1::verify_proof_artifact_v1;

    use super::{
        accept_mock_transition_v1, accept_transition_v1, LocalSettlementErrorV1,
        LocalSettlementStateV1,
    };

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn canonical_case() -> (
        LocalSettlementStateV1,
        [u8; aura_l2_public_input_v1::PUBLIC_INPUT_SCHEMA_LEN_V1],
        aura_l2_prover_v1::LocalMockProofArtifactV1,
    ) {
        let genesis = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 90,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x22),
                balance: 10,
                nonce: 0,
            },
        ])
        .unwrap();
        let config = LocalExecutionConfigV1::new(id(0xAA));
        let executed = execute_transfer_batch_v1(
            &genesis,
            &config,
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 9,
                }],
            },
        )
        .unwrap();
        let public_inputs = TransitionEnvelopeV1::from_executed_batch(&executed).encode_bytes();
        let proof = prove_executed_batch_with_mock_prover_v1(&executed).unwrap();
        let settlement = LocalSettlementStateV1::new(config.rollup_id, genesis.state_root());
        (settlement, public_inputs, proof)
    }

    fn canonical_stark_case() -> (
        LocalSettlementStateV1,
        [u8; aura_l2_public_input_v1::PUBLIC_INPUT_SCHEMA_LEN_V1],
        aura_l2_prover_v1::LocalStarkProofArtifactV1,
    ) {
        let genesis = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 90,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x22),
                balance: 10,
                nonce: 0,
            },
        ])
        .unwrap();
        let config = LocalExecutionConfigV1::new(id(0xAA));
        let executed = execute_transfer_batch_v1(
            &genesis,
            &config,
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 9,
                }],
            },
        )
        .unwrap();
        let public_inputs = TransitionEnvelopeV1::from_executed_batch(&executed).encode_bytes();
        let proof = prove_executed_batch_with_stark_prover_v1(&executed).unwrap();
        let settlement = LocalSettlementStateV1::new(config.rollup_id, genesis.state_root());
        (settlement, public_inputs, proof)
    }

    #[test]
    fn local_settlement_advances_state_only_on_valid_proof() {
        let (mut settlement, public_inputs, proof) = canonical_case();
        let accepted = accept_mock_transition_v1(&mut settlement, &public_inputs, &proof).unwrap();
        assert_eq!(accepted.batch_number, 0);
        assert_eq!(settlement.expected_batch_number, 1);
        assert_eq!(settlement.current_state_root, accepted.new_state_root);
    }

    #[test]
    fn generic_acceptance_matches_mock_wrapper_semantics() {
        let (settlement_a, public_inputs, proof) = canonical_case();
        let mut settlement_b = settlement_a.clone();
        let wrapper = accept_mock_transition_v1(&mut settlement_b, &public_inputs, &proof).unwrap();

        let mut settlement_c = settlement_a;
        let generic = accept_transition_v1(
            &mut settlement_c,
            &public_inputs,
            &LocalProofArtifactV1::Mock(proof),
        )
        .unwrap();

        assert_eq!(wrapper, generic);
        assert_eq!(settlement_b, settlement_c);
    }

    #[test]
    fn local_settlement_rejects_invalid_transition() {
        let (mut settlement, mut public_inputs, proof) = canonical_case();
        public_inputs[44] = 1;
        let error = accept_mock_transition_v1(&mut settlement, &public_inputs, &proof).unwrap_err();
        assert!(matches!(
            error,
            LocalSettlementErrorV1::PublicInputSchema(_)
                | LocalSettlementErrorV1::BatchNumberMismatch { .. }
                | LocalSettlementErrorV1::VerificationFailed(_)
        ));
    }

    #[test]
    fn real_stark_settlement_advances_state() {
        let (mut settlement, public_inputs, proof) = canonical_stark_case();
        let accepted = accept_transition_v1(
            &mut settlement,
            &public_inputs,
            &LocalProofArtifactV1::Stark(proof),
        )
        .unwrap();
        assert_eq!(accepted.batch_number, 0);
        assert_eq!(settlement.expected_batch_number, 1);
        assert_eq!(settlement.current_state_root, accepted.new_state_root);
    }

    #[test]
    fn mock_and_real_settlement_paths_match() {
        let (settlement_base, public_inputs_mock, mock_proof) = canonical_case();
        let (mut settlement_mock, _, _) = canonical_case();
        let mock_accepted =
            accept_mock_transition_v1(&mut settlement_mock, &public_inputs_mock, &mock_proof)
                .unwrap();

        let (mut settlement_real, public_inputs_real, real_proof) = canonical_stark_case();
        assert_eq!(settlement_base, settlement_real);
        assert_eq!(public_inputs_mock, public_inputs_real);

        let real_accepted = accept_transition_v1(
            &mut settlement_real,
            &public_inputs_real,
            &LocalProofArtifactV1::Stark(real_proof),
        )
        .unwrap();

        assert_eq!(mock_accepted, real_accepted);
        assert_eq!(settlement_mock, settlement_real);
    }

    #[test]
    fn duplicate_transition_acceptance_rejects() {
        let (mut settlement, public_inputs, proof) = canonical_stark_case();
        let first = accept_transition_v1(
            &mut settlement,
            &public_inputs,
            &LocalProofArtifactV1::Stark(proof.clone()),
        )
        .unwrap();

        let second = accept_transition_v1(
            &mut settlement,
            &public_inputs,
            &LocalProofArtifactV1::Stark(proof),
        )
        .unwrap_err();

        assert_eq!(first.batch_number, 0);
        assert!(matches!(
            second,
            LocalSettlementErrorV1::BatchNumberMismatch { .. }
                | LocalSettlementErrorV1::DuplicateBatchNumber { .. }
                | LocalSettlementErrorV1::DuplicateTransitionHash { .. }
        ));
    }

    #[test]
    fn truncated_public_inputs_reject_before_acceptance() {
        let (mut settlement, public_inputs, proof) = canonical_stark_case();
        let error = accept_transition_v1(
            &mut settlement,
            &public_inputs[..public_inputs.len() - 1],
            &LocalProofArtifactV1::Stark(proof),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            LocalSettlementErrorV1::PublicInputSchema(_)
        ));
    }

    #[test]
    fn execution_trace_air_proof_and_settlement_are_consistent_for_real_stark() {
        let genesis = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x11),
                balance: 90,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x22),
                balance: 10,
                nonce: 0,
            },
        ])
        .unwrap();
        let config = LocalExecutionConfigV1::new(id(0xAA));
        let executed = execute_transfer_batch_v1(
            &genesis,
            &config,
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x11),
                    recipient_account_id: id(0x22),
                    sender_nonce: 0,
                    amount: 9,
                }],
            },
        )
        .unwrap();
        let bundle = build_trace_witness_bundle_v1(&executed).unwrap();
        validate_air_expectations_v1(&bundle).unwrap();

        let public_inputs = TransitionEnvelopeV1::from_executed_batch(&executed).encode_bytes();
        let proof = prove_executed_batch_with_stark_prover_v1(&executed).unwrap();
        let verified =
            verify_proof_artifact_v1(&public_inputs, &LocalProofArtifactV1::Stark(proof.clone()))
                .unwrap();
        let mut settlement = LocalSettlementStateV1::new(config.rollup_id, genesis.state_root());
        let accepted = accept_transition_v1(
            &mut settlement,
            &public_inputs,
            &LocalProofArtifactV1::Stark(proof),
        )
        .unwrap();

        assert_eq!(
            executed.post_state_root,
            bundle.public_inputs.post_state_root
        );
        assert_eq!(accepted.new_state_root, executed.post_state_root);
        assert_eq!(
            verified.transition_binding_hash,
            bundle.public_inputs.transition_binding_hash_v1()
        );
        assert_eq!(
            accepted.transition_binding_hash,
            verified.transition_binding_hash
        );
        assert_eq!(settlement.current_state_root, executed.post_state_root);
    }
}
