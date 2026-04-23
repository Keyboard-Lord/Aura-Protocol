//! Exact Aura L2 public-input schema implementation for version 1.
//!
//! This crate implements the frozen 13-field, 284-byte public-input surface
//! defined by:
//!
//! - `AURA_L2_TRANSITION_BINDING_CONTRACT_V1.md`
//! - `AURA_L2_PUBLIC_INPUT_SCHEMA_V1.md`
//!
//! The surface is strict:
//!
//! - one field order
//! - one fixed width
//! - one byte encoding
//! - one transition-binding hash path
//!
//! This crate does not implement witness parsing, proving, or settlement logic.

use core::fmt;

use aura_l2_execution_v1::{
    sha256_bytes, ExecutedBatchV1, HASH_LEN_V1, TRANSITION_BINDING_VERSION_V1,
};

pub const PUBLIC_INPUT_SCHEMA_LEN_V1: usize = 284;
pub const D_BINDING_V1: &[u8] = b"AURA_L2_TRANSITION_BINDING_V1";
pub const ZERO32_V1: [u8; HASH_LEN_V1] = [0u8; HASH_LEN_V1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionClaimV1 {
    pub pre_state_root: [u8; HASH_LEN_V1],
    pub post_state_root: [u8; HASH_LEN_V1],
    pub transactions_commitment: [u8; HASH_LEN_V1],
    pub outcomes_commitment: [u8; HASH_LEN_V1],
    pub batch_context_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionEnvelopeV1 {
    pub transition_binding_version: u32,
    pub rollup_id: [u8; HASH_LEN_V1],
    pub execution_model_version: u32,
    pub batch_version: u32,
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; HASH_LEN_V1],
    pub tx_count: u64,
    pub fee_summary_commitment: [u8; HASH_LEN_V1],
    pub pre_state_root: [u8; HASH_LEN_V1],
    pub post_state_root: [u8; HASH_LEN_V1],
    pub transactions_commitment: [u8; HASH_LEN_V1],
    pub outcomes_commitment: [u8; HASH_LEN_V1],
    pub batch_context_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicInputSchemaErrorV1 {
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    UnsupportedTransitionBindingVersion {
        expected: u32,
        actual: u32,
    },
    RollupIdMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ExecutionModelVersionMismatch {
        expected: u32,
        actual: u32,
    },
    BatchVersionMismatch {
        expected: u32,
        actual: u32,
    },
    BatchNumberMismatch {
        expected: u64,
        actual: u64,
    },
    ParentBatchCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    TxCountMismatch {
        expected: u64,
        actual: u64,
    },
    FeeSummaryCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    PreStateRootMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    PostStateRootMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    TransactionsCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    OutcomesCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    BatchContextCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    NonZeroGenesisParent {
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for PublicInputSchemaErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid public input length: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedTransitionBindingVersion { expected, actual } => write!(
                f,
                "unsupported transition binding version: expected {expected}, got {actual}"
            ),
            Self::RollupIdMismatch { .. } => write!(f, "rollup id mismatch"),
            Self::ExecutionModelVersionMismatch { expected, actual } => write!(
                f,
                "execution model version mismatch: expected {expected}, got {actual}"
            ),
            Self::BatchVersionMismatch { expected, actual } => {
                write!(
                    f,
                    "batch version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::BatchNumberMismatch { expected, actual } => {
                write!(
                    f,
                    "batch number mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ParentBatchCommitmentMismatch { .. } => {
                write!(f, "parent batch commitment mismatch")
            }
            Self::TxCountMismatch { expected, actual } => {
                write!(f, "tx count mismatch: expected {expected}, got {actual}")
            }
            Self::FeeSummaryCommitmentMismatch { .. } => {
                write!(f, "fee summary commitment mismatch")
            }
            Self::PreStateRootMismatch { .. } => write!(f, "pre-state root mismatch"),
            Self::PostStateRootMismatch { .. } => write!(f, "post-state root mismatch"),
            Self::TransactionsCommitmentMismatch { .. } => {
                write!(f, "transactions commitment mismatch")
            }
            Self::OutcomesCommitmentMismatch { .. } => {
                write!(f, "outcomes commitment mismatch")
            }
            Self::BatchContextCommitmentMismatch { .. } => {
                write!(f, "batch context commitment mismatch")
            }
            Self::NonZeroGenesisParent { .. } => write!(f, "genesis parent must be zero32"),
        }
    }
}

impl std::error::Error for PublicInputSchemaErrorV1 {}

impl TransitionEnvelopeV1 {
    pub fn from_executed_batch(executed: &ExecutedBatchV1) -> Self {
        Self {
            transition_binding_version: TRANSITION_BINDING_VERSION_V1,
            rollup_id: executed.config.rollup_id,
            execution_model_version: executed.config.execution_model_version,
            batch_version: executed.config.batch_version,
            batch_number: executed.batch_number,
            parent_batch_commitment: executed.parent_batch_commitment,
            tx_count: executed.tx_count,
            fee_summary_commitment: executed.fee_summary_commitment,
            pre_state_root: executed.pre_state_root,
            post_state_root: executed.post_state_root,
            transactions_commitment: executed.transactions_commitment,
            outcomes_commitment: executed.outcomes_commitment,
            batch_context_commitment: executed.batch_context_commitment,
        }
    }

    pub fn claim(&self) -> TransitionClaimV1 {
        TransitionClaimV1 {
            pre_state_root: self.pre_state_root,
            post_state_root: self.post_state_root,
            transactions_commitment: self.transactions_commitment,
            outcomes_commitment: self.outcomes_commitment,
            batch_context_commitment: self.batch_context_commitment,
        }
    }

    pub fn encode_bytes(&self) -> [u8; PUBLIC_INPUT_SCHEMA_LEN_V1] {
        let mut bytes = [0u8; PUBLIC_INPUT_SCHEMA_LEN_V1];
        bytes[0..4].copy_from_slice(&self.transition_binding_version.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.rollup_id);
        bytes[36..40].copy_from_slice(&self.execution_model_version.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.batch_version.to_le_bytes());
        bytes[44..52].copy_from_slice(&self.batch_number.to_le_bytes());
        bytes[52..84].copy_from_slice(&self.parent_batch_commitment);
        bytes[84..92].copy_from_slice(&self.tx_count.to_le_bytes());
        bytes[92..124].copy_from_slice(&self.fee_summary_commitment);
        bytes[124..156].copy_from_slice(&self.pre_state_root);
        bytes[156..188].copy_from_slice(&self.post_state_root);
        bytes[188..220].copy_from_slice(&self.transactions_commitment);
        bytes[220..252].copy_from_slice(&self.outcomes_commitment);
        bytes[252..284].copy_from_slice(&self.batch_context_commitment);
        bytes
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, PublicInputSchemaErrorV1> {
        if bytes.len() != PUBLIC_INPUT_SCHEMA_LEN_V1 {
            return Err(PublicInputSchemaErrorV1::InvalidLength {
                expected: PUBLIC_INPUT_SCHEMA_LEN_V1,
                actual: bytes.len(),
            });
        }

        let mut rollup_id = [0u8; HASH_LEN_V1];
        rollup_id.copy_from_slice(&bytes[4..36]);
        let mut parent_batch_commitment = [0u8; HASH_LEN_V1];
        parent_batch_commitment.copy_from_slice(&bytes[52..84]);
        let mut fee_summary_commitment = [0u8; HASH_LEN_V1];
        fee_summary_commitment.copy_from_slice(&bytes[92..124]);
        let mut pre_state_root = [0u8; HASH_LEN_V1];
        pre_state_root.copy_from_slice(&bytes[124..156]);
        let mut post_state_root = [0u8; HASH_LEN_V1];
        post_state_root.copy_from_slice(&bytes[156..188]);
        let mut transactions_commitment = [0u8; HASH_LEN_V1];
        transactions_commitment.copy_from_slice(&bytes[188..220]);
        let mut outcomes_commitment = [0u8; HASH_LEN_V1];
        outcomes_commitment.copy_from_slice(&bytes[220..252]);
        let mut batch_context_commitment = [0u8; HASH_LEN_V1];
        batch_context_commitment.copy_from_slice(&bytes[252..284]);

        let transition_binding_version =
            u32::from_le_bytes(bytes[0..4].try_into().expect("exact slice"));
        if transition_binding_version != TRANSITION_BINDING_VERSION_V1 {
            return Err(
                PublicInputSchemaErrorV1::UnsupportedTransitionBindingVersion {
                    expected: TRANSITION_BINDING_VERSION_V1,
                    actual: transition_binding_version,
                },
            );
        }

        Ok(Self {
            transition_binding_version,
            rollup_id,
            execution_model_version: u32::from_le_bytes(
                bytes[36..40].try_into().expect("exact slice"),
            ),
            batch_version: u32::from_le_bytes(bytes[40..44].try_into().expect("exact slice")),
            batch_number: u64::from_le_bytes(bytes[44..52].try_into().expect("exact slice")),
            parent_batch_commitment,
            tx_count: u64::from_le_bytes(bytes[84..92].try_into().expect("exact slice")),
            fee_summary_commitment,
            pre_state_root,
            post_state_root,
            transactions_commitment,
            outcomes_commitment,
            batch_context_commitment,
        })
    }

    pub fn transition_binding_hash_v1(&self) -> [u8; HASH_LEN_V1] {
        let bytes = self.encode_bytes();
        let mut preimage = Vec::with_capacity(D_BINDING_V1.len() + PUBLIC_INPUT_SCHEMA_LEN_V1);
        preimage.extend_from_slice(D_BINDING_V1);
        preimage.extend_from_slice(&bytes);
        sha256_bytes(&preimage)
    }

    pub fn public_inputs_hash(&self) -> [u8; HASH_LEN_V1] {
        sha256_bytes(&self.encode_bytes())
    }

    pub fn ensure_matches_executed_batch(
        &self,
        executed: &ExecutedBatchV1,
    ) -> Result<(), PublicInputSchemaErrorV1> {
        if self.transition_binding_version != TRANSITION_BINDING_VERSION_V1 {
            return Err(
                PublicInputSchemaErrorV1::UnsupportedTransitionBindingVersion {
                    expected: TRANSITION_BINDING_VERSION_V1,
                    actual: self.transition_binding_version,
                },
            );
        }
        if self.rollup_id != executed.config.rollup_id {
            return Err(PublicInputSchemaErrorV1::RollupIdMismatch {
                expected: executed.config.rollup_id,
                actual: self.rollup_id,
            });
        }
        if self.execution_model_version != executed.config.execution_model_version {
            return Err(PublicInputSchemaErrorV1::ExecutionModelVersionMismatch {
                expected: executed.config.execution_model_version,
                actual: self.execution_model_version,
            });
        }
        if self.batch_version != executed.config.batch_version {
            return Err(PublicInputSchemaErrorV1::BatchVersionMismatch {
                expected: executed.config.batch_version,
                actual: self.batch_version,
            });
        }
        if self.batch_number != executed.batch_number {
            return Err(PublicInputSchemaErrorV1::BatchNumberMismatch {
                expected: executed.batch_number,
                actual: self.batch_number,
            });
        }
        if self.parent_batch_commitment != executed.parent_batch_commitment {
            return Err(PublicInputSchemaErrorV1::ParentBatchCommitmentMismatch {
                expected: executed.parent_batch_commitment,
                actual: self.parent_batch_commitment,
            });
        }
        if self.batch_number == 0 && self.parent_batch_commitment != ZERO32_V1 {
            return Err(PublicInputSchemaErrorV1::NonZeroGenesisParent {
                actual: self.parent_batch_commitment,
            });
        }
        if self.tx_count != executed.tx_count {
            return Err(PublicInputSchemaErrorV1::TxCountMismatch {
                expected: executed.tx_count,
                actual: self.tx_count,
            });
        }
        if self.fee_summary_commitment != executed.fee_summary_commitment {
            return Err(PublicInputSchemaErrorV1::FeeSummaryCommitmentMismatch {
                expected: executed.fee_summary_commitment,
                actual: self.fee_summary_commitment,
            });
        }
        if self.pre_state_root != executed.pre_state_root {
            return Err(PublicInputSchemaErrorV1::PreStateRootMismatch {
                expected: executed.pre_state_root,
                actual: self.pre_state_root,
            });
        }
        if self.post_state_root != executed.post_state_root {
            return Err(PublicInputSchemaErrorV1::PostStateRootMismatch {
                expected: executed.post_state_root,
                actual: self.post_state_root,
            });
        }
        if self.transactions_commitment != executed.transactions_commitment {
            return Err(PublicInputSchemaErrorV1::TransactionsCommitmentMismatch {
                expected: executed.transactions_commitment,
                actual: self.transactions_commitment,
            });
        }
        if self.outcomes_commitment != executed.outcomes_commitment {
            return Err(PublicInputSchemaErrorV1::OutcomesCommitmentMismatch {
                expected: executed.outcomes_commitment,
                actual: self.outcomes_commitment,
            });
        }
        if self.batch_context_commitment != executed.batch_context_commitment {
            return Err(PublicInputSchemaErrorV1::BatchContextCommitmentMismatch {
                expected: executed.batch_context_commitment,
                actual: self.batch_context_commitment,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::D_BINDING_V1;
    use aura_l2_execution_v1::sha256_bytes;
    use aura_l2_execution_v1::{
        execute_transfer_batch_v1, BatchExecutionRequestV1, LocalAccountV1, LocalExecutionConfigV1,
        LocalStateV1, TransferTransactionV1, TRANSFER_TX_VERSION_V1, TRANSITION_BINDING_VERSION_V1,
        ZERO32_V1 as EXEC_ZERO32_V1,
    };

    use super::{PublicInputSchemaErrorV1, TransitionEnvelopeV1, PUBLIC_INPUT_SCHEMA_LEN_V1};

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn executed_batch() -> aura_l2_execution_v1::ExecutedBatchV1 {
        let state = LocalStateV1::new([
            LocalAccountV1 {
                account_id: id(0x10),
                balance: 500,
                nonce: 0,
            },
            LocalAccountV1 {
                account_id: id(0x20),
                balance: 50,
                nonce: 0,
            },
        ])
        .unwrap();
        execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(id(0xAA)),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: EXEC_ZERO32_V1,
                transactions: vec![TransferTransactionV1 {
                    tx_version: TRANSFER_TX_VERSION_V1,
                    sender_account_id: id(0x10),
                    recipient_account_id: id(0x20),
                    sender_nonce: 0,
                    amount: 25,
                }],
            },
        )
        .unwrap()
    }

    #[test]
    fn public_input_encoding_matches_frozen_length() {
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed_batch());
        let bytes = envelope.encode_bytes();
        assert_eq!(bytes.len(), PUBLIC_INPUT_SCHEMA_LEN_V1);
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(&bytes[44..52], &0u64.to_le_bytes());
    }

    #[test]
    fn decode_roundtrips_exact_bytes() {
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed_batch());
        let bytes = envelope.encode_bytes();
        let decoded = TransitionEnvelopeV1::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn binding_checks_succeed_for_canonical_case() {
        let executed = executed_batch();
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed);
        envelope.ensure_matches_executed_batch(&executed).unwrap();
    }

    #[test]
    fn recomputed_hashes_and_claim_match_exact_public_input_bytes() {
        let executed = executed_batch();
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed);
        let bytes = envelope.encode_bytes();
        let claim = envelope.claim();

        assert_eq!(claim.pre_state_root, envelope.pre_state_root);
        assert_eq!(claim.post_state_root, envelope.post_state_root);
        assert_eq!(
            claim.transactions_commitment,
            envelope.transactions_commitment
        );
        assert_eq!(claim.outcomes_commitment, envelope.outcomes_commitment);
        assert_eq!(
            claim.batch_context_commitment,
            envelope.batch_context_commitment
        );

        let mut binding_preimage = Vec::with_capacity(D_BINDING_V1.len() + bytes.len());
        binding_preimage.extend_from_slice(D_BINDING_V1);
        binding_preimage.extend_from_slice(&bytes);

        assert_eq!(envelope.public_inputs_hash(), sha256_bytes(&bytes));
        assert_eq!(
            envelope.transition_binding_hash_v1(),
            sha256_bytes(&binding_preimage)
        );
        assert_eq!(
            TransitionEnvelopeV1::decode_exact(&bytes).unwrap(),
            envelope
        );
    }

    #[test]
    fn tampered_field_rejects() {
        let executed = executed_batch();
        let mut envelope = TransitionEnvelopeV1::from_executed_batch(&executed);
        envelope.tx_count += 1;
        let error = envelope
            .ensure_matches_executed_batch(&executed)
            .unwrap_err();
        assert_eq!(
            error,
            PublicInputSchemaErrorV1::TxCountMismatch {
                expected: executed.tx_count,
                actual: executed.tx_count + 1,
            }
        );
    }

    #[test]
    fn truncated_or_extended_public_input_bytes_reject() {
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed_batch());
        let bytes = envelope.encode_bytes();

        let truncated = TransitionEnvelopeV1::decode_exact(&bytes[..bytes.len() - 1]).unwrap_err();
        assert_eq!(
            truncated,
            PublicInputSchemaErrorV1::InvalidLength {
                expected: PUBLIC_INPUT_SCHEMA_LEN_V1,
                actual: PUBLIC_INPUT_SCHEMA_LEN_V1 - 1,
            }
        );

        let mut extended = bytes.to_vec();
        extended.push(0);
        let extended_error = TransitionEnvelopeV1::decode_exact(&extended).unwrap_err();
        assert_eq!(
            extended_error,
            PublicInputSchemaErrorV1::InvalidLength {
                expected: PUBLIC_INPUT_SCHEMA_LEN_V1,
                actual: PUBLIC_INPUT_SCHEMA_LEN_V1 + 1,
            }
        );
    }

    #[test]
    fn unsupported_transition_binding_version_rejects() {
        let envelope = TransitionEnvelopeV1::from_executed_batch(&executed_batch());
        let mut bytes = envelope.encode_bytes();
        bytes[0..4].copy_from_slice(&99u32.to_le_bytes());

        let error = TransitionEnvelopeV1::decode_exact(&bytes).unwrap_err();
        assert_eq!(
            error,
            PublicInputSchemaErrorV1::UnsupportedTransitionBindingVersion {
                expected: TRANSITION_BINDING_VERSION_V1,
                actual: 99,
            }
        );
    }
}
