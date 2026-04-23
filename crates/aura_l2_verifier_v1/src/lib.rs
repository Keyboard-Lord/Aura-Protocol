//! Aura L2 local verifier for the first proving-chain milestone.
//!
//! Current status:
//!
//! - `MockVerifierV1` verifies the current mock proof artifact honestly
//! - `StarkVerifierV1` verifies the current Winterfell-backed STARK artifact
//! - the full frozen witness and commitment semantics are still enforced by the host-side
//!   witness validator, while the STARK backend proves the algebraic trace relation

use core::fmt;

use aura_l2_execution_v1::{sha256_bytes, HASH_LEN_V1};
use aura_l2_prover_v1::{
    derive_mock_proof_binding_digest_v1, derive_stark_proof_binding_digest_v1,
    verify_with_winterfell_backend_v1, LocalMockProofArtifactV1, LocalProofArtifactV1,
    LocalStarkProofArtifactV1, StarkBackendErrorV1, LOCAL_MOCK_PROOF_VERSION_V1,
    LOCAL_PROVER_KIND_MOCK_V1, LOCAL_PROVER_KIND_STARK_V1, LOCAL_STARK_PROOF_VERSION_V1,
};
use aura_l2_public_input_v1::{PublicInputSchemaErrorV1, TransitionEnvelopeV1};
use aura_l2_trace_builder_v1::{
    derive_witness_digest_v1, validate_trace_witness_bundle_v1, TraceBuilderErrorV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedTransitionV1 {
    pub public_inputs: TransitionEnvelopeV1,
    pub transition_binding_hash: [u8; HASH_LEN_V1],
}

#[derive(Debug)]
pub enum LocalVerifierErrorV1 {
    PublicInputSchema(PublicInputSchemaErrorV1),
    UnsupportedProverKind {
        expected: u32,
        actual: u32,
    },
    UnsupportedProofVersion {
        expected: u32,
        actual: u32,
    },
    WitnessBundleValidation(TraceBuilderErrorV1),
    PublicInputBytesMismatch,
    PublicInputsHashMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
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
    ProofBindingDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    StarkBackend(StarkBackendErrorV1),
}

impl fmt::Display for LocalVerifierErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicInputSchema(error) => write!(f, "public input schema error: {error}"),
            Self::UnsupportedProverKind { expected, actual } => write!(
                f,
                "unsupported prover kind: expected {expected}, got {actual}"
            ),
            Self::UnsupportedProofVersion { expected, actual } => write!(
                f,
                "unsupported proof version: expected {expected}, got {actual}"
            ),
            Self::WitnessBundleValidation(error) => {
                write!(f, "witness bundle validation error: {error}")
            }
            Self::PublicInputBytesMismatch => write!(f, "public input bytes mismatch"),
            Self::PublicInputsHashMismatch { .. } => write!(f, "public inputs hash mismatch"),
            Self::TraceDigestMismatch { .. } => write!(f, "trace digest mismatch"),
            Self::TraceLayoutDigestMismatch { .. } => write!(f, "trace layout digest mismatch"),
            Self::WitnessDigestMismatch { .. } => write!(f, "witness digest mismatch"),
            Self::ProofBindingDigestMismatch { .. } => write!(f, "proof binding digest mismatch"),
            Self::StarkBackend(error) => write!(f, "stark backend error: {error}"),
        }
    }
}

impl std::error::Error for LocalVerifierErrorV1 {}

impl From<PublicInputSchemaErrorV1> for LocalVerifierErrorV1 {
    fn from(value: PublicInputSchemaErrorV1) -> Self {
        Self::PublicInputSchema(value)
    }
}

impl From<StarkBackendErrorV1> for LocalVerifierErrorV1 {
    fn from(value: StarkBackendErrorV1) -> Self {
        Self::StarkBackend(value)
    }
}

pub trait LocalVerifierBackendV1 {
    fn verify(
        &self,
        public_inputs_bytes: &[u8],
        proof_artifact: &LocalProofArtifactV1,
    ) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MockVerifierV1;

impl MockVerifierV1 {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_mock_artifact(
        &self,
        public_inputs_bytes: &[u8],
        proof_artifact: &LocalMockProofArtifactV1,
    ) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1> {
        let public_inputs = TransitionEnvelopeV1::decode_exact(public_inputs_bytes)?;

        if proof_artifact.prover_kind != LOCAL_PROVER_KIND_MOCK_V1 {
            return Err(LocalVerifierErrorV1::UnsupportedProverKind {
                expected: LOCAL_PROVER_KIND_MOCK_V1,
                actual: proof_artifact.prover_kind,
            });
        }
        if proof_artifact.proof_version != LOCAL_MOCK_PROOF_VERSION_V1 {
            return Err(LocalVerifierErrorV1::UnsupportedProofVersion {
                expected: LOCAL_MOCK_PROOF_VERSION_V1,
                actual: proof_artifact.proof_version,
            });
        }
        if proof_artifact.witness_bundle.public_inputs_bytes.as_slice() != public_inputs_bytes {
            return Err(LocalVerifierErrorV1::PublicInputBytesMismatch);
        }
        if proof_artifact.witness_bundle.public_inputs != public_inputs {
            return Err(LocalVerifierErrorV1::PublicInputBytesMismatch);
        }

        validate_trace_witness_bundle_v1(&proof_artifact.witness_bundle)
            .map_err(LocalVerifierErrorV1::WitnessBundleValidation)?;

        let expected_public_inputs_hash = sha256_bytes(public_inputs_bytes);
        if proof_artifact.public_inputs_hash != expected_public_inputs_hash {
            return Err(LocalVerifierErrorV1::PublicInputsHashMismatch {
                expected: expected_public_inputs_hash,
                actual: proof_artifact.public_inputs_hash,
            });
        }

        let expected_trace_digest = proof_artifact.witness_bundle.trace_digest;
        if proof_artifact.trace_digest != expected_trace_digest {
            return Err(LocalVerifierErrorV1::TraceDigestMismatch {
                expected: expected_trace_digest,
                actual: proof_artifact.trace_digest,
            });
        }

        let expected_trace_layout_digest = proof_artifact.witness_bundle.trace_layout_digest;
        if proof_artifact.trace_layout_digest != expected_trace_layout_digest {
            return Err(LocalVerifierErrorV1::TraceLayoutDigestMismatch {
                expected: expected_trace_layout_digest,
                actual: proof_artifact.trace_layout_digest,
            });
        }

        let expected_witness_digest = derive_witness_digest_v1(&proof_artifact.witness_bundle);
        if proof_artifact.witness_digest != expected_witness_digest {
            return Err(LocalVerifierErrorV1::WitnessDigestMismatch {
                expected: expected_witness_digest,
                actual: proof_artifact.witness_digest,
            });
        }

        let expected_binding_digest = derive_mock_proof_binding_digest_v1(
            proof_artifact.proof_version,
            &expected_public_inputs_hash,
            &expected_trace_digest,
            &expected_trace_layout_digest,
            &expected_witness_digest,
        );
        if proof_artifact.proof_binding_digest != expected_binding_digest {
            return Err(LocalVerifierErrorV1::ProofBindingDigestMismatch {
                expected: expected_binding_digest,
                actual: proof_artifact.proof_binding_digest,
            });
        }

        Ok(VerifiedTransitionV1 {
            public_inputs,
            transition_binding_hash: public_inputs.transition_binding_hash_v1(),
        })
    }
}

impl LocalVerifierBackendV1 for MockVerifierV1 {
    fn verify(
        &self,
        public_inputs_bytes: &[u8],
        proof_artifact: &LocalProofArtifactV1,
    ) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1> {
        match proof_artifact {
            LocalProofArtifactV1::Mock(proof) => {
                self.verify_mock_artifact(public_inputs_bytes, proof)
            }
            LocalProofArtifactV1::Stark(proof) => {
                Err(LocalVerifierErrorV1::UnsupportedProverKind {
                    expected: LOCAL_PROVER_KIND_MOCK_V1,
                    actual: proof.prover_kind,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StarkVerifierV1;

impl StarkVerifierV1 {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_stark_artifact(
        &self,
        public_inputs_bytes: &[u8],
        proof_artifact: &LocalStarkProofArtifactV1,
    ) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1> {
        let public_inputs = TransitionEnvelopeV1::decode_exact(public_inputs_bytes)?;

        if proof_artifact.prover_kind != LOCAL_PROVER_KIND_STARK_V1 {
            return Err(LocalVerifierErrorV1::UnsupportedProverKind {
                expected: LOCAL_PROVER_KIND_STARK_V1,
                actual: proof_artifact.prover_kind,
            });
        }
        if proof_artifact.proof_version != LOCAL_STARK_PROOF_VERSION_V1 {
            return Err(LocalVerifierErrorV1::UnsupportedProofVersion {
                expected: LOCAL_STARK_PROOF_VERSION_V1,
                actual: proof_artifact.proof_version,
            });
        }

        let expected_public_inputs_hash = sha256_bytes(public_inputs_bytes);
        if proof_artifact.public_inputs_hash != expected_public_inputs_hash {
            return Err(LocalVerifierErrorV1::PublicInputsHashMismatch {
                expected: expected_public_inputs_hash,
                actual: proof_artifact.public_inputs_hash,
            });
        }

        let expected_binding_digest = derive_stark_proof_binding_digest_v1(
            proof_artifact.proof_version,
            &proof_artifact.public_inputs_hash,
            &proof_artifact.trace_digest,
            &proof_artifact.trace_layout_digest,
            &proof_artifact.proof_bytes,
        );
        if proof_artifact.proof_binding_digest != expected_binding_digest {
            return Err(LocalVerifierErrorV1::ProofBindingDigestMismatch {
                expected: expected_binding_digest,
                actual: proof_artifact.proof_binding_digest,
            });
        }

        let prepared =
            verify_with_winterfell_backend_v1(public_inputs_bytes, &proof_artifact.proof_bytes)?;
        if prepared.public_inputs_hash != proof_artifact.public_inputs_hash {
            return Err(LocalVerifierErrorV1::PublicInputsHashMismatch {
                expected: prepared.public_inputs_hash,
                actual: proof_artifact.public_inputs_hash,
            });
        }
        if prepared.trace_digest != proof_artifact.trace_digest {
            return Err(LocalVerifierErrorV1::TraceDigestMismatch {
                expected: prepared.trace_digest,
                actual: proof_artifact.trace_digest,
            });
        }
        if prepared.trace_layout_digest != proof_artifact.trace_layout_digest {
            return Err(LocalVerifierErrorV1::TraceLayoutDigestMismatch {
                expected: prepared.trace_layout_digest,
                actual: proof_artifact.trace_layout_digest,
            });
        }

        Ok(VerifiedTransitionV1 {
            public_inputs,
            transition_binding_hash: public_inputs.transition_binding_hash_v1(),
        })
    }
}

impl LocalVerifierBackendV1 for StarkVerifierV1 {
    fn verify(
        &self,
        public_inputs_bytes: &[u8],
        proof_artifact: &LocalProofArtifactV1,
    ) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1> {
        match proof_artifact {
            LocalProofArtifactV1::Mock(proof) => Err(LocalVerifierErrorV1::UnsupportedProverKind {
                expected: LOCAL_PROVER_KIND_STARK_V1,
                actual: proof.prover_kind,
            }),
            LocalProofArtifactV1::Stark(proof) => {
                self.verify_stark_artifact(public_inputs_bytes, proof)
            }
        }
    }
}

pub fn verify_mock_proof_artifact_v1(
    public_inputs_bytes: &[u8],
    proof_artifact: &LocalMockProofArtifactV1,
) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1> {
    MockVerifierV1::new().verify_mock_artifact(public_inputs_bytes, proof_artifact)
}

pub fn verify_proof_artifact_v1(
    public_inputs_bytes: &[u8],
    proof_artifact: &LocalProofArtifactV1,
) -> Result<VerifiedTransitionV1, LocalVerifierErrorV1> {
    match proof_artifact {
        LocalProofArtifactV1::Mock(proof) => {
            MockVerifierV1::new().verify_mock_artifact(public_inputs_bytes, proof)
        }
        LocalProofArtifactV1::Stark(proof) => {
            StarkVerifierV1::new().verify_stark_artifact(public_inputs_bytes, proof)
        }
    }
}

#[cfg(test)]
mod tests {
    use aura_l2_execution_v1::{
        execute_transfer_batch_v1, sha256_bytes, BatchExecutionRequestV1, LocalAccountV1,
        LocalExecutionConfigV1, LocalStateV1, TransferTransactionV1, TRANSFER_TX_VERSION_V1,
        ZERO32_V1,
    };
    use aura_l2_prover_v1::{
        decode_winterfell_stark_proof_envelope_v1, derive_stark_proof_binding_digest_v1,
        encode_winterfell_stark_proof_envelope_v1, prove_executed_batch_with_mock_prover_v1,
        prove_executed_batch_with_stark_prover_v1,
        reconstruct_executed_batch_from_winterfell_envelope_v1, LocalProofArtifactV1,
        StarkBackendErrorV1,
    };
    use aura_l2_public_input_v1::{TransitionEnvelopeV1, PUBLIC_INPUT_SCHEMA_LEN_V1};
    use aura_l2_trace_builder_v1::build_trace_witness_bundle_v1;

    use super::{
        verify_mock_proof_artifact_v1, verify_proof_artifact_v1, LocalVerifierBackendV1,
        LocalVerifierErrorV1, MockVerifierV1, StarkVerifierV1,
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

    fn two_transfer_executed_batch() -> aura_l2_execution_v1::ExecutedBatchV1 {
        let state = LocalStateV1::new([
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
        ])
        .unwrap();
        execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(id(0xAA)),
            &BatchExecutionRequestV1 {
                batch_number: 0,
                parent_batch_commitment: ZERO32_V1,
                transactions: vec![
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
            },
        )
        .unwrap()
    }

    fn canonical_mock_case() -> (
        [u8; PUBLIC_INPUT_SCHEMA_LEN_V1],
        aura_l2_prover_v1::LocalMockProofArtifactV1,
    ) {
        let executed = canonical_executed_batch();
        let public_inputs = TransitionEnvelopeV1::from_executed_batch(&executed).encode_bytes();
        let proof = prove_executed_batch_with_mock_prover_v1(&executed).unwrap();
        (public_inputs, proof)
    }

    fn canonical_stark_case() -> (
        [u8; PUBLIC_INPUT_SCHEMA_LEN_V1],
        aura_l2_prover_v1::LocalStarkProofArtifactV1,
    ) {
        let executed = canonical_executed_batch();
        let public_inputs = TransitionEnvelopeV1::from_executed_batch(&executed).encode_bytes();
        let proof = prove_executed_batch_with_stark_prover_v1(&executed).unwrap();
        (public_inputs, proof)
    }

    #[test]
    fn canonical_mock_proof_verifies() {
        let (public_inputs, proof) = canonical_mock_case();
        let verified = verify_mock_proof_artifact_v1(&public_inputs, &proof).unwrap();
        assert_eq!(verified.public_inputs.batch_number, 0);
        assert_eq!(public_inputs.len(), PUBLIC_INPUT_SCHEMA_LEN_V1);
    }

    #[test]
    fn one_transfer_real_stark_proof_verifies() {
        let (public_inputs, proof) = canonical_stark_case();
        let verified = StarkVerifierV1::new()
            .verify_stark_artifact(&public_inputs, &proof)
            .unwrap();
        assert_eq!(verified.public_inputs.batch_number, 0);
    }

    #[test]
    fn two_transfer_real_stark_proof_verifies() {
        let executed = two_transfer_executed_batch();
        let public_inputs = TransitionEnvelopeV1::from_executed_batch(&executed).encode_bytes();
        let proof = prove_executed_batch_with_stark_prover_v1(&executed).unwrap();

        let verified = StarkVerifierV1::new()
            .verify_stark_artifact(&public_inputs, &proof)
            .unwrap();

        assert_eq!(verified.public_inputs.tx_count, 2);
        assert_eq!(verified.public_inputs.batch_number, 0);
    }

    #[test]
    fn public_input_schema_length_remains_frozen() {
        assert_eq!(PUBLIC_INPUT_SCHEMA_LEN_V1, 284);
    }

    #[test]
    fn mock_wrapper_struct_and_generic_dispatch_match() {
        let (public_inputs, proof) = canonical_mock_case();
        let via_wrapper = verify_mock_proof_artifact_v1(&public_inputs, &proof).unwrap();
        let via_struct = MockVerifierV1::new()
            .verify_mock_artifact(&public_inputs, &proof)
            .unwrap();
        let artifact = LocalProofArtifactV1::Mock(proof.clone());
        let via_generic = verify_proof_artifact_v1(&public_inputs, &artifact).unwrap();

        assert_eq!(via_wrapper, via_struct);
        assert_eq!(via_wrapper, via_generic);
    }

    #[test]
    fn stark_struct_and_generic_dispatch_match() {
        let (public_inputs, proof) = canonical_stark_case();
        let via_struct = StarkVerifierV1::new()
            .verify_stark_artifact(&public_inputs, &proof)
            .unwrap();
        let artifact = LocalProofArtifactV1::Stark(proof.clone());
        let via_generic = verify_proof_artifact_v1(&public_inputs, &artifact).unwrap();

        assert_eq!(via_struct, via_generic);
    }

    #[test]
    fn tampered_public_input_causes_rejection() {
        let (mut public_inputs, proof) = canonical_mock_case();
        public_inputs[44] = 1;
        let error = verify_mock_proof_artifact_v1(&public_inputs, &proof).unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::PublicInputBytesMismatch
                | LocalVerifierErrorV1::WitnessBundleValidation(_)
                | LocalVerifierErrorV1::PublicInputSchema(_)
        ));
    }

    #[test]
    fn tampered_public_input_rejects_real_stark_artifact() {
        let (mut public_inputs, proof) = canonical_stark_case();
        public_inputs[44] ^= 1;
        let error = StarkVerifierV1::new()
            .verify_stark_artifact(&public_inputs, &proof)
            .unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::PublicInputsHashMismatch { .. }
                | LocalVerifierErrorV1::StarkBackend(StarkBackendErrorV1::PublicInputBytesMismatch)
                | LocalVerifierErrorV1::PublicInputSchema(_)
        ));
    }

    #[test]
    fn tampered_mock_proof_artifact_causes_rejection() {
        let (public_inputs, mut proof) = canonical_mock_case();
        proof.proof_binding_digest[0] ^= 0xFF;
        let error = verify_mock_proof_artifact_v1(&public_inputs, &proof).unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::ProofBindingDigestMismatch { .. }
        ));
    }

    #[test]
    fn tampered_real_stark_proof_bytes_cause_rejection() {
        let (public_inputs, mut proof) = canonical_stark_case();
        let tamper_index = proof.proof_bytes.len() / 2;
        proof.proof_bytes[tamper_index] ^= 0x01;
        let via_struct = StarkVerifierV1::new().verify_stark_artifact(&public_inputs, &proof);
        let via_generic =
            verify_proof_artifact_v1(&public_inputs, &LocalProofArtifactV1::Stark(proof));
        assert!(matches!(
            via_struct,
            Err(LocalVerifierErrorV1::StarkBackend(_))
                | Err(LocalVerifierErrorV1::ProofBindingDigestMismatch { .. })
        ));
        assert!(matches!(
            via_generic,
            Err(LocalVerifierErrorV1::StarkBackend(_))
                | Err(LocalVerifierErrorV1::ProofBindingDigestMismatch { .. })
        ));
    }

    #[test]
    fn truncated_real_stark_envelope_rejects_even_if_binding_is_recomputed() {
        let (public_inputs, mut proof) = canonical_stark_case();
        proof.proof_bytes.pop();
        proof.proof_binding_digest = derive_stark_proof_binding_digest_v1(
            proof.proof_version,
            &proof.public_inputs_hash,
            &proof.trace_digest,
            &proof.trace_layout_digest,
            &proof.proof_bytes,
        );

        let error = StarkVerifierV1::new()
            .verify_stark_artifact(&public_inputs, &proof)
            .unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::StarkBackend(StarkBackendErrorV1::ProofEnvelopeDecode { .. })
        ));
    }

    #[test]
    fn tampered_real_stark_public_input_hash_rejects_even_if_binding_is_recomputed() {
        let (public_inputs, mut proof) = canonical_stark_case();
        proof.public_inputs_hash[0] ^= 0x01;
        proof.proof_binding_digest = derive_stark_proof_binding_digest_v1(
            proof.proof_version,
            &proof.public_inputs_hash,
            &proof.trace_digest,
            &proof.trace_layout_digest,
            &proof.proof_bytes,
        );

        let error = StarkVerifierV1::new()
            .verify_stark_artifact(&public_inputs, &proof)
            .unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::PublicInputsHashMismatch { .. }
        ));
    }

    #[test]
    fn tampered_transaction_vs_row_mismatch_rejects_real_stark_artifact() {
        let (_public_inputs, mut proof) = canonical_stark_case();
        let mut envelope = decode_winterfell_stark_proof_envelope_v1(&proof.proof_bytes).unwrap();
        envelope.transactions[0].amount += 1;
        proof.proof_bytes = encode_winterfell_stark_proof_envelope_v1(&envelope);

        let tampered_executed =
            reconstruct_executed_batch_from_winterfell_envelope_v1(&envelope).unwrap();
        let tampered_public_inputs =
            TransitionEnvelopeV1::from_executed_batch(&tampered_executed).encode_bytes();
        let tampered_bundle = build_trace_witness_bundle_v1(&tampered_executed).unwrap();

        proof.public_inputs_hash = sha256_bytes(&tampered_public_inputs);
        proof.trace_digest = tampered_bundle.trace_digest;
        proof.trace_layout_digest = tampered_bundle.trace_layout_digest;
        proof.proof_binding_digest = derive_stark_proof_binding_digest_v1(
            proof.proof_version,
            &proof.public_inputs_hash,
            &proof.trace_digest,
            &proof.trace_layout_digest,
            &proof.proof_bytes,
        );

        let error = StarkVerifierV1::new()
            .verify_stark_artifact(&tampered_public_inputs, &proof)
            .unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::StarkBackend(StarkBackendErrorV1::WinterfellVerifier(_))
        ));
    }

    #[test]
    fn mock_and_stark_verifier_interfaces_are_distinct() {
        let (public_inputs, proof) = canonical_mock_case();
        let mock_artifact = LocalProofArtifactV1::Mock(proof);

        let verified =
            LocalVerifierBackendV1::verify(&MockVerifierV1::new(), &public_inputs, &mock_artifact)
                .unwrap();
        assert_eq!(verified.public_inputs.batch_number, 0);

        let error =
            LocalVerifierBackendV1::verify(&StarkVerifierV1::new(), &public_inputs, &mock_artifact)
                .unwrap_err();
        assert!(matches!(
            error,
            LocalVerifierErrorV1::UnsupportedProverKind { .. }
        ));
    }
}
