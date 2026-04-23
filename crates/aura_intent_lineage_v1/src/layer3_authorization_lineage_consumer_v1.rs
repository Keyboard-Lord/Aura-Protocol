//! First frozen Layer 3 verifier/consumer closure above the real STARK proof boundary.
//!
//! This object is RESEARCH / SUPPORTING only. It binds one exact verified Layer 3 proof result,
//! one exact frozen Layer 2 object, and one exact Layer 3 public claim into a deterministic
//! consumer object so downstream supporting layers stop reaching into the raw proof struct ad hoc.
//! It does not modify the active canonical pipeline, settlement, burn, ledger, wallet,
//! attestation, or report authority.

use core::fmt;

use crate::{
    canonical_layer3_authorization_lineage_public_claim_bytes_v1,
    canonical_native_layer2_authorization_lineage_primary_bytes_v1,
    canonical_layer3_bound_layer2_lineage_commitment_v1,
    canonical_layer3_bound_layer2_lineage_hash_v1, derive_dcm_layer1_commitments_521_v1,
    derive_deterministic_commitment_521_v1, sha256_bytes, sha256_domain_separated,
    verify_layer3_authorization_lineage_real_stark_v1, DcmCommitmentKindV1,
    DcmExecution521ErrorV1, DcmExecution521V1, DcmInput521V1, DeterministicCommitment521V1,
    DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1, IntentTypeV1,
    Layer3AuthorizationLineagePublicClaimV1, Layer3AuthorizationLineageRealStarkProofV1,
    Layer3AuthorizationLineageVerifierErrorV1, LowerHex32, LowerHex521,
    NativeLayer2AuthorizationLineageObjectV1Error,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR, HASH_LEN_V1,
};

pub const LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_VERSION_V1: u8 = 1;
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_V1";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_V1";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_V1";
pub const AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_COMMITMENT_V1";
pub const LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_PROOF_RESULT_SERIALIZED_LEN_V1: usize =
    (HASH_LEN_V1 * 9) + (DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Layer3AuthorizationLineageConsumerDecisionV1 {
    AcceptVerifiedProofV1 = 0x01,
}

impl Layer3AuthorizationLineageConsumerDecisionV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageConsumerProofResultV1 {
    pub public_claim_digest: [u8; HASH_LEN_V1],
    pub layer3_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_binding_digest: [u8; HASH_LEN_V1],
    pub lineage_commitment: DeterministicCommitment521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub dcm_trace_commitment: [u8; HASH_LEN_V1],
    pub intent_hash: [u8; HASH_LEN_V1],
    pub result_commitment: DeterministicCommitment521V1,
    pub result_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageConsumerObjectV1 {
    pub consumer_version: u8,
    pub consumer_flags: u16,
    pub decision: Layer3AuthorizationLineageConsumerDecisionV1,
    pub proof_result: Layer3AuthorizationLineageConsumerProofResultV1,
    pub public_claim: Layer3AuthorizationLineagePublicClaimV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3AuthorizationLineageConsumerAcceptanceV1 {
    pub decision: Layer3AuthorizationLineageConsumerDecisionV1,
    pub proof_result: Layer3AuthorizationLineageConsumerProofResultV1,
    pub consumer_object_commitment: DeterministicCommitment521V1,
    pub consumer_object_hash: [u8; HASH_LEN_V1],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Layer3AuthorizationLineageConsumerErrorV1 {
    InvalidVersion {
        expected: u8,
        actual: u8,
    },
    ReservedFlagsNonZero {
        actual: u16,
    },
    InvalidLayer2Object(NativeLayer2AuthorizationLineageObjectV1Error),
    Layer1ParametersInvalid(DcmExecution521ErrorV1),
    Layer3VerificationRejected(Layer3AuthorizationLineageVerifierErrorV1),
    InvalidFieldCombination {
        reason: &'static str,
    },
    ClaimRelationshipMismatch {
        field: &'static str,
    },
    CommitmentMismatch {
        field: &'static str,
        expected: DeterministicCommitment521V1,
        actual: DeterministicCommitment521V1,
    },
    HashMismatch {
        field: &'static str,
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl fmt::Display for Layer3AuthorizationLineageConsumerErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => write!(
                f,
                "invalid consumer version: expected {expected}, got {actual}"
            ),
            Self::ReservedFlagsNonZero { actual } => {
                write!(f, "consumer flags reserved bits non-zero: 0x{actual:04x}")
            }
            Self::InvalidLayer2Object(error) => write!(f, "invalid layer2 object: {error}"),
            Self::Layer1ParametersInvalid(error) => {
                write!(f, "layer1 parameters invalid: {error}")
            }
            Self::Layer3VerificationRejected(error) => {
                write!(f, "layer3 verification rejected consumer source: {error}")
            }
            Self::InvalidFieldCombination { reason } => {
                write!(f, "invalid field combination: {reason}")
            }
            Self::ClaimRelationshipMismatch { field } => {
                write!(f, "claim relationship mismatch: {field}")
            }
            Self::CommitmentMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} mismatch: expected {}, got {}",
                LowerHex521(expected),
                LowerHex521(actual)
            ),
            Self::HashMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
        }
    }
}

impl std::error::Error for Layer3AuthorizationLineageConsumerErrorV1 {}

struct ValidatedLayer3AuthorizationLineageConsumerObjectV1 {
    acceptance: Layer3AuthorizationLineageConsumerAcceptanceV1,
    public_claim_bytes: Vec<u8>,
    canonical_proof_result: Layer3AuthorizationLineageConsumerProofResultV1,
}

pub fn produce_layer3_authorization_lineage_consumer_object_v1(
    proof: &Layer3AuthorizationLineageRealStarkProofV1,
) -> Result<Layer3AuthorizationLineageConsumerObjectV1, Layer3AuthorizationLineageConsumerErrorV1> {
    let acceptance = verify_layer3_authorization_lineage_real_stark_v1(proof)
        .map_err(Layer3AuthorizationLineageConsumerErrorV1::Layer3VerificationRejected)?;
    let public_claim_bytes =
        canonical_layer3_authorization_lineage_public_claim_bytes_v1(&proof.public_claim)
            .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;
    let public_claim_digest = sha256_domain_separated(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
        &public_claim_bytes,
    );

    let decision = Layer3AuthorizationLineageConsumerDecisionV1::AcceptVerifiedProofV1;
    let result_commitment = derive_layer3_authorization_lineage_consumer_result_commitment_v1(
        decision,
        &proof.public_claim,
        acceptance.layer3_transcript_digest,
        acceptance.layer3_proof_bound_transcript_digest,
        acceptance.proof_binding_digest,
    )
    .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;
    let result_digest = derive_layer3_authorization_lineage_consumer_result_digest_v1(
        decision,
        &proof.public_claim,
        acceptance.layer3_transcript_digest,
        acceptance.layer3_proof_bound_transcript_digest,
        acceptance.proof_binding_digest,
    )
    .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;

    let proof_result = Layer3AuthorizationLineageConsumerProofResultV1 {
        public_claim_digest,
        layer3_transcript_digest: acceptance.layer3_transcript_digest,
        layer3_proof_bound_transcript_digest: acceptance.layer3_proof_bound_transcript_digest,
        layer3_proof_binding_digest: acceptance.proof_binding_digest,
        lineage_commitment: acceptance.lineage_commitment,
        lineage_hash: acceptance.lineage_hash,
        dcm_commitment_root: acceptance.dcm_commitment_root,
        dcm_trace_commitment: acceptance.dcm_trace_commitment,
        intent_hash: acceptance.intent_hash,
        result_commitment,
        result_digest,
    };

    let object = Layer3AuthorizationLineageConsumerObjectV1 {
        consumer_version: LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_VERSION_V1,
        consumer_flags: 0,
        decision,
        proof_result,
        public_claim: proof.public_claim.clone(),
    };
    object.validate()?;
    Ok(object)
}

pub fn consume_layer3_authorization_lineage_consumer_object_v1(
    object: &Layer3AuthorizationLineageConsumerObjectV1,
) -> Result<Layer3AuthorizationLineageConsumerAcceptanceV1, Layer3AuthorizationLineageConsumerErrorV1>
{
    Ok(object.validate_inner()?.acceptance)
}

impl Layer3AuthorizationLineageConsumerObjectV1 {
    pub fn validate(&self) -> Result<(), Layer3AuthorizationLineageConsumerErrorV1> {
        self.validate_inner().map(|_| ())
    }

    pub fn serialized_object(&self) -> Result<Vec<u8>, Layer3AuthorizationLineageConsumerErrorV1> {
        let validated = self.validate_inner()?;
        Ok(
            canonical_layer3_authorization_lineage_consumer_object_bytes_v1(
                self,
                &validated.public_claim_bytes,
                &validated.canonical_proof_result,
            ),
        )
    }

    pub fn consumer_hash(
        &self,
    ) -> Result<[u8; HASH_LEN_V1], Layer3AuthorizationLineageConsumerErrorV1> {
        Ok(self.validate_inner()?.acceptance.consumer_object_hash)
    }

    pub fn consumer_commitment(
        &self,
    ) -> Result<DeterministicCommitment521V1, Layer3AuthorizationLineageConsumerErrorV1> {
        Ok(self.validate_inner()?.acceptance.consumer_object_commitment)
    }

    fn validate_inner(
        &self,
    ) -> Result<
        ValidatedLayer3AuthorizationLineageConsumerObjectV1,
        Layer3AuthorizationLineageConsumerErrorV1,
    > {
        if self.consumer_version != LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_VERSION_V1 {
            return Err(Layer3AuthorizationLineageConsumerErrorV1::InvalidVersion {
                expected: LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_VERSION_V1,
                actual: self.consumer_version,
            });
        }

        if self.consumer_flags != 0 {
            return Err(
                Layer3AuthorizationLineageConsumerErrorV1::ReservedFlagsNonZero {
                    actual: self.consumer_flags,
                },
            );
        }

        let recomputed_lineage_commitment =
            canonical_layer3_bound_layer2_lineage_commitment_v1(&self.public_claim.layer2_object)
                .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;
        let recomputed_lineage_hash =
            canonical_layer3_bound_layer2_lineage_hash_v1(&self.public_claim.layer2_object)
                .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;

        if self.public_claim.layer2_object.lineage.dcm_commitment_kind
            != DcmCommitmentKindV1::DcmRootCommitmentV1
        {
            return Err(
                Layer3AuthorizationLineageConsumerErrorV1::InvalidFieldCombination {
                    reason: "layer3_consumer_requires_native_dcm_root_commitment",
                },
            );
        }

        if self.public_claim.layer2_object.lineage.intent_type
            != IntentTypeV1::AuraLayer4IntentHashV1
        {
            return Err(
                Layer3AuthorizationLineageConsumerErrorV1::InvalidFieldCombination {
                    reason: "layer3_consumer_requires_aura_layer4_intent_hash_v1",
                },
            );
        }

        self.public_claim
            .lower_layer_claim
            .config
            .validate()
            .map_err(Layer3AuthorizationLineageConsumerErrorV1::Layer1ParametersInvalid)?;

        let dcm_input = DcmInput521V1 {
            x0: self.public_claim.lower_layer_claim.initial_state.x,
            y0: self.public_claim.lower_layer_claim.initial_state.y,
        };
        let execution =
            DcmExecution521V1::run(&self.public_claim.lower_layer_claim.config, &dcm_input)
                .map_err(Layer3AuthorizationLineageConsumerErrorV1::Layer1ParametersInvalid)?;

        if execution.final_state != self.public_claim.lower_layer_claim.final_state {
            return Err(
                Layer3AuthorizationLineageConsumerErrorV1::ClaimRelationshipMismatch {
                    field: "public_claim.lower_layer_claim.final_state",
                },
            );
        }

        if execution.trace_length != self.public_claim.lower_layer_claim.trace_state_count() {
            return Err(
                Layer3AuthorizationLineageConsumerErrorV1::ClaimRelationshipMismatch {
                    field: "public_claim.lower_layer_claim.trace_state_count",
                },
            );
        }

        let recomputed_commitments = derive_dcm_layer1_commitments_521_v1(
            &self.public_claim.lower_layer_claim.config,
            &execution,
        );

        compare_hashes_v1(
            "public_claim.lower_layer_claim.commitment_root",
            recomputed_commitments.dcm_commitment_root,
            self.public_claim.lower_layer_claim.commitment_root,
        )?;
        compare_hashes_v1(
            "public_claim.layer2_object.dcm_commitment_root",
            self.public_claim.lower_layer_claim.commitment_root,
            self.public_claim.layer2_object.lineage.dcm_commitment_root,
        )?;
        compare_hashes_v1(
            "public_claim.layer2_object.dcm_trace_commitment",
            recomputed_commitments.dcm_trace_commitment,
            self.public_claim.layer2_object.lineage.dcm_trace_commitment,
        )?;

        let public_claim_bytes =
            canonical_layer3_authorization_lineage_public_claim_bytes_v1(&self.public_claim)
                .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;
        let expected_public_claim_digest = sha256_domain_separated(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
            &public_claim_bytes,
        );

        compare_commitments_v1(
            "proof_result.lineage_commitment",
            recomputed_lineage_commitment,
            self.proof_result.lineage_commitment,
        )?;
        compare_hashes_v1(
            "proof_result.dcm_commitment_root",
            self.public_claim.lower_layer_claim.commitment_root,
            self.proof_result.dcm_commitment_root,
        )?;
        compare_hashes_v1(
            "proof_result.dcm_trace_commitment",
            recomputed_commitments.dcm_trace_commitment,
            self.proof_result.dcm_trace_commitment,
        )?;
        compare_hashes_v1(
            "proof_result.intent_hash",
            self.public_claim.layer2_object.lineage.intent_hash,
            self.proof_result.intent_hash,
        )?;

        let expected_result_commitment = derive_layer3_authorization_lineage_consumer_result_commitment_v1(
            self.decision,
            &self.public_claim,
            self.proof_result.layer3_transcript_digest,
            self.proof_result.layer3_proof_bound_transcript_digest,
            self.proof_result.layer3_proof_binding_digest,
        )
        .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;
        compare_commitments_v1(
            "proof_result.result_commitment",
            expected_result_commitment,
            self.proof_result.result_commitment,
        )?;
        let expected_result_digest = derive_layer3_authorization_lineage_consumer_result_digest_v1(
            self.decision,
            &self.public_claim,
            self.proof_result.layer3_transcript_digest,
            self.proof_result.layer3_proof_bound_transcript_digest,
            self.proof_result.layer3_proof_binding_digest,
        )
        .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;
        let canonical_proof_result = Layer3AuthorizationLineageConsumerProofResultV1 {
            public_claim_digest: expected_public_claim_digest,
            layer3_transcript_digest: self.proof_result.layer3_transcript_digest,
            layer3_proof_bound_transcript_digest: self
                .proof_result
                .layer3_proof_bound_transcript_digest,
            layer3_proof_binding_digest: self.proof_result.layer3_proof_binding_digest,
            lineage_commitment: recomputed_lineage_commitment,
            lineage_hash: recomputed_lineage_hash,
            dcm_commitment_root: self.public_claim.lower_layer_claim.commitment_root,
            dcm_trace_commitment: recomputed_commitments.dcm_trace_commitment,
            intent_hash: self.public_claim.layer2_object.lineage.intent_hash,
            result_commitment: expected_result_commitment,
            result_digest: expected_result_digest,
        };

        let consumer_object_bytes = canonical_layer3_authorization_lineage_consumer_object_bytes_v1(
            self,
            &public_claim_bytes,
            &canonical_proof_result,
        );
        let consumer_object_hash = sha256_bytes(&consumer_object_bytes);
        let consumer_object_commitment =
            derive_layer3_authorization_lineage_consumer_object_commitment_v1(
                self.consumer_version,
                self.consumer_flags,
                self.decision,
                &self.public_claim,
                expected_result_commitment,
            )
            .map_err(Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object)?;

        Ok(ValidatedLayer3AuthorizationLineageConsumerObjectV1 {
            acceptance: Layer3AuthorizationLineageConsumerAcceptanceV1 {
                decision: self.decision,
                proof_result: canonical_proof_result,
                consumer_object_commitment,
                consumer_object_hash,
            },
            public_claim_bytes,
            canonical_proof_result,
        })
    }
}

fn compare_hashes_v1(
    field: &'static str,
    expected: [u8; HASH_LEN_V1],
    actual: [u8; HASH_LEN_V1],
) -> Result<(), Layer3AuthorizationLineageConsumerErrorV1> {
    if expected != actual {
        return Err(Layer3AuthorizationLineageConsumerErrorV1::HashMismatch {
            field,
            expected,
            actual,
        });
    }

    Ok(())
}

fn compare_commitments_v1(
    field: &'static str,
    expected: DeterministicCommitment521V1,
    actual: DeterministicCommitment521V1,
) -> Result<(), Layer3AuthorizationLineageConsumerErrorV1> {
    if expected != actual {
        return Err(
            Layer3AuthorizationLineageConsumerErrorV1::CommitmentMismatch {
                field,
                expected,
                actual,
            },
        );
    }

    Ok(())
}

pub(crate) fn derive_layer3_authorization_lineage_consumer_result_commitment_v1(
    decision: Layer3AuthorizationLineageConsumerDecisionV1,
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    layer3_transcript_digest: [u8; HASH_LEN_V1],
    layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    layer3_proof_binding_digest: [u8; HASH_LEN_V1],
) -> Result<DeterministicCommitment521V1, NativeLayer2AuthorizationLineageObjectV1Error> {
    Ok(derive_deterministic_commitment_521_v1(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_layer3_authorization_lineage_consumer_result_primary_material_bytes_v1(
            decision,
            public_claim,
            layer3_transcript_digest,
            layer3_proof_bound_transcript_digest,
            layer3_proof_binding_digest,
        )?,
    ))
}

fn derive_layer3_authorization_lineage_consumer_result_digest_v1(
    decision: Layer3AuthorizationLineageConsumerDecisionV1,
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    layer3_transcript_digest: [u8; HASH_LEN_V1],
    layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    layer3_proof_binding_digest: [u8; HASH_LEN_V1],
) -> Result<[u8; HASH_LEN_V1], NativeLayer2AuthorizationLineageObjectV1Error> {
    Ok(sha256_domain_separated(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
        &canonical_layer3_authorization_lineage_consumer_result_primary_material_bytes_v1(
            decision,
            public_claim,
            layer3_transcript_digest,
            layer3_proof_bound_transcript_digest,
            layer3_proof_binding_digest,
        )?,
    ))
}

fn canonical_layer3_authorization_lineage_consumer_result_primary_material_bytes_v1(
    decision: Layer3AuthorizationLineageConsumerDecisionV1,
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    layer3_transcript_digest: [u8; HASH_LEN_V1],
    layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    layer3_proof_binding_digest: [u8; HASH_LEN_V1],
) -> Result<Vec<u8>, NativeLayer2AuthorizationLineageObjectV1Error> {
    let lower_layer_claim_bytes = public_claim.lower_layer_claim.canonical_bytes();
    let layer2_primary_bytes =
        canonical_native_layer2_authorization_lineage_primary_bytes_v1(&public_claim.layer2_object)?;
    let mut bytes = Vec::with_capacity(
        1
            + lower_layer_claim_bytes.len()
            + layer2_primary_bytes.len()
            + (HASH_LEN_V1 * 3),
    );
    bytes.push(decision.as_u8());
    bytes.extend_from_slice(&lower_layer_claim_bytes);
    bytes.extend_from_slice(&layer2_primary_bytes);
    bytes.extend_from_slice(&layer3_transcript_digest);
    bytes.extend_from_slice(&layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&layer3_proof_binding_digest);
    Ok(bytes)
}

pub(crate) fn derive_layer3_authorization_lineage_consumer_object_commitment_v1(
    consumer_version: u8,
    consumer_flags: u16,
    decision: Layer3AuthorizationLineageConsumerDecisionV1,
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    result_commitment: DeterministicCommitment521V1,
) -> Result<DeterministicCommitment521V1, NativeLayer2AuthorizationLineageObjectV1Error> {
    Ok(derive_deterministic_commitment_521_v1(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_layer3_authorization_lineage_consumer_object_primary_material_bytes_v1(
            consumer_version,
            consumer_flags,
            decision,
            public_claim,
            result_commitment,
        )?,
    ))
}

fn canonical_layer3_authorization_lineage_consumer_object_primary_material_bytes_v1(
    consumer_version: u8,
    consumer_flags: u16,
    decision: Layer3AuthorizationLineageConsumerDecisionV1,
    public_claim: &Layer3AuthorizationLineagePublicClaimV1,
    result_commitment: DeterministicCommitment521V1,
) -> Result<Vec<u8>, NativeLayer2AuthorizationLineageObjectV1Error> {
    let lower_layer_claim_bytes = public_claim.lower_layer_claim.canonical_bytes();
    let layer2_primary_bytes =
        canonical_native_layer2_authorization_lineage_primary_bytes_v1(&public_claim.layer2_object)?;
    let mut bytes = Vec::with_capacity(
        1
            + 2
            + 1
            + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1
            + lower_layer_claim_bytes.len()
            + layer2_primary_bytes.len(),
    );
    bytes.push(consumer_version);
    bytes.extend_from_slice(&consumer_flags.to_le_bytes());
    bytes.push(decision.as_u8());
    bytes.extend_from_slice(&result_commitment.to_bytes());
    bytes.extend_from_slice(&lower_layer_claim_bytes);
    bytes.extend_from_slice(&layer2_primary_bytes);
    Ok(bytes)
}

fn canonical_layer3_authorization_lineage_consumer_object_bytes_v1(
    object: &Layer3AuthorizationLineageConsumerObjectV1,
    public_claim_bytes: &[u8],
    canonical_proof_result: &Layer3AuthorizationLineageConsumerProofResultV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1.len()
            + 1
            + 2
            + 1
            + LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_PROOF_RESULT_SERIALIZED_LEN_V1
            + public_claim_bytes.len(),
    );
    bytes.extend_from_slice(AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1);
    bytes.push(object.consumer_version);
    bytes.extend_from_slice(&object.consumer_flags.to_le_bytes());
    bytes.push(object.decision.as_u8());
    bytes.extend_from_slice(&canonical_proof_result.public_claim_digest);
    bytes.extend_from_slice(&canonical_proof_result.layer3_transcript_digest);
    bytes.extend_from_slice(&canonical_proof_result.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&canonical_proof_result.layer3_proof_binding_digest);
    bytes.extend_from_slice(&canonical_proof_result.lineage_commitment.to_bytes());
    bytes.extend_from_slice(&canonical_proof_result.lineage_hash);
    bytes.extend_from_slice(&canonical_proof_result.dcm_commitment_root);
    bytes.extend_from_slice(&canonical_proof_result.dcm_trace_commitment);
    bytes.extend_from_slice(&canonical_proof_result.intent_hash);
    bytes.extend_from_slice(&canonical_proof_result.result_commitment.to_bytes());
    bytes.extend_from_slice(&canonical_proof_result.result_digest);
    bytes.extend_from_slice(public_claim_bytes);
    bytes
}
