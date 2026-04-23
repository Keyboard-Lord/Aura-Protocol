//! First Layer 3 -> Layer 4 verified-authorization ingress object for Aura.
//!
//! This object is RESEARCH / SUPPORTING only. It conveys one verified Layer 3
//! authorization result into one canonical Layer 4 intent context. It does not
//! modify the active canonical pipeline and does not add settlement, report,
//! burn, ledger, wallet, attestation, or verifier-adapter authority.

use core::fmt;

use crate::{
    canonical_native_layer2_authorization_lineage_primary_bytes_v1,
    construct_layer3_authorization_lineage_proof_transcript_v1,
    consume_layer3_authorization_lineage_consumer_object_v1,
    derive_deterministic_commitment_521_v1,
    derive_layer3_authorization_lineage_consumer_object_commitment_v1,
    derive_layer3_authorization_lineage_consumer_result_commitment_v1,
    sha256_bytes, AuraLayer4IntentBodyV1, AuraLayer4IntentHashV1Error,
    AuthorizationEnvelopeValidityBoundsV1, DcmCommitmentKindV1, DeterministicCommitment521V1,
    DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1, FreshnessModeV1, IntentTypeV1,
    Layer3AuthorizationLineageBoundaryErrorV1, Layer3AuthorizationLineageConsumerErrorV1,
    Layer3AuthorizationLineageConsumerObjectV1, Layer3AuthorizationLineageProvingInputV1,
    Layer3AuthorizationLineageVerifierErrorV1, LowerHex32, LowerHex521,
    NativeLayer2AuthorizationLineageObjectV1, NativeLayer2AuthorizationLineageObjectV1Error,
    SubjectBindingTypeV1, HASH_LEN_V1,
};

pub const LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_VERSION_V1: u8 = 1;
pub const AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_V1";
pub const AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_V1";
pub const AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3VerifiedAuthorizationResultV1 {
    pub lineage_commitment: DeterministicCommitment521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub result_commitment: DeterministicCommitment521V1,
    pub layer3_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_binding_digest: [u8; HASH_LEN_V1],
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub dcm_trace_commitment: [u8; HASH_LEN_V1],
    pub intent_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalLayer4IntentContextV1 {
    pub controlled_account_id: [u8; HASH_LEN_V1],
    pub sender_nonce: u64,
    pub envelope_validity_bounds: AuthorizationEnvelopeValidityBoundsV1,
    pub intent_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer4VerifiedAuthorizationPublicStatementV1 {
    pub version: u8,
    pub lineage_flags: u16,
    pub dcm_commitment_kind: DcmCommitmentKindV1,
    pub lineage_commitment: DeterministicCommitment521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub subject_binding_type: SubjectBindingTypeV1,
    pub subject_id: [u8; HASH_LEN_V1],
    pub intent_type: IntentTypeV1,
    pub intent_hash: [u8; HASH_LEN_V1],
    pub freshness_mode: FreshnessModeV1,
    pub freshness_nonce: [u8; HASH_LEN_V1],
    pub freshness_reference: u64,
    pub layer3_result_commitment: DeterministicCommitment521V1,
    pub layer3_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_bound_transcript_digest: [u8; HASH_LEN_V1],
    pub layer3_proof_binding_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer3Layer4VerifiedAuthorizationIngressV1 {
    pub ingress_version: u8,
    pub ingress_flags: u16,
    pub consumer_object: Layer3AuthorizationLineageConsumerObjectV1,
    pub intent_body: AuraLayer4IntentBodyV1,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Layer3Layer4VerifiedAuthorizationIngressErrorV1 {
    InvalidVersion {
        expected: u8,
        actual: u8,
    },
    ReservedFlagsNonZero {
        actual: u16,
    },
    InvalidIntent(AuraLayer4IntentHashV1Error),
    Layer3VerificationRejected(Layer3AuthorizationLineageVerifierErrorV1),
    Layer3ConsumerRejected(Layer3AuthorizationLineageConsumerErrorV1),
    InvalidFieldCombination {
        reason: &'static str,
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

impl fmt::Display for Layer3Layer4VerifiedAuthorizationIngressErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid ingress version: expected {expected}, got {actual}"
                )
            }
            Self::ReservedFlagsNonZero { actual } => {
                write!(f, "ingress flags reserved bits non-zero: 0x{actual:04x}")
            }
            Self::InvalidIntent(error) => write!(f, "invalid intent body: {error}"),
            Self::Layer3VerificationRejected(error) => {
                write!(f, "layer3 verification rejected ingress source: {error}")
            }
            Self::Layer3ConsumerRejected(error) => {
                write!(f, "layer3 consumer rejected ingress source: {error}")
            }
            Self::InvalidFieldCombination { reason } => {
                write!(f, "invalid field combination: {reason}")
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

impl std::error::Error for Layer3Layer4VerifiedAuthorizationIngressErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer3Layer4VerifiedAuthorizationAcceptanceV1 {
    pub lineage_commitment: DeterministicCommitment521V1,
    pub result_commitment: DeterministicCommitment521V1,
    pub consumer_commitment: DeterministicCommitment521V1,
    pub ingress_commitment: DeterministicCommitment521V1,
    pub public_statement_commitment: DeterministicCommitment521V1,
    pub verified_authorization: Layer3VerifiedAuthorizationResultV1,
    pub context: CanonicalLayer4IntentContextV1,
    pub public_statement: Layer4VerifiedAuthorizationPublicStatementV1,
}

pub fn produce_layer3_layer4_verified_authorization_ingress_v1(
    consumer_object: &Layer3AuthorizationLineageConsumerObjectV1,
    intent_body: AuraLayer4IntentBodyV1,
) -> Result<
    Layer3Layer4VerifiedAuthorizationIngressV1,
    Layer3Layer4VerifiedAuthorizationIngressErrorV1,
> {
    let ingress = Layer3Layer4VerifiedAuthorizationIngressV1 {
        ingress_version: LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_VERSION_V1,
        ingress_flags: 0,
        consumer_object: consumer_object.clone(),
        intent_body,
    };
    ingress.validate()?;
    Ok(ingress)
}

pub fn accept_layer3_layer4_verified_authorization_ingress_v1(
    ingress: &Layer3Layer4VerifiedAuthorizationIngressV1,
) -> Result<
    Layer3Layer4VerifiedAuthorizationAcceptanceV1,
    Layer3Layer4VerifiedAuthorizationIngressErrorV1,
> {
    ingress.validate_inner()
}

impl Layer3Layer4VerifiedAuthorizationIngressV1 {
    pub fn validate(&self) -> Result<(), Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
        self.validate_inner().map(|_| ())
    }

    pub fn canonical_layer4_intent_context(
        &self,
    ) -> Result<CanonicalLayer4IntentContextV1, Layer3Layer4VerifiedAuthorizationIngressErrorV1>
    {
        Ok(self.validate_inner()?.context)
    }

    pub fn verified_authorization_result(
        &self,
    ) -> Result<Layer3VerifiedAuthorizationResultV1, Layer3Layer4VerifiedAuthorizationIngressErrorV1>
    {
        Ok(self.validate_inner()?.verified_authorization)
    }

    pub fn layer2_object(&self) -> &NativeLayer2AuthorizationLineageObjectV1 {
        &self.consumer_object.public_claim.layer2_object
    }

    pub fn verified_authorization_public_statement(
        &self,
    ) -> Result<
        Layer4VerifiedAuthorizationPublicStatementV1,
        Layer3Layer4VerifiedAuthorizationIngressErrorV1,
    > {
        Ok(self.validate_inner()?.public_statement)
    }

    pub fn serialized_object(
        &self,
    ) -> Result<Vec<u8>, Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
        self.validate()?;

        let consumer_bytes = self
            .consumer_object
            .serialized_object()
            .map_err(map_layer3_consumer_error_to_ingress_error_v1)?;
        let intent_hash_preimage = self
            .intent_body
            .canonical_hash_preimage()
            .map_err(Layer3Layer4VerifiedAuthorizationIngressErrorV1::InvalidIntent)?;

        let mut bytes = Vec::with_capacity(
            AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_DOMAIN_SEPARATOR_V1.len()
                + 1
                + 2
                + consumer_bytes.len()
                + 4
                + intent_hash_preimage.len(),
        );
        bytes.extend_from_slice(
            AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_DOMAIN_SEPARATOR_V1,
        );
        bytes.push(self.ingress_version);
        bytes.extend_from_slice(&self.ingress_flags.to_le_bytes());
        bytes.extend_from_slice(&consumer_bytes);
        bytes.extend_from_slice(&(intent_hash_preimage.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&intent_hash_preimage);
        Ok(bytes)
    }

    pub fn ingress_hash(
        &self,
    ) -> Result<[u8; HASH_LEN_V1], Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
        Ok(sha256_bytes(&self.serialized_object()?))
    }

    pub fn ingress_commitment(
        &self,
    ) -> Result<DeterministicCommitment521V1, Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
        Ok(self.validate_inner()?.ingress_commitment)
    }

    pub fn verified_authorization_public_statement_commitment(
        &self,
    ) -> Result<DeterministicCommitment521V1, Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
        Ok(self.validate_inner()?.public_statement_commitment)
    }

    fn validate_inner(
        &self,
    ) -> Result<
        Layer3Layer4VerifiedAuthorizationAcceptanceV1,
        Layer3Layer4VerifiedAuthorizationIngressErrorV1,
    > {
        if self.ingress_version != LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_VERSION_V1 {
            return Err(
                Layer3Layer4VerifiedAuthorizationIngressErrorV1::InvalidVersion {
                    expected: LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_VERSION_V1,
                    actual: self.ingress_version,
                },
            );
        }

        if self.ingress_flags != 0 {
            return Err(
                Layer3Layer4VerifiedAuthorizationIngressErrorV1::ReservedFlagsNonZero {
                    actual: self.ingress_flags,
                },
            );
        }

        let acceptance =
            consume_layer3_authorization_lineage_consumer_object_v1(&self.consumer_object)
                .map_err(map_layer3_consumer_error_to_ingress_error_v1)?;
        let layer2_object = &self.consumer_object.public_claim.layer2_object;
        let expected_transcript_digest =
            canonical_layer3_transcript_digest_from_ingress_v1(&self.consumer_object, self.intent_body)?;

        if layer2_object.lineage.dcm_commitment_kind != DcmCommitmentKindV1::DcmRootCommitmentV1 {
            return Err(
                Layer3Layer4VerifiedAuthorizationIngressErrorV1::InvalidFieldCombination {
                    reason: "layer3_layer4_ingress_requires_native_dcm_root_commitment",
                },
            );
        }

        if layer2_object.lineage.intent_type != IntentTypeV1::AuraLayer4IntentHashV1 {
            return Err(
                Layer3Layer4VerifiedAuthorizationIngressErrorV1::InvalidFieldCombination {
                    reason: "layer3_layer4_ingress_requires_aura_layer4_intent_hash_v1",
                },
            );
        }

        let intent_hash = self
            .intent_body
            .intent_hash()
            .map_err(Layer3Layer4VerifiedAuthorizationIngressErrorV1::InvalidIntent)?;
        let expected_result_commitment = derive_layer3_authorization_lineage_consumer_result_commitment_v1(
            self.consumer_object.decision,
            &self.consumer_object.public_claim,
            expected_transcript_digest,
            acceptance.proof_result.layer3_proof_bound_transcript_digest,
            acceptance.proof_result.layer3_proof_binding_digest,
        )
        .map_err(map_native_layer2_object_error_to_ingress_error_v1)?;
        let consumer_commitment = derive_layer3_authorization_lineage_consumer_object_commitment_v1(
            self.consumer_object.consumer_version,
            self.consumer_object.consumer_flags,
            self.consumer_object.decision,
            &self.consumer_object.public_claim,
            expected_result_commitment,
        )
        .map_err(map_native_layer2_object_error_to_ingress_error_v1)?;
        let verified_authorization = Layer3VerifiedAuthorizationResultV1 {
            lineage_commitment: acceptance.proof_result.lineage_commitment,
            lineage_hash: acceptance.proof_result.lineage_hash,
            result_commitment: expected_result_commitment,
            layer3_transcript_digest: expected_transcript_digest,
            layer3_proof_bound_transcript_digest: acceptance
                .proof_result
                .layer3_proof_bound_transcript_digest,
            layer3_proof_binding_digest: acceptance.proof_result.layer3_proof_binding_digest,
            dcm_commitment_root: acceptance.proof_result.dcm_commitment_root,
            dcm_trace_commitment: acceptance.proof_result.dcm_trace_commitment,
            intent_hash: acceptance.proof_result.intent_hash,
        };

        compare_commitments_v1(
            "verified_authorization.lineage_commitment",
            layer2_object.lineage_commitment,
            verified_authorization.lineage_commitment,
        )?;
        compare_commitments_v1(
            "consumer_object.proof_result.result_commitment",
            expected_result_commitment,
            acceptance.proof_result.result_commitment,
        )?;
        compare_hashes_v1(
            "verified_authorization.dcm_commitment_root",
            layer2_object.lineage.dcm_commitment_root,
            verified_authorization.dcm_commitment_root,
        )?;
        compare_hashes_v1(
            "verified_authorization.dcm_trace_commitment",
            layer2_object.lineage.dcm_trace_commitment,
            verified_authorization.dcm_trace_commitment,
        )?;
        compare_hashes_v1(
            "layer2_object.intent_hash",
            intent_hash,
            layer2_object.lineage.intent_hash,
        )?;
        compare_hashes_v1(
            "verified_authorization.intent_hash",
            intent_hash,
            verified_authorization.intent_hash,
        )?;
        compare_hashes_v1(
            "consumer_object.proof_result.layer3_transcript_digest",
            expected_transcript_digest,
            acceptance.proof_result.layer3_transcript_digest,
        )?;
        compare_commitments_v1(
            "consumer_object.consumer_commitment",
            consumer_commitment,
            acceptance.consumer_object_commitment,
        )?;

        let context = CanonicalLayer4IntentContextV1 {
            controlled_account_id: self.intent_body.sender_account_id,
            sender_nonce: self.intent_body.sender_nonce,
            envelope_validity_bounds: AuthorizationEnvelopeValidityBoundsV1 {
                validity_flags: self.intent_body.validity_flags,
                not_before_unix_seconds: self.intent_body.not_before_unix_seconds,
                not_after_unix_seconds: self.intent_body.not_after_unix_seconds,
                not_before_batch_number: self.intent_body.not_before_batch_number,
                not_after_batch_number: self.intent_body.not_after_batch_number,
            },
            intent_hash,
        };

        let public_statement = Layer4VerifiedAuthorizationPublicStatementV1 {
            version: layer2_object.lineage.version,
            lineage_flags: layer2_object.lineage.lineage_flags,
            dcm_commitment_kind: layer2_object.lineage.dcm_commitment_kind,
            lineage_commitment: layer2_object.lineage_commitment,
            lineage_hash: acceptance.proof_result.lineage_hash,
            subject_binding_type: layer2_object.lineage.subject_binding_type,
            subject_id: layer2_object.lineage.subject_id,
            intent_type: layer2_object.lineage.intent_type,
            intent_hash: layer2_object.lineage.intent_hash,
            freshness_mode: layer2_object.lineage.freshness_mode,
            freshness_nonce: layer2_object.lineage.freshness_nonce,
            freshness_reference: layer2_object.lineage.freshness_reference,
            layer3_result_commitment: expected_result_commitment,
            layer3_transcript_digest: verified_authorization.layer3_transcript_digest,
            layer3_proof_bound_transcript_digest: verified_authorization
                .layer3_proof_bound_transcript_digest,
            layer3_proof_binding_digest: verified_authorization.layer3_proof_binding_digest,
        };
        compare_hashes_v1(
            "public_statement.layer3_transcript_digest",
            acceptance.proof_result.layer3_transcript_digest,
            public_statement.layer3_transcript_digest,
        )?;
        compare_commitments_v1(
            "public_statement.lineage_commitment",
            layer2_object.lineage_commitment,
            public_statement.lineage_commitment,
        )?;
        compare_commitments_v1(
            "public_statement.layer3_result_commitment",
            expected_result_commitment,
            public_statement.layer3_result_commitment,
        )?;
        compare_hashes_v1(
            "public_statement.layer3_proof_bound_transcript_digest",
            acceptance.proof_result.layer3_proof_bound_transcript_digest,
            public_statement.layer3_proof_bound_transcript_digest,
        )?;
        compare_hashes_v1(
            "public_statement.layer3_proof_binding_digest",
            acceptance.proof_result.layer3_proof_binding_digest,
            public_statement.layer3_proof_binding_digest,
        )?;
        let ingress_commitment = derive_layer3_layer4_verified_authorization_ingress_commitment_v1(
            self.ingress_version,
            self.ingress_flags,
            &self.consumer_object.public_claim,
            verified_authorization.lineage_commitment,
            expected_result_commitment,
            consumer_commitment,
            &self.intent_body,
        )
        ?;
        let public_statement_commitment =
            derive_layer4_verified_authorization_public_statement_commitment_v1(
                &public_statement,
                ingress_commitment,
            );

        Ok(Layer3Layer4VerifiedAuthorizationAcceptanceV1 {
            lineage_commitment: verified_authorization.lineage_commitment,
            result_commitment: expected_result_commitment,
            consumer_commitment,
            ingress_commitment,
            public_statement_commitment,
            verified_authorization,
            context,
            public_statement,
        })
    }
}

fn compare_hashes_v1(
    field: &'static str,
    expected: [u8; HASH_LEN_V1],
    actual: [u8; HASH_LEN_V1],
) -> Result<(), Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
    if expected != actual {
        return Err(
            Layer3Layer4VerifiedAuthorizationIngressErrorV1::HashMismatch {
                field,
                expected,
                actual,
            },
        );
    }

    Ok(())
}

fn compare_commitments_v1(
    field: &'static str,
    expected: DeterministicCommitment521V1,
    actual: DeterministicCommitment521V1,
) -> Result<(), Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
    if expected != actual {
        return Err(
            Layer3Layer4VerifiedAuthorizationIngressErrorV1::CommitmentMismatch {
                field,
                expected,
                actual,
            },
        );
    }

    Ok(())
}

fn derive_layer3_layer4_verified_authorization_ingress_commitment_v1(
    ingress_version: u8,
    ingress_flags: u16,
    public_claim: &crate::Layer3AuthorizationLineagePublicClaimV1,
    lineage_commitment: DeterministicCommitment521V1,
    result_commitment: DeterministicCommitment521V1,
    consumer_commitment: DeterministicCommitment521V1,
    intent_body: &AuraLayer4IntentBodyV1,
) -> Result<DeterministicCommitment521V1, Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
    Ok(derive_deterministic_commitment_521_v1(
        AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_layer3_layer4_verified_authorization_ingress_primary_material_bytes_v1(
            ingress_version,
            ingress_flags,
            public_claim,
            lineage_commitment,
            result_commitment,
            consumer_commitment,
            intent_body,
        )?,
    ))
}

fn canonical_layer3_layer4_verified_authorization_ingress_primary_material_bytes_v1(
    ingress_version: u8,
    ingress_flags: u16,
    public_claim: &crate::Layer3AuthorizationLineagePublicClaimV1,
    lineage_commitment: DeterministicCommitment521V1,
    result_commitment: DeterministicCommitment521V1,
    consumer_commitment: DeterministicCommitment521V1,
    intent_body: &AuraLayer4IntentBodyV1,
) -> Result<Vec<u8>, Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
    let layer2_primary_bytes =
        canonical_native_layer2_authorization_lineage_primary_bytes_v1(&public_claim.layer2_object)
            .map_err(map_native_layer2_object_error_to_ingress_error_v1)?;
    let intent_hash_preimage = intent_body
        .canonical_hash_preimage()
        .map_err(Layer3Layer4VerifiedAuthorizationIngressErrorV1::InvalidIntent)?;
    let mut bytes = Vec::with_capacity(
        1
            + 2
            + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 3
            + layer2_primary_bytes.len()
            + intent_hash_preimage.len(),
    );
    bytes.push(ingress_version);
    bytes.extend_from_slice(&ingress_flags.to_le_bytes());
    bytes.extend_from_slice(&lineage_commitment.to_bytes());
    bytes.extend_from_slice(&result_commitment.to_bytes());
    bytes.extend_from_slice(&consumer_commitment.to_bytes());
    bytes.extend_from_slice(&layer2_primary_bytes);
    bytes.extend_from_slice(&intent_hash_preimage);
    Ok(bytes)
}

fn derive_layer4_verified_authorization_public_statement_commitment_v1(
    statement: &Layer4VerifiedAuthorizationPublicStatementV1,
    ingress_commitment: DeterministicCommitment521V1,
) -> DeterministicCommitment521V1 {
    derive_deterministic_commitment_521_v1(
        AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_layer4_verified_authorization_public_statement_primary_material_bytes_v1(
            statement,
            ingress_commitment,
        ),
    )
}

fn canonical_layer4_verified_authorization_public_statement_primary_material_bytes_v1(
    statement: &Layer4VerifiedAuthorizationPublicStatementV1,
    ingress_commitment: DeterministicCommitment521V1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 2 + 1 + (DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 3) + (HASH_LEN_V1 * 3) + 8,
    );
    bytes.push(statement.version);
    bytes.extend_from_slice(&statement.lineage_flags.to_le_bytes());
    bytes.push(statement.dcm_commitment_kind.as_u8());
    bytes.extend_from_slice(&statement.lineage_commitment.to_bytes());
    bytes.push(statement.subject_binding_type.as_u8());
    bytes.extend_from_slice(&statement.subject_id);
    bytes.push(statement.intent_type.as_u8());
    bytes.extend_from_slice(&statement.intent_hash);
    bytes.push(statement.freshness_mode.as_u8());
    bytes.extend_from_slice(&statement.freshness_nonce);
    bytes.extend_from_slice(&statement.freshness_reference.to_le_bytes());
    bytes.extend_from_slice(&statement.layer3_result_commitment.to_bytes());
    bytes.extend_from_slice(&ingress_commitment.to_bytes());
    bytes
}

fn canonical_layer3_transcript_digest_from_ingress_v1(
    consumer_object: &Layer3AuthorizationLineageConsumerObjectV1,
    intent_body: AuraLayer4IntentBodyV1,
) -> Result<[u8; HASH_LEN_V1], Layer3Layer4VerifiedAuthorizationIngressErrorV1> {
    let transcript = construct_layer3_authorization_lineage_proof_transcript_v1(
        &Layer3AuthorizationLineageProvingInputV1::new(
            consumer_object.public_claim.lower_layer_claim,
            consumer_object.public_claim.layer2_object.clone(),
            intent_body,
        ),
    )
    .map_err(map_layer3_boundary_error_to_ingress_error_v1)?;
    Ok(transcript.transcript_digest)
}

fn map_layer3_consumer_error_to_ingress_error_v1(
    error: Layer3AuthorizationLineageConsumerErrorV1,
) -> Layer3Layer4VerifiedAuthorizationIngressErrorV1 {
    match error {
        Layer3AuthorizationLineageConsumerErrorV1::Layer3VerificationRejected(error) => {
            Layer3Layer4VerifiedAuthorizationIngressErrorV1::Layer3VerificationRejected(error)
        }
        other => Layer3Layer4VerifiedAuthorizationIngressErrorV1::Layer3ConsumerRejected(other),
    }
}

fn map_layer3_boundary_error_to_ingress_error_v1(
    error: Layer3AuthorizationLineageBoundaryErrorV1,
) -> Layer3Layer4VerifiedAuthorizationIngressErrorV1 {
    Layer3Layer4VerifiedAuthorizationIngressErrorV1::Layer3VerificationRejected(
        Layer3AuthorizationLineageVerifierErrorV1::BoundaryValidationFailed(error),
    )
}

fn map_native_layer2_object_error_to_ingress_error_v1(
    error: NativeLayer2AuthorizationLineageObjectV1Error,
) -> Layer3Layer4VerifiedAuthorizationIngressErrorV1 {
    Layer3Layer4VerifiedAuthorizationIngressErrorV1::Layer3ConsumerRejected(
        Layer3AuthorizationLineageConsumerErrorV1::InvalidLayer2Object(error),
    )
}
