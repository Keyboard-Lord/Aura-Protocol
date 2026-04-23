//! First frozen Layer 2 authorization-lineage object for the native cat-map path.
//!
//! This object is RESEARCH / SUPPORTING only. It does not modify the active canonical
//! request/report pipeline, settlement, or verifier-adapter surfaces.

use core::fmt;

use crate::{
    derive_dcm_layer1_commitments_521_v1, derive_deterministic_commitment_521_v1,
    AuthorizationLineageV1, AuthorizationLineageV1Error, DcmCommitmentKindV1, DcmConfig521V1,
    DcmInput521V1, DeterministicCommitment521V1, FreshnessModeV1, IntentTypeV1,
    Layer1Layer2BridgeErrorV1, Layer1Layer2BridgeFreshnessV1, Layer1Layer2BridgeIntentSourceV1,
    Layer1Layer2BridgeSubjectBindingV1, Layer1Layer2BridgeSuccess521V1, SubjectBindingTypeV1,
    AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1, DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
    HASH_LEN_V1, LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT, LowerHex521,
};

pub const NATIVE_LAYER2_AUTHORIZATION_LINEAGE_PREIMAGE_LEN_V1: usize = 300;
pub const AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_V1";
pub const NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1: usize =
    NATIVE_LAYER2_AUTHORIZATION_LINEAGE_PREIMAGE_LEN_V1
        + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1
        + HASH_LEN_V1;
const NATIVE_LAYER2_OBJECT_REQUIRES_CANONICAL_LAYER1_COMMITMENTS_REASON_V1: &str =
    "native_layer2_object_requires_canonical_layer1_commitments";
const NATIVE_LAYER2_OBJECT_BRIDGE_LINEAGE_HASH_MISMATCH_REASON_V1: &str =
    "native_layer2_object_bridge_lineage_hash_mismatch";
const NATIVE_LAYER2_OBJECT_BRIDGE_LINEAGE_MUST_NOT_PREBIND_TRACE_REASON_V1: &str =
    "native_layer2_object_bridge_lineage_must_not_prebind_trace_commitment";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLayer2AuthorizationLineageObjectV1 {
    pub lineage: AuthorizationLineageV1,
    pub lineage_commitment: DeterministicCommitment521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLayer2AuthorizationLineageObjectV1Error {
    InvalidSerializedLength {
        expected: usize,
        actual: usize,
    },
    InvalidDomainSeparator,
    InvalidLineageCommitmentEncoding,
    InvalidDcmCommitmentKind {
        actual: u8,
    },
    InvalidSubjectBindingType {
        actual: u8,
    },
    InvalidIntentType {
        actual: u8,
    },
    InvalidFreshnessMode {
        actual: u8,
    },
    NativeDcmRootedLineageRequired {
        actual: DcmCommitmentKindV1,
    },
    CommitmentRootMustNotBeZero,
    TraceCommitmentRequired,
    TraceCommitmentMustNotBeZero,
    LineageValidation(AuthorizationLineageV1Error),
    LineageCommitmentMismatch {
        expected: DeterministicCommitment521V1,
        actual: DeterministicCommitment521V1,
    },
    LineageHashMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
}

impl NativeLayer2AuthorizationLineageObjectV1Error {
    pub const fn reject_reason(self) -> &'static str {
        match self {
            Self::InvalidSerializedLength { .. } => {
                "native_layer2_object_serialized_length_invalid"
            }
            Self::InvalidDomainSeparator => "native_layer2_object_domain_separator_invalid",
            Self::InvalidLineageCommitmentEncoding => {
                "native_layer2_object_lineage_commitment_encoding_invalid"
            }
            Self::InvalidDcmCommitmentKind { .. } => {
                "native_layer2_object_dcm_commitment_kind_invalid"
            }
            Self::InvalidSubjectBindingType { .. } => {
                "native_layer2_object_subject_binding_type_invalid"
            }
            Self::InvalidIntentType { .. } => "native_layer2_object_intent_type_invalid",
            Self::InvalidFreshnessMode { .. } => "native_layer2_object_freshness_mode_invalid",
            Self::NativeDcmRootedLineageRequired { .. } => {
                "native_layer2_object_native_dcm_rooted_lineage_required"
            }
            Self::CommitmentRootMustNotBeZero => {
                "native_layer2_object_commitment_root_must_not_be_zero"
            }
            Self::TraceCommitmentRequired => "native_layer2_object_trace_commitment_required",
            Self::TraceCommitmentMustNotBeZero => {
                "native_layer2_object_trace_commitment_must_not_be_zero"
            }
            Self::LineageValidation(error) => error.reject_reason(),
            Self::LineageCommitmentMismatch { .. } => {
                "native_layer2_object_lineage_commitment_mismatch"
            }
            Self::LineageHashMismatch { .. } => "native_layer2_object_lineage_hash_mismatch",
        }
    }
}

impl fmt::Display for NativeLayer2AuthorizationLineageObjectV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSerializedLength { expected, actual } => write!(
                f,
                "invalid serialized object length: expected {expected}, got {actual}"
            ),
            Self::InvalidDomainSeparator => {
                write!(f, "invalid native layer2 object domain separator")
            }
            Self::InvalidLineageCommitmentEncoding => {
                write!(f, "invalid native layer2 object lineage commitment encoding")
            }
            Self::InvalidDcmCommitmentKind { actual } => {
                write!(f, "invalid dcm commitment kind byte: 0x{actual:02x}")
            }
            Self::InvalidSubjectBindingType { actual } => {
                write!(f, "invalid subject binding type byte: 0x{actual:02x}")
            }
            Self::InvalidIntentType { actual } => {
                write!(f, "invalid intent type byte: 0x{actual:02x}")
            }
            Self::InvalidFreshnessMode { actual } => {
                write!(f, "invalid freshness mode byte: 0x{actual:02x}")
            }
            Self::NativeDcmRootedLineageRequired { actual } => write!(
                f,
                "native layer2 object requires dcm-rooted lineage, got {:?}",
                actual
            ),
            Self::CommitmentRootMustNotBeZero => {
                write!(
                    f,
                    "native layer2 object requires a non-zero commitment root"
                )
            }
            Self::TraceCommitmentRequired => {
                write!(f, "native layer2 object requires the trace commitment flag")
            }
            Self::TraceCommitmentMustNotBeZero => {
                write!(
                    f,
                    "native layer2 object requires a non-zero trace commitment"
                )
            }
            Self::LineageValidation(error) => write!(f, "lineage validation failed: {error}"),
            Self::LineageCommitmentMismatch { expected, actual } => write!(
                f,
                "native layer2 object lineage commitment mismatch: expected {}, got {}",
                LowerHex521(expected),
                LowerHex521(actual)
            ),
            Self::LineageHashMismatch { .. } => {
                write!(f, "native layer2 object lineage digest mismatch")
            }
        }
    }
}

impl std::error::Error for NativeLayer2AuthorizationLineageObjectV1Error {}

impl NativeLayer2AuthorizationLineageObjectV1 {
    pub fn new(
        lineage: AuthorizationLineageV1,
    ) -> Result<Self, NativeLayer2AuthorizationLineageObjectV1Error> {
        let lineage_commitment = derive_native_layer2_authorization_lineage_commitment_v1(&lineage)
            .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)?;
        let lineage_hash = lineage
            .lineage_hash()
            .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)?;
        let object = Self {
            lineage,
            lineage_commitment,
            lineage_hash,
        };
        object.validate()?;
        Ok(object)
    }

    pub fn validate(&self) -> Result<(), NativeLayer2AuthorizationLineageObjectV1Error> {
        self.lineage
            .validate()
            .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)?;

        if self.lineage.dcm_commitment_kind != DcmCommitmentKindV1::DcmRootCommitmentV1 {
            return Err(
                NativeLayer2AuthorizationLineageObjectV1Error::NativeDcmRootedLineageRequired {
                    actual: self.lineage.dcm_commitment_kind,
                },
            );
        }

        if self.lineage.dcm_commitment_root == [0u8; HASH_LEN_V1] {
            return Err(NativeLayer2AuthorizationLineageObjectV1Error::CommitmentRootMustNotBeZero);
        }

        if self.lineage.lineage_flags & LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT == 0 {
            return Err(NativeLayer2AuthorizationLineageObjectV1Error::TraceCommitmentRequired);
        }

        if self.lineage.dcm_trace_commitment == [0u8; HASH_LEN_V1] {
            return Err(
                NativeLayer2AuthorizationLineageObjectV1Error::TraceCommitmentMustNotBeZero,
            );
        }

        let actual_commitment = derive_native_layer2_authorization_lineage_commitment_v1(&self.lineage)
            .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)?;
        if actual_commitment != self.lineage_commitment {
            return Err(
                NativeLayer2AuthorizationLineageObjectV1Error::LineageCommitmentMismatch {
                    expected: self.lineage_commitment,
                    actual: actual_commitment,
                },
            );
        }

        Ok(())
    }

    pub fn serialized_object(
        &self,
    ) -> Result<Vec<u8>, NativeLayer2AuthorizationLineageObjectV1Error> {
        self.validate()?;
        let preimage =
            canonical_native_layer2_authorization_lineage_preimage_v1(&self.lineage).map_err(
                NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation,
            )?;
        let lineage_hash =
            canonical_native_layer2_authorization_lineage_helper_hash_v1(&self.lineage).map_err(
                NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation,
            )?;
        let mut bytes = Vec::with_capacity(NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1);
        bytes.extend_from_slice(&preimage);
        bytes.extend_from_slice(&self.lineage_commitment.to_bytes());
        bytes.extend_from_slice(&lineage_hash);
        Ok(bytes)
    }

    pub fn from_serialized_object_bytes(
        bytes: &[u8],
    ) -> Result<Self, NativeLayer2AuthorizationLineageObjectV1Error> {
        if bytes.len() != NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1 {
            return Err(
                NativeLayer2AuthorizationLineageObjectV1Error::InvalidSerializedLength {
                    expected: NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1,
                    actual: bytes.len(),
                },
            );
        }

        let (preimage, remaining_bytes) =
            bytes.split_at(NATIVE_LAYER2_AUTHORIZATION_LINEAGE_PREIMAGE_LEN_V1);
        let (stored_commitment_bytes, stored_hash_bytes) =
            remaining_bytes.split_at(DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1);
        if !preimage.starts_with(AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1) {
            return Err(NativeLayer2AuthorizationLineageObjectV1Error::InvalidDomainSeparator);
        }

        let mut offset = AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1.len();
        let version = preimage[offset];
        offset += 1;
        let lineage_flags = u16::from_le_bytes([preimage[offset], preimage[offset + 1]]);
        offset += 2;

        let dcm_commitment_kind = DcmCommitmentKindV1::from_u8(preimage[offset]).ok_or(
            NativeLayer2AuthorizationLineageObjectV1Error::InvalidDcmCommitmentKind {
                actual: preimage[offset],
            },
        )?;
        offset += 1;

        let dcm_commitment_root = copy_32(preimage, offset);
        offset += HASH_LEN_V1;
        let dcm_trace_commitment = copy_32(preimage, offset);
        offset += HASH_LEN_V1;

        let subject_binding_type = SubjectBindingTypeV1::from_u8(preimage[offset]).ok_or(
            NativeLayer2AuthorizationLineageObjectV1Error::InvalidSubjectBindingType {
                actual: preimage[offset],
            },
        )?;
        offset += 1;

        let subject_id = copy_32(preimage, offset);
        offset += HASH_LEN_V1;
        let subject_public_key = copy_32(preimage, offset);
        offset += HASH_LEN_V1;

        let intent_type = IntentTypeV1::from_u8(preimage[offset]).ok_or(
            NativeLayer2AuthorizationLineageObjectV1Error::InvalidIntentType {
                actual: preimage[offset],
            },
        )?;
        offset += 1;

        let intent_hash = copy_32(preimage, offset);
        offset += HASH_LEN_V1;

        let freshness_mode = FreshnessModeV1::from_u8(preimage[offset]).ok_or(
            NativeLayer2AuthorizationLineageObjectV1Error::InvalidFreshnessMode {
                actual: preimage[offset],
            },
        )?;
        offset += 1;

        let freshness_nonce = copy_32(preimage, offset);
        offset += HASH_LEN_V1;

        let freshness_reference = u64::from_le_bytes([
            preimage[offset],
            preimage[offset + 1],
            preimage[offset + 2],
            preimage[offset + 3],
            preimage[offset + 4],
            preimage[offset + 5],
            preimage[offset + 6],
            preimage[offset + 7],
        ]);
        offset += 8;

        let proof_material_v1_hash = copy_32(preimage, offset);
        offset += HASH_LEN_V1;
        let fractal_key_v1_hash = copy_32(preimage, offset);
        offset += HASH_LEN_V1;

        debug_assert_eq!(offset, NATIVE_LAYER2_AUTHORIZATION_LINEAGE_PREIMAGE_LEN_V1);

        let lineage_commitment = copy_521(stored_commitment_bytes, 0)?;

        let mut _stored_lineage_hash = [0u8; HASH_LEN_V1];
        _stored_lineage_hash.copy_from_slice(stored_hash_bytes);

        let lineage = AuthorizationLineageV1 {
            version,
            lineage_flags,
            dcm_commitment_kind,
            dcm_commitment_root,
            dcm_trace_commitment,
            subject_binding_type,
            subject_id,
            subject_public_key,
            intent_type,
            intent_hash,
            freshness_mode,
            freshness_nonce,
            freshness_reference,
            proof_material_v1_hash,
            fractal_key_v1_hash,
        };
        let lineage_hash = canonical_native_layer2_authorization_lineage_helper_hash_v1(&lineage)
            .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)?;
        let object = Self {
            lineage,
            lineage_commitment,
            lineage_hash,
        };

        object.validate()?;
        Ok(object)
    }
}

pub fn produce_native_layer2_authorization_lineage_object_521_v1(
    dcm_config: &DcmConfig521V1,
    dcm_input: &DcmInput521V1,
    intent_source: Layer1Layer2BridgeIntentSourceV1,
    subject_binding: Layer1Layer2BridgeSubjectBindingV1,
    freshness: Layer1Layer2BridgeFreshnessV1,
) -> Result<NativeLayer2AuthorizationLineageObjectV1, Layer1Layer2BridgeErrorV1> {
    let bridge = crate::run_native_layer1_layer2_bridge_521_v1(
        dcm_config,
        dcm_input,
        intent_source,
        subject_binding,
        freshness,
    )?;

    produce_native_layer2_authorization_lineage_object_from_bridge_521_v1(bridge)
}

fn map_object_error(
    error: NativeLayer2AuthorizationLineageObjectV1Error,
) -> Layer1Layer2BridgeErrorV1 {
    match error {
        NativeLayer2AuthorizationLineageObjectV1Error::NativeDcmRootedLineageRequired {
            ..
        } => Layer1Layer2BridgeErrorV1::ModeConflict {
            reason: error.reject_reason(),
        },
        _ => Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
            reason: error.reject_reason(),
        },
    }
}

fn map_lineage_error(error: AuthorizationLineageV1Error) -> Layer1Layer2BridgeErrorV1 {
    match error {
        AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyIntentType
        | AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyFreshnessMode
        | AuthorizationLineageV1Error::NativeDcmRootedCannotCarryProofMaterialV1Hash
        | AuthorizationLineageV1Error::NativeDcmRootedCannotCarryFractalKeyV1Hash
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresZeroDcmCommitmentRoot
        | AuthorizationLineageV1Error::LegacyCompatibilityCannotCarryDcmTraceCommitment
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyIntentType
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyFreshnessMode
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresProofMaterialV1Hash
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresFractalKeyV1Hash => {
            Layer1Layer2BridgeErrorV1::ModeConflict {
                reason: error.reject_reason(),
            }
        }
        _ => Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
            reason: error.reject_reason(),
        },
    }
}

fn copy_32(bytes: &[u8], offset: usize) -> [u8; HASH_LEN_V1] {
    let mut output = [0u8; HASH_LEN_V1];
    output.copy_from_slice(&bytes[offset..offset + HASH_LEN_V1]);
    output
}

fn copy_521(
    bytes: &[u8],
    offset: usize,
) -> Result<DeterministicCommitment521V1, NativeLayer2AuthorizationLineageObjectV1Error> {
    let mut output = [0u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1];
    output.copy_from_slice(&bytes[offset..offset + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]);
    DeterministicCommitment521V1::from_bytes(output)
        .map_err(|_| NativeLayer2AuthorizationLineageObjectV1Error::InvalidLineageCommitmentEncoding)
}

pub(crate) fn derive_native_layer2_authorization_lineage_commitment_v1(
    lineage: &AuthorizationLineageV1,
) -> Result<DeterministicCommitment521V1, AuthorizationLineageV1Error> {
    Ok(derive_deterministic_commitment_521_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_native_layer2_authorization_lineage_preimage_v1(lineage)?,
    ))
}

pub(crate) fn canonical_native_layer2_authorization_lineage_preimage_v1(
    lineage: &AuthorizationLineageV1,
) -> Result<Vec<u8>, AuthorizationLineageV1Error> {
    lineage.canonical_preimage()
}

pub(crate) fn canonical_native_layer2_authorization_lineage_helper_hash_v1(
    lineage: &AuthorizationLineageV1,
) -> Result<[u8; HASH_LEN_V1], AuthorizationLineageV1Error> {
    lineage.lineage_hash()
}

pub(crate) fn canonical_native_layer2_authorization_lineage_primary_bytes_v1(
    object: &NativeLayer2AuthorizationLineageObjectV1,
) -> Result<Vec<u8>, NativeLayer2AuthorizationLineageObjectV1Error> {
    object.validate()?;
    let preimage = canonical_native_layer2_authorization_lineage_preimage_v1(&object.lineage)
        .map_err(NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation)?;
    let mut bytes =
        Vec::with_capacity(preimage.len() + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1);
    bytes.extend_from_slice(&preimage);
    bytes.extend_from_slice(&object.lineage_commitment.to_bytes());
    Ok(bytes)
}

fn produce_native_layer2_authorization_lineage_object_from_bridge_521_v1(
    bridge: Layer1Layer2BridgeSuccess521V1,
) -> Result<NativeLayer2AuthorizationLineageObjectV1, Layer1Layer2BridgeErrorV1> {
    let canonical_commitments =
        derive_dcm_layer1_commitments_521_v1(&bridge.dcm_claim.config, &bridge.dcm_execution);
    if canonical_commitments != bridge.dcm_commitments
        || bridge.dcm_claim.commitment_root != bridge.dcm_commitments.dcm_commitment_root
        || bridge.lineage.dcm_commitment_root != bridge.dcm_commitments.dcm_commitment_root
    {
        return Err(Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
            reason: NATIVE_LAYER2_OBJECT_REQUIRES_CANONICAL_LAYER1_COMMITMENTS_REASON_V1,
        });
    }

    if bridge.lineage.lineage_flags & LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT != 0
        || bridge.lineage.dcm_trace_commitment != [0u8; HASH_LEN_V1]
    {
        return Err(Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
            reason: NATIVE_LAYER2_OBJECT_BRIDGE_LINEAGE_MUST_NOT_PREBIND_TRACE_REASON_V1,
        });
    }

    let bridge_lineage_hash = bridge.lineage.lineage_hash().map_err(map_lineage_error)?;
    if bridge_lineage_hash != bridge.lineage_hash {
        return Err(Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
            reason: NATIVE_LAYER2_OBJECT_BRIDGE_LINEAGE_HASH_MISMATCH_REASON_V1,
        });
    }

    let mut lineage = bridge.lineage;
    lineage.lineage_flags |= LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT;
    lineage.dcm_trace_commitment = bridge.dcm_commitments.dcm_trace_commitment;

    NativeLayer2AuthorizationLineageObjectV1::new(lineage).map_err(map_object_error)
}

#[cfg(test)]
mod tests {
    use super::{
        produce_native_layer2_authorization_lineage_object_from_bridge_521_v1,
        NATIVE_LAYER2_OBJECT_BRIDGE_LINEAGE_MUST_NOT_PREBIND_TRACE_REASON_V1,
        NATIVE_LAYER2_OBJECT_REQUIRES_CANONICAL_LAYER1_COMMITMENTS_REASON_V1,
    };
    use crate::{
        run_native_layer1_layer2_bridge_521_v1, AuraLayer4FeePolicyKindV1, AuraLayer4IntentBodyV1,
        AuraLayer4OperationBodyV1, AuraLayer4TxKindV1, DcmConfig521V1, DcmInput521V1,
        FreshnessModeV1, Layer1Layer2BridgeErrorV1, Layer1Layer2BridgeFreshnessV1,
        Layer1Layer2BridgeIntentSourceV1, Layer1Layer2BridgeSubjectBindingV1, SubjectBindingTypeV1,
        ValueTransferOperationV1, HASH_LEN_V1,
    };

    #[test]
    fn layer2_object_production_consumes_exact_bridge_handoff() {
        let bridge = canonical_bridge_result();
        let object =
            produce_native_layer2_authorization_lineage_object_from_bridge_521_v1(bridge.clone())
                .unwrap();

        assert_eq!(
            object.lineage.dcm_commitment_root,
            bridge.dcm_commitments.dcm_commitment_root
        );
        assert_eq!(
            object.lineage.dcm_trace_commitment,
            bridge.dcm_commitments.dcm_trace_commitment
        );
        assert_eq!(object.lineage.intent_hash, bridge.lineage.intent_hash);
        assert_eq!(
            object.lineage.subject_binding_type,
            bridge.lineage.subject_binding_type
        );
        assert_eq!(bridge.lineage.dcm_trace_commitment, [0u8; HASH_LEN_V1]);
    }

    #[test]
    fn layer2_object_production_rejects_tampered_bridge_commitments() {
        let mut bridge = canonical_bridge_result();
        bridge.dcm_commitments.dcm_trace_commitment[0] ^= 0x01;

        let error = produce_native_layer2_authorization_lineage_object_from_bridge_521_v1(bridge)
            .unwrap_err();

        assert_eq!(
            error,
            Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
                reason: NATIVE_LAYER2_OBJECT_REQUIRES_CANONICAL_LAYER1_COMMITMENTS_REASON_V1,
            }
        );
    }

    #[test]
    fn layer2_object_production_rejects_bridge_lineage_with_prebound_trace_commitment() {
        let mut bridge = canonical_bridge_result();
        bridge.lineage.lineage_flags |= crate::LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT;
        bridge.lineage.dcm_trace_commitment = bridge.dcm_commitments.dcm_trace_commitment;

        let error = produce_native_layer2_authorization_lineage_object_from_bridge_521_v1(bridge)
            .unwrap_err();

        assert_eq!(
            error,
            Layer1Layer2BridgeErrorV1::InvalidFieldCombination {
                reason: NATIVE_LAYER2_OBJECT_BRIDGE_LINEAGE_MUST_NOT_PREBIND_TRACE_REASON_V1,
            }
        );
    }

    fn canonical_bridge_result() -> crate::Layer1Layer2BridgeSuccess521V1 {
        run_native_layer1_layer2_bridge_521_v1(
            &DcmConfig521V1 { iteration_count: 2 },
            &DcmInput521V1::from_u64(3, 7),
            Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
            canonical_subject_binding(),
            canonical_freshness(),
        )
        .unwrap()
    }

    fn canonical_intent() -> AuraLayer4IntentBodyV1 {
        AuraLayer4IntentBodyV1 {
            intent_version: 1,
            intent_flags: 0,
            rollup_id: [0x11; 32],
            tx_kind: AuraLayer4TxKindV1::ValueTransfer,
            sender_account_id: [0x22; 32],
            sender_nonce: 7,
            validity_flags: 0x000c,
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 0,
            not_before_batch_number: 120,
            not_after_batch_number: 125,
            fee_policy_kind: AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
            max_fee_native: 500,
            client_context_commitment: [0u8; 32],
            operation_body: AuraLayer4OperationBodyV1::ValueTransfer(ValueTransferOperationV1 {
                recipient_account_id: [0x33; 32],
                amount: 2500,
            }),
        }
    }

    fn canonical_subject_binding() -> Layer1Layer2BridgeSubjectBindingV1 {
        Layer1Layer2BridgeSubjectBindingV1 {
            subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            subject_id: [0x55; 32],
            subject_public_key: None,
        }
    }

    fn canonical_freshness() -> Layer1Layer2BridgeFreshnessV1 {
        Layer1Layer2BridgeFreshnessV1 {
            freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
            freshness_nonce: [0x66; 32],
            freshness_reference: 4242,
        }
    }
}
