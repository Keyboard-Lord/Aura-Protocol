//! RESEARCH / SUPPORTING ONLY
//!
//! The layer is RESEARCH / SUPPORTING and does not modify:
//! - canonical request/report pipeline
//! - cat-map transition
//! - AIR/prover boundaries
//! - settlement, burn, attestation, wallet binding, or UDOT authority
//!
//! This future-facing typed proof-material boundary has no active protocol interface.
//! Any downstream integration requires an explicit protocol upgrade.

#[cfg(feature = "active_integration")]
compile_error!(
    "RESEARCH / SUPPORTING crate aura_proof_material_v2 does not modify active protocol and cannot compile into the single authoritative pipeline without explicit protocol upgrade."
);

use aura_intent_lineage_v1::{
    NativeLayer2AuthorizationLineageObjectV1, NativeLayer2AuthorizationLineageObjectV1Error,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const PROOF_MATERIAL_VERSION_V2: u8 = 2;
pub const PROOF_MATERIAL_DOMAIN_SEPARATOR_V2: &[u8] = b"AURA_PROOF_MATERIAL_V2";
pub const PROOF_MATERIAL_HASH_LEN_V2: usize = 32;
pub const PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V2: usize = 2;
pub const CANONICAL_VERIFIER_BUNDLE_V2_TYPE: ProofMaterialTypeV2 = ProofMaterialTypeV2::new(0x1001);
pub const NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE: ProofMaterialTypeV2 =
    ProofMaterialTypeV2::new(0x2001);

pub type ProofMaterialHashV2 = [u8; PROOF_MATERIAL_HASH_LEN_V2];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProofMaterialTypeV2(u16);

impl ProofMaterialTypeV2 {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ProofMaterialTypeV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofMaterialV2Header {
    pub proof_material_version: u8,
    pub proof_material_type: ProofMaterialTypeV2,
}

impl ProofMaterialV2Header {
    pub const fn new(proof_material_type: ProofMaterialTypeV2) -> Self {
        Self {
            proof_material_version: PROOF_MATERIAL_VERSION_V2,
            proof_material_type,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalVerifierBundleV2Payload {
    proof_blob_hash: ProofMaterialHashV2,
    public_inputs_hash: ProofMaterialHashV2,
    verification_key_hash: ProofMaterialHashV2,
}

impl CanonicalVerifierBundleV2Payload {
    pub fn from_input(input: &CanonicalVerifierBundleV2Input) -> Self {
        Self {
            proof_blob_hash: sha256_bytes(input.proof_blob_bytes()),
            public_inputs_hash: sha256_bytes(input.public_inputs_bytes()),
            verification_key_hash: sha256_bytes(input.verification_key_bytes()),
        }
    }

    pub fn proof_blob_hash(&self) -> ProofMaterialHashV2 {
        self.proof_blob_hash
    }

    pub fn public_inputs_hash(&self) -> ProofMaterialHashV2 {
        self.public_inputs_hash
    }

    pub fn verification_key_hash(&self) -> ProofMaterialHashV2 {
        self.verification_key_hash
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PROOF_MATERIAL_DOMAIN_SEPARATOR_V2.len()
                + 1
                + PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V2
                + (PROOF_MATERIAL_HASH_LEN_V2 * 3),
        );
        bytes.extend_from_slice(PROOF_MATERIAL_DOMAIN_SEPARATOR_V2);
        bytes.push(PROOF_MATERIAL_VERSION_V2);
        bytes.extend_from_slice(&CANONICAL_VERIFIER_BUNDLE_V2_TYPE.as_u16().to_le_bytes());
        bytes.extend_from_slice(&self.proof_blob_hash);
        bytes.extend_from_slice(&self.public_inputs_hash);
        bytes.extend_from_slice(&self.verification_key_hash);
        bytes
    }

    fn proof_material_hash(&self) -> ProofMaterialHashV2 {
        sha256_bytes(&self.canonical_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalVerifierBundleV2Input {
    proof_blob_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    verification_key_bytes: Vec<u8>,
}

impl CanonicalVerifierBundleV2Input {
    pub fn new(
        proof_blob_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
        verification_key_bytes: Vec<u8>,
    ) -> Self {
        Self {
            proof_blob_bytes,
            public_inputs_bytes,
            verification_key_bytes,
        }
    }

    pub fn proof_blob_bytes(&self) -> &[u8] {
        &self.proof_blob_bytes
    }

    pub fn public_inputs_bytes(&self) -> &[u8] {
        &self.public_inputs_bytes
    }

    pub fn verification_key_bytes(&self) -> &[u8] {
        &self.verification_key_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLayer2AuthorizationLineageV1Payload {
    lineage_hash: ProofMaterialHashV2,
}

impl NativeLayer2AuthorizationLineageV1Payload {
    pub fn from_input(
        input: &NativeLayer2AuthorizationLineageV1Input,
    ) -> Result<Self, ProofMaterialV2Error> {
        let object = validated_native_layer2_authorization_lineage_object_v1(input)?;
        Ok(Self {
            lineage_hash: object
                .lineage
                .lineage_hash()
                .map_err(|error| {
                    map_native_layer2_authorization_lineage_object_error(
                        NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation(error),
                    )
                })?,
        })
    }

    pub fn lineage_hash(&self) -> ProofMaterialHashV2 {
        self.lineage_hash
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PROOF_MATERIAL_DOMAIN_SEPARATOR_V2.len()
                + 1
                + PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V2
                + PROOF_MATERIAL_HASH_LEN_V2,
        );
        bytes.extend_from_slice(PROOF_MATERIAL_DOMAIN_SEPARATOR_V2);
        bytes.push(PROOF_MATERIAL_VERSION_V2);
        bytes.extend_from_slice(
            &NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE
                .as_u16()
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.lineage_hash);
        bytes
    }

    fn proof_material_hash(&self) -> ProofMaterialHashV2 {
        sha256_bytes(&self.canonical_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLayer2AuthorizationLineageV1Input {
    serialized_object_bytes: Vec<u8>,
}

impl NativeLayer2AuthorizationLineageV1Input {
    pub fn new(serialized_object_bytes: Vec<u8>) -> Self {
        Self {
            serialized_object_bytes,
        }
    }

    pub fn serialized_object_bytes(&self) -> &[u8] {
        &self.serialized_object_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExtensionPayloadBodyV2 {
    Opaque(Vec<u8>),
    CanonicalVerifierBundle(CanonicalVerifierBundleV2Payload),
    NativeLayer2AuthorizationLineage(NativeLayer2AuthorizationLineageV1Payload),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionPayloadV2 {
    owning_proof_material_type: ProofMaterialTypeV2,
    body: ExtensionPayloadBodyV2,
}

impl ExtensionPayloadV2 {
    pub fn opaque(owning_proof_material_type: ProofMaterialTypeV2, payload_bytes: Vec<u8>) -> Self {
        Self {
            owning_proof_material_type,
            body: ExtensionPayloadBodyV2::Opaque(payload_bytes),
        }
    }

    pub fn canonical_verifier_bundle(payload: CanonicalVerifierBundleV2Payload) -> Self {
        Self {
            owning_proof_material_type: CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
            body: ExtensionPayloadBodyV2::CanonicalVerifierBundle(payload),
        }
    }

    pub fn native_layer2_authorization_lineage(
        payload: NativeLayer2AuthorizationLineageV1Payload,
    ) -> Self {
        Self {
            owning_proof_material_type: NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE,
            body: ExtensionPayloadBodyV2::NativeLayer2AuthorizationLineage(payload),
        }
    }

    pub fn owning_proof_material_type(&self) -> ProofMaterialTypeV2 {
        self.owning_proof_material_type
    }

    pub fn as_canonical_verifier_bundle(&self) -> Option<&CanonicalVerifierBundleV2Payload> {
        match &self.body {
            ExtensionPayloadBodyV2::CanonicalVerifierBundle(payload) => Some(payload),
            ExtensionPayloadBodyV2::NativeLayer2AuthorizationLineage(_) => None,
            ExtensionPayloadBodyV2::Opaque(_) => None,
        }
    }

    pub fn as_native_layer2_authorization_lineage(
        &self,
    ) -> Option<&NativeLayer2AuthorizationLineageV1Payload> {
        match &self.body {
            ExtensionPayloadBodyV2::NativeLayer2AuthorizationLineage(payload) => Some(payload),
            ExtensionPayloadBodyV2::CanonicalVerifierBundle(_) => None,
            ExtensionPayloadBodyV2::Opaque(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExtensionInputBodyV2 {
    Opaque(Vec<u8>),
    CanonicalVerifierBundle(CanonicalVerifierBundleV2Input),
    NativeLayer2AuthorizationLineage(NativeLayer2AuthorizationLineageV1Input),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionInputV2 {
    owning_proof_material_type: ProofMaterialTypeV2,
    body: ExtensionInputBodyV2,
}

impl ExtensionInputV2 {
    pub fn opaque(owning_proof_material_type: ProofMaterialTypeV2, input_bytes: Vec<u8>) -> Self {
        Self {
            owning_proof_material_type,
            body: ExtensionInputBodyV2::Opaque(input_bytes),
        }
    }

    pub fn canonical_verifier_bundle(input: CanonicalVerifierBundleV2Input) -> Self {
        Self {
            owning_proof_material_type: CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
            body: ExtensionInputBodyV2::CanonicalVerifierBundle(input),
        }
    }

    pub fn native_layer2_authorization_lineage(
        input: NativeLayer2AuthorizationLineageV1Input,
    ) -> Self {
        Self {
            owning_proof_material_type: NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE,
            body: ExtensionInputBodyV2::NativeLayer2AuthorizationLineage(input),
        }
    }

    pub fn owning_proof_material_type(&self) -> ProofMaterialTypeV2 {
        self.owning_proof_material_type
    }

    pub fn as_canonical_verifier_bundle(&self) -> Option<&CanonicalVerifierBundleV2Input> {
        match &self.body {
            ExtensionInputBodyV2::CanonicalVerifierBundle(input) => Some(input),
            ExtensionInputBodyV2::NativeLayer2AuthorizationLineage(_) => None,
            ExtensionInputBodyV2::Opaque(_) => None,
        }
    }

    pub fn as_native_layer2_authorization_lineage(
        &self,
    ) -> Option<&NativeLayer2AuthorizationLineageV1Input> {
        match &self.body {
            ExtensionInputBodyV2::NativeLayer2AuthorizationLineage(input) => Some(input),
            ExtensionInputBodyV2::CanonicalVerifierBundle(_) => None,
            ExtensionInputBodyV2::Opaque(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMaterialV2 {
    pub header: ProofMaterialV2Header,
    extension_payload: ExtensionPayloadV2,
}

impl ProofMaterialV2 {
    pub fn proof_material_hash(&self) -> Result<ProofMaterialHashV2, ProofMaterialV2Error> {
        let proof_material_type = self.declared_type();
        self.verify_structure()?;

        match proof_material_type {
            proof_material_type if proof_material_type == CANONICAL_VERIFIER_BUNDLE_V2_TYPE => {
                let payload = canonical_verifier_bundle_v2_payload(self.extension_payload())?;
                Ok(payload.proof_material_hash())
            }
            proof_material_type
                if proof_material_type == NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE =>
            {
                let payload =
                    native_layer2_authorization_lineage_v1_payload(self.extension_payload())?;
                Ok(payload.proof_material_hash())
            }
            _ => Err(ProofMaterialV2Error::UnsupportedProofMaterialType {
                actual: proof_material_type,
            }),
        }
    }

    pub fn build(request: ProofMaterialV2BuildRequest) -> Result<Self, ProofMaterialV2Error> {
        let proof_material_type = request.proof_material_type;
        request.verify_type_binding()?;

        match proof_material_type {
            proof_material_type if proof_material_type == CANONICAL_VERIFIER_BUNDLE_V2_TYPE => {
                let input = canonical_verifier_bundle_v2_input(request.extension_input())?;
                let payload = CanonicalVerifierBundleV2Payload::from_input(input);
                Ok(Self::new(
                    CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
                    ExtensionPayloadV2::canonical_verifier_bundle(payload),
                ))
            }
            proof_material_type
                if proof_material_type == NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE =>
            {
                let input =
                    native_layer2_authorization_lineage_v1_input(request.extension_input())?;
                let payload = NativeLayer2AuthorizationLineageV1Payload::from_input(input)?;
                Ok(Self::new(
                    NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE,
                    ExtensionPayloadV2::native_layer2_authorization_lineage(payload),
                ))
            }
            _ => Err(ProofMaterialV2Error::UnsupportedProofMaterialType {
                actual: proof_material_type,
            }),
        }
    }

    pub fn new(
        proof_material_type: ProofMaterialTypeV2,
        extension_payload: ExtensionPayloadV2,
    ) -> Self {
        Self {
            header: ProofMaterialV2Header::new(proof_material_type),
            extension_payload,
        }
    }

    pub fn declared_type(&self) -> ProofMaterialTypeV2 {
        self.header.proof_material_type
    }

    pub fn extension_payload(&self) -> &ExtensionPayloadV2 {
        &self.extension_payload
    }

    pub fn verify_structure(&self) -> Result<(), ProofMaterialV2Error> {
        verify_header(self.header)?;
        verify_artifact_payload_binding(
            self.header.proof_material_type,
            self.extension_payload.owning_proof_material_type(),
        )?;
        ensure_supported_type(self.header.proof_material_type)?;
        validate_supported_payload_family(
            self.header.proof_material_type,
            self.extension_payload(),
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMaterialV2BuildRequest {
    pub proof_material_type: ProofMaterialTypeV2,
    extension_input: ExtensionInputV2,
}

impl ProofMaterialV2BuildRequest {
    pub fn new(
        proof_material_type: ProofMaterialTypeV2,
        extension_input: ExtensionInputV2,
    ) -> Self {
        Self {
            proof_material_type,
            extension_input,
        }
    }

    pub fn extension_input(&self) -> &ExtensionInputV2 {
        &self.extension_input
    }

    pub fn verify_type_binding(&self) -> Result<(), ProofMaterialV2Error> {
        if self.proof_material_type != self.extension_input.owning_proof_material_type() {
            return Err(ProofMaterialV2Error::BuildTypeInputMismatch {
                request_type: self.proof_material_type,
                input_type: self.extension_input.owning_proof_material_type(),
            });
        }

        ensure_supported_type(self.proof_material_type)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMaterialV2VerifyRequest {
    pub expected_type: ProofMaterialTypeV2,
    pub artifact: ProofMaterialV2,
    extension_input: ExtensionInputV2,
    pub expected_proof_material_hash: ProofMaterialHashV2,
}

impl ProofMaterialV2VerifyRequest {
    pub fn new(
        expected_type: ProofMaterialTypeV2,
        artifact: ProofMaterialV2,
        extension_input: ExtensionInputV2,
        expected_proof_material_hash: ProofMaterialHashV2,
    ) -> Self {
        Self {
            expected_type,
            artifact,
            extension_input,
            expected_proof_material_hash,
        }
    }

    pub fn extension_input(&self) -> &ExtensionInputV2 {
        &self.extension_input
    }

    pub fn verify_outer_consistency(&self) -> Result<(), ProofMaterialV2Error> {
        verify_header(self.artifact.header)?;

        let artifact_type = self.artifact.declared_type();
        if self.expected_type != artifact_type {
            return Err(ProofMaterialV2Error::VerifyExpectedArtifactTypeMismatch {
                expected_type: self.expected_type,
                artifact_type,
            });
        }

        if self.expected_type != self.extension_input.owning_proof_material_type() {
            return Err(ProofMaterialV2Error::VerifyExpectedInputTypeMismatch {
                expected_type: self.expected_type,
                input_type: self.extension_input.owning_proof_material_type(),
            });
        }

        verify_artifact_payload_binding(
            artifact_type,
            self.artifact.extension_payload.owning_proof_material_type(),
        )?;
        ensure_supported_type(self.expected_type)?;
        Ok(())
    }
}

impl ProofMaterialV2 {
    pub fn verify(
        request: &ProofMaterialV2VerifyRequest,
    ) -> Result<ProofMaterialHashV2, ProofMaterialV2Error> {
        let expected_type = request.expected_type;
        request.verify_outer_consistency()?;

        match expected_type {
            proof_material_type if proof_material_type == CANONICAL_VERIFIER_BUNDLE_V2_TYPE => {
                let payload =
                    canonical_verifier_bundle_v2_payload(request.artifact.extension_payload())?;
                let input = canonical_verifier_bundle_v2_input(request.extension_input())?;

                if payload.proof_blob_hash() != sha256_bytes(input.proof_blob_bytes()) {
                    return Err(ProofMaterialV2Error::CanonicalVerifierBundleProofBlobHashMismatch);
                }

                if payload.public_inputs_hash() != sha256_bytes(input.public_inputs_bytes()) {
                    return Err(
                        ProofMaterialV2Error::CanonicalVerifierBundlePublicInputsHashMismatch,
                    );
                }

                if payload.verification_key_hash() != sha256_bytes(input.verification_key_bytes()) {
                    return Err(
                        ProofMaterialV2Error::CanonicalVerifierBundleVerificationKeyHashMismatch,
                    );
                }

                let actual_proof_material_hash = payload.proof_material_hash();
                if actual_proof_material_hash != request.expected_proof_material_hash {
                    return Err(ProofMaterialV2Error::ProofMaterialHashMismatch);
                }

                Ok(actual_proof_material_hash)
            }
            proof_material_type
                if proof_material_type == NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE =>
            {
                let payload = native_layer2_authorization_lineage_v1_payload(
                    request.artifact.extension_payload(),
                )?;
                let input =
                    native_layer2_authorization_lineage_v1_input(request.extension_input())?;
                let object = validated_native_layer2_authorization_lineage_object_v1(input)?;
                let canonical_lineage_hash = object
                    .lineage
                    .lineage_hash()
                    .map_err(|error| {
                        map_native_layer2_authorization_lineage_object_error(
                            NativeLayer2AuthorizationLineageObjectV1Error::LineageValidation(error),
                        )
                    })?;

                if payload.lineage_hash() != canonical_lineage_hash {
                    return Err(ProofMaterialV2Error::NativeLayer2AuthorizationLineageHashMismatch);
                }

                let actual_proof_material_hash = payload.proof_material_hash();
                if actual_proof_material_hash != request.expected_proof_material_hash {
                    return Err(ProofMaterialV2Error::ProofMaterialHashMismatch);
                }

                Ok(actual_proof_material_hash)
            }
            _ => Err(ProofMaterialV2Error::UnsupportedProofMaterialType {
                actual: expected_type,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofMaterialV2Error {
    InvalidVersion {
        expected: u8,
        actual: u8,
    },
    UnsupportedProofMaterialType {
        actual: ProofMaterialTypeV2,
    },
    AmbiguousProofMaterialTypeOwnership {
        actual: ProofMaterialTypeV2,
        owner_count: usize,
    },
    ArtifactPayloadTypeMismatch {
        artifact_type: ProofMaterialTypeV2,
        payload_type: ProofMaterialTypeV2,
    },
    BuildTypeInputMismatch {
        request_type: ProofMaterialTypeV2,
        input_type: ProofMaterialTypeV2,
    },
    VerifyExpectedArtifactTypeMismatch {
        expected_type: ProofMaterialTypeV2,
        artifact_type: ProofMaterialTypeV2,
    },
    VerifyExpectedInputTypeMismatch {
        expected_type: ProofMaterialTypeV2,
        input_type: ProofMaterialTypeV2,
    },
    CanonicalVerifierBundlePayloadRequired,
    CanonicalVerifierBundleInputRequired,
    NativeLayer2AuthorizationLineagePayloadRequired,
    NativeLayer2AuthorizationLineageInputRequired,
    NativeLayer2AuthorizationLineageObjectInvalid {
        reason: &'static str,
    },
    CanonicalVerifierBundleProofBlobHashMismatch,
    CanonicalVerifierBundlePublicInputsHashMismatch,
    CanonicalVerifierBundleVerificationKeyHashMismatch,
    NativeLayer2AuthorizationLineageHashMismatch,
    ProofMaterialHashMismatch,
}

impl fmt::Display for ProofMaterialV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(f, "invalid version: expected {expected}, got {actual}")
            }
            Self::UnsupportedProofMaterialType { actual } => {
                write!(f, "unsupported proof material type: {actual}")
            }
            Self::AmbiguousProofMaterialTypeOwnership {
                actual,
                owner_count,
            } => {
                write!(
                    f,
                    "ambiguous proof material type ownership for {actual}: {owner_count} owners registered"
                )
            }
            Self::ArtifactPayloadTypeMismatch {
                artifact_type,
                payload_type,
            } => {
                write!(
                    f,
                    "artifact type {artifact_type} does not match payload type {payload_type}"
                )
            }
            Self::BuildTypeInputMismatch {
                request_type,
                input_type,
            } => {
                write!(
                    f,
                    "build request type {request_type} does not match input type {input_type}"
                )
            }
            Self::VerifyExpectedArtifactTypeMismatch {
                expected_type,
                artifact_type,
            } => {
                write!(
                    f,
                    "verify expected type {expected_type} does not match artifact type {artifact_type}"
                )
            }
            Self::VerifyExpectedInputTypeMismatch {
                expected_type,
                input_type,
            } => {
                write!(
                    f,
                    "verify expected type {expected_type} does not match input type {input_type}"
                )
            }
            Self::CanonicalVerifierBundlePayloadRequired => {
                write!(
                    f,
                    "canonical verifier bundle payload is required for type 0x1001"
                )
            }
            Self::CanonicalVerifierBundleInputRequired => {
                write!(
                    f,
                    "canonical verifier bundle input is required for type 0x1001"
                )
            }
            Self::NativeLayer2AuthorizationLineagePayloadRequired => {
                write!(
                    f,
                    "native layer2 authorization lineage payload is required for type 0x2001"
                )
            }
            Self::NativeLayer2AuthorizationLineageInputRequired => {
                write!(
                    f,
                    "native layer2 authorization lineage input is required for type 0x2001"
                )
            }
            Self::NativeLayer2AuthorizationLineageObjectInvalid { reason } => {
                write!(
                    f,
                    "native layer2 authorization lineage object invalid: {reason}"
                )
            }
            Self::CanonicalVerifierBundleProofBlobHashMismatch => {
                write!(f, "canonical verifier bundle proof blob hash mismatch")
            }
            Self::CanonicalVerifierBundlePublicInputsHashMismatch => {
                write!(f, "canonical verifier bundle public inputs hash mismatch")
            }
            Self::CanonicalVerifierBundleVerificationKeyHashMismatch => {
                write!(
                    f,
                    "canonical verifier bundle verification key hash mismatch"
                )
            }
            Self::NativeLayer2AuthorizationLineageHashMismatch => {
                write!(f, "native layer2 authorization lineage hash mismatch")
            }
            Self::ProofMaterialHashMismatch => write!(f, "proof material hash mismatch"),
        }
    }
}

impl std::error::Error for ProofMaterialV2Error {}

pub fn supported_proof_material_types_v2() -> &'static [ProofMaterialTypeV2] {
    &[
        CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
        NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE,
    ]
}

pub fn is_supported_proof_material_type_v2(proof_material_type: ProofMaterialTypeV2) -> bool {
    ensure_exact_dispatch_owner(proof_material_type, supported_proof_material_types_v2()).is_ok()
}

fn verify_header(header: ProofMaterialV2Header) -> Result<(), ProofMaterialV2Error> {
    if header.proof_material_version != PROOF_MATERIAL_VERSION_V2 {
        return Err(ProofMaterialV2Error::InvalidVersion {
            expected: PROOF_MATERIAL_VERSION_V2,
            actual: header.proof_material_version,
        });
    }

    Ok(())
}

fn verify_artifact_payload_binding(
    artifact_type: ProofMaterialTypeV2,
    payload_type: ProofMaterialTypeV2,
) -> Result<(), ProofMaterialV2Error> {
    if artifact_type != payload_type {
        return Err(ProofMaterialV2Error::ArtifactPayloadTypeMismatch {
            artifact_type,
            payload_type,
        });
    }

    Ok(())
}

fn ensure_supported_type(
    proof_material_type: ProofMaterialTypeV2,
) -> Result<(), ProofMaterialV2Error> {
    ensure_exact_dispatch_owner(proof_material_type, supported_proof_material_types_v2())?;

    Ok(())
}

fn validate_supported_payload_family(
    proof_material_type: ProofMaterialTypeV2,
    extension_payload: &ExtensionPayloadV2,
) -> Result<(), ProofMaterialV2Error> {
    match proof_material_type {
        proof_material_type if proof_material_type == CANONICAL_VERIFIER_BUNDLE_V2_TYPE => {
            canonical_verifier_bundle_v2_payload(extension_payload)?;
            Ok(())
        }
        proof_material_type
            if proof_material_type == NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE =>
        {
            native_layer2_authorization_lineage_v1_payload(extension_payload)?;
            Ok(())
        }
        _ => Err(ProofMaterialV2Error::UnsupportedProofMaterialType {
            actual: proof_material_type,
        }),
    }
}

fn canonical_verifier_bundle_v2_payload(
    extension_payload: &ExtensionPayloadV2,
) -> Result<&CanonicalVerifierBundleV2Payload, ProofMaterialV2Error> {
    extension_payload
        .as_canonical_verifier_bundle()
        .ok_or(ProofMaterialV2Error::CanonicalVerifierBundlePayloadRequired)
}

fn canonical_verifier_bundle_v2_input(
    extension_input: &ExtensionInputV2,
) -> Result<&CanonicalVerifierBundleV2Input, ProofMaterialV2Error> {
    extension_input
        .as_canonical_verifier_bundle()
        .ok_or(ProofMaterialV2Error::CanonicalVerifierBundleInputRequired)
}

fn native_layer2_authorization_lineage_v1_payload(
    extension_payload: &ExtensionPayloadV2,
) -> Result<&NativeLayer2AuthorizationLineageV1Payload, ProofMaterialV2Error> {
    extension_payload
        .as_native_layer2_authorization_lineage()
        .ok_or(ProofMaterialV2Error::NativeLayer2AuthorizationLineagePayloadRequired)
}

fn native_layer2_authorization_lineage_v1_input(
    extension_input: &ExtensionInputV2,
) -> Result<&NativeLayer2AuthorizationLineageV1Input, ProofMaterialV2Error> {
    extension_input
        .as_native_layer2_authorization_lineage()
        .ok_or(ProofMaterialV2Error::NativeLayer2AuthorizationLineageInputRequired)
}

fn validated_native_layer2_authorization_lineage_object_v1(
    input: &NativeLayer2AuthorizationLineageV1Input,
) -> Result<NativeLayer2AuthorizationLineageObjectV1, ProofMaterialV2Error> {
    NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(
        input.serialized_object_bytes(),
    )
    .map_err(map_native_layer2_authorization_lineage_object_error)
}

fn sha256_bytes(bytes: &[u8]) -> ProofMaterialHashV2 {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; PROOF_MATERIAL_HASH_LEN_V2];
    hash.copy_from_slice(&digest);
    hash
}

fn map_native_layer2_authorization_lineage_object_error(
    error: NativeLayer2AuthorizationLineageObjectV1Error,
) -> ProofMaterialV2Error {
    ProofMaterialV2Error::NativeLayer2AuthorizationLineageObjectInvalid {
        reason: error.reject_reason(),
    }
}

fn ensure_exact_dispatch_owner(
    proof_material_type: ProofMaterialTypeV2,
    registered_types: &[ProofMaterialTypeV2],
) -> Result<(), ProofMaterialV2Error> {
    let owner_count = registered_types
        .iter()
        .copied()
        .filter(|registered_type| *registered_type == proof_material_type)
        .count();

    match owner_count {
        0 => Err(ProofMaterialV2Error::UnsupportedProofMaterialType {
            actual: proof_material_type,
        }),
        1 => Ok(()),
        owner_count => Err(ProofMaterialV2Error::AmbiguousProofMaterialTypeOwnership {
            actual: proof_material_type,
            owner_count,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_exact_dispatch_owner, ProofMaterialTypeV2, ProofMaterialV2Error,
        CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
    };

    fn sample_type() -> ProofMaterialTypeV2 {
        CANONICAL_VERIFIER_BUNDLE_V2_TYPE
    }

    fn other_type() -> ProofMaterialTypeV2 {
        ProofMaterialTypeV2::new(0x1002)
    }

    #[test]
    fn exact_single_owner_is_dispatchable() {
        let registered_types = [sample_type()];

        assert_eq!(
            ensure_exact_dispatch_owner(sample_type(), &registered_types),
            Ok(())
        );
    }

    #[test]
    fn zero_registered_owners_fail_closed_as_unsupported() {
        let registered_types = [other_type()];

        assert_eq!(
            ensure_exact_dispatch_owner(sample_type(), &registered_types),
            Err(ProofMaterialV2Error::UnsupportedProofMaterialType {
                actual: sample_type(),
            })
        );
    }

    #[test]
    fn multiple_registered_owners_fail_closed_as_ambiguous() {
        let registered_types = [sample_type(), other_type(), sample_type()];

        assert_eq!(
            ensure_exact_dispatch_owner(sample_type(), &registered_types),
            Err(ProofMaterialV2Error::AmbiguousProofMaterialTypeOwnership {
                actual: sample_type(),
                owner_count: 2,
            })
        );
    }
}
