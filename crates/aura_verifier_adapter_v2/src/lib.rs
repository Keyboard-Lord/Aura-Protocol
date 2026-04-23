//! RESEARCH / SUPPORTING ONLY
//!
//! The layer is RESEARCH / SUPPORTING and does not modify:
//! - canonical request/report pipeline
//! - cat-map transition
//! - AIR/prover boundaries
//! - settlement, burn, attestation, wallet binding, or UDOT authority
//!
//! This future-facing verifier-adapter boundary has no active protocol interface.
//! Any downstream integration requires an explicit protocol upgrade.

#[cfg(feature = "active_integration")]
compile_error!(
    "RESEARCH / SUPPORTING crate aura_verifier_adapter_v2 does not modify active protocol and cannot compile into the single authoritative pipeline without explicit protocol upgrade."
);

use aura_proof_material_v2::{
    ProofMaterialHashV2, ProofMaterialTypeV2, ProofMaterialV2, ProofMaterialV2Error,
    ProofMaterialV2VerifyRequest,
};
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierAdapterInputV2 {
    owning_proof_material_type: ProofMaterialTypeV2,
    _context_bytes: Vec<u8>,
}

impl VerifierAdapterInputV2 {
    pub fn opaque(owning_proof_material_type: ProofMaterialTypeV2, context_bytes: Vec<u8>) -> Self {
        Self {
            owning_proof_material_type,
            _context_bytes: context_bytes,
        }
    }

    pub fn owning_proof_material_type(&self) -> ProofMaterialTypeV2 {
        self.owning_proof_material_type
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierAdapterVerifyRequestV2 {
    proof_material_request: ProofMaterialV2VerifyRequest,
    adapter_input: VerifierAdapterInputV2,
}

impl VerifierAdapterVerifyRequestV2 {
    pub fn new(
        proof_material_request: ProofMaterialV2VerifyRequest,
        adapter_input: VerifierAdapterInputV2,
    ) -> Self {
        Self {
            proof_material_request,
            adapter_input,
        }
    }

    pub fn proof_material_request(&self) -> &ProofMaterialV2VerifyRequest {
        &self.proof_material_request
    }

    pub fn adapter_input(&self) -> &VerifierAdapterInputV2 {
        &self.adapter_input
    }

    pub fn declared_type(&self) -> ProofMaterialTypeV2 {
        self.proof_material_request.expected_type
    }

    pub fn verify_type_binding(&self) -> Result<(), VerifierAdapterV2Error> {
        let expected_type = self.declared_type();
        let input_type = self.adapter_input.owning_proof_material_type();

        if expected_type != input_type {
            return Err(VerifierAdapterV2Error::AdapterInputTypeMismatch {
                expected_type,
                input_type,
            });
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierAdapterVerifySuccessV2 {
    pub verified_type: ProofMaterialTypeV2,
    pub proof_material_hash: ProofMaterialHashV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierAdapterV2Error {
    UnsupportedProofMaterialType {
        actual: ProofMaterialTypeV2,
    },
    AmbiguousProofMaterialTypeOwnership {
        actual: ProofMaterialTypeV2,
        owner_count: usize,
    },
    AdapterInputTypeMismatch {
        expected_type: ProofMaterialTypeV2,
        input_type: ProofMaterialTypeV2,
    },
    ProofMaterialVerificationFailed(ProofMaterialV2Error),
}

impl fmt::Display for VerifierAdapterV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProofMaterialType { actual } => {
                write!(
                    f,
                    "unsupported verifier adapter proof material type: {actual}"
                )
            }
            Self::AmbiguousProofMaterialTypeOwnership {
                actual,
                owner_count,
            } => {
                write!(
                    f,
                    "ambiguous verifier adapter ownership for {actual}: {owner_count} owners registered"
                )
            }
            Self::AdapterInputTypeMismatch {
                expected_type,
                input_type,
            } => {
                write!(
                    f,
                    "adapter input type {input_type} does not match expected type {expected_type}"
                )
            }
            Self::ProofMaterialVerificationFailed(error) => {
                write!(f, "proof material verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for VerifierAdapterV2Error {}

pub fn verify_with_adapter_v2(
    request: &VerifierAdapterVerifyRequestV2,
) -> Result<VerifierAdapterVerifySuccessV2, VerifierAdapterV2Error> {
    verify_with_registered_adapter_types_v2(request, supported_verifier_adapter_types_v2())
}

fn verify_with_registered_adapter_types_v2(
    request: &VerifierAdapterVerifyRequestV2,
    registered_types: &[ProofMaterialTypeV2],
) -> Result<VerifierAdapterVerifySuccessV2, VerifierAdapterV2Error> {
    request.verify_type_binding()?;

    // Adapter semantic verification is allowed only after lower-layer proof-material
    // verification succeeds for the exact same declared type.
    let proof_material_hash = ProofMaterialV2::verify(request.proof_material_request())
        .map_err(VerifierAdapterV2Error::ProofMaterialVerificationFailed)?;
    ensure_exact_adapter_owner(request.declared_type(), registered_types)?;

    Ok(VerifierAdapterVerifySuccessV2 {
        verified_type: request.declared_type(),
        proof_material_hash,
    })
}

pub fn supported_verifier_adapter_types_v2() -> &'static [ProofMaterialTypeV2] {
    &[]
}

pub fn is_supported_verifier_adapter_type_v2(proof_material_type: ProofMaterialTypeV2) -> bool {
    ensure_exact_adapter_owner(proof_material_type, supported_verifier_adapter_types_v2()).is_ok()
}

fn ensure_exact_adapter_owner(
    proof_material_type: ProofMaterialTypeV2,
    registered_types: &[ProofMaterialTypeV2],
) -> Result<(), VerifierAdapterV2Error> {
    let owner_count = registered_types
        .iter()
        .copied()
        .filter(|registered_type| *registered_type == proof_material_type)
        .count();

    match owner_count {
        0 => Err(VerifierAdapterV2Error::UnsupportedProofMaterialType {
            actual: proof_material_type,
        }),
        1 => Ok(()),
        owner_count => Err(
            VerifierAdapterV2Error::AmbiguousProofMaterialTypeOwnership {
                actual: proof_material_type,
                owner_count,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_exact_adapter_owner, verify_with_registered_adapter_types_v2,
        VerifierAdapterInputV2, VerifierAdapterV2Error, VerifierAdapterVerifyRequestV2,
    };
    use aura_proof_material_v2::{
        CanonicalVerifierBundleV2Input, ExtensionInputV2, ProofMaterialTypeV2, ProofMaterialV2,
        ProofMaterialV2BuildRequest, ProofMaterialV2Error, ProofMaterialV2VerifyRequest,
        CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
    };

    fn sample_type() -> ProofMaterialTypeV2 {
        CANONICAL_VERIFIER_BUNDLE_V2_TYPE
    }

    fn other_type() -> ProofMaterialTypeV2 {
        ProofMaterialTypeV2::new(0x1002)
    }

    fn sample_bundle_input() -> CanonicalVerifierBundleV2Input {
        CanonicalVerifierBundleV2Input::new(
            vec![0x10, 0x11, 0x12, 0x13],
            vec![0x20, 0x21, 0x22],
            vec![0x30, 0x31, 0x32, 0x33, 0x34],
        )
    }

    fn supported_proof_material_request() -> ProofMaterialV2VerifyRequest {
        let input = sample_bundle_input();
        let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
            sample_type(),
            ExtensionInputV2::canonical_verifier_bundle(input.clone()),
        ))
        .expect("supported build should succeed");
        let expected_hash = artifact
            .proof_material_hash()
            .expect("supported artifact hash should succeed");

        ProofMaterialV2VerifyRequest::new(
            sample_type(),
            artifact,
            ExtensionInputV2::canonical_verifier_bundle(input),
            expected_hash,
        )
    }

    #[test]
    fn exact_single_owner_is_dispatchable() {
        let registered_types = [sample_type()];

        assert_eq!(
            ensure_exact_adapter_owner(sample_type(), &registered_types),
            Ok(())
        );
    }

    #[test]
    fn zero_registered_owners_fail_closed_as_unsupported() {
        let registered_types = [other_type()];

        assert_eq!(
            ensure_exact_adapter_owner(sample_type(), &registered_types),
            Err(VerifierAdapterV2Error::UnsupportedProofMaterialType {
                actual: sample_type(),
            })
        );
    }

    #[test]
    fn multiple_registered_owners_fail_closed_as_ambiguous() {
        let registered_types = [sample_type(), other_type(), sample_type()];

        assert_eq!(
            ensure_exact_adapter_owner(sample_type(), &registered_types),
            Err(
                VerifierAdapterV2Error::AmbiguousProofMaterialTypeOwnership {
                    actual: sample_type(),
                    owner_count: 2,
                }
            )
        );
    }

    #[test]
    fn ambiguous_owner_rejects_after_lower_layer_verification_succeeds() {
        let request = VerifierAdapterVerifyRequestV2::new(
            supported_proof_material_request(),
            VerifierAdapterInputV2::opaque(sample_type(), vec![0x42]),
        );
        let registered_types = [sample_type(), sample_type()];

        assert_eq!(request.verify_type_binding(), Ok(()));
        assert_eq!(
            verify_with_registered_adapter_types_v2(&request, &registered_types),
            Err(
                VerifierAdapterV2Error::AmbiguousProofMaterialTypeOwnership {
                    actual: sample_type(),
                    owner_count: 2,
                }
            )
        );
    }

    #[test]
    fn lower_layer_failure_propagates_before_ambiguous_owner_failure() {
        let request = supported_proof_material_request();
        let bad_request = VerifierAdapterVerifyRequestV2::new(
            ProofMaterialV2VerifyRequest::new(
                request.expected_type,
                request.artifact.clone(),
                ExtensionInputV2::canonical_verifier_bundle(sample_bundle_input()),
                [0x99; 32],
            ),
            VerifierAdapterInputV2::opaque(sample_type(), vec![0x24]),
        );
        let registered_types = [sample_type(), sample_type()];

        assert_eq!(bad_request.verify_type_binding(), Ok(()));
        assert_eq!(
            verify_with_registered_adapter_types_v2(&bad_request, &registered_types),
            Err(VerifierAdapterV2Error::ProofMaterialVerificationFailed(
                ProofMaterialV2Error::ProofMaterialHashMismatch,
            ))
        );
    }
}
