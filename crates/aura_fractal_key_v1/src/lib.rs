//! Frozen Aura v1 FractalKey binding layer.

use core::fmt;
use sha2::{Digest, Sha256};

pub const FRACTAL_KEY_VERSION_V1: u8 = 1;
pub const FRACTAL_COMPONENT_COUNT_V1: u8 = 3;
pub const FRACTAL_KEY_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_FRACTAL_KEY_V1";
pub const FRACTAL_COMPONENT_PAYLOAD_LEN_V1: usize = 32;
pub const FRACTAL_COMPONENT_SERIALIZED_LEN_V1: usize = 2 + FRACTAL_COMPONENT_PAYLOAD_LEN_V1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FractalComponentTypeV1 {
    SubjectBinding = 0x0001,
    ChallengeBinding = 0x0002,
    ProofMaterialHash = 0x0003,
}

impl FractalComponentTypeV1 {
    pub const ORDERED: [Self; FRACTAL_COMPONENT_COUNT_V1 as usize] = [
        Self::SubjectBinding,
        Self::ChallengeBinding,
        Self::ProofMaterialHash,
    ];

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::SubjectBinding),
            0x0002 => Some(Self::ChallengeBinding),
            0x0003 => Some(Self::ProofMaterialHash),
            _ => None,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::SubjectBinding => 0,
            Self::ChallengeBinding => 1,
            Self::ProofMaterialHash => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FractalComponentV1 {
    pub component_type: u16,
    pub payload32: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
}

impl FractalComponentV1 {
    pub const fn new(
        component_type: FractalComponentTypeV1,
        payload32: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
    ) -> Self {
        Self {
            component_type: component_type.as_u16(),
            payload32,
        }
    }

    pub fn canonical_bytes(&self) -> [u8; FRACTAL_COMPONENT_SERIALIZED_LEN_V1] {
        let mut bytes = [0u8; FRACTAL_COMPONENT_SERIALIZED_LEN_V1];
        bytes[..2].copy_from_slice(&self.component_type.to_le_bytes());
        bytes[2..].copy_from_slice(&self.payload32);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FractalKeyV1 {
    pub fractal_key_version: u8,
    pub component_count: u8,
    pub components: [FractalComponentV1; FRACTAL_COMPONENT_COUNT_V1 as usize],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FractalKeyBuilderInputV1 {
    pub subject_binding: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
    pub challenge_binding: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
    pub proof_material_hash: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FractalKeyVerifierInputV1 {
    pub expected_subject_binding: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
    pub expected_challenge_binding: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
    pub expected_proof_material_hash: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
    pub expected_proof_hash: [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FractalKeyV1Error {
    InvalidVersion { expected: u8, actual: u8 },
    InvalidComponentCount { expected: u8, actual: u8 },
    MissingComponent { component_type: u16 },
    DuplicateComponent { component_type: u16 },
    UnexpectedComponentType { component_type: u16 },
    InvalidComponentOrder,
    SubjectBindingMismatch,
    ChallengeBindingMismatch,
    ProofMaterialHashMismatch,
    ProofHashMismatch,
}

impl fmt::Display for FractalKeyV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(f, "invalid version: expected {expected}, got {actual}")
            }
            Self::InvalidComponentCount { expected, actual } => {
                write!(
                    f,
                    "invalid component count: expected {expected}, got {actual}"
                )
            }
            Self::MissingComponent { component_type } => {
                write!(f, "missing required component: 0x{component_type:04x}")
            }
            Self::DuplicateComponent { component_type } => {
                write!(f, "duplicate component: 0x{component_type:04x}")
            }
            Self::UnexpectedComponentType { component_type } => {
                write!(f, "unexpected component type: 0x{component_type:04x}")
            }
            Self::InvalidComponentOrder => write!(f, "invalid component order"),
            Self::SubjectBindingMismatch => write!(f, "subject binding mismatch"),
            Self::ChallengeBindingMismatch => write!(f, "challenge binding mismatch"),
            Self::ProofMaterialHashMismatch => write!(f, "proof-material hash mismatch"),
            Self::ProofHashMismatch => write!(f, "proof hash mismatch"),
        }
    }
}

impl std::error::Error for FractalKeyV1Error {}

impl FractalKeyV1 {
    pub fn build(input: FractalKeyBuilderInputV1) -> Self {
        Self {
            fractal_key_version: FRACTAL_KEY_VERSION_V1,
            component_count: FRACTAL_COMPONENT_COUNT_V1,
            components: [
                FractalComponentV1::new(
                    FractalComponentTypeV1::SubjectBinding,
                    input.subject_binding,
                ),
                FractalComponentV1::new(
                    FractalComponentTypeV1::ChallengeBinding,
                    input.challenge_binding,
                ),
                FractalComponentV1::new(
                    FractalComponentTypeV1::ProofMaterialHash,
                    input.proof_material_hash,
                ),
            ],
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            FRACTAL_KEY_DOMAIN_SEPARATOR_V1.len()
                + 2
                + (FRACTAL_COMPONENT_COUNT_V1 as usize * FRACTAL_COMPONENT_SERIALIZED_LEN_V1),
        );
        bytes.extend_from_slice(FRACTAL_KEY_DOMAIN_SEPARATOR_V1);
        bytes.push(self.fractal_key_version);
        bytes.push(self.component_count);

        for component in self.components {
            bytes.extend_from_slice(&component.canonical_bytes());
        }

        bytes
    }

    pub fn proof_hash(&self) -> [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1] {
        let digest = Sha256::digest(self.canonical_bytes());
        let mut proof_hash = [0u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1];
        proof_hash.copy_from_slice(&digest);
        proof_hash
    }

    pub fn verify(
        &self,
        input: &FractalKeyVerifierInputV1,
    ) -> Result<[u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1], FractalKeyV1Error> {
        self.verify_structure()?;

        if self.components[0].payload32 != input.expected_subject_binding {
            return Err(FractalKeyV1Error::SubjectBindingMismatch);
        }

        if self.components[1].payload32 != input.expected_challenge_binding {
            return Err(FractalKeyV1Error::ChallengeBindingMismatch);
        }

        if self.components[2].payload32 != input.expected_proof_material_hash {
            return Err(FractalKeyV1Error::ProofMaterialHashMismatch);
        }

        let recomputed_proof_hash = self.proof_hash();
        if recomputed_proof_hash != input.expected_proof_hash {
            return Err(FractalKeyV1Error::ProofHashMismatch);
        }

        Ok(recomputed_proof_hash)
    }

    fn verify_structure(&self) -> Result<(), FractalKeyV1Error> {
        if self.fractal_key_version != FRACTAL_KEY_VERSION_V1 {
            return Err(FractalKeyV1Error::InvalidVersion {
                expected: FRACTAL_KEY_VERSION_V1,
                actual: self.fractal_key_version,
            });
        }

        if self.component_count != FRACTAL_COMPONENT_COUNT_V1 {
            return Err(FractalKeyV1Error::InvalidComponentCount {
                expected: FRACTAL_COMPONENT_COUNT_V1,
                actual: self.component_count,
            });
        }

        let mut seen = [0u8; FRACTAL_COMPONENT_COUNT_V1 as usize];
        for component in self.components {
            let component_type = FractalComponentTypeV1::from_u16(component.component_type).ok_or(
                FractalKeyV1Error::UnexpectedComponentType {
                    component_type: component.component_type,
                },
            )?;
            seen[component_type.index()] = seen[component_type.index()].saturating_add(1);
        }

        for component_type in FractalComponentTypeV1::ORDERED {
            let seen_count = seen[component_type.index()];
            if seen_count == 0 {
                return Err(FractalKeyV1Error::MissingComponent {
                    component_type: component_type.as_u16(),
                });
            }
            if seen_count > 1 {
                return Err(FractalKeyV1Error::DuplicateComponent {
                    component_type: component_type.as_u16(),
                });
            }
        }

        for (component, expected_type) in self
            .components
            .iter()
            .zip(FractalComponentTypeV1::ORDERED.iter())
        {
            if component.component_type != expected_type.as_u16() {
                return Err(FractalKeyV1Error::InvalidComponentOrder);
            }
        }

        Ok(())
    }
}
