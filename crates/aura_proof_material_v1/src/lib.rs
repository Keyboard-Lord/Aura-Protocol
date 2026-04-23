//! Frozen Aura v1 proof-material commitment layer.

use core::fmt;
use sha2::{Digest, Sha256};

pub const PROOF_MATERIAL_VERSION_V1: u8 = 1;
pub const PROOF_MATERIAL_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_PROOF_MATERIAL_V1";
pub const PROOF_MATERIAL_HASH_LEN_V1: usize = 32;
pub const PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V1: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ProofMaterialTypeV1 {
    CanonicalVerifierBundle = 0x0001,
}

impl ProofMaterialTypeV1 {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::CanonicalVerifierBundle),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofMaterialV1 {
    pub proof_material_version: u8,
    pub proof_material_type: u16,
    pub proof_blob_hash: [u8; PROOF_MATERIAL_HASH_LEN_V1],
    pub public_inputs_hash: [u8; PROOF_MATERIAL_HASH_LEN_V1],
    pub verification_key_hash: [u8; PROOF_MATERIAL_HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofMaterialV1Error {
    InvalidVersion { expected: u8, actual: u8 },
    InvalidProofMaterialType { expected: u16, actual: u16 },
    ProofBlobHashMismatch,
    PublicInputsHashMismatch,
    VerificationKeyHashMismatch,
    ProofMaterialHashMismatch,
}

impl fmt::Display for ProofMaterialV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(f, "invalid version: expected {expected}, got {actual}")
            }
            Self::InvalidProofMaterialType { expected, actual } => {
                write!(
                    f,
                    "invalid proof material type: expected 0x{expected:04x}, got 0x{actual:04x}"
                )
            }
            Self::ProofBlobHashMismatch => write!(f, "proof blob hash mismatch"),
            Self::PublicInputsHashMismatch => write!(f, "public inputs hash mismatch"),
            Self::VerificationKeyHashMismatch => write!(f, "verification key hash mismatch"),
            Self::ProofMaterialHashMismatch => write!(f, "proof material hash mismatch"),
        }
    }
}

impl std::error::Error for ProofMaterialV1Error {}

pub fn proof_blob_hash_v1(proof_blob_bytes: &[u8]) -> [u8; PROOF_MATERIAL_HASH_LEN_V1] {
    sha256_bytes(proof_blob_bytes)
}

pub fn public_inputs_hash_v1(public_inputs_bytes: &[u8]) -> [u8; PROOF_MATERIAL_HASH_LEN_V1] {
    sha256_bytes(public_inputs_bytes)
}

pub fn verification_key_hash_v1(verification_key_bytes: &[u8]) -> [u8; PROOF_MATERIAL_HASH_LEN_V1] {
    sha256_bytes(verification_key_bytes)
}

impl ProofMaterialV1 {
    pub fn build(
        proof_blob_bytes: &[u8],
        public_inputs_bytes: &[u8],
        verification_key_bytes: &[u8],
    ) -> Self {
        Self {
            proof_material_version: PROOF_MATERIAL_VERSION_V1,
            proof_material_type: ProofMaterialTypeV1::CanonicalVerifierBundle.as_u16(),
            proof_blob_hash: proof_blob_hash_v1(proof_blob_bytes),
            public_inputs_hash: public_inputs_hash_v1(public_inputs_bytes),
            verification_key_hash: verification_key_hash_v1(verification_key_bytes),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PROOF_MATERIAL_DOMAIN_SEPARATOR_V1.len()
                + 1
                + PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V1
                + (PROOF_MATERIAL_HASH_LEN_V1 * 3),
        );
        bytes.extend_from_slice(PROOF_MATERIAL_DOMAIN_SEPARATOR_V1);
        bytes.push(self.proof_material_version);
        bytes.extend_from_slice(&self.proof_material_type.to_le_bytes());
        bytes.extend_from_slice(&self.proof_blob_hash);
        bytes.extend_from_slice(&self.public_inputs_hash);
        bytes.extend_from_slice(&self.verification_key_hash);
        bytes
    }

    pub fn proof_material_hash(&self) -> [u8; PROOF_MATERIAL_HASH_LEN_V1] {
        sha256_bytes(&self.canonical_bytes())
    }

    pub fn verify(
        &self,
        proof_blob_bytes: &[u8],
        public_inputs_bytes: &[u8],
        verification_key_bytes: &[u8],
        expected_proof_material_hash: [u8; PROOF_MATERIAL_HASH_LEN_V1],
    ) -> Result<[u8; PROOF_MATERIAL_HASH_LEN_V1], ProofMaterialV1Error> {
        self.verify_structure()?;

        if self.proof_blob_hash != proof_blob_hash_v1(proof_blob_bytes) {
            return Err(ProofMaterialV1Error::ProofBlobHashMismatch);
        }

        if self.public_inputs_hash != public_inputs_hash_v1(public_inputs_bytes) {
            return Err(ProofMaterialV1Error::PublicInputsHashMismatch);
        }

        if self.verification_key_hash != verification_key_hash_v1(verification_key_bytes) {
            return Err(ProofMaterialV1Error::VerificationKeyHashMismatch);
        }

        let recomputed_proof_material_hash = self.proof_material_hash();
        if recomputed_proof_material_hash != expected_proof_material_hash {
            return Err(ProofMaterialV1Error::ProofMaterialHashMismatch);
        }

        Ok(recomputed_proof_material_hash)
    }

    fn verify_structure(&self) -> Result<(), ProofMaterialV1Error> {
        if self.proof_material_version != PROOF_MATERIAL_VERSION_V1 {
            return Err(ProofMaterialV1Error::InvalidVersion {
                expected: PROOF_MATERIAL_VERSION_V1,
                actual: self.proof_material_version,
            });
        }

        let expected_type = ProofMaterialTypeV1::CanonicalVerifierBundle.as_u16();
        if self.proof_material_type != expected_type {
            return Err(ProofMaterialV1Error::InvalidProofMaterialType {
                expected: expected_type,
                actual: self.proof_material_type,
            });
        }

        Ok(())
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; PROOF_MATERIAL_HASH_LEN_V1] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; PROOF_MATERIAL_HASH_LEN_V1];
    hash.copy_from_slice(&digest);
    hash
}

#[cfg(test)]
mod tests {
    use super::{
        proof_blob_hash_v1, public_inputs_hash_v1, verification_key_hash_v1, ProofMaterialV1,
        PROOF_MATERIAL_DOMAIN_SEPARATOR_V1, PROOF_MATERIAL_HASH_LEN_V1,
        PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V1, PROOF_MATERIAL_VERSION_V1,
    };

    fn decode_hex_32(input: &str) -> [u8; 32] {
        let trimmed = input.trim();
        assert_eq!(trimmed.len(), 64);
        let mut out = [0u8; 32];
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            out[index] = (decode_nibble(chunk[0]) << 4) | decode_nibble(chunk[1]);
        }
        out
    }

    fn decode_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid hex nibble"),
        }
    }

    #[test]
    fn canonical_prepare_fixture_matches_hash_pm_equation() {
        let proof_blob = include_bytes!("../../../fixtures/v1/canonical_prepare/proof_blob.bin");
        let public_inputs =
            include_bytes!("../../../fixtures/v1/canonical_prepare/public_inputs.bin");
        let verification_key =
            include_bytes!("../../../fixtures/v1/canonical_prepare/verification_key.bin");
        let expected_proof_blob_hash = decode_hex_32(include_str!(
            "../../../fixtures/v1/canonical_prepare/proof_blob_hash.hex"
        ));
        let expected_public_inputs_hash = decode_hex_32(include_str!(
            "../../../fixtures/v1/canonical_prepare/public_inputs_hash.hex"
        ));
        let expected_verification_key_hash = decode_hex_32(include_str!(
            "../../../fixtures/v1/canonical_prepare/verification_key_hash.hex"
        ));
        let expected_proof_material_hash = decode_hex_32(include_str!(
            "../../../fixtures/v1/canonical_prepare/proof_material_hash.hex"
        ));

        let proof_material = ProofMaterialV1::build(proof_blob, public_inputs, verification_key);

        assert_eq!(proof_blob_hash_v1(proof_blob), expected_proof_blob_hash);
        assert_eq!(
            public_inputs_hash_v1(public_inputs),
            expected_public_inputs_hash
        );
        assert_eq!(
            verification_key_hash_v1(verification_key),
            expected_verification_key_hash
        );
        assert_eq!(proof_material.proof_blob_hash, expected_proof_blob_hash);
        assert_eq!(
            proof_material.public_inputs_hash,
            expected_public_inputs_hash
        );
        assert_eq!(
            proof_material.verification_key_hash,
            expected_verification_key_hash
        );

        let canonical_bytes = proof_material.canonical_bytes();
        let expected_len = PROOF_MATERIAL_DOMAIN_SEPARATOR_V1.len()
            + 1
            + PROOF_MATERIAL_TYPE_SERIALIZED_LEN_V1
            + (PROOF_MATERIAL_HASH_LEN_V1 * 3);
        assert_eq!(canonical_bytes.len(), expected_len);
        assert_eq!(
            &canonical_bytes[..PROOF_MATERIAL_DOMAIN_SEPARATOR_V1.len()],
            PROOF_MATERIAL_DOMAIN_SEPARATOR_V1
        );
        assert_eq!(
            canonical_bytes[PROOF_MATERIAL_DOMAIN_SEPARATOR_V1.len()],
            PROOF_MATERIAL_VERSION_V1
        );
        assert_eq!(
            proof_material.proof_material_hash(),
            expected_proof_material_hash
        );
    }
}
