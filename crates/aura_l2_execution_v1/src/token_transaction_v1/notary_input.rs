use crate::{sha256_bytes, HASH_LEN_V1};

use super::proof_binding::derive_token_transaction_proof_binding_digest_v1;
use super::{
    TokenTransactionErrorV1, TokenTransactionNotaryInputV1, TokenTransactionProofBindingV1,
    AURA_TOKEN_NOTARY_INPUT_DOMAIN_SEPARATOR_V1,
};

impl TokenTransactionNotaryInputV1 {
    pub fn from_proof_binding(
        proof_binding: TokenTransactionProofBindingV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        proof_binding.public_statement.validate()?;

        let expected_bytes = proof_binding.public_statement.canonical_bytes()?;
        if proof_binding.public_statement_bytes != expected_bytes {
            return Err(TokenTransactionErrorV1::InvalidProofBindingBytes);
        }

        let expected_digest =
            derive_token_transaction_proof_binding_digest_v1(&proof_binding.public_statement_bytes);
        if proof_binding.proof_binding_digest != expected_digest {
            return Err(TokenTransactionErrorV1::InvalidProofBindingDigest {
                expected: expected_digest,
                actual: proof_binding.proof_binding_digest,
            });
        }

        let notary_input_digest = derive_token_transaction_notary_input_digest_v1(
            &proof_binding.public_statement_bytes,
            &proof_binding.proof_binding_digest,
        );

        Ok(Self {
            proof_statement_type: proof_binding.proof_statement_type,
            proof_binding_bytes: proof_binding.public_statement_bytes.clone(),
            proof_binding_digest: proof_binding.proof_binding_digest,
            proof_binding,
            notary_input_digest,
        })
    }
}

pub fn build_token_transaction_notary_input_v1(
    proof_binding: TokenTransactionProofBindingV1,
) -> Result<TokenTransactionNotaryInputV1, TokenTransactionErrorV1> {
    TokenTransactionNotaryInputV1::from_proof_binding(proof_binding)
}

pub fn derive_token_transaction_notary_input_digest_v1(
    proof_binding_bytes: &[u8],
    proof_binding_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARY_INPUT_DOMAIN_SEPARATOR_V1.len()
            + proof_binding_digest.len()
            + proof_binding_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARY_INPUT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(proof_binding_digest);
    preimage.extend_from_slice(proof_binding_bytes);
    sha256_bytes(&preimage)
}
