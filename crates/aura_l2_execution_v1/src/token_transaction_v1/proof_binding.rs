use crate::HASH_LEN_V1;

use super::{
    DeterministicTransactionPublicStatementV1, TokenTransactionErrorV1,
    TokenTransactionProofBindingV1, AURA_TOKEN_PROOF_BINDING_DOMAIN_SEPARATOR_V1,
};
use crate::sha256_bytes;

impl TokenTransactionProofBindingV1 {
    pub fn from_public_statement(
        public_statement: DeterministicTransactionPublicStatementV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        public_statement.validate()?;
        let public_statement_bytes = public_statement.canonical_bytes()?;
        let proof_binding_digest =
            derive_token_transaction_proof_binding_digest_v1(&public_statement_bytes);

        Ok(Self {
            proof_statement_type: public_statement.proof_statement_type,
            public_statement,
            public_statement_bytes,
            proof_binding_digest,
        })
    }
}

pub fn build_token_transaction_proof_binding_v1(
    public_statement: DeterministicTransactionPublicStatementV1,
) -> Result<TokenTransactionProofBindingV1, TokenTransactionErrorV1> {
    TokenTransactionProofBindingV1::from_public_statement(public_statement)
}

pub fn derive_token_transaction_proof_binding_digest_v1(
    public_statement_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_PROOF_BINDING_DOMAIN_SEPARATOR_V1.len() + public_statement_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_PROOF_BINDING_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(public_statement_bytes);
    sha256_bytes(&preimage)
}
