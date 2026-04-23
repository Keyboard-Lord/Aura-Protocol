use crate::{sha256_bytes, HASH_LEN_V1};

use super::{
    TokenTransactionErrorV1, TokenTransactionNotaryInputV1,
    TokenTransactionNotaryReceiptPreimageV1, AURA_TOKEN_NOTARY_RECEIPT_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_DOMAIN_SEPARATOR_V1,
};

impl TokenTransactionNotaryReceiptPreimageV1 {
    pub fn from_notary_input(
        notary_input: TokenTransactionNotaryInputV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_notary_input =
            TokenTransactionNotaryInputV1::from_proof_binding(notary_input.proof_binding.clone())?;
        if notary_input.proof_statement_type != rebuilt_notary_input.proof_statement_type {
            return Err(
                TokenTransactionErrorV1::InvalidNotaryInputProofStatementType {
                    expected: rebuilt_notary_input.proof_statement_type,
                    actual: notary_input.proof_statement_type,
                },
            );
        }
        if notary_input.notary_input_digest != rebuilt_notary_input.notary_input_digest {
            return Err(TokenTransactionErrorV1::InvalidNotaryInputDigest {
                expected: rebuilt_notary_input.notary_input_digest,
                actual: notary_input.notary_input_digest,
            });
        }

        let receipt_preimage_bytes = encode_token_transaction_notary_receipt_preimage_bytes_v1(
            notary_input.proof_statement_type,
            &notary_input.notary_input_digest,
            &notary_input.proof_binding_digest,
            &notary_input.proof_binding_bytes,
        );
        let receipt_digest =
            derive_token_transaction_notary_receipt_digest_v1(&receipt_preimage_bytes);

        Ok(Self {
            proof_statement_type: notary_input.proof_statement_type,
            notary_input,
            receipt_preimage_bytes,
            receipt_digest,
        })
    }
}

pub fn build_token_transaction_notary_receipt_preimage_v1(
    notary_input: TokenTransactionNotaryInputV1,
) -> Result<TokenTransactionNotaryReceiptPreimageV1, TokenTransactionErrorV1> {
    TokenTransactionNotaryReceiptPreimageV1::from_notary_input(notary_input)
}

pub(crate) fn encode_token_transaction_notary_receipt_preimage_bytes_v1(
    proof_statement_type: u8,
    notary_input_digest: &[u8; HASH_LEN_V1],
    proof_binding_digest: &[u8; HASH_LEN_V1],
    proof_binding_bytes: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_DOMAIN_SEPARATOR_V1.len()
            + 1
            + notary_input_digest.len()
            + proof_binding_digest.len()
            + 8
            + proof_binding_bytes.len(),
    );
    bytes.extend_from_slice(AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_DOMAIN_SEPARATOR_V1);
    bytes.push(proof_statement_type);
    bytes.extend_from_slice(notary_input_digest);
    bytes.extend_from_slice(proof_binding_digest);
    bytes.extend_from_slice(&(proof_binding_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(proof_binding_bytes);
    bytes
}

pub fn derive_token_transaction_notary_receipt_digest_v1(
    receipt_preimage_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARY_RECEIPT_DOMAIN_SEPARATOR_V1.len() + receipt_preimage_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARY_RECEIPT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(receipt_preimage_bytes);
    sha256_bytes(&preimage)
}
