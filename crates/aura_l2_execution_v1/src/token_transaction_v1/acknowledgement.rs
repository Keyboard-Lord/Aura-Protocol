use crate::{sha256_bytes, HASH_LEN_V1};

use super::{
    TokenTransactionErrorV1, TokenTransactionNotaryAcknowledgementV1,
    TokenTransactionNotaryReceiptPreimageV1, AURA_TOKEN_NOTARY_ACK_DIGEST_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_NOTARY_ACK_DOMAIN_SEPARATOR_V1, AURA_TOKEN_SYMBOLIC_RECEIPT_DOMAIN_SEPARATOR_V1,
    TOKEN_NOTARY_ACK_VERSION_V1,
};

impl TokenTransactionNotaryAcknowledgementV1 {
    pub fn from_receipt(
        receipt: TokenTransactionNotaryReceiptPreimageV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_receipt = TokenTransactionNotaryReceiptPreimageV1::from_notary_input(
            receipt.notary_input.clone(),
        )?;
        if receipt.proof_statement_type != rebuilt_receipt.proof_statement_type {
            return Err(TokenTransactionErrorV1::InvalidReceiptProofStatementType {
                expected: rebuilt_receipt.proof_statement_type,
                actual: receipt.proof_statement_type,
            });
        }
        if receipt.receipt_digest != rebuilt_receipt.receipt_digest {
            return Err(TokenTransactionErrorV1::InvalidReceiptDigest {
                expected: rebuilt_receipt.receipt_digest,
                actual: receipt.receipt_digest,
            });
        }

        let ack_bytes = encode_token_transaction_notary_acknowledgement_bytes_v1(
            TOKEN_NOTARY_ACK_VERSION_V1,
            receipt.proof_statement_type,
            &receipt.receipt_digest,
        );
        let ack_digest = derive_token_transaction_notary_acknowledgement_digest_v1(&ack_bytes);
        let symbolic_receipt_preimage =
            derive_token_transaction_symbolic_receipt_preimage_v1(&ack_digest);

        Ok(Self {
            ack_version: TOKEN_NOTARY_ACK_VERSION_V1,
            proof_statement_type: receipt.proof_statement_type,
            receipt,
            ack_bytes,
            ack_digest,
            symbolic_receipt_preimage,
        })
    }
}

pub fn build_token_transaction_notary_acknowledgement_v1(
    receipt: TokenTransactionNotaryReceiptPreimageV1,
) -> Result<TokenTransactionNotaryAcknowledgementV1, TokenTransactionErrorV1> {
    TokenTransactionNotaryAcknowledgementV1::from_receipt(receipt)
}

pub(crate) fn encode_token_transaction_notary_acknowledgement_bytes_v1(
    ack_version: u32,
    proof_statement_type: u8,
    receipt_digest: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_NOTARY_ACK_DOMAIN_SEPARATOR_V1.len() + 4 + 1 + receipt_digest.len(),
    );
    bytes.extend_from_slice(AURA_TOKEN_NOTARY_ACK_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&ack_version.to_le_bytes());
    bytes.push(proof_statement_type);
    bytes.extend_from_slice(receipt_digest);
    bytes
}

pub fn derive_token_transaction_notary_acknowledgement_digest_v1(
    ack_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARY_ACK_DIGEST_DOMAIN_SEPARATOR_V1.len() + ack_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARY_ACK_DIGEST_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(ack_bytes);
    sha256_bytes(&preimage)
}

pub fn derive_token_transaction_symbolic_receipt_preimage_v1(
    ack_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_SYMBOLIC_RECEIPT_DOMAIN_SEPARATOR_V1.len() + ack_digest.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_SYMBOLIC_RECEIPT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(ack_digest);
    sha256_bytes(&preimage)
}
