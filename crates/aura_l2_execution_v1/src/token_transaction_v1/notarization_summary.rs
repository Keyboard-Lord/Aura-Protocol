use super::shared::encode_hex_lower_v1;
use super::{
    TokenTransactionErrorV1, TokenTransactionNotarizationRecordV1,
    TokenTransactionNotarizationRecordWireV1, TokenTransactionNotarizationSummaryV1,
    EXACT_PUBLIC_STATEMENT_TYPE_V1, TOKEN_NOTARIZATION_SUMMARY_VERSION_V1,
};

impl TokenTransactionNotarizationSummaryV1 {
    pub fn from_record_wire(
        payload: TokenTransactionNotarizationRecordWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let record = TokenTransactionNotarizationRecordV1::from_wire(payload)?;
        let proof_statement_label = proof_statement_label_v1(record.proof_statement_type)?;

        Ok(Self {
            summary_version: TOKEN_NOTARIZATION_SUMMARY_VERSION_V1,
            record_version: record.record_version,
            proof_statement_type: record.proof_statement_type,
            proof_statement_label: proof_statement_label.to_owned(),
            ack_digest_hex: encode_hex_lower_v1(&record.ack_digest),
            seal_payload_digest_hex: encode_hex_lower_v1(&record.seal_payload_digest),
            udot_seed_digest_hex: encode_hex_lower_v1(&record.udot_seed_digest),
            notarization_record_digest_hex: encode_hex_lower_v1(&record.notarization_record_digest),
        })
    }
}

pub fn build_token_transaction_notarization_summary_v1(
    payload: TokenTransactionNotarizationRecordWireV1,
) -> Result<TokenTransactionNotarizationSummaryV1, TokenTransactionErrorV1> {
    TokenTransactionNotarizationSummaryV1::from_record_wire(payload)
}

fn proof_statement_label_v1(
    proof_statement_type: u8,
) -> Result<&'static str, TokenTransactionErrorV1> {
    match proof_statement_type {
        EXACT_PUBLIC_STATEMENT_TYPE_V1 => Ok("private_transfer_burn_v1"),
        actual => Err(TokenTransactionErrorV1::UnsupportedProofStatementType {
            expected: EXACT_PUBLIC_STATEMENT_TYPE_V1,
            actual,
        }),
    }
}
