//! Downstream export boundary for the frozen Aura token/notary v1 notarization surfaces.

use aura_l2_execution_v1::{
    build_token_transaction_notarization_summary_v1, TokenTransactionErrorV1,
    TokenTransactionNotarizationRecordV1, TokenTransactionNotarizationRecordWireV1,
    TokenTransactionNotarizationSummaryV1,
};
use core::fmt;

pub use aura_l2_execution_v1::{
    TokenTransactionNotarizationRecordV1 as CanonicalTokenTransactionNotarizationRecordV1,
    TokenTransactionNotarizationRecordWireV1 as CanonicalTokenTransactionNotarizationRecordWireV1,
    TokenTransactionNotarizationSummaryV1 as CanonicalTokenTransactionNotarizationSummaryV1,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuraNotarizationExportErrorV1 {
    InvalidNotarizationRecord(TokenTransactionErrorV1),
}

impl fmt::Display for AuraNotarizationExportErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNotarizationRecord(error) => {
                write!(f, "invalid notarization record: {error}")
            }
        }
    }
}

impl std::error::Error for AuraNotarizationExportErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidNotarizationRecord(error) => Some(error),
        }
    }
}

pub fn validate_notarization_record_wire_v1(
    payload: TokenTransactionNotarizationRecordWireV1,
) -> Result<TokenTransactionNotarizationRecordWireV1, AuraNotarizationExportErrorV1> {
    TokenTransactionNotarizationRecordV1::from_wire(payload)
        .map(|record| record.to_wire())
        .map_err(AuraNotarizationExportErrorV1::InvalidNotarizationRecord)
}

pub fn build_notarization_export_summary_v1(
    payload: TokenTransactionNotarizationRecordWireV1,
) -> Result<TokenTransactionNotarizationSummaryV1, AuraNotarizationExportErrorV1> {
    build_token_transaction_notarization_summary_v1(payload)
        .map_err(AuraNotarizationExportErrorV1::InvalidNotarizationRecord)
}

#[cfg(test)]
mod tests {
    use super::{
        build_notarization_export_summary_v1, validate_notarization_record_wire_v1,
        AuraNotarizationExportErrorV1,
    };
    use aura_l2_execution_v1::{
        build_token_transaction_notarization_summary_v1, TokenTransactionErrorV1,
        TokenTransactionNotarizationRecordWireV1, TokenTransactionNotarizationSummaryV1,
    };
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureVectorFileV1 {
        vectors: Vec<FixtureVectorV1>,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureVectorV1 {
        notarization_summary: TokenTransactionNotarizationSummaryV1,
        notarization_record_digest_hex: String,
        notary_ack_digest_hex: String,
        seal_payload_digest_hex: String,
        udot_seed_digest_hex: String,
        #[serde(flatten)]
        rest: std::collections::BTreeMap<String, serde_json::Value>,
    }

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/v1/deterministic_transaction_v1/test_vectors.json")
    }

    fn load_fixture_vectors() -> FixtureVectorFileV1 {
        serde_json::from_str(&fs::read_to_string(fixture_path()).unwrap()).unwrap()
    }

    fn sample_record_wire_from_fixture() -> TokenTransactionNotarizationRecordWireV1 {
        let file = load_fixture_vectors();
        fixture_record_wire(&file.vectors[0])
    }

    fn fixture_record_wire(vector: &FixtureVectorV1) -> TokenTransactionNotarizationRecordWireV1 {
        TokenTransactionNotarizationRecordWireV1 {
            record_version: vector.notarization_summary.record_version,
            proof_statement_type: vector.notarization_summary.proof_statement_type,
            ack_digest_hex: vector.notary_ack_digest_hex.clone(),
            seal_payload_digest_hex: vector.seal_payload_digest_hex.clone(),
            udot_seed_digest_hex: vector.udot_seed_digest_hex.clone(),
            notarization_record_digest_hex: vector.notarization_record_digest_hex.clone(),
        }
    }

    #[test]
    fn downstream_boundary_consumes_canonical_record_wire_without_upstream_assembly() {
        let wire = sample_record_wire_from_fixture();
        let validated = validate_notarization_record_wire_v1(wire.clone()).unwrap();
        let summary = build_notarization_export_summary_v1(wire).unwrap();

        assert_eq!(validated.record_version, summary.record_version);
        assert_eq!(validated.proof_statement_type, summary.proof_statement_type);
    }

    #[test]
    fn valid_record_wire_produces_exact_existing_summary_output() {
        let file = load_fixture_vectors();

        for vector in file.vectors {
            let wire = fixture_record_wire(&vector);

            let summary = build_notarization_export_summary_v1(wire).unwrap();
            assert_eq!(summary, vector.notarization_summary);
        }
    }

    #[test]
    fn malformed_tampered_wire_input_fails_closed() {
        let mut wire = sample_record_wire_from_fixture();
        wire.notarization_record_digest_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();

        let error = build_notarization_export_summary_v1(wire).unwrap_err();
        match error {
            AuraNotarizationExportErrorV1::InvalidNotarizationRecord(
                TokenTransactionErrorV1::InvalidNotarizationRecordDigest { .. },
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fixture_backed_behavior_is_preserved() {
        let file = load_fixture_vectors();

        for vector in file.vectors {
            let wire = fixture_record_wire(&vector);

            let validated = validate_notarization_record_wire_v1(wire.clone()).unwrap();
            let direct = build_notarization_export_summary_v1(wire.clone()).unwrap();
            let canonical =
                build_token_transaction_notarization_summary_v1(validated.clone()).unwrap();

            assert_eq!(validated, wire);
            assert_eq!(direct, canonical);
            assert_eq!(direct, vector.notarization_summary);
            assert!(vector.rest.contains_key("transaction"));
        }
    }

    #[test]
    fn downstream_boundary_is_deterministic_for_identical_wire_inputs() {
        let wire = sample_record_wire_from_fixture();

        let first_validated = validate_notarization_record_wire_v1(wire.clone()).unwrap();
        let second_validated = validate_notarization_record_wire_v1(wire.clone()).unwrap();
        let first_summary = build_notarization_export_summary_v1(wire.clone()).unwrap();
        let second_summary = build_notarization_export_summary_v1(wire).unwrap();

        assert_eq!(first_validated, second_validated);
        assert_eq!(first_summary, second_summary);
    }
}
