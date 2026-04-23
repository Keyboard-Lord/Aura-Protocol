//! High-level summary-to-files workflow facade for the frozen Aura notarization receipt pair.
//!
//! Canonical non-CLI automation path:
//!
//! ```no_run
//! use aura_notarization_workflow_v1::{
//!     export_notarization_record_wire_v1, CanonicalTokenTransactionNotarizationRecordWireV1,
//! };
//!
//! let record_wire_json = r#"{
//!   "record_version": 1,
//!   "proof_statement_type": 1,
//!   "ack_digest_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!   "seal_payload_digest_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
//!   "udot_seed_digest_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
//!   "notarization_record_digest_hex": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
//! }"#;
//!
//! let record_wire: CanonicalTokenTransactionNotarizationRecordWireV1 =
//!     serde_json::from_str(record_wire_json)?;
//!
//! let receipt_paths =
//!     export_notarization_record_wire_v1(&record_wire, "/tmp/aura_notarization_receipt")?;
//!
//! assert!(receipt_paths.markdown_path.ends_with("aura_notarization_receipt.md"));
//! assert!(receipt_paths.html_path.ends_with("aura_notarization_receipt.html"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::path::Path;

pub use aura_notarization_export_service_v1::{
    export_notarization_receipt_bundle_v1, AuraNotarizationRenderErrorV1,
    CanonicalTokenTransactionNotarizationSummaryV1, NotarizationReceiptBundlePathsV1,
};
pub use aura_notarization_export_v1::{
    build_notarization_export_summary_v1, validate_notarization_record_wire_v1,
    AuraNotarizationExportErrorV1, CanonicalTokenTransactionNotarizationRecordWireV1,
};

pub fn export_validated_notarization_summary_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationRenderErrorV1> {
    export_notarization_receipt_bundle_v1(summary, base_output_path)
}

#[derive(Debug)]
pub enum AuraNotarizationWorkflowErrorV1 {
    InvalidUtf8(std::str::Utf8Error),
    InvalidJsonValueSerialization(serde_json::Error),
    InvalidJson(serde_json::Error),
    InvalidNotarizationRecord(AuraNotarizationExportErrorV1),
    Render(AuraNotarizationRenderErrorV1),
}

impl core::fmt::Display for AuraNotarizationWorkflowErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUtf8(error) => {
                write!(f, "invalid notarization record json utf-8: {error}")
            }
            Self::InvalidJsonValueSerialization(error) => {
                write!(
                    f,
                    "invalid notarization record json value serialization: {error}"
                )
            }
            Self::InvalidJson(error) => write!(f, "invalid notarization record json: {error}"),
            Self::InvalidNotarizationRecord(error) => write!(f, "{error}"),
            Self::Render(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuraNotarizationWorkflowErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(error) => Some(error),
            Self::InvalidJsonValueSerialization(error) => Some(error),
            Self::InvalidJson(error) => Some(error),
            Self::InvalidNotarizationRecord(error) => Some(error),
            Self::Render(error) => Some(error),
        }
    }
}

impl From<std::str::Utf8Error> for AuraNotarizationWorkflowErrorV1 {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8(error)
    }
}

impl From<serde_json::Error> for AuraNotarizationWorkflowErrorV1 {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

impl From<AuraNotarizationExportErrorV1> for AuraNotarizationWorkflowErrorV1 {
    fn from(error: AuraNotarizationExportErrorV1) -> Self {
        Self::InvalidNotarizationRecord(error)
    }
}

impl From<AuraNotarizationRenderErrorV1> for AuraNotarizationWorkflowErrorV1 {
    fn from(error: AuraNotarizationRenderErrorV1) -> Self {
        Self::Render(error)
    }
}

pub fn export_notarization_record_wire_v1(
    record_wire: &CanonicalTokenTransactionNotarizationRecordWireV1,
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationWorkflowErrorV1> {
    let validated = validate_notarization_record_wire_v1(record_wire.clone())?;
    let summary = build_notarization_export_summary_v1(validated)?;
    export_validated_notarization_summary_v1(&summary, base_output_path).map_err(Into::into)
}

pub fn export_notarization_record_json_v1(
    record_wire_json: &str,
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationWorkflowErrorV1> {
    let record_wire: CanonicalTokenTransactionNotarizationRecordWireV1 =
        serde_json::from_str(record_wire_json)?;
    export_notarization_record_wire_v1(&record_wire, base_output_path)
}

pub fn export_notarization_record_bytes_v1(
    record_wire_json_bytes: &[u8],
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationWorkflowErrorV1> {
    let record_wire_json = std::str::from_utf8(record_wire_json_bytes)?;
    export_notarization_record_json_v1(record_wire_json, base_output_path)
}

pub fn export_notarization_record_value_v1(
    record_wire_value: &serde_json::Value,
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationWorkflowErrorV1> {
    let record_wire_json = serde_json::to_string(record_wire_value)
        .map_err(AuraNotarizationWorkflowErrorV1::InvalidJsonValueSerialization)?;
    export_notarization_record_json_v1(&record_wire_json, base_output_path)
}

#[cfg(test)]
mod tests {
    use super::{
        export_notarization_record_bytes_v1, export_notarization_record_json_v1,
        export_notarization_record_value_v1, export_notarization_record_wire_v1,
        export_validated_notarization_summary_v1,
    };
    use aura_notarization_export_service_v1::{
        AuraNotarizationRenderErrorV1, CanonicalTokenTransactionNotarizationSummaryV1,
        NotarizationReceiptBundlePathsV1,
    };
    use aura_notarization_export_v1::{
        AuraNotarizationExportErrorV1, CanonicalTokenTransactionNotarizationRecordWireV1,
    };
    use aura_notarization_render_v1::{
        render_notarization_summary_html_v1, render_notarization_summary_markdown_v1,
    };
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureVectorFileV1 {
        vectors: Vec<FixtureVectorV1>,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureVectorV1 {
        notarization_summary: CanonicalTokenTransactionNotarizationSummaryV1,
        notarization_record_digest_hex: String,
        notary_ack_digest_hex: String,
        seal_payload_digest_hex: String,
        udot_seed_digest_hex: String,
        #[allow(dead_code)]
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

    fn sample_summary() -> CanonicalTokenTransactionNotarizationSummaryV1 {
        load_fixture_vectors().vectors[0]
            .notarization_summary
            .clone()
    }

    fn sample_record_wire() -> CanonicalTokenTransactionNotarizationRecordWireV1 {
        let vector = &load_fixture_vectors().vectors[0];
        fixture_record_wire(vector)
    }

    fn fixture_record_wire(
        vector: &FixtureVectorV1,
    ) -> CanonicalTokenTransactionNotarizationRecordWireV1 {
        CanonicalTokenTransactionNotarizationRecordWireV1 {
            record_version: vector.notarization_summary.record_version,
            proof_statement_type: vector.notarization_summary.proof_statement_type,
            ack_digest_hex: vector.notary_ack_digest_hex.clone(),
            seal_payload_digest_hex: vector.seal_payload_digest_hex.clone(),
            udot_seed_digest_hex: vector.udot_seed_digest_hex.clone(),
            notarization_record_digest_hex: vector.notarization_record_digest_hex.clone(),
        }
    }

    fn fixture_record_wire_json_string(vector: &FixtureVectorV1) -> String {
        serde_json::json!({
            "record_version": vector.notarization_summary.record_version,
            "proof_statement_type": vector.notarization_summary.proof_statement_type,
            "ack_digest_hex": vector.notary_ack_digest_hex,
            "seal_payload_digest_hex": vector.seal_payload_digest_hex,
            "udot_seed_digest_hex": vector.udot_seed_digest_hex,
            "notarization_record_digest_hex": vector.notarization_record_digest_hex,
        })
        .to_string()
    }

    fn fixture_record_wire_json_value(vector: &FixtureVectorV1) -> serde_json::Value {
        serde_json::json!({
            "record_version": vector.notarization_summary.record_version,
            "proof_statement_type": vector.notarization_summary.proof_statement_type,
            "ack_digest_hex": vector.notary_ack_digest_hex,
            "seal_payload_digest_hex": vector.seal_payload_digest_hex,
            "udot_seed_digest_hex": vector.udot_seed_digest_hex,
            "notarization_record_digest_hex": vector.notarization_record_digest_hex,
        })
    }

    fn temp_base_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aura_notarization_workflow_{}_{}_{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed),
            label,
        ))
    }

    #[test]
    fn higher_level_consumer_writes_standard_markdown_and_html_pair_exactly() {
        let summary = sample_summary();
        let base_path = temp_base_path("pair");

        let paths = export_validated_notarization_summary_v1(&summary, &base_path).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.markdown_path).unwrap(),
            render_notarization_summary_markdown_v1(&summary)
        );
        assert_eq!(
            fs::read_to_string(&paths.html_path).unwrap(),
            render_notarization_summary_html_v1(&summary)
        );
    }

    #[test]
    fn returned_paths_match_frozen_bundle_path_rule() {
        let summary = sample_summary();
        let base_path = temp_base_path("paths.with.existing.ext");

        let paths = export_validated_notarization_summary_v1(&summary, &base_path).unwrap();

        assert_eq!(
            paths,
            NotarizationReceiptBundlePathsV1 {
                markdown_path: PathBuf::from(format!("{}.md", base_path.to_string_lossy())),
                html_path: PathBuf::from(format!("{}.html", base_path.to_string_lossy())),
            }
        );
    }

    #[test]
    fn deterministic_repeatability_holds() {
        let summary = sample_summary();
        let first_base = temp_base_path("first");
        let second_base = temp_base_path("second");

        let first_paths = export_validated_notarization_summary_v1(&summary, &first_base).unwrap();
        let second_paths =
            export_validated_notarization_summary_v1(&summary, &second_base).unwrap();

        assert_eq!(
            fs::read_to_string(&first_paths.markdown_path).unwrap(),
            fs::read_to_string(&second_paths.markdown_path).unwrap()
        );
        assert_eq!(
            fs::read_to_string(&first_paths.html_path).unwrap(),
            fs::read_to_string(&second_paths.html_path).unwrap()
        );
    }

    #[test]
    fn file_writing_failures_surface_cleanly() {
        let summary = sample_summary();
        let missing_parent = std::env::temp_dir()
            .join(format!(
                "aura_notarization_workflow_missing_{}",
                TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
            .join("receipt");

        let error =
            export_validated_notarization_summary_v1(&summary, &missing_parent).unwrap_err();

        match error {
            AuraNotarizationRenderErrorV1::Io(_) => {}
        }
    }

    #[test]
    fn downstream_callers_can_use_high_level_helper_without_manual_render_composition() {
        let summary = sample_summary();
        let base_path = temp_base_path("facade_only");

        let paths = export_validated_notarization_summary_v1(&summary, &base_path).unwrap();

        assert!(paths.markdown_path.exists());
        assert!(paths.html_path.exists());
    }

    #[test]
    fn valid_canonical_record_wire_input_writes_standard_pair_exactly() {
        let summary = sample_summary();
        let record_wire = sample_record_wire();
        let base_path = temp_base_path("record_pair");

        let paths = export_notarization_record_wire_v1(&record_wire, &base_path).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.markdown_path).unwrap(),
            render_notarization_summary_markdown_v1(&summary)
        );
        assert_eq!(
            fs::read_to_string(&paths.html_path).unwrap(),
            render_notarization_summary_html_v1(&summary)
        );
    }

    #[test]
    fn malformed_record_wire_input_fails_closed() {
        let mut record_wire = sample_record_wire();
        record_wire.ack_digest_hex = "abcd".to_owned();
        let base_path = temp_base_path("malformed");

        let error = export_notarization_record_wire_v1(&record_wire, &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidNotarizationRecord(
                AuraNotarizationExportErrorV1::InvalidNotarizationRecord(_),
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bad_record_digest_fails_closed() {
        let mut record_wire = sample_record_wire();
        record_wire.notarization_record_digest_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let base_path = temp_base_path("bad_digest");

        let error = export_notarization_record_wire_v1(&record_wire, &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidNotarizationRecord(
                AuraNotarizationExportErrorV1::InvalidNotarizationRecord(_),
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn record_wire_paths_match_frozen_bundle_path_rule() {
        let record_wire = sample_record_wire();
        let base_path = temp_base_path("record_paths.with.ext");

        let paths = export_notarization_record_wire_v1(&record_wire, &base_path).unwrap();

        assert_eq!(
            paths,
            NotarizationReceiptBundlePathsV1 {
                markdown_path: PathBuf::from(format!("{}.md", base_path.to_string_lossy())),
                html_path: PathBuf::from(format!("{}.html", base_path.to_string_lossy())),
            }
        );
    }

    #[test]
    fn record_wire_repeatability_holds() {
        let record_wire = sample_record_wire();
        let first_base = temp_base_path("record_first");
        let second_base = temp_base_path("record_second");

        let first_paths = export_notarization_record_wire_v1(&record_wire, &first_base).unwrap();
        let second_paths = export_notarization_record_wire_v1(&record_wire, &second_base).unwrap();

        assert_eq!(
            fs::read_to_string(&first_paths.markdown_path).unwrap(),
            fs::read_to_string(&second_paths.markdown_path).unwrap()
        );
        assert_eq!(
            fs::read_to_string(&first_paths.html_path).unwrap(),
            fs::read_to_string(&second_paths.html_path).unwrap()
        );
    }

    #[test]
    fn downstream_callers_can_use_record_wire_helper_without_touching_lower_layers() {
        let record_wire = sample_record_wire();
        let base_path = temp_base_path("record_facade_only");

        let paths = export_notarization_record_wire_v1(&record_wire, &base_path).unwrap();

        assert!(paths.markdown_path.exists());
        assert!(paths.html_path.exists());
    }

    #[test]
    fn canonical_record_wire_json_in_memory_can_be_parsed_and_exported_through_workflow_crate() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_json = fixture_record_wire_json_string(vector);
        let record_wire: CanonicalTokenTransactionNotarizationRecordWireV1 =
            serde_json::from_str(&record_wire_json).unwrap();
        let base_path = temp_base_path("record_json_memory");

        let paths = export_notarization_record_wire_v1(&record_wire, &base_path).unwrap();

        assert!(paths.markdown_path.exists());
        assert!(paths.html_path.exists());
        assert_eq!(
            fs::read_to_string(&paths.markdown_path).unwrap(),
            render_notarization_summary_markdown_v1(&vector.notarization_summary)
        );
        assert_eq!(
            fs::read_to_string(&paths.html_path).unwrap(),
            render_notarization_summary_html_v1(&vector.notarization_summary)
        );
    }

    #[test]
    fn valid_canonical_record_wire_json_string_exports_standard_pair_exactly() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_json = fixture_record_wire_json_string(vector);
        let base_path = temp_base_path("record_json_string");

        let paths = export_notarization_record_json_v1(&record_wire_json, &base_path).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.markdown_path).unwrap(),
            render_notarization_summary_markdown_v1(&vector.notarization_summary)
        );
        assert_eq!(
            fs::read_to_string(&paths.html_path).unwrap(),
            render_notarization_summary_html_v1(&vector.notarization_summary)
        );
    }

    #[test]
    fn valid_canonical_record_wire_json_bytes_export_standard_pair_exactly() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_json = fixture_record_wire_json_string(vector);
        let base_path = temp_base_path("record_json_bytes");

        let paths =
            export_notarization_record_bytes_v1(record_wire_json.as_bytes(), &base_path).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.markdown_path).unwrap(),
            render_notarization_summary_markdown_v1(&vector.notarization_summary)
        );
        assert_eq!(
            fs::read_to_string(&paths.html_path).unwrap(),
            render_notarization_summary_html_v1(&vector.notarization_summary)
        );
    }

    #[test]
    fn malformed_json_fails_closed() {
        let base_path = temp_base_path("bad_json");
        let error = export_notarization_record_json_v1("{", &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidJson(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_utf8_fails_closed() {
        let base_path = temp_base_path("bad_utf8");
        let error = export_notarization_record_bytes_v1(&[0xff], &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidUtf8(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bad_record_digest_via_json_string_fails_closed() {
        let vector = &load_fixture_vectors().vectors[0];
        let mut record_wire: CanonicalTokenTransactionNotarizationRecordWireV1 =
            serde_json::from_str(&fixture_record_wire_json_string(vector)).unwrap();
        record_wire.notarization_record_digest_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let record_wire_json = serde_json::to_string(&record_wire).unwrap();
        let base_path = temp_base_path("bad_digest_json");

        let error = export_notarization_record_json_v1(&record_wire_json, &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidNotarizationRecord(
                AuraNotarizationExportErrorV1::InvalidNotarizationRecord(_),
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn json_and_bytes_helpers_preserve_deterministic_repeatability() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_json = fixture_record_wire_json_string(vector);
        let first_base = temp_base_path("json_first");
        let second_base = temp_base_path("bytes_second");

        let first_paths =
            export_notarization_record_json_v1(&record_wire_json, &first_base).unwrap();
        let second_paths =
            export_notarization_record_bytes_v1(record_wire_json.as_bytes(), &second_base).unwrap();

        assert_eq!(
            fs::read_to_string(&first_paths.markdown_path).unwrap(),
            fs::read_to_string(&second_paths.markdown_path).unwrap()
        );
        assert_eq!(
            fs::read_to_string(&first_paths.html_path).unwrap(),
            fs::read_to_string(&second_paths.html_path).unwrap()
        );
    }

    #[test]
    fn valid_canonical_record_wire_json_value_exports_standard_pair_exactly() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_value = fixture_record_wire_json_value(vector);
        let base_path = temp_base_path("record_json_value");

        let paths = export_notarization_record_value_v1(&record_wire_value, &base_path).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.markdown_path).unwrap(),
            render_notarization_summary_markdown_v1(&vector.notarization_summary)
        );
        assert_eq!(
            fs::read_to_string(&paths.html_path).unwrap(),
            render_notarization_summary_html_v1(&vector.notarization_summary)
        );
    }

    #[test]
    fn malformed_structured_payload_fails_closed() {
        let record_wire_value = serde_json::json!({
            "record_version": 1,
            "proof_statement_type": 1,
            "ack_digest_hex": "abcd",
        });
        let base_path = temp_base_path("bad_value_shape");

        let error =
            export_notarization_record_value_v1(&record_wire_value, &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidJson(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bad_record_digest_via_json_value_fails_closed() {
        let vector = &load_fixture_vectors().vectors[0];
        let mut record_wire_value = fixture_record_wire_json_value(vector);
        record_wire_value["notarization_record_digest_hex"] = serde_json::Value::String(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
        );
        let base_path = temp_base_path("bad_digest_value");

        let error =
            export_notarization_record_value_v1(&record_wire_value, &base_path).unwrap_err();

        match error {
            super::AuraNotarizationWorkflowErrorV1::InvalidNotarizationRecord(
                AuraNotarizationExportErrorV1::InvalidNotarizationRecord(_),
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn json_value_helper_preserves_deterministic_repeatability() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_value = fixture_record_wire_json_value(vector);
        let first_base = temp_base_path("value_first");
        let second_base = temp_base_path("value_second");

        let first_paths =
            export_notarization_record_value_v1(&record_wire_value, &first_base).unwrap();
        let second_paths =
            export_notarization_record_value_v1(&record_wire_value, &second_base).unwrap();

        assert_eq!(
            fs::read_to_string(&first_paths.markdown_path).unwrap(),
            fs::read_to_string(&second_paths.markdown_path).unwrap()
        );
        assert_eq!(
            fs::read_to_string(&first_paths.html_path).unwrap(),
            fs::read_to_string(&second_paths.html_path).unwrap()
        );
    }

    #[test]
    fn downstream_callers_can_use_json_value_helper_without_manual_stringification() {
        let vector = &load_fixture_vectors().vectors[0];
        let record_wire_value = fixture_record_wire_json_value(vector);
        let base_path = temp_base_path("value_facade_only");

        let paths = export_notarization_record_value_v1(&record_wire_value, &base_path).unwrap();

        assert!(paths.markdown_path.exists());
        assert!(paths.html_path.exists());
    }
}
