//! High-level downstream facade for exporting the standard Aura notarization receipt bundle.

use std::path::Path;

pub use aura_notarization_render_v1::{
    write_notarization_summary_receipt_bundle_v1, AuraNotarizationRenderErrorV1,
    CanonicalTokenTransactionNotarizationSummaryV1, NotarizationReceiptBundlePathsV1,
};

pub fn export_notarization_receipt_bundle_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationRenderErrorV1> {
    write_notarization_summary_receipt_bundle_v1(summary, base_output_path)
}

#[cfg(test)]
mod tests {
    use super::export_notarization_receipt_bundle_v1;
    use aura_notarization_render_v1::{
        render_notarization_summary_html_v1, render_notarization_summary_markdown_v1,
        AuraNotarizationRenderErrorV1, CanonicalTokenTransactionNotarizationSummaryV1,
        NotarizationReceiptBundlePathsV1,
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

    fn temp_base_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aura_notarization_export_service_{}_{}_{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed),
            label,
        ))
    }

    #[test]
    fn facade_writes_standard_markdown_and_html_pair_exactly() {
        let summary = sample_summary();
        let base_path = temp_base_path("pair");

        let paths = export_notarization_receipt_bundle_v1(&summary, &base_path).unwrap();

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
    fn facade_returns_paths_matching_frozen_bundle_rule() {
        let summary = sample_summary();
        let base_path = temp_base_path("paths.with.existing.ext");

        let paths = export_notarization_receipt_bundle_v1(&summary, &base_path).unwrap();

        assert_eq!(
            paths,
            NotarizationReceiptBundlePathsV1 {
                markdown_path: PathBuf::from(format!("{}.md", base_path.to_string_lossy())),
                html_path: PathBuf::from(format!("{}.html", base_path.to_string_lossy())),
            }
        );
    }

    #[test]
    fn facade_is_deterministic_for_identical_inputs() {
        let summary = sample_summary();
        let first_base = temp_base_path("first");
        let second_base = temp_base_path("second");

        let first_paths = export_notarization_receipt_bundle_v1(&summary, &first_base).unwrap();
        let second_paths = export_notarization_receipt_bundle_v1(&summary, &second_base).unwrap();

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
    fn facade_surfaces_file_writing_failures_cleanly() {
        let summary = sample_summary();
        let missing_parent = std::env::temp_dir()
            .join(format!(
                "aura_notarization_export_service_missing_{}",
                TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
            .join("receipt");

        let error = export_notarization_receipt_bundle_v1(&summary, &missing_parent).unwrap_err();

        match error {
            AuraNotarizationRenderErrorV1::Io(_) => {}
        }
    }

    #[test]
    fn downstream_callers_can_use_facade_without_lower_level_render_composition() {
        let summary = sample_summary();
        let base_path = temp_base_path("facade_only");

        let paths = export_notarization_receipt_bundle_v1(&summary, &base_path).unwrap();

        assert!(paths.markdown_path.exists());
        assert!(paths.html_path.exists());
    }
}
