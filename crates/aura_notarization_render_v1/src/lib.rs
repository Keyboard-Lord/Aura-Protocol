//! Reusable presentation renderer for the frozen Aura notarization summary surface.

use core::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub use aura_notarization_export_v1::CanonicalTokenTransactionNotarizationSummaryV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotarizationRenderFormatV1 {
    Markdown,
    Html,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizationReceiptBundlePathsV1 {
    pub markdown_path: PathBuf,
    pub html_path: PathBuf,
}

#[derive(Debug)]
pub enum AuraNotarizationRenderErrorV1 {
    Io(std::io::Error),
}

impl fmt::Display for AuraNotarizationRenderErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o error: {error}"),
        }
    }
}

impl std::error::Error for AuraNotarizationRenderErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for AuraNotarizationRenderErrorV1 {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn render_notarization_summary_markdown_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
) -> String {
    format!(
        concat!(
            "## Token Notarization Summary\n",
            "- Summary Version: {}\n",
            "- Record Version: {}\n",
            "- Proof Statement Type: {}\n",
            "- Proof Statement Label: {}\n",
            "- Ack Digest: {}\n",
            "- Seal Payload Digest: {}\n",
            "- UDOT Seed Digest: {}\n",
            "- Notarization Record Digest: {}\n",
        ),
        summary.summary_version,
        summary.record_version,
        summary.proof_statement_type,
        summary.proof_statement_label,
        summary.ack_digest_hex,
        summary.seal_payload_digest_hex,
        summary.udot_seed_digest_hex,
        summary.notarization_record_digest_hex,
    )
}

pub fn render_notarization_summary_html_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
) -> String {
    format!(
        concat!(
            "<section data-kind=\"token-notarization-summary-v1\">",
            "<h2>Token Notarization Summary</h2>",
            "<dl>",
            "<dt>Summary Version</dt><dd>{}</dd>",
            "<dt>Record Version</dt><dd>{}</dd>",
            "<dt>Proof Statement Type</dt><dd>{}</dd>",
            "<dt>Proof Statement Label</dt><dd>{}</dd>",
            "<dt>Ack Digest</dt><dd>{}</dd>",
            "<dt>Seal Payload Digest</dt><dd>{}</dd>",
            "<dt>UDOT Seed Digest</dt><dd>{}</dd>",
            "<dt>Notarization Record Digest</dt><dd>{}</dd>",
            "</dl>",
            "</section>",
        ),
        summary.summary_version,
        summary.record_version,
        summary.proof_statement_type,
        escape_html_v1(&summary.proof_statement_label),
        escape_html_v1(&summary.ack_digest_hex),
        escape_html_v1(&summary.seal_payload_digest_hex),
        escape_html_v1(&summary.udot_seed_digest_hex),
        escape_html_v1(&summary.notarization_record_digest_hex),
    )
}

pub fn render_notarization_summary_fragment_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
    format: NotarizationRenderFormatV1,
) -> String {
    match format {
        NotarizationRenderFormatV1::Markdown => render_notarization_summary_markdown_v1(summary),
        NotarizationRenderFormatV1::Html => render_notarization_summary_html_v1(summary),
    }
}

pub fn write_notarization_summary_fragment_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
    format: NotarizationRenderFormatV1,
    output_path: impl AsRef<Path>,
) -> Result<(), AuraNotarizationRenderErrorV1> {
    let rendered = render_notarization_summary_fragment_v1(summary, format);
    fs::write(output_path, rendered.as_bytes())?;
    Ok(())
}

pub fn write_notarization_summary_receipt_bundle_v1(
    summary: &CanonicalTokenTransactionNotarizationSummaryV1,
    base_output_path: impl AsRef<Path>,
) -> Result<NotarizationReceiptBundlePathsV1, AuraNotarizationRenderErrorV1> {
    let base = base_output_path.as_ref().to_string_lossy();
    let markdown_path = PathBuf::from(format!("{base}.md"));
    let html_path = PathBuf::from(format!("{base}.html"));

    write_notarization_summary_fragment_v1(
        summary,
        NotarizationRenderFormatV1::Markdown,
        &markdown_path,
    )?;
    write_notarization_summary_fragment_v1(summary, NotarizationRenderFormatV1::Html, &html_path)?;

    Ok(NotarizationReceiptBundlePathsV1 {
        markdown_path,
        html_path,
    })
}

fn escape_html_v1(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(ch),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        render_notarization_summary_fragment_v1, render_notarization_summary_html_v1,
        render_notarization_summary_markdown_v1, write_notarization_summary_fragment_v1,
        write_notarization_summary_receipt_bundle_v1, AuraNotarizationRenderErrorV1,
        CanonicalTokenTransactionNotarizationSummaryV1, NotarizationReceiptBundlePathsV1,
        NotarizationRenderFormatV1,
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

    fn temp_output_path(label: &str, extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aura_notarization_render_{}_{}_{}.{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed),
            label,
            extension
        ))
    }

    #[test]
    fn markdown_rendering_is_deterministic_for_canonical_summary_input() {
        let summary = sample_summary();
        let first = render_notarization_summary_markdown_v1(&summary);
        let second = render_notarization_summary_markdown_v1(&summary);

        assert_eq!(first, second);
        assert_eq!(
            first,
            format!(
                concat!(
                    "## Token Notarization Summary\n",
                    "- Summary Version: 1\n",
                    "- Record Version: 1\n",
                    "- Proof Statement Type: 1\n",
                    "- Proof Statement Label: private_transfer_burn_v1\n",
                    "- Ack Digest: {}\n",
                    "- Seal Payload Digest: {}\n",
                    "- UDOT Seed Digest: {}\n",
                    "- Notarization Record Digest: {}\n",
                ),
                summary.ack_digest_hex,
                summary.seal_payload_digest_hex,
                summary.udot_seed_digest_hex,
                summary.notarization_record_digest_hex,
            )
        );
    }

    #[test]
    fn html_rendering_is_deterministic_for_canonical_summary_input() {
        let summary = sample_summary();
        let first = render_notarization_summary_html_v1(&summary);
        let second = render_notarization_summary_html_v1(&summary);

        assert_eq!(first, second);
        assert_eq!(
            first,
            format!(
                concat!(
                    "<section data-kind=\"token-notarization-summary-v1\">",
                    "<h2>Token Notarization Summary</h2>",
                    "<dl>",
                    "<dt>Summary Version</dt><dd>1</dd>",
                    "<dt>Record Version</dt><dd>1</dd>",
                    "<dt>Proof Statement Type</dt><dd>1</dd>",
                    "<dt>Proof Statement Label</dt><dd>private_transfer_burn_v1</dd>",
                    "<dt>Ack Digest</dt><dd>{}</dd>",
                    "<dt>Seal Payload Digest</dt><dd>{}</dd>",
                    "<dt>UDOT Seed Digest</dt><dd>{}</dd>",
                    "<dt>Notarization Record Digest</dt><dd>{}</dd>",
                    "</dl>",
                    "</section>",
                ),
                summary.ack_digest_hex,
                summary.seal_payload_digest_hex,
                summary.udot_seed_digest_hex,
                summary.notarization_record_digest_hex,
            )
        );
    }

    #[test]
    fn rendered_outputs_contain_frozen_fields_in_expected_order() {
        let summary = sample_summary();
        let markdown = render_notarization_summary_markdown_v1(&summary);
        let html = render_notarization_summary_html_v1(&summary);

        let markdown_positions = [
            markdown.find("Summary Version").unwrap(),
            markdown.find("Record Version").unwrap(),
            markdown.find("Proof Statement Type").unwrap(),
            markdown.find("Proof Statement Label").unwrap(),
            markdown.find("Ack Digest").unwrap(),
            markdown.find("Seal Payload Digest").unwrap(),
            markdown.find("UDOT Seed Digest").unwrap(),
            markdown.find("Notarization Record Digest").unwrap(),
        ];
        assert!(markdown_positions.windows(2).all(|pair| pair[0] < pair[1]));

        let html_positions = [
            html.find("<dt>Summary Version</dt>").unwrap(),
            html.find("<dt>Record Version</dt>").unwrap(),
            html.find("<dt>Proof Statement Type</dt>").unwrap(),
            html.find("<dt>Proof Statement Label</dt>").unwrap(),
            html.find("<dt>Ack Digest</dt>").unwrap(),
            html.find("<dt>Seal Payload Digest</dt>").unwrap(),
            html.find("<dt>UDOT Seed Digest</dt>").unwrap(),
            html.find("<dt>Notarization Record Digest</dt>").unwrap(),
        ];
        assert!(html_positions.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn rendering_uses_only_carried_summary_fields_without_recomputation() {
        let summary = CanonicalTokenTransactionNotarizationSummaryV1 {
            summary_version: 99,
            record_version: 77,
            proof_statement_type: 42,
            proof_statement_label: "custom_label".to_owned(),
            ack_digest_hex: "aa".repeat(32),
            seal_payload_digest_hex: "bb".repeat(32),
            udot_seed_digest_hex: "cc".repeat(32),
            notarization_record_digest_hex: "dd".repeat(32),
        };

        let markdown = render_notarization_summary_markdown_v1(&summary);
        let html = render_notarization_summary_html_v1(&summary);

        assert!(markdown.contains("Summary Version: 99"));
        assert!(markdown.contains("Record Version: 77"));
        assert!(markdown.contains("Proof Statement Type: 42"));
        assert!(markdown.contains("Proof Statement Label: custom_label"));
        assert!(html.contains("<dd>99</dd>"));
        assert!(html.contains("<dd>77</dd>"));
        assert!(html.contains("<dd>42</dd>"));
        assert!(html.contains("<dd>custom_label</dd>"));
    }

    #[test]
    fn writing_markdown_produces_exact_frozen_renderer_output() {
        let summary = sample_summary();
        let output_path = temp_output_path("markdown", "md");

        write_notarization_summary_fragment_v1(
            &summary,
            NotarizationRenderFormatV1::Markdown,
            &output_path,
        )
        .unwrap();

        let written = fs::read_to_string(&output_path).unwrap();
        assert_eq!(written, render_notarization_summary_markdown_v1(&summary));
    }

    #[test]
    fn writing_html_produces_exact_frozen_renderer_output() {
        let summary = sample_summary();
        let output_path = temp_output_path("html", "html");

        write_notarization_summary_fragment_v1(
            &summary,
            NotarizationRenderFormatV1::Html,
            &output_path,
        )
        .unwrap();

        let written = fs::read_to_string(&output_path).unwrap();
        assert_eq!(written, render_notarization_summary_html_v1(&summary));
    }

    #[test]
    fn file_writing_is_deterministic_for_identical_inputs() {
        let summary = sample_summary();
        let first_path = temp_output_path("first", "md");
        let second_path = temp_output_path("second", "md");

        write_notarization_summary_fragment_v1(
            &summary,
            NotarizationRenderFormatV1::Markdown,
            &first_path,
        )
        .unwrap();
        write_notarization_summary_fragment_v1(
            &summary,
            NotarizationRenderFormatV1::Markdown,
            &second_path,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(&first_path).unwrap(),
            fs::read_to_string(&second_path).unwrap()
        );
        assert_eq!(
            render_notarization_summary_fragment_v1(&summary, NotarizationRenderFormatV1::Markdown),
            fs::read_to_string(&first_path).unwrap()
        );
    }

    #[test]
    fn file_writing_errors_are_surfaced_cleanly() {
        let summary = sample_summary();
        let missing_parent = std::env::temp_dir()
            .join(format!(
                "aura_notarization_render_missing_{}",
                TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
            .join("receipt.md");

        let error = write_notarization_summary_fragment_v1(
            &summary,
            NotarizationRenderFormatV1::Markdown,
            &missing_parent,
        )
        .unwrap_err();

        match error {
            AuraNotarizationRenderErrorV1::Io(_) => {}
        }
    }

    #[test]
    fn bundle_helper_writes_exactly_two_files_with_frozen_suffixes() {
        let summary = sample_summary();
        let base_path = temp_output_path("bundle", "receipt");

        let paths = write_notarization_summary_receipt_bundle_v1(&summary, &base_path).unwrap();

        assert_eq!(
            paths,
            NotarizationReceiptBundlePathsV1 {
                markdown_path: PathBuf::from(format!("{}.md", base_path.to_string_lossy())),
                html_path: PathBuf::from(format!("{}.html", base_path.to_string_lossy())),
            }
        );
        assert!(paths.markdown_path.exists());
        assert!(paths.html_path.exists());
    }

    #[test]
    fn bundle_helper_writes_exact_frozen_markdown_and_html_outputs() {
        let summary = sample_summary();
        let base_path = temp_output_path("bundle_exact", "receipt");

        let paths = write_notarization_summary_receipt_bundle_v1(&summary, &base_path).unwrap();

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
    fn bundle_helper_is_deterministic_for_identical_inputs() {
        let summary = sample_summary();
        let first_base = temp_output_path("bundle_first", "stem");
        let second_base = temp_output_path("bundle_second", "stem");

        let first_paths =
            write_notarization_summary_receipt_bundle_v1(&summary, &first_base).unwrap();
        let second_paths =
            write_notarization_summary_receipt_bundle_v1(&summary, &second_base).unwrap();

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
    fn bundle_helper_surfaces_file_writing_failures_cleanly() {
        let summary = sample_summary();
        let missing_parent = std::env::temp_dir()
            .join(format!(
                "aura_notarization_bundle_missing_{}",
                TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
            .join("receipt");

        let error =
            write_notarization_summary_receipt_bundle_v1(&summary, &missing_parent).unwrap_err();

        match error {
            AuraNotarizationRenderErrorV1::Io(_) => {}
        }
    }
}
