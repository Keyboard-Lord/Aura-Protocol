use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn read(relative: &str) -> String {
    fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn collect_top_level_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", root.display()))
    {
        let path = entry
            .unwrap_or_else(|error| {
                panic!("failed to read entry under {}: {error}", root.display())
            })
            .path();
        if path.is_file() {
            files.push(path);
        }
    }
    files
}

fn collect_doc_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", root.display()))
    {
        let path = entry
            .unwrap_or_else(|error| {
                panic!("failed to read entry under {}: {error}", root.display())
            })
            .path();
        if path.is_dir() {
            files.extend(collect_doc_files(&path));
            continue;
        }
        let is_doc = matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("md" | "json" | "pdf")
        );
        if is_doc {
            files.push(path);
        }
    }
    files
}

fn relative_string(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or_else(|error| panic!("failed to strip repo prefix from {}: {error}", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
}

fn expected_authoritative_docs() -> BTreeSet<String> {
    [
        "docs/authoritative/AURA_ARTIFACT_STRUCTURE_V1.md",
        "docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md",
        "docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md",
        "docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md",
        "docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md",
        "docs/authoritative/AURA_DERIVATION_FUNCTIONS_V1.md",
        "docs/authoritative/AURA_FAILURE_CLASSES_V1.md",
        "docs/authoritative/AURA_FIELD_ARITHMETIC_V1.md",
        "docs/authoritative/AURA_HARDENING_LOG_V1.md",
        "docs/authoritative/AURA_HASH_V1.md",
        "docs/authoritative/AURA_INVARIANTS_V1.md",
        "docs/authoritative/AURA_LEDGER_AND_BURN_V1.md",
        "docs/authoritative/AURA_PROVER_BINDING_V1.md",
        "docs/authoritative/AURA_REPORT_CONTRACT_V1.md",
        "docs/authoritative/AURA_STARK_SPEC_V1.md",
        "docs/authoritative/AURA_STORM_RECURSION_V1_1.md",
        "docs/authoritative/AURA_TRACE_COMMITMENT_V1.md",
        "docs/authoritative/AURA_TRACE_LAYOUT_V1.md",
        "docs/authoritative/AURA_UDOT_SPEC_V1.md",
        "docs/authoritative/AURA_VECTOR_MATRIX_V1.md",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn workspace_manifest_still_pins_root_verifiers() {
    let manifest = read("Cargo.toml");
    assert!(
        manifest.contains("canonical_repo_verifier = \"scripts/verify_repo_truth.sh\""),
        "workspace metadata must pin the repository verifier"
    );
    assert!(
        manifest.contains("canonical_active_verifier = \"scripts/verify_active_foundation.sh\""),
        "workspace metadata must pin the active verifier"
    );
}

#[test]
fn docs_root_is_compressed_to_exactly_twenty_canonical_documents() {
    assert!(repo_path("docs/authoritative").is_dir(), "docs/authoritative must exist");

    let expected = expected_authoritative_docs();
    let actual: BTreeSet<String> = collect_top_level_files(&repo_path("docs/authoritative"))
        .into_iter()
        .map(|path| relative_string(&path))
        .collect();

    assert_eq!(actual.len(), 20, "docs/authoritative must contain exactly 20 files");
    assert_eq!(actual, expected, "docs/authoritative must match the locked 20-file set");

    let all_docs: BTreeSet<String> = collect_doc_files(&repo_path("docs"))
        .into_iter()
        .map(|path| relative_string(&path))
        .collect();
    assert_eq!(
        all_docs, expected,
        "no markdown/json/pdf files may remain under docs outside the canonical 20-file set"
    );
}

#[test]
fn source_of_truth_locks_the_compressed_authority_order() {
    let source = read("docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md");
    for required in [
        "There is exactly one canonical pipeline.",
        "The canonical documentation set is exactly the 20 files under `docs/authoritative/`.",
        "AURA_HASH_V1.md",
        "AURA_STORM_RECURSION_V1_1.md",
        "AURA_CANONICAL_PIPELINE_V1.md",
        "AURA_REPORT_CONTRACT_V1.md",
        "AURA_HARDENING_LOG_V1.md",
        "No file outside `docs/authoritative/` defines:",
    ] {
        assert!(
            source.contains(required),
            "source of truth must contain {required:?}"
        );
    }
}

#[test]
fn compressed_authoritative_docs_are_machine_path_free() {
    for relative in [
        "README.md",
        "docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md",
        "docs/authoritative/AURA_HASH_V1.md",
        "docs/authoritative/AURA_STORM_RECURSION_V1_1.md",
        "docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md",
        "docs/authoritative/AURA_REPORT_CONTRACT_V1.md",
        "docs/authoritative/AURA_HARDENING_LOG_V1.md",
    ] {
        let text = read(relative);
        assert!(
            !text.contains("/Users/"),
            "{relative} must not encode a machine-specific path"
        );
    }
}

#[test]
fn readme_points_to_the_compressed_entrypoint() {
    let readme = read("README.md");
    assert!(
        readme.contains("docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md"),
        "README must point to the source-of-truth entrypoint"
    );
    assert!(
        readme.contains("There is exactly one canonical pipeline."),
        "README must state the single-pipeline rule"
    );
    assert!(
        readme.contains("The canonical documentation set is exactly the 20 files under `docs/authoritative/`."),
        "README must state the compressed 20-document rule"
    );
    assert!(
        !readme.contains("docs/implementation"),
        "README must not refer to deleted taxonomy docs"
    );
}

#[test]
fn storm_validation_script_tracks_the_compressed_docs() {
    let script = read("scripts/validate_storm_hash_quantum_hardening_v1.sh");
    assert!(
        script.contains("docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md"),
        "validation script must point to the compressed source-of-truth document"
    );
    assert!(
        script.contains("docs/authoritative/AURA_HARDENING_LOG_V1.md"),
        "validation script must point to the hardening log"
    );
    assert!(
        script.contains("docs/authoritative/AURA_HASH_V1.md"),
        "validation script must point to the compressed hash spec"
    );
}
