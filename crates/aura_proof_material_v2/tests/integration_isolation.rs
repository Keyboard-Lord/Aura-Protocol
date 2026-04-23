use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_V2_SURFACE_MARKERS: &[&str] = &[
    "aura_proof_material_v2",
    "ProofMaterialV2",
    "CanonicalVerifierBundleV2",
    "CANONICAL_VERIFIER_BUNDLE_V2",
    "AURA_PROOF_MATERIAL_V2",
];

const FROZEN_V1_MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "crates/aura_proof_material_v1/Cargo.toml",
    "crates/aura_fractal_key_v1/Cargo.toml",
    "crates/aura_fractal_key_integration_v1/Cargo.toml",
    "crates/aura_sdk_v1/Cargo.toml",
    "crates/aura_cli_v1/Cargo.toml",
    "crates/aura_submission_client_v1/Cargo.toml",
    "crates/aura_reference_demo_v1/Cargo.toml",
];

const FROZEN_V1_TYPESCRIPT_FILES: &[&str] = &[
    "packages/aura_sdk_v1_ts/package.json",
    "packages/aura_sdk_v1_ts/README.md",
    "packages/aura_submission_client_v1_ts/package.json",
    "packages/aura_submission_client_v1_ts/README.md",
];

const FROZEN_V1_RUST_DIRS: &[&str] = &[
    "src",
    "tests",
    "crates/aura_proof_material_v1/src",
    "crates/aura_proof_material_v1/tests",
    "crates/aura_fractal_key_v1/src",
    "crates/aura_fractal_key_v1/tests",
    "crates/aura_fractal_key_integration_v1/src",
    "crates/aura_fractal_key_integration_v1/tests",
    "crates/aura_sdk_v1/src",
    "crates/aura_sdk_v1/tests",
    "crates/aura_cli_v1/src",
    "crates/aura_cli_v1/tests",
    "crates/aura_submission_client_v1/src",
    "crates/aura_submission_client_v1/tests",
    "crates/aura_reference_demo_v1/src",
    "crates/aura_reference_demo_v1/tests",
];

const FROZEN_V1_TYPESCRIPT_DIRS: &[&str] = &[
    "packages/aura_sdk_v1_ts/src",
    "packages/aura_sdk_v1_ts/tests",
    "packages/aura_submission_client_v1_ts/src",
    "packages/aura_submission_client_v1_ts/tests",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("aura_proof_material_v2 should live under crates/ in the Aura repo")
        .to_path_buf()
}

fn gather_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", dir.display()));

    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "failed to read directory entry in {}: {error}",
                dir.display()
            )
        });
        let path = entry.path();

        if path.is_dir() {
            gather_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn gather_typescript_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", dir.display()));

    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "failed to read directory entry in {}: {error}",
                dir.display()
            )
        });
        let path = entry.path();

        if path.is_dir() {
            gather_typescript_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "ts") {
            files.push(path);
        }
    }
}

fn assert_no_forbidden_v2_markers(source: &str, surface_path: &Path) {
    for marker in FORBIDDEN_V2_SURFACE_MARKERS {
        assert!(
            !source.contains(marker),
            "frozen v1 surface {} unexpectedly references v2 marker {}",
            surface_path.display(),
            marker
        );
    }
}

#[test]
fn frozen_v1_rust_manifests_do_not_reference_proof_material_v2_owner_path() {
    let repo_root = repo_root();

    for relative_path in FROZEN_V1_MANIFESTS {
        let manifest_path = repo_root.join(relative_path);
        let manifest = fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
            panic!(
                "failed to read manifest {}: {error}",
                manifest_path.display()
            )
        });

        assert_no_forbidden_v2_markers(&manifest, &manifest_path);
    }
}

#[test]
fn frozen_v1_rust_surfaces_do_not_reference_proof_material_v2_owner_path() {
    let repo_root = repo_root();
    let mut rust_files = Vec::new();

    for relative_dir in FROZEN_V1_RUST_DIRS {
        let dir_path = repo_root.join(relative_dir);
        if dir_path.exists() {
            gather_rust_files(&dir_path, &mut rust_files);
        }
    }

    rust_files.sort();

    for rust_file in rust_files {
        if rust_file.ends_with("tests/repository_hardening.rs") {
            continue;
        }
        let source = fs::read_to_string(&rust_file).unwrap_or_else(|error| {
            panic!(
                "failed to read Rust source {}: {error}",
                rust_file.display()
            )
        });

        assert_no_forbidden_v2_markers(&source, &rust_file);
    }
}

#[test]
fn frozen_v1_typescript_surfaces_do_not_reference_proof_material_v2_owner_path() {
    let repo_root = repo_root();
    let mut typescript_files = Vec::new();

    for relative_path in FROZEN_V1_TYPESCRIPT_FILES {
        typescript_files.push(repo_root.join(relative_path));
    }

    for relative_dir in FROZEN_V1_TYPESCRIPT_DIRS {
        let dir_path = repo_root.join(relative_dir);
        if dir_path.exists() {
            gather_typescript_files(&dir_path, &mut typescript_files);
        }
    }

    typescript_files.sort();

    for typescript_file in typescript_files {
        let source = fs::read_to_string(&typescript_file).unwrap_or_else(|error| {
            panic!(
                "failed to read TypeScript/package surface {}: {error}",
                typescript_file.display()
            )
        });

        assert_no_forbidden_v2_markers(&source, &typescript_file);
    }
}
