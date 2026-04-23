use serde::de::DeserializeOwned;
use std::{fs, path::PathBuf};

pub fn load_canonical_pipeline_fixture_text_v1(name: &str) -> String {
    fs::read_to_string(fixture_path_v1(name))
        .unwrap_or_else(|error| panic!("failed to read canonical pipeline fixture {name}: {error}"))
        .trim_end()
        .to_owned()
}

pub fn load_canonical_pipeline_fixture_json_v1<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_str(&load_canonical_pipeline_fixture_text_v1(name)).unwrap_or_else(|error| {
        panic!("failed to parse canonical pipeline fixture {name}: {error}")
    })
}

fn fixture_path_v1(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("canonical_pipeline_v1")
        .join(name)
}
