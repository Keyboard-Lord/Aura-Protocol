//! Explicit test-vector producer; never run by tests to rewrite expected results.
#[path = "../tests/support/compute_job_vectors.rs"]
mod support;
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&if std::env::args().any(|a| a == "--core-policies") {
            support::core_policy_snapshot()
        } else {
            support::snapshot()
        })
        .unwrap()
    );
}
