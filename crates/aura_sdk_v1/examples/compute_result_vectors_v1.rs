#[path = "../tests/support/compute_result_vectors.rs"]
mod support;
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&support::snapshot()).unwrap()
    );
}
