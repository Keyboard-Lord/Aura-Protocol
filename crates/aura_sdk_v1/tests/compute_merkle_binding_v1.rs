//! C3 guest specialization must agree with the unchanged C1 content owner.
use aura_sdk_v1::compute_job::{compute_content_commitment_v1, ComputeContentKindV1};
fn decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn c3_candidate_vectors_use_the_existing_c1_input_commitment() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../workloads/merkle_risc0_v1/vectors/batch-v1.json"
    ))
    .unwrap();
    for x in v["cases"].as_array().unwrap() {
        let input = decode(x["input_hex"].as_str().unwrap());
        let expected = decode(x["input_commitment_hex"].as_str().unwrap());
        assert_eq!(
            compute_content_commitment_v1(ComputeContentKindV1::Input, &input)
                .unwrap()
                .as_slice(),
            expected
        );
    }
}
