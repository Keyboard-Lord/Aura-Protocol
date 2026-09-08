use aura_bitcoin_v1::{validate_anchor_outputs_v1, BitcoinAnchorRequestV1, BitcoinOutputV1};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/bitcoin_v1/anchor_vectors_v1.json"
    ))
    .unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn sample() -> BitcoinAnchorRequestV1 {
    serde_json::from_value(fixture()["vectors"][3]["request"].clone()).unwrap()
}
fn output(request: &BitcoinAnchorRequestV1) -> BitcoinOutputV1 {
    BitcoinOutputV1 {
        value_sat: 0,
        script_pubkey: request.script_pubkey().to_vec(),
    }
}

#[test]
fn shared_vectors_round_trip_without_changing_proof_reference() {
    for vector in fixture()["vectors"].as_array().unwrap() {
        let request: BitcoinAnchorRequestV1 =
            serde_json::from_value(vector["request"].clone()).unwrap();
        let script = bytes(vector["script_hex"].as_str().unwrap());
        assert_eq!(request.script_pubkey().as_slice(), script);
        assert_eq!(
            BitcoinAnchorRequestV1::from_script(&script).unwrap(),
            request
        );
        assert_eq!(serde_json::to_value(&request).unwrap(), vector["request"]);
        assert_eq!(
            request.proof_hash_hex(),
            vector["request"]["proof_hash_hex"].as_str().unwrap()
        );
    }
}

#[test]
fn shared_malformed_requests_and_scripts_are_rejected() {
    for request in fixture()["invalid_requests"].as_array().unwrap() {
        assert!(
            serde_json::from_value::<BitcoinAnchorRequestV1>(request.clone()).is_err(),
            "{request}"
        );
    }
    for script in fixture()["invalid_scripts"].as_array().unwrap() {
        assert!(BitcoinAnchorRequestV1::from_script(&bytes(script.as_str().unwrap())).is_err());
    }
}

#[test]
fn validates_exactly_one_zero_value_matching_anchor_among_change_outputs() {
    let request = sample();
    let change = BitcoinOutputV1 {
        value_sat: 1000,
        script_pubkey: vec![0x51],
    };
    assert_eq!(
        validate_anchor_outputs_v1(&[change.clone(), output(&request)], &request).unwrap(),
        1
    );
    assert!(validate_anchor_outputs_v1(&[change], &request).is_err());
    assert!(validate_anchor_outputs_v1(&[output(&request), output(&request)], &request).is_err());
    let mut nonzero = output(&request);
    nonzero.value_sat = 1;
    assert!(validate_anchor_outputs_v1(&[nonzero], &request).is_err());
    for vector in fixture()["vectors"].as_array().unwrap() {
        let other: BitcoinAnchorRequestV1 =
            serde_json::from_value(vector["request"].clone()).unwrap();
        if other.network() != request.network() {
            assert!(validate_anchor_outputs_v1(&[output(&other)], &request).is_err());
        }
    }
    let wrong_hash = BitcoinAnchorRequestV1::new(request.network(), "ff".repeat(32)).unwrap();
    assert!(validate_anchor_outputs_v1(&[output(&wrong_hash)], &request).is_err());
}

#[test]
fn rejects_nonminimal_or_malformed_second_aura_output() {
    let request = sample();
    for prefix in [
        vec![0x6a, 0x4c, 38],
        vec![0x6a, 0x4d, 38, 0],
        vec![0x6a, 0x4e, 38, 0, 0, 0],
    ] {
        let mut script = prefix;
        script.extend_from_slice(&request.script_pubkey()[2..]);
        let bad = BitcoinOutputV1 {
            value_sat: 0,
            script_pubkey: script,
        };
        assert!(validate_anchor_outputs_v1(&[bad.clone()], &request).is_err());
        assert!(validate_anchor_outputs_v1(&[output(&request), bad.clone()], &request).is_err());
        assert!(validate_anchor_outputs_v1(&[bad, output(&request)], &request).is_err());
    }
}
