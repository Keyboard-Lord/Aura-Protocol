use std::{fs, path::PathBuf};

use aura_intent_lineage_v1::{
    aura_hash521_v1, build_storm_claim_v1, build_storm_public_inputs_v1,
    compute_storm_trace_root, derive_a, derive_b, derive_phi_n, derive_psi_n, derive_x0,
    derive_y0, execute_storm_v1, FieldElement521V1, StormExecutionInputsV1, StormState521V1,
    STORM_CONTEXT_V1_LEN, STORM_SIDE_INPUT_LEN_V1,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct StormParityFixtureV1 {
    contract: String,
    fixture_name: String,
    aura_hash521_v1_message_hex: String,
    side_a_hex: String,
    side_b_hex: String,
    context_bytes_v1_hex: String,
    iteration_count: u64,
    expected: StormParityExpectedV1,
}

#[derive(Deserialize)]
struct StormParityExpectedV1 {
    aura_hash521_v1_hex: String,
    x0_hex: String,
    y0_hex: String,
    a_hex: String,
    b_hex: String,
    phi_0_hex: String,
    psi_0_hex: String,
    phi_last_hex: String,
    psi_last_hex: String,
    initial_state: StormParityStateFixtureV1,
    initial_row_hex: String,
    final_state: StormParityStateFixtureV1,
    final_row_hex: String,
    trace_root_hex: String,
    claim_trace_root_hex: String,
    storm_claim_wire: StormClaimWireFixtureV1,
    public_inputs: StormPublicInputsFixtureV1,
}

#[derive(Deserialize)]
struct StormParityStateFixtureV1 {
    x_hex: String,
    y_hex: String,
}

#[derive(Deserialize)]
struct StormClaimWireFixtureV1 {
    version: u8,
    modulus_id: u8,
    iteration_count: u64,
    side_a_hex: String,
    side_b_hex: String,
    context_bytes_hex: String,
    initial_state: StormStateWireFixtureV1,
    final_state: StormStateWireFixtureV1,
    trace_root_hex: String,
    legacy_commitment_root_hex: String,
    legacy_trace_commitment_hex: String,
}

#[derive(Deserialize)]
struct StormPublicInputsFixtureV1 {
    version: u8,
    modulus_id: u8,
    iteration_count: u64,
    side_a_hash_hex: String,
    side_b_hash_hex: String,
    context_hash_hex: String,
    initial_state: StormStateWireFixtureV1,
    final_state: StormStateWireFixtureV1,
    trace_root_hex: String,
}

#[derive(Deserialize)]
struct StormStateWireFixtureV1 {
    x_hex_66_be: String,
    y_hex_66_be: String,
}

#[test]
fn rust_matches_the_shared_storm_execution_parity_vector() {
    let fixture = load_fixture();
    assert_eq!(fixture.contract, "AURA_STORM_EXECUTION_PARITY_VECTOR_V1");
    assert_eq!(fixture.fixture_name, "storm_execution_parity_vector_v1");

    let side_a = decode_fixed_hex::<STORM_SIDE_INPUT_LEN_V1>(&fixture.side_a_hex);
    let side_b = decode_fixed_hex::<STORM_SIDE_INPUT_LEN_V1>(&fixture.side_b_hex);
    let context_bytes_v1 = decode_fixed_hex::<STORM_CONTEXT_V1_LEN>(&fixture.context_bytes_v1_hex);
    let inputs = StormExecutionInputsV1 {
        side_a,
        side_b,
        context_bytes_v1,
        iteration_count: fixture.iteration_count,
    };

    let execution = execute_storm_v1(&inputs);
    let claim = build_storm_claim_v1(&inputs, [0u8; 32], [0u8; 32]);
    let public_inputs = build_storm_public_inputs_v1(&claim);

    assert_eq!(
        encode_field_hex(aura_hash521_v1(&decode_hex(&fixture.aura_hash521_v1_message_hex))),
        fixture.expected.aura_hash521_v1_hex
    );
    assert_eq!(encode_field_hex(derive_x0(&inputs.side_a)), fixture.expected.x0_hex);
    assert_eq!(encode_field_hex(derive_y0(&inputs.side_b)), fixture.expected.y0_hex);
    assert_eq!(encode_field_hex(derive_a(&inputs.context_bytes_v1)), fixture.expected.a_hex);
    assert_eq!(encode_field_hex(derive_b(&inputs.context_bytes_v1)), fixture.expected.b_hex);
    assert_eq!(
        encode_field_hex(derive_phi_n(
            &inputs.side_a,
            &inputs.side_b,
            &inputs.context_bytes_v1,
            0
        )),
        fixture.expected.phi_0_hex
    );
    assert_eq!(
        encode_field_hex(derive_psi_n(
            &inputs.side_a,
            &inputs.side_b,
            &inputs.context_bytes_v1,
            0
        )),
        fixture.expected.psi_0_hex
    );
    assert_eq!(
        encode_field_hex(derive_phi_n(
            &inputs.side_a,
            &inputs.side_b,
            &inputs.context_bytes_v1,
            fixture.iteration_count - 1
        )),
        fixture.expected.phi_last_hex
    );
    assert_eq!(
        encode_field_hex(derive_psi_n(
            &inputs.side_a,
            &inputs.side_b,
            &inputs.context_bytes_v1,
            fixture.iteration_count - 1
        )),
        fixture.expected.psi_last_hex
    );
    assert_eq!(
        encode_state_hex(execution.initial_state),
        (
            fixture.expected.initial_state.x_hex,
            fixture.expected.initial_state.y_hex
        )
    );
    assert_eq!(
        encode_hex(execution.initial_state.encode_row_bytes()),
        fixture.expected.initial_row_hex
    );
    assert_eq!(
        encode_state_hex(execution.final_state),
        (
            fixture.expected.final_state.x_hex,
            fixture.expected.final_state.y_hex
        )
    );
    assert_eq!(
        encode_hex(execution.final_state.encode_row_bytes()),
        fixture.expected.final_row_hex
    );
    assert_eq!(
        encode_hex32(&compute_storm_trace_root(&execution.trace)),
        fixture.expected.trace_root_hex
    );
    assert_eq!(
        encode_hex32(&claim.trace_root),
        fixture.expected.claim_trace_root_hex
    );
    assert_claim_wire_matches(&claim, &fixture.expected.storm_claim_wire);
    assert_public_inputs_match(&public_inputs, &fixture.expected.public_inputs);
}

fn load_fixture() -> StormParityFixtureV1 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn decode_fixed_hex<const N: usize>(hex: &str) -> [u8; N] {
    let decoded = decode_hex(hex);
    assert_eq!(decoded.len(), N);
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(&decoded);
    bytes
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    let mut output = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).unwrap();
        output.push(u8::from_str_radix(pair, 16).unwrap());
    }
    output
}

fn encode_field_hex(value: FieldElement521V1) -> String {
    encode_hex(value.to_bytes())
}

fn encode_state_hex(state: StormState521V1) -> (String, String) {
    (encode_field_hex(state.x), encode_field_hex(state.y))
}

fn encode_state_wire_hex(state: StormState521V1) -> (String, String) {
    (encode_field_hex(state.x), encode_field_hex(state.y))
}

fn encode_hex<T: AsRef<[u8]>>(bytes: T) -> String {
    bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_claim_wire_matches(
    claim: &aura_intent_lineage_v1::StormClaim521V1,
    fixture: &StormClaimWireFixtureV1,
) {
    assert_eq!(claim.version, fixture.version);
    assert_eq!(claim.modulus_id, fixture.modulus_id);
    assert_eq!(claim.iteration_count, fixture.iteration_count);
    assert_eq!(encode_hex(claim.side_a), fixture.side_a_hex);
    assert_eq!(encode_hex(claim.side_b), fixture.side_b_hex);
    assert_eq!(encode_hex(claim.context_bytes_v1), fixture.context_bytes_hex);
    assert_eq!(
        encode_state_wire_hex(claim.initial_state),
        (
            fixture.initial_state.x_hex_66_be.clone(),
            fixture.initial_state.y_hex_66_be.clone()
        )
    );
    assert_eq!(
        encode_state_wire_hex(claim.final_state),
        (
            fixture.final_state.x_hex_66_be.clone(),
            fixture.final_state.y_hex_66_be.clone()
        )
    );
    assert_eq!(encode_hex32(&claim.trace_root), fixture.trace_root_hex);
    assert_eq!(
        encode_hex32(&claim.legacy_commitment_root),
        fixture.legacy_commitment_root_hex
    );
    assert_eq!(
        encode_hex32(&claim.legacy_trace_commitment),
        fixture.legacy_trace_commitment_hex
    );
}

fn assert_public_inputs_match(
    public_inputs: &aura_intent_lineage_v1::StormPublicInputs521V1,
    fixture: &StormPublicInputsFixtureV1,
) {
    assert_eq!(public_inputs.version, fixture.version);
    assert_eq!(public_inputs.modulus_id, fixture.modulus_id);
    assert_eq!(public_inputs.iteration_count, fixture.iteration_count);
    assert_eq!(encode_hex32(&public_inputs.side_a_hash), fixture.side_a_hash_hex);
    assert_eq!(encode_hex32(&public_inputs.side_b_hash), fixture.side_b_hash_hex);
    assert_eq!(encode_hex32(&public_inputs.context_hash), fixture.context_hash_hex);
    assert_eq!(
        encode_state_wire_hex(public_inputs.initial_state),
        (
            fixture.initial_state.x_hex_66_be.clone(),
            fixture.initial_state.y_hex_66_be.clone()
        )
    );
    assert_eq!(
        encode_state_wire_hex(public_inputs.final_state),
        (
            fixture.final_state.x_hex_66_be.clone(),
            fixture.final_state.y_hex_66_be.clone()
        )
    );
    assert_eq!(encode_hex32(&public_inputs.trace_root), fixture.trace_root_hex);
}
