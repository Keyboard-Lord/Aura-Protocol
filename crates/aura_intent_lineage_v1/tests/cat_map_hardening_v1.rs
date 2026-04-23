// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use aura_intent_lineage_v1::{
    advance_dcm_state_521_v1, advance_dcm_state_v1, build_dcm_claim_521_v1,
    canonical_dcm_air_trace_bytes_v1, coordinate_recurrence_next_521_v1,
    dcm_air_public_inputs_from_claim_521_v1, dcm_cat_map_inverse_matrix_521_v1,
    dcm_cat_map_matrix_521_v1, derive_dcm_air_stark_public_input_digest_v1,
    derive_dcm_layer1_commitments_521_v1, fast_forward_dcm_state_521_v1, fast_forward_dcm_state_v1,
    fast_rewind_dcm_state_521_v1, package_dcm_air_proof_session_v1,
    prove_dcm_air_with_mock_proof_v1, rewind_dcm_state_521_v1, rewind_dcm_state_v1,
    DcmAirMockVerifierBindingsV1, DcmAirPublicInputsV1, DcmAirTraceV1, DcmConfig521V1,
    DcmExecution521V1, DcmInput521V1, DcmMatrix521V1, DcmState521V1, DcmStateV1, FieldElement521V1,
    AURA_DCM_AIR_MOCK_PROOF_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
    AURA_DCM_STARK_TRANSCRIPT_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
    DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1, DCM_STATE_521_CANONICAL_BYTE_LEN_V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
};
use num_bigint::BigUint;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct CatMapTestVectorsFileV1 {
    version: u8,
    primitive: String,
    modulus: ModulusFixtureV1,
    matrix: MatrixFixtureV1,
    encoding: EncodingFixtureV1,
    hashes: HashRulesFixtureV1,
    checkpoints: Vec<String>,
    production_vectors: Vec<ProductionVectorFixtureV1>,
    toy_prime_cycle_suites: Vec<ToyPrimeCycleSuiteFixtureV1>,
}

#[derive(Debug, Deserialize)]
struct ModulusFixtureV1 {
    name: String,
    hex: String,
}

#[derive(Debug, Deserialize)]
struct MatrixFixtureV1 {
    forward: [[i64; 2]; 2],
    inverse: [[i64; 2]; 2],
}

#[derive(Debug, Deserialize)]
struct EncodingFixtureV1 {
    coordinate_encoding: String,
    state_encoding: String,
}

#[derive(Debug, Deserialize)]
struct HashRulesFixtureV1 {
    final_state_hash: String,
    trace_commitment: String,
    commitment_root: String,
}

#[derive(Debug, Deserialize)]
struct ProductionVectorFixtureV1 {
    name: String,
    entropy_hex: String,
    challenge_hex: String,
    initial: FixtureHexStateV1,
    initial_state_encoding_hex: String,
    states: CheckpointStatesFixtureV1,
    final_state_encoding_hex: String,
    final_state_hash: String,
    trace_commitment: String,
    commitment_root: String,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CheckpointStatesFixtureV1 {
    s1: FixtureHexStateV1,
    s2: FixtureHexStateV1,
    s3: FixtureHexStateV1,
    s5: FixtureHexStateV1,
    s8: FixtureHexStateV1,
    s16: FixtureHexStateV1,
    s32: FixtureHexStateV1,
}

#[derive(Debug, Deserialize)]
struct FixtureHexStateV1 {
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
struct ToyPrimeCycleSuiteFixtureV1 {
    p: u64,
    cycle_lengths: Vec<usize>,
    representatives: Vec<[u64; 2]>,
}

#[test]
fn matrix_identity_inverse_and_composition_laws_hold() {
    let matrix = dcm_cat_map_matrix_521_v1();
    let inverse = dcm_cat_map_inverse_matrix_521_v1();
    let identity = DcmMatrix521V1::identity();

    assert_eq!(matrix.determinant(), FieldElement521V1::one());
    assert_eq!(inverse.determinant(), FieldElement521V1::one());
    assert_eq!(matrix.pow(0), identity);
    assert_eq!(matrix.pow(1), matrix);
    assert_eq!(inverse.pow(0), identity);
    assert_eq!(matrix.multiply(&inverse), identity);
    assert_eq!(inverse.multiply(&matrix), identity);

    for &(left, right) in &[
        (0, 0),
        (1, 0),
        (0, 1),
        (2, 3),
        (5, 8),
        (13, 21),
        (32, 16),
        (63, 64),
    ] {
        assert_eq!(
            matrix.pow(left + right),
            matrix.pow(left).multiply(&matrix.pow(right))
        );
    }
}

#[test]
fn one_step_matches_matrix_application_and_inverse_formula() {
    let matrix = dcm_cat_map_matrix_521_v1();
    let inverse = dcm_cat_map_inverse_matrix_521_v1();

    for state in structured_states() {
        let next = advance_dcm_state_521_v1(state);
        assert_eq!(matrix.apply(&state), next);
        assert_eq!(inverse.apply(&next), state);
        assert_eq!(rewind_dcm_state_521_v1(next), state);
    }
}

#[test]
fn step_and_inverse_step_match_explicit_coordinate_formulas() {
    for state in structured_states() {
        let stepped = advance_dcm_state_521_v1(state);
        let rewound = rewind_dcm_state_521_v1(state);

        assert_eq!(
            stepped,
            DcmState521V1 {
                x: state.x.add_mod(&state.y),
                y: state.x.add_mod(&state.y.add_mod(&state.y)),
            }
        );
        assert_eq!(
            rewound,
            DcmState521V1 {
                x: state.x.add_mod(&state.x).sub_mod(&state.y),
                y: state.y.sub_mod(&state.x),
            }
        );
    }
}

#[test]
fn fast_forward_matches_repeated_step_for_structured_and_generated_states() {
    let mut states = structured_states();
    states.extend(deterministic_sampled_states(128));

    for state in states {
        for &step_count in &[0u64, 1, 2, 3, 5, 8, 13, 21, 32] {
            let mut repeated = state;
            for _ in 0..step_count {
                repeated = advance_dcm_state_521_v1(repeated);
            }

            assert_eq!(
                fast_forward_dcm_state_521_v1(state, step_count),
                repeated,
                "state={state} step_count={step_count}"
            );
        }
    }
}

#[test]
fn fast_rewind_cancels_fast_forward_even_for_large_exponents() {
    let mut states = structured_states();
    states.extend(deterministic_sampled_states(128));

    for state in states {
        for &step_count in &[
            0u64,
            1,
            2,
            3,
            5,
            8,
            13,
            21,
            32,
            63,
            256,
            1024,
            1 << 20,
            (1 << 63) + 12345,
        ] {
            let jumped = fast_forward_dcm_state_521_v1(state, step_count);
            assert_eq!(fast_rewind_dcm_state_521_v1(jumped, step_count), state);
            assert_eq!(
                fast_forward_dcm_state_521_v1(
                    fast_rewind_dcm_state_521_v1(state, step_count),
                    step_count
                ),
                state
            );
        }
    }
}

#[test]
fn coordinate_recurrence_holds_for_structured_and_generated_states() {
    let mut states = structured_states();
    states.extend(deterministic_sampled_states(128));

    for initial in states {
        let first = initial;
        let second = advance_dcm_state_521_v1(first);
        let third = advance_dcm_state_521_v1(second);

        assert_eq!(
            coordinate_recurrence_next_521_v1(first.x, second.x),
            third.x
        );
        assert_eq!(
            coordinate_recurrence_next_521_v1(first.y, second.y),
            third.y
        );
    }
}

#[test]
fn seed_byte_reduction_matches_biguint_and_is_deterministic() {
    let reduction_cases = vec![
        Vec::new(),
        vec![0u8],
        vec![1u8],
        vec![0xff; 80],
        vec![0xaa; 80],
        vec![0x55; 80],
        repeat_pattern(&[0xaa, 0x55], 80),
        repeat_pattern(&[0x00, 0xff], 80),
        FIELD_MODULUS_521_V1.to_vec(),
        {
            let mut bytes = FIELD_MODULUS_521_V1.to_vec();
            bytes.push(1);
            bytes
        },
        {
            let mut bytes = FIELD_MODULUS_521_V1.to_vec();
            bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
            bytes
        },
        repeat_pattern(&[0x13, 0x37, 0xc0, 0xde], 96),
    ];

    for bytes in reduction_cases {
        let reduced = FieldElement521V1::reduce_bytes_mod(&bytes);
        let expected = biguint_to_field(bytes_to_biguint(&bytes) % modulus_biguint());
        assert_eq!(reduced, expected, "bytes={}", hex_encode(&bytes));
        assert_eq!(FieldElement521V1::reduce_bytes_mod(&bytes), reduced);
    }

    let entropy = repeat_pattern(&[0xff, 0x00, 0xaa, 0x55], 96);
    let challenge = repeat_pattern(&[0x01, 0x23, 0x45, 0x67], 91);
    let first = DcmInput521V1::from_seed_bytes(&entropy, &challenge);
    let second = DcmInput521V1::from_seed_bytes(&entropy, &challenge);
    assert_eq!(first, second);
    assert_eq!(first.initial_state().x, first.x0);
    assert_eq!(first.initial_state().y, first.y0);
}

#[test]
fn field_arithmetic_matches_biguint_for_structured_vectors() {
    let samples = field_samples();
    let modulus = modulus_biguint();

    for value in &samples {
        let bigint = field_to_biguint(*value);
        assert_eq!(
            value.square_mod(),
            biguint_to_field((&bigint * &bigint) % &modulus)
        );
    }

    for lhs in &samples {
        let lhs_big = field_to_biguint(*lhs);
        for rhs in &samples {
            let rhs_big = field_to_biguint(*rhs);
            assert_eq!(
                lhs.add_mod(rhs),
                biguint_to_field((&lhs_big + &rhs_big) % &modulus)
            );
            assert_eq!(
                lhs.sub_mod(rhs),
                biguint_to_field((&lhs_big + &modulus - &rhs_big) % &modulus)
            );
            assert_eq!(
                lhs.mul_mod(rhs),
                biguint_to_field((&lhs_big * &rhs_big) % &modulus)
            );
        }
    }
}

#[test]
fn sampled_production_states_are_injective_and_round_trip_cleanly() {
    let mut sampled = deterministic_sampled_states(4096);
    sampled.extend(structured_states());
    let mut seen_successors = HashMap::with_capacity(sampled.len());

    for state in sampled {
        let successor = advance_dcm_state_521_v1(state);
        assert_eq!(rewind_dcm_state_521_v1(successor), state);
        assert_eq!(
            advance_dcm_state_521_v1(rewind_dcm_state_521_v1(state)),
            state
        );
        let successor_bytes = successor.canonical_bytes();
        let state_bytes = state.canonical_bytes();
        if let Some(previous_state_bytes) = seen_successors.insert(successor_bytes, state_bytes) {
            assert_eq!(
                previous_state_bytes, state_bytes,
                "distinct sampled states mapped to the same successor: {successor}"
            );
        }
    }
}

#[test]
fn toy_prime_moduli_are_exhaustively_bijective_and_match_cycle_vectors() {
    let fixture = load_cat_map_test_vectors();

    for vector in fixture.toy_prime_cycle_suites {
        let analysis = analyze_toy_modulus(vector.p);
        let representatives: Vec<(u64, u64)> = vector
            .representatives
            .iter()
            .map(|state| (state[0], state[1]))
            .collect();

        assert_eq!(analysis.cycle_lengths, vector.cycle_lengths);
        assert_eq!(analysis.cycle_representatives, representatives);
        assert_eq!(analysis.state_count as u64, vector.p * vector.p);

        for x in 0..vector.p {
            for y in 0..vector.p {
                let state = DcmStateV1 { x, y };
                let successor = advance_dcm_state_v1(state, vector.p);
                let predecessor = rewind_dcm_state_v1(state, vector.p);

                assert_eq!(rewind_dcm_state_v1(successor, vector.p), state);
                assert_eq!(advance_dcm_state_v1(predecessor, vector.p), state);

                for &jump in &[0u64, 1, 2, 3, 5, 8, 13] {
                    let mut repeated = state;
                    for _ in 0..jump {
                        repeated = advance_dcm_state_v1(repeated, vector.p);
                    }
                    assert_eq!(fast_forward_dcm_state_v1(state, jump, vector.p), repeated);
                }
            }
        }
    }
}

#[test]
fn canonical_pair_state_bytes_and_hashes_are_stable_and_unambiguous() {
    let state = DcmState521V1::from_u64(10946, 17711);
    let swapped = DcmState521V1::from_u64(17711, 10946);
    let state_bytes = state.canonical_bytes();

    assert_eq!(state_bytes.len(), DCM_STATE_521_CANONICAL_BYTE_LEN_V1);
    assert_ne!(state_bytes, swapped.canonical_bytes());
    assert_eq!(
        hex_encode(&Sha256::digest(state_bytes)),
        "026c72aff98d9725d4b49ffdca3e1965dc80fb8457949bba0a414cf018035a94"
    );
}

#[test]
fn pair_state_serialization_is_exact_x_then_y_66_byte_concatenation() {
    let state = DcmState521V1 {
        x: reduced_pattern_field(&[0x13, 0x37, 0xc0, 0xde]),
        y: reduced_pattern_field(&[0xaa, 0x55, 0x00, 0xff]),
    };
    let bytes = state.canonical_bytes();

    assert_eq!(&bytes[..FIELD_ELEMENT_521_BYTE_LEN_V1], &state.x.to_bytes());
    assert_eq!(&bytes[FIELD_ELEMENT_521_BYTE_LEN_V1..], &state.y.to_bytes());
}

#[test]
fn production_vectors_match_checked_in_suite() {
    let fixture = load_cat_map_test_vectors();

    for vector in fixture.production_vectors {
        let input = DcmInput521V1::from_seed_bytes(
            &decode_hex(&vector.entropy_hex),
            &decode_hex(&vector.challenge_hex),
        );
        let config = DcmConfig521V1 {
            iteration_count: 32,
        };
        let execution = DcmExecution521V1::run(&config, &input).unwrap();
        let commitments = derive_dcm_layer1_commitments_521_v1(&config, &execution);

        assert_eq!(
            field_to_prefixed_hex(input.x0),
            vector.initial.x,
            "{}",
            vector.name
        );
        assert_eq!(
            field_to_prefixed_hex(input.y0),
            vector.initial.y,
            "{}",
            vector.name
        );
        assert_eq!(
            hex_encode(&input.initial_state().canonical_bytes()),
            vector.initial_state_encoding_hex,
            "{}",
            vector.name
        );
        assert_state_matches_fixture_hex(
            execution.states[1],
            &vector.states.s1,
            &vector.name,
            "s1",
        );
        assert_state_matches_fixture_hex(
            execution.states[2],
            &vector.states.s2,
            &vector.name,
            "s2",
        );
        assert_state_matches_fixture_hex(
            execution.states[3],
            &vector.states.s3,
            &vector.name,
            "s3",
        );
        assert_state_matches_fixture_hex(
            execution.states[5],
            &vector.states.s5,
            &vector.name,
            "s5",
        );
        assert_state_matches_fixture_hex(
            execution.states[8],
            &vector.states.s8,
            &vector.name,
            "s8",
        );
        assert_state_matches_fixture_hex(
            execution.states[16],
            &vector.states.s16,
            &vector.name,
            "s16",
        );
        assert_state_matches_fixture_hex(
            execution.final_state,
            &vector.states.s32,
            &vector.name,
            "s32",
        );
        assert_eq!(
            fast_forward_dcm_state_521_v1(input.initial_state(), 32),
            execution.final_state,
            "{}",
            vector.name
        );
        assert_eq!(
            fast_rewind_dcm_state_521_v1(execution.final_state, 32),
            input.initial_state(),
            "{}",
            vector.name
        );
        assert_eq!(
            hex_encode(&execution.final_state.canonical_bytes()),
            vector.final_state_encoding_hex,
            "{}",
            vector.name
        );
        assert_eq!(
            hex_encode(&Sha256::digest(execution.final_state.canonical_bytes())),
            vector.final_state_hash,
            "{}",
            vector.name
        );
        assert_eq!(
            hex_encode(&execution.trace_commitment),
            vector.trace_commitment,
            "{}",
            vector.name
        );
        assert_eq!(
            hex_encode(&commitments.dcm_commitment_root),
            vector.commitment_root,
            "{}",
            vector.name
        );
        assert!(vector.notes.is_some(), "{}", vector.name);
    }
}

#[test]
fn checked_in_test_vector_schema_is_stable() {
    let fixture = load_cat_map_test_vectors();
    let vector_names: Vec<&str> = fixture
        .production_vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .collect();

    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.primitive, "aura_cat_map_v1");
    assert_eq!(fixture.modulus.name, "mersenne_521");
    assert_eq!(
        fixture.modulus.hex,
        format!("0x{}", hex_encode(&FIELD_MODULUS_521_V1))
    );
    assert_eq!(fixture.matrix.forward, [[1, 1], [1, 2]]);
    assert_eq!(fixture.matrix.inverse, [[2, -1], [-1, 1]]);
    assert_eq!(fixture.encoding.coordinate_encoding, "66-byte big-endian");
    assert_eq!(fixture.encoding.state_encoding, "x_bytes_66 || y_bytes_66");
    assert_eq!(fixture.hashes.final_state_hash, "sha256(state_encoding)");
    assert_eq!(
        fixture.hashes.trace_commitment,
        "derive_trace_commitment_521_v1"
    );
    assert_eq!(
        fixture.hashes.commitment_root,
        "derive_dcm_layer1_commitments_521_v1"
    );
    assert_eq!(
        fixture.checkpoints,
        vec!["s1", "s2", "s3", "s5", "s8", "s16", "s32"]
    );
    assert_eq!(fixture.production_vectors.len(), 13);
    assert_eq!(fixture.toy_prime_cycle_suites.len(), 3);
    assert!(vector_names.contains(&"zero_zero_32"));
    assert!(vector_names.contains(&"one_one_32"));
    assert!(vector_names.contains(&"boundary_nm1_one_32"));
    assert!(vector_names.contains(&"oversized_modulus_plus_one_32"));
    assert!(vector_names.contains(&"endian_probe_32"));
}

#[test]
fn required_fixed_vectors_are_pinned_exactly_in_the_canonical_fixture() {
    let fixture = load_cat_map_test_vectors();

    let zero_zero = production_vector_by_name(&fixture, "zero_zero_32");
    assert_eq!(zero_zero.entropy_hex, "00");
    assert_eq!(zero_zero.challenge_hex, "00");
    assert_eq!(zero_zero.initial.x, "0x0");
    assert_eq!(zero_zero.initial.y, "0x0");
    assert_eq!(zero_zero.states.s32.x, "0x0");
    assert_eq!(zero_zero.states.s32.y, "0x0");
    assert_eq!(
        zero_zero.final_state_hash,
        "115bad14f1c9f2c027a84de21b107015722cb76be8d0abf3760ad8e00d6c24a5"
    );
    assert_eq!(
        zero_zero.trace_commitment,
        "c75ef729d5de83a0e5be44e2fddf1c6f72dad2c34a989b48d7bb6887d16da93e"
    );
    assert_eq!(
        zero_zero.commitment_root,
        "441f2a91262a7f7f049bdd57eaf666ea2a18fc7304d189c5fe8272dc20ef048f"
    );

    let one_one = production_vector_by_name(&fixture, "one_one_32");
    assert_eq!(one_one.entropy_hex, "01");
    assert_eq!(one_one.challenge_hex, "01");
    assert_eq!(one_one.initial.x, "0x1");
    assert_eq!(one_one.initial.y, "0x1");
    assert_eq!(one_one.states.s1.x, "0x2");
    assert_eq!(one_one.states.s1.y, "0x3");
    assert_eq!(one_one.states.s2.x, "0x5");
    assert_eq!(one_one.states.s2.y, "0x8");
    assert_eq!(one_one.states.s3.x, "0xd");
    assert_eq!(one_one.states.s3.y, "0x15");
    assert_eq!(one_one.states.s5.x, "0x59");
    assert_eq!(one_one.states.s5.y, "0x90");
    assert_eq!(one_one.states.s8.x, "0x63d");
    assert_eq!(one_one.states.s8.y, "0xa18");
    assert_eq!(one_one.states.s16.x, "0x35c7e2");
    assert_eq!(one_one.states.s16.y, "0x5704e7");
    assert_eq!(one_one.states.s32.x, "0xf9d297a859d");
    assert_eq!(one_one.states.s32.y, "0x19438b44a658");
    assert_eq!(
        one_one.final_state_hash,
        "141538194ffc0c79075b3da10133381d8353fea54e0663612a9ebc368bb45caf"
    );
    assert_eq!(
        one_one.trace_commitment,
        "9396363345f04c7d7d7fcb48adb9f6502dd6a91bc944a47c640cd4f142880bba"
    );
    assert_eq!(
        one_one.commitment_root,
        "4699ed73c0756bb782631d24e8735f5563e847ed0e3fdca219519e82c1935727"
    );

    let boundary = production_vector_by_name(&fixture, "boundary_nm1_one_32");
    assert_eq!(
        boundary.entropy_hex,
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
    );
    assert_eq!(boundary.challenge_hex, "01");
    assert_eq!(
        boundary.initial.x,
        "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
    );
    assert_eq!(boundary.initial.y, "0x1");
    assert_eq!(boundary.states.s1.x, "0x0");
    assert_eq!(boundary.states.s1.y, "0x1");
    assert_eq!(boundary.states.s2.x, "0x1");
    assert_eq!(boundary.states.s2.y, "0x2");
    assert_eq!(boundary.states.s3.x, "0x3");
    assert_eq!(boundary.states.s3.y, "0x5");
    assert_eq!(boundary.states.s5.x, "0x15");
    assert_eq!(boundary.states.s5.y, "0x22");
    assert_eq!(boundary.states.s8.x, "0x179");
    assert_eq!(boundary.states.s8.y, "0x262");
    assert_eq!(boundary.states.s16.x, "0xcb228");
    assert_eq!(boundary.states.s16.y, "0x148add");
    assert_eq!(boundary.states.s32.x, "0x3af9a19bbd9");
    assert_eq!(boundary.states.s32.y, "0x5f6c7b064e2");
    assert_eq!(
        boundary.final_state_hash,
        "e5d8e5fe1bdee8464e62ed475107fbe1420a2b3baeac22d30645f9ffafe3fd4d"
    );
    assert_eq!(
        boundary.trace_commitment,
        "162de09bc21e8f6e9e8efa82db5659f9e4cae0ea937ec6b4e9f67d482baed9b5"
    );
    assert_eq!(
        boundary.commitment_root,
        "d959a71999b484fffeea333f2f498f3cf7d797f043aeb386def5f7f7244428b4"
    );
}

#[test]
fn seed_reduction_uses_big_endian_byte_order() {
    assert_eq!(
        FieldElement521V1::reduce_bytes_mod(&[0x01, 0x00]),
        FieldElement521V1::from_u64(256)
    );
    assert_eq!(
        FieldElement521V1::reduce_bytes_mod(&[0x00, 0x01]),
        FieldElement521V1::from_u64(1)
    );
    assert_ne!(
        FieldElement521V1::reduce_bytes_mod(&[0x01, 0x00]),
        FieldElement521V1::reduce_bytes_mod(&[0x00, 0x01])
    );
}

#[test]
fn matrix_power_composition_holds_for_large_exponents() {
    let matrix = dcm_cat_map_matrix_521_v1();

    for &(left, right) in &[
        (0u64, 0u64),
        (1, 1),
        (3, 5),
        (32, 63),
        (1 << 20, 12_345),
        ((1u64 << 32) + 1, (1u64 << 31) + 7),
        (1u64 << 63, 12_345),
    ] {
        assert_eq!(
            matrix.pow(left + right),
            matrix.pow(left).multiply(&matrix.pow(right))
        );
    }
}

#[test]
fn fast_forward_respects_large_jump_composition_laws() {
    let mut states = structured_states();
    states.extend(deterministic_sampled_states(96));

    for state in states {
        for &(left, right) in &[
            (0u64, 0u64),
            (1, 1),
            (3, 5),
            (32, 63),
            (1 << 20, 12_345),
            ((1u64 << 32) + 1, (1u64 << 31) + 7),
            (1u64 << 63, 12_345),
        ] {
            assert_eq!(
                fast_forward_dcm_state_521_v1(state, left + right),
                fast_forward_dcm_state_521_v1(fast_forward_dcm_state_521_v1(state, left), right),
                "state={state} left={left} right={right}"
            );
        }
    }
}

#[test]
fn coordinate_recurrence_holds_across_longer_trajectories() {
    let mut states = structured_states();
    states.extend(deterministic_sampled_states(64));

    for initial in states {
        let mut previous = initial;
        let mut current = advance_dcm_state_521_v1(previous);

        for _ in 0..32 {
            let next = advance_dcm_state_521_v1(current);
            assert_eq!(
                coordinate_recurrence_next_521_v1(previous.x, current.x),
                next.x
            );
            assert_eq!(
                coordinate_recurrence_next_521_v1(previous.y, current.y),
                next.y
            );
            previous = current;
            current = next;
        }
    }
}

#[test]
fn canonical_public_input_bytes_are_shared_fixed_width_and_tamper_sensitive() {
    let input = DcmInput521V1::from_seed_bytes(&decode_hex("01"), &decode_hex("01"));
    let config = DcmConfig521V1 {
        iteration_count: 32,
    };
    let execution = DcmExecution521V1::run(&config, &input).unwrap();
    let trace = DcmAirTraceV1::new(execution.states.clone());
    let claim = build_dcm_claim_521_v1(&config, &input, &execution);
    let public_inputs = dcm_air_public_inputs_from_claim_521_v1(&claim);
    let session = package_dcm_air_proof_session_v1(&public_inputs, &trace).unwrap();
    let mock_output = prove_dcm_air_with_mock_proof_v1(&public_inputs, &trace).unwrap();
    let verifier_bindings = DcmAirMockVerifierBindingsV1::from(session.verifier_input());
    let canonical_bytes = public_inputs.canonical_bytes();
    let stark_digest = domain_separated_sha256(
        AURA_DCM_STARK_TRANSCRIPT_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
        &canonical_bytes,
    );
    let mock_digest = domain_separated_sha256(
        AURA_DCM_AIR_MOCK_PROOF_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
        &canonical_bytes,
    );
    let tampered = DcmAirPublicInputsV1 {
        final_state: DcmState521V1 {
            x: public_inputs.final_state.y,
            y: public_inputs.final_state.x,
        },
        ..public_inputs
    };
    let tampered_stark_digest = domain_separated_sha256(
        AURA_DCM_STARK_TRANSCRIPT_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
        &tampered.canonical_bytes(),
    );
    let tampered_mock_digest = domain_separated_sha256(
        AURA_DCM_AIR_MOCK_PROOF_V1_PUBLIC_INPUT_DOMAIN_SEPARATOR,
        &tampered.canonical_bytes(),
    );

    assert_eq!(
        canonical_bytes.len(),
        DCM_AIR_PUBLIC_INPUTS_521_CANONICAL_BYTE_LEN_V1
    );
    assert_eq!(
        verifier_bindings.public_inputs.canonical_bytes(),
        canonical_bytes
    );
    assert_eq!(
        derive_dcm_air_stark_public_input_digest_v1(&public_inputs),
        stark_digest
    );
    assert_eq!(
        mock_output.mock_proof_artifact.bound_public_input_digest,
        mock_digest
    );
    assert_ne!(canonical_bytes, tampered.canonical_bytes());
    assert_ne!(
        derive_dcm_air_stark_public_input_digest_v1(&public_inputs),
        tampered_stark_digest
    );
    assert_ne!(mock_digest, tampered_mock_digest);
}

#[test]
fn canonical_trace_bytes_are_fixed_width_and_tamper_sensitive() {
    let execution = DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 8 },
        &DcmInput521V1::from_seed_bytes(&decode_hex("01"), &decode_hex("01")),
    )
    .unwrap();
    let trace = DcmAirTraceV1::new(execution.states.clone());
    let canonical_bytes = canonical_dcm_air_trace_bytes_v1(&trace);
    let mut swapped_rows = execution.states.clone();
    swapped_rows.swap(1, 2);
    let swapped_trace = DcmAirTraceV1::new(swapped_rows);
    let truncated_trace =
        DcmAirTraceV1::new(execution.states[..execution.states.len() - 1].to_vec());

    assert_eq!(
        canonical_bytes.len(),
        8 + execution.states.len() * DCM_STATE_521_CANONICAL_BYTE_LEN_V1
    );
    assert_eq!(
        &canonical_bytes[..8],
        &(execution.states.len() as u64).to_le_bytes()
    );
    assert_ne!(
        canonical_bytes,
        canonical_dcm_air_trace_bytes_v1(&swapped_trace)
    );
    assert_ne!(
        canonical_bytes,
        canonical_dcm_air_trace_bytes_v1(&truncated_trace)
    );
}

fn load_cat_map_test_vectors() -> CatMapTestVectorsFileV1 {
    let path = cat_map_test_vectors_path();
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn cat_map_test_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/cat_map_v1")
        .join("test_vectors.json")
}

fn production_vector_by_name<'a>(
    fixture: &'a CatMapTestVectorsFileV1,
    name: &str,
) -> &'a ProductionVectorFixtureV1 {
    fixture
        .production_vectors
        .iter()
        .find(|vector| vector.name == name)
        .unwrap_or_else(|| panic!("missing production vector {name}"))
}

fn assert_state_matches_fixture_hex(
    state: DcmState521V1,
    expected: &FixtureHexStateV1,
    vector_name: &str,
    checkpoint: &str,
) {
    assert_eq!(
        field_to_prefixed_hex(state.x),
        expected.x,
        "{vector_name} {checkpoint} x"
    );
    assert_eq!(
        field_to_prefixed_hex(state.y),
        expected.y,
        "{vector_name} {checkpoint} y"
    );
}

fn domain_separated_sha256(domain_separator: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain_separator);
    hasher.update(payload);
    hasher.finalize().into()
}

fn structured_states() -> Vec<DcmState521V1> {
    vec![
        DcmState521V1::from_u64(0, 0),
        DcmState521V1::from_u64(1, 0),
        DcmState521V1::from_u64(0, 1),
        DcmState521V1::from_u64(1, 1),
        DcmState521V1 {
            x: modulus_minus(1),
            y: FieldElement521V1::zero(),
        },
        DcmState521V1 {
            x: FieldElement521V1::zero(),
            y: modulus_minus(1),
        },
        DcmState521V1 {
            x: modulus_minus(1),
            y: modulus_minus(1),
        },
        DcmState521V1 {
            x: modulus_minus(2),
            y: FieldElement521V1::from_u64(2),
        },
        DcmState521V1 {
            x: top_bit_value(0x00),
            y: top_bit_value(0x55),
        },
        DcmState521V1 {
            x: reduced_pattern_field(&[0xff]),
            y: reduced_pattern_field(&[0xaa, 0x55]),
        },
    ]
}

fn deterministic_sampled_states(count: usize) -> Vec<DcmState521V1> {
    let mut seed = 0x4d595df4d0f33173u64;
    let mut states = Vec::with_capacity(count);

    for index in 0..count {
        let x = xorshift64(&mut seed);
        let y = xorshift64(&mut seed);
        let state = match index % 4 {
            0 => DcmState521V1::from_u64(x, y),
            1 => DcmState521V1 {
                x: FieldElement521V1::reduce_bytes_mod(&repeat_pattern(&x.to_be_bytes(), 80)),
                y: FieldElement521V1::reduce_bytes_mod(&repeat_pattern(&y.to_be_bytes(), 80)),
            },
            2 => DcmState521V1 {
                x: FieldElement521V1::reduce_bytes_mod(&repeat_pattern(
                    &[0xaa, 0x55, (x & 0xff) as u8],
                    83,
                )),
                y: FieldElement521V1::reduce_bytes_mod(&repeat_pattern(
                    &[0x00, 0xff, (y & 0xff) as u8],
                    83,
                )),
            },
            _ => DcmState521V1 {
                x: FieldElement521V1::reduce_bytes_mod(&repeat_pattern(
                    &x.rotate_left(7).to_le_bytes(),
                    77,
                )),
                y: FieldElement521V1::reduce_bytes_mod(&repeat_pattern(
                    &y.rotate_right(11).to_le_bytes(),
                    77,
                )),
            },
        };
        states.push(state);
    }

    states
}

fn field_samples() -> Vec<FieldElement521V1> {
    let mut samples = vec![
        FieldElement521V1::zero(),
        FieldElement521V1::one(),
        FieldElement521V1::from_u64(2),
        modulus_minus(1),
        modulus_minus(2),
        top_bit_value(0),
        top_bit_value(1),
        top_bit_value(0xaa),
        reduced_pattern_field(&[0xff]),
        reduced_pattern_field(&[0x00]),
        reduced_pattern_field(&[0xaa]),
        reduced_pattern_field(&[0x55]),
        reduced_pattern_field(&[0xaa, 0x55]),
        reduced_pattern_field(&[0x13, 0x37, 0xc0, 0xde]),
    ];
    let mut seed = 0xa5a5_5a5a_1234_5678u64;
    for _ in 0..12 {
        samples.push(FieldElement521V1::from_u64(xorshift64(&mut seed)));
    }
    samples
}

fn modulus_minus(amount: u8) -> FieldElement521V1 {
    let mut bytes = FIELD_MODULUS_521_V1;
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xff - amount;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn top_bit_value(low_byte: u8) -> FieldElement521V1 {
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    bytes[0] = 0x01;
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = low_byte;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn reduced_pattern_field(pattern: &[u8]) -> FieldElement521V1 {
    FieldElement521V1::reduce_bytes_mod(&repeat_pattern(pattern, 80))
}

fn repeat_pattern(pattern: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let remaining = len - bytes.len();
        let take = remaining.min(pattern.len());
        bytes.extend_from_slice(&pattern[..take]);
    }
    bytes
}

fn xorshift64(seed: &mut u64) -> u64 {
    let mut value = *seed;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *seed = value;
    value
}

fn modulus_biguint() -> BigUint {
    (BigUint::from(1u8) << 521u32) - BigUint::from(1u8)
}

fn bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn field_to_biguint(value: FieldElement521V1) -> BigUint {
    BigUint::from_bytes_be(&value.to_bytes())
}

fn biguint_to_field(value: BigUint) -> FieldElement521V1 {
    let raw = value.to_bytes_be();
    assert!(raw.len() <= FIELD_ELEMENT_521_BYTE_LEN_V1);
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - raw.len()..].copy_from_slice(&raw);
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn field_to_prefixed_hex(value: FieldElement521V1) -> String {
    let bigint = field_to_biguint(value);
    if bigint == BigUint::from(0u8) {
        "0x0".to_owned()
    } else {
        format!("0x{bigint:x}")
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    assert_eq!(bytes.len() % 2, 0);

    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0usize;
    while index < bytes.len() {
        let high = decode_hex_nibble(bytes[index]);
        let low = decode_hex_nibble(bytes[index + 1]);
        decoded.push((high << 4) | low);
        index += 2;
    }
    decoded
}

fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, PartialEq, Eq)]
struct ToyAnalysisV1 {
    state_count: usize,
    cycle_lengths: Vec<usize>,
    cycle_representatives: Vec<(u64, u64)>,
}

fn analyze_toy_modulus(modulus: u64) -> ToyAnalysisV1 {
    let mut visited = HashSet::new();
    let mut cycles = Vec::new();

    for x in 0..modulus {
        for y in 0..modulus {
            let state = DcmStateV1 { x, y };
            if visited.contains(&(state.x, state.y)) {
                continue;
            }

            let mut cycle = Vec::new();
            let mut current = state;
            while visited.insert((current.x, current.y)) {
                cycle.push(current);
                current = advance_dcm_state_v1(current, modulus);
            }
            cycles.push(cycle);
        }
    }

    cycles.sort_by_key(|cycle| (cycle.len(), cycle[0].x, cycle[0].y));

    ToyAnalysisV1 {
        state_count: visited.len(),
        cycle_lengths: cycles.iter().map(Vec::len).collect(),
        cycle_representatives: cycles
            .iter()
            .map(|cycle| (cycle[0].x, cycle[0].y))
            .collect(),
    }
}
