use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
};

use aura_intent_lineage_v1::{
    aura_hash521_v1, build_storm_trace, build_encrypted_envelope_v1, decrypt_payload_v1,
    derive_a, derive_b, derive_phi_n, derive_psi_n, derive_session_public_key_v1, derive_x0,
    derive_y0, validate_encrypted_envelope_v1, AuraSessionEncryptionContextV1,
    SessionPublicKeyV1, SessionSecretKeyV1, StormEncryptionBindingV1, StormExecutionInputsV1,
    FIELD_MODULUS_521_V1,
    AURA_C_A_V1_DOMAIN_SEPARATOR, AURA_C_B_V1_DOMAIN_SEPARATOR,
    AURA_STORM_X_V1_DOMAIN_SEPARATOR, AURA_STORM_Y_V1_DOMAIN_SEPARATOR,
    AURA_X0_V1_DOMAIN_SEPARATOR, AURA_Y0_V1_DOMAIN_SEPARATOR, HASH_LEN_V1,
    ENCRYPTED_ENVELOPE_V1_NONCE_LEN, SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
    STORM_CONTEXT_V1_LEN, STORM_SIDE_INPUT_LEN_V1,
};
use serde::Deserialize;
use sha3::{Digest, Sha3_512};
use sha2::Sha256;

const PHASE_A_SAMPLE_COUNT_V1: usize = 100_000;
const PHASE_B_SURFACE_SAMPLE_COUNT_V1: usize = 128;
const PHASE_D_TRACE_STEPS_V1: u64 = 64;
const PHASE_E_TRACE_STEPS_V1: u64 = 10_000;
const PHASE_F_DOMAIN_SIZES_V1: [u32; 4] = [1 << 8, 1 << 10, 1 << 12, 1 << 14];
const FROZEN_STORM_FIXTURE_SHA256_V1: &str =
    "6e38910c2f174882b1456dbbe53b47d19d0f796cc6aff8b6771414bf40e914eb";
const FROZEN_SESSION_FIXTURE_SHA256_V1: &str =
    "a0c5359675d4564c752646a5e24aed246a6894a68cc74cfcc12a3ab277c5240d";
const CONTEXT_MUTABLE_BYTE_RANGES_V1: &[(usize, usize)] = &[
    (1, 32),
    (65, 32),
    (97, 32),
    (129, 8),
    (137, 8),
    (145, 32),
    (177, 32),
];

#[derive(Deserialize)]
struct StormFixtureV1 {
    side_a_hex: String,
    side_b_hex: String,
    context_bytes_v1_hex: String,
    iteration_count: u64,
}

#[derive(Deserialize)]
struct SessionFixtureV1 {
    sender_secret_key_hex: String,
    sender_public_key_hex: String,
    receiver_secret_key_hex: String,
    receiver_public_key_hex: String,
    storm_claim_digest_hex: String,
    trace_root_hex: String,
    final_state_x_hex: String,
    final_state_y_hex: String,
    context_hash_hex: String,
    sender_id_hex: String,
    receiver_id_hex: String,
    freshness_nonce_hex: String,
    valid_from: u64,
    valid_until: u64,
    route_tag_hex: String,
    session_key_id_hex: String,
    nonce_hex: String,
    plaintext_hex: String,
    ciphertext_hex: String,
    aad_context_hash_hex: String,
}

#[derive(Debug)]
struct PhaseAMetricsV1 {
    max_bit_bias_ratio: f64,
    avg_bit_one_ratio: f64,
    top_9_bit_chi_square: f64,
    top_9_bucket_min: usize,
    top_9_bucket_max: usize,
    modulus_hits: usize,
    zero_outputs: usize,
}

#[derive(Debug)]
struct AvalancheMetricsV1 {
    label: &'static str,
    sample_count: usize,
    min_changed_bits: usize,
    max_changed_bits: usize,
    avg_changed_bits: f64,
    avg_changed_fraction: f64,
}

#[derive(Debug)]
struct PhaseDMetricsV1 {
    label: &'static str,
    initial_distance_bits: usize,
    final_distance_bits: usize,
    peak_distance_bits: usize,
    first_non_zero_step: usize,
}

#[derive(Debug)]
struct PhaseFMetricsV1 {
    domain_size: u32,
    target_index: u32,
    attempts: u32,
    unique_outputs: usize,
}

#[test]
fn phase_a_uniformity_and_distribution_hold() {
    let metrics = phase_a_metrics_v1();
    println!("phase_a_metrics={metrics:?}");

    assert!(
        metrics.max_bit_bias_ratio <= 0.006,
        "expected per-bit one ratio skew <= 0.006, got {:.4}",
        metrics.max_bit_bias_ratio
    );
    assert!(
        metrics.avg_bit_one_ratio >= 0.499 && metrics.avg_bit_one_ratio <= 0.501,
        "expected mean one ratio near 50%, got {:.4}",
        metrics.avg_bit_one_ratio
    );
    assert!(
        metrics.top_9_bit_chi_square < 900.0,
        "expected top-9 chi-square below 900, got {:.2}",
        metrics.top_9_bit_chi_square
    );
    assert_eq!(
        metrics.modulus_hits, 0,
        "did not expect to hit the 2^521-1 modulus remap surface in {} samples",
        PHASE_A_SAMPLE_COUNT_V1
    );
    assert_eq!(metrics.zero_outputs, 0, "did not expect zero outputs in the sampled set");
    assert!(metrics.top_9_bucket_min > 0, "expected every top-9 bucket to appear at least once");
    assert!(
        metrics.top_9_bucket_max < 300,
        "expected no top-9 bucket to dominate the sample, got {}",
        metrics.top_9_bucket_max
    );
}

#[test]
fn phase_b_avalanche_effect_holds_across_hash_and_derivation_surfaces() {
    let inputs = canonical_storm_inputs_v1(None);
    let metrics = [
        avalanche_for_message_mutations_v1(),
        avalanche_for_input_mutations_v1("x0_from_side_a", &inputs, mutate_side_a_bit_v1, |value| {
            derive_x0(&value.side_a).to_bytes()
        }),
        avalanche_for_input_mutations_v1("y0_from_side_b", &inputs, mutate_side_b_bit_v1, |value| {
            derive_y0(&value.side_b).to_bytes()
        }),
        avalanche_for_input_mutations_v1("a_from_context", &inputs, mutate_context_bit_v1, |value| {
            derive_a(&value.context_bytes_v1).to_bytes()
        }),
        avalanche_for_input_mutations_v1("b_from_context", &inputs, mutate_context_bit_v1, |value| {
            derive_b(&value.context_bytes_v1).to_bytes()
        }),
        avalanche_for_step_mutations_v1("phi_step_index", &inputs, |step| {
            derive_phi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, step).to_bytes()
        }),
        avalanche_for_step_mutations_v1("psi_step_index", &inputs, |step| {
            derive_psi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, step).to_bytes()
        }),
    ];

    for metric in &metrics {
        println!("phase_b_metric={metric:?}");
        assert!(metric.sample_count > 0, "expected {} to record samples", metric.label);
        assert!(
            metric.avg_changed_fraction >= 0.48 && metric.avg_changed_fraction <= 0.52,
            "expected {} average diffusion in [0.48, 0.52], got {:.4}",
            metric.label,
            metric.avg_changed_fraction
        );
        assert!(
            metric.avg_changed_bits >= 240.0 && metric.avg_changed_bits <= 280.0,
            "expected {} average changed bits in [240, 280], got {:.2}",
            metric.label,
            metric.avg_changed_bits
        );
        assert!(
            metric.min_changed_bits >= 200,
            "expected {} min changed bits >= 200, got {}",
            metric.label,
            metric.min_changed_bits
        );
        assert!(
            metric.max_changed_bits <= 320,
            "expected {} max changed bits to stay below 320, got {}",
            metric.label,
            metric.max_changed_bits
        );
    }
}

#[test]
fn phase_c_domain_separation_integrity_holds() {
    let payload = deterministic_bytes_v1(7, 96);
    let domains = [
        ("x0", AURA_X0_V1_DOMAIN_SEPARATOR),
        ("y0", AURA_Y0_V1_DOMAIN_SEPARATOR),
        ("a", AURA_C_A_V1_DOMAIN_SEPARATOR),
        ("b", AURA_C_B_V1_DOMAIN_SEPARATOR),
        ("phi", AURA_STORM_X_V1_DOMAIN_SEPARATOR),
        ("psi", AURA_STORM_Y_V1_DOMAIN_SEPARATOR),
    ];

    let mut outputs = Vec::new();
    for (label, domain) in domains {
        let mut material = Vec::with_capacity(domain.len() + payload.len());
        material.extend_from_slice(domain);
        material.extend_from_slice(&payload);
        outputs.push((label, aura_hash521_v1(&material).to_bytes()));

        let mut truncated_material = Vec::with_capacity(domain.len() - 1 + payload.len());
        truncated_material.extend_from_slice(&domain[..domain.len() - 1]);
        truncated_material.extend_from_slice(&payload);
        let truncated = aura_hash521_v1(&truncated_material).to_bytes();
        let distance = hamming_distance_v1(&outputs.last().unwrap().1, &truncated);
        assert!(
            distance >= 200,
            "expected truncated domain {label} to diverge strongly, got {distance} changed bits"
        );
    }

    let mut min_distance = usize::MAX;
    for left in 0..outputs.len() {
        for right in (left + 1)..outputs.len() {
            assert_ne!(
                outputs[left].1, outputs[right].1,
                "domain-separated outputs collided for {} and {}",
                outputs[left].0, outputs[right].0
            );
            min_distance = min_distance.min(hamming_distance_v1(&outputs[left].1, &outputs[right].1));
        }
    }

    println!("phase_c_min_pairwise_distance_bits={min_distance}");
    assert!(
        min_distance >= 200,
        "expected pairwise domain outputs to differ by at least 200 bits, got {min_distance}"
    );
}

#[test]
fn phase_d_storm_amplification_preserves_strong_divergence() {
    let baseline_inputs = canonical_storm_inputs_v1(Some(PHASE_D_TRACE_STEPS_V1));
    let baseline_trace = build_storm_trace(&baseline_inputs);
    let variants = [
        phase_d_metrics_v1("side_a_bit_0", &baseline_inputs, mutate_side_a_bit_v1, 0, &baseline_trace),
        phase_d_metrics_v1("side_b_bit_0", &baseline_inputs, mutate_side_b_bit_v1, 0, &baseline_trace),
        phase_d_metrics_v1("context_bit_0", &baseline_inputs, mutate_context_bit_v1, 0, &baseline_trace),
    ];

    for metric in &variants {
        println!("phase_d_metric={metric:?}");
        assert!(
            metric.initial_distance_bits <= metric.peak_distance_bits,
            "initial distance must not exceed peak distance for {}",
            metric.label
        );
        assert!(
            metric.final_distance_bits >= 500,
            "expected {} final divergence >= 500 bits, got {}",
            metric.label,
            metric.final_distance_bits
        );
        assert!(
            metric.peak_distance_bits >= metric.final_distance_bits,
            "peak distance must dominate final distance for {}",
            metric.label
        );
        assert!(
            metric.first_non_zero_step <= 1,
            "expected divergence to appear immediately for {}, first non-zero step was {}",
            metric.label,
            metric.first_non_zero_step
        );
    }
}

#[test]
fn phase_e_cycle_detection_finds_no_loops_in_a_10k_step_trace() {
    let inputs = canonical_storm_inputs_v1(Some(PHASE_E_TRACE_STEPS_V1));
    let trace = build_storm_trace(&inputs);
    let mut visited = HashSet::with_capacity(trace.len());
    for (index, state) in trace.iter().enumerate() {
        let row = state.encode_row_bytes();
        assert!(
            visited.insert(row),
            "detected a repeated state at trace index {index}"
        );
    }

    println!(
        "phase_e_unique_states={} trace_len={}",
        visited.len(),
        trace.len()
    );
    assert_eq!(visited.len(), trace.len());
}

#[test]
fn phase_f_reduced_space_attack_simulation_shows_no_shortcut() {
    let mut metrics = Vec::new();
    for domain_size in PHASE_F_DOMAIN_SIZES_V1 {
        let target_index = domain_size * 3 / 4;
        let target = aura_hash521_v1(&u32::to_le_bytes(target_index)).to_bytes();
        let mut attempts = 0u32;
        let mut unique_outputs = HashSet::with_capacity(domain_size as usize);
        let mut found = None;

        for candidate in 0..domain_size {
            attempts += 1;
            let output = aura_hash521_v1(&u32::to_le_bytes(candidate)).to_bytes();
            unique_outputs.insert(output);
            if output == target {
                found = Some(candidate);
                break;
            }
        }

        let metric = PhaseFMetricsV1 {
            domain_size,
            target_index,
            attempts,
            unique_outputs: unique_outputs.len(),
        };
        println!("phase_f_metric={metric:?}");
        assert_eq!(found, Some(metric.target_index));
        assert_eq!(metric.attempts, metric.target_index + 1);
        assert_eq!(metric.unique_outputs, metric.attempts as usize);
        assert!(metric.domain_size > 0);
        metrics.push(metric);
    }

    assert_eq!(metrics.len(), PHASE_F_DOMAIN_SIZES_V1.len());
}

#[test]
fn phase_g_binding_integrity_fails_closed_under_single_field_mutations() {
    let fixture = load_session_fixture_v1();
    let sender_secret_key = SessionSecretKeyV1 {
        bytes: decode_fixed_hex::<32>(&fixture.sender_secret_key_hex),
    };
    let sender_public_key = SessionPublicKeyV1 {
        bytes: decode_fixed_hex::<32>(&fixture.sender_public_key_hex),
    };
    let receiver_secret_key = SessionSecretKeyV1 {
        bytes: decode_fixed_hex::<32>(&fixture.receiver_secret_key_hex),
    };
    let receiver_public_key = SessionPublicKeyV1 {
        bytes: decode_fixed_hex::<32>(&fixture.receiver_public_key_hex),
    };
    let context = AuraSessionEncryptionContextV1 {
        version: SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
        storm_claim_digest: decode_fixed_hex::<HASH_LEN_V1>(&fixture.storm_claim_digest_hex),
        sender_id: decode_fixed_hex::<HASH_LEN_V1>(&fixture.sender_id_hex),
        receiver_id: decode_fixed_hex::<HASH_LEN_V1>(&fixture.receiver_id_hex),
        freshness_nonce: decode_fixed_hex::<HASH_LEN_V1>(&fixture.freshness_nonce_hex),
        valid_from: fixture.valid_from,
        valid_until: fixture.valid_until,
        route_tag: decode_fixed_hex::<HASH_LEN_V1>(&fixture.route_tag_hex),
        session_key_id: decode_fixed_hex::<HASH_LEN_V1>(&fixture.session_key_id_hex),
    };
    let binding = StormEncryptionBindingV1 {
        storm_claim_digest: decode_fixed_hex::<HASH_LEN_V1>(&fixture.storm_claim_digest_hex),
        trace_root: decode_fixed_hex::<HASH_LEN_V1>(&fixture.trace_root_hex),
        final_state_x: decode_fixed_hex::<66>(&fixture.final_state_x_hex),
        final_state_y: decode_fixed_hex::<66>(&fixture.final_state_y_hex),
        context_hash: decode_fixed_hex::<HASH_LEN_V1>(&fixture.context_hash_hex),
        sender_id: decode_fixed_hex::<HASH_LEN_V1>(&fixture.sender_id_hex),
        receiver_id: decode_fixed_hex::<HASH_LEN_V1>(&fixture.receiver_id_hex),
        session_key_id: decode_fixed_hex::<HASH_LEN_V1>(&fixture.session_key_id_hex),
    };
    let nonce = decode_fixed_hex::<ENCRYPTED_ENVELOPE_V1_NONCE_LEN>(&fixture.nonce_hex);
    let plaintext = decode_hex(&fixture.plaintext_hex);

    let envelope = build_encrypted_envelope_v1(
        &sender_secret_key,
        &receiver_public_key,
        &context,
        &binding,
        &plaintext,
        Some(nonce),
    )
    .unwrap();

    assert_eq!(envelope.sender_public_key, derive_session_public_key_v1(&sender_secret_key));
    assert_eq!(envelope.sender_public_key, sender_public_key);
    assert_eq!(envelope.receiver_public_key, receiver_public_key);
    assert_eq!(encode_hex(&envelope.ciphertext), fixture.ciphertext_hex);
    assert_eq!(encode_hex(&envelope.aad_context_hash), fixture.aad_context_hash_hex);
    assert_eq!(
        decrypt_payload_v1(
            &receiver_secret_key,
            &envelope.sender_public_key,
            &context,
            &binding,
            envelope.nonce,
            &envelope.ciphertext,
        )
        .unwrap(),
        plaintext
    );
    validate_encrypted_envelope_v1(&envelope, &context, &binding).unwrap();

    let mutation_cases = [
        {
            let mut context = context;
            context.storm_claim_digest[0] ^= 0x01;
            ("storm_claim_digest", context, binding)
        },
        {
            let mut binding = binding;
            binding.trace_root[31] ^= 0x01;
            ("trace_root", context, binding)
        },
        {
            let mut binding = binding;
            binding.final_state_x[65] ^= 0x01;
            ("final_state_x", context, binding)
        },
        {
            let mut binding = binding;
            binding.final_state_y[65] ^= 0x01;
            ("final_state_y", context, binding)
        },
        {
            let mut binding = binding;
            binding.context_hash[31] ^= 0x01;
            ("context_hash", context, binding)
        },
        {
            let mut context = context;
            context.route_tag[31] ^= 0x01;
            ("route_tag", context, binding)
        },
        {
            let mut binding = binding;
            binding.sender_id[31] ^= 0x01;
            ("sender_id", context, binding)
        },
        {
            let mut binding = binding;
            binding.receiver_id[31] ^= 0x01;
            ("receiver_id", context, binding)
        },
        {
            let mut binding = binding;
            binding.session_key_id[31] ^= 0x01;
            ("session_key_id", context, binding)
        },
    ];

    for (label, mutated_context, mutated_binding) in mutation_cases {
        println!("phase_g_mutation={label}");
        assert!(
            validate_encrypted_envelope_v1(&envelope, &mutated_context, &mutated_binding).is_err(),
            "expected envelope validation to fail for mutation case {label}"
        );
        assert!(
            decrypt_payload_v1(
                &receiver_secret_key,
                &envelope.sender_public_key,
                &mutated_context,
                &mutated_binding,
                envelope.nonce,
                &envelope.ciphertext,
            )
            .is_err(),
            "expected decrypt to fail for mutation case {label}"
        );
    }
}

#[test]
fn canonical_storm_and_session_fixture_hashes_are_frozen() {
    let storm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json");
    let session_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/session_encryption_v1/session_encryption_parity_vector_v1.json");

    assert_eq!(
        sha256_hex_v1(&fs::read(&storm_path).unwrap()),
        FROZEN_STORM_FIXTURE_SHA256_V1,
        "storm fixture changed; bump the fixture version instead of silently editing it"
    );
    assert_eq!(
        sha256_hex_v1(&fs::read(&session_path).unwrap()),
        FROZEN_SESSION_FIXTURE_SHA256_V1,
        "session fixture changed; bump the fixture version instead of silently editing it"
    );
}

fn phase_a_metrics_v1() -> PhaseAMetricsV1 {
    let mut ones_per_bit = vec![0usize; 521];
    let mut top_9_counts = vec![0usize; 512];
    let mut modulus_hits = 0usize;
    let mut zero_outputs = 0usize;

    for sample in 0..PHASE_A_SAMPLE_COUNT_V1 {
        let message = deterministic_bytes_v1(sample as u64, 40);
        let (encoded, hit_modulus) = raw_hash521_encoded_v1(&message);
        if hit_modulus {
            modulus_hits += 1;
        }
        if encoded.iter().all(|byte| *byte == 0) {
            zero_outputs += 1;
        }

        for bit_index in 0..521usize {
            ones_per_bit[bit_index] += field_bit_v1(&encoded, bit_index) as usize;
        }
        top_9_counts[top_9_bits_v1(&encoded) as usize] += 1;
    }

    let expected_ones = PHASE_A_SAMPLE_COUNT_V1 as f64 / 2.0;
    let mut total_ratio = 0.0f64;
    let mut max_bias_ratio = 0.0f64;
    for count in ones_per_bit {
        let ratio = count as f64 / PHASE_A_SAMPLE_COUNT_V1 as f64;
        total_ratio += ratio;
        max_bias_ratio = max_bias_ratio.max((count as f64 - expected_ones).abs() / PHASE_A_SAMPLE_COUNT_V1 as f64);
    }

    let expected_bucket = PHASE_A_SAMPLE_COUNT_V1 as f64 / 512.0;
    let top_9_bit_chi_square = top_9_counts
        .iter()
        .map(|count| {
            let delta = *count as f64 - expected_bucket;
            (delta * delta) / expected_bucket
        })
        .sum::<f64>();

    PhaseAMetricsV1 {
        max_bit_bias_ratio: max_bias_ratio,
        avg_bit_one_ratio: total_ratio / 521.0,
        top_9_bit_chi_square,
        top_9_bucket_min: *top_9_counts.iter().min().unwrap(),
        top_9_bucket_max: *top_9_counts.iter().max().unwrap(),
        modulus_hits,
        zero_outputs,
    }
}

fn avalanche_for_message_mutations_v1() -> AvalancheMetricsV1 {
    let baseline_message = deterministic_bytes_v1(4242, 40);
    let baseline = aura_hash521_v1(&baseline_message).to_bytes();
    let bit_positions = evenly_spaced_bit_positions_v1(baseline_message.len() * 8, PHASE_B_SURFACE_SAMPLE_COUNT_V1);
    let mut changed_bits = Vec::with_capacity(bit_positions.len());
    for bit in bit_positions {
        let mut mutated = baseline_message.clone();
        flip_bit_v1(&mut mutated, bit);
        let mutated_hash = aura_hash521_v1(&mutated).to_bytes();
        changed_bits.push(hamming_distance_v1(&baseline, &mutated_hash));
    }
    summarize_avalanche_v1("raw_hash_message", &changed_bits, 521)
}

fn avalanche_for_input_mutations_v1<FMut, FOut>(
    label: &'static str,
    baseline: &StormExecutionInputsV1,
    mutator: FMut,
    output_fn: FOut,
) -> AvalancheMetricsV1
where
    FMut: Fn(&StormExecutionInputsV1, usize) -> StormExecutionInputsV1,
    FOut: Fn(&StormExecutionInputsV1) -> [u8; 66],
{
    let total_bits = match label {
        "x0_from_side_a" => baseline.side_a.len() * 8,
        "y0_from_side_b" => baseline.side_b.len() * 8,
        _ => context_mutable_bit_count_v1(),
    };
    let bit_positions = evenly_spaced_bit_positions_v1(total_bits, PHASE_B_SURFACE_SAMPLE_COUNT_V1);
    let baseline_output = output_fn(baseline);
    let mut changed_bits = Vec::with_capacity(bit_positions.len());

    for bit in bit_positions {
        let mutated = mutator(baseline, bit);
        let mutated_output = output_fn(&mutated);
        changed_bits.push(hamming_distance_v1(&baseline_output, &mutated_output));
    }

    summarize_avalanche_v1(label, &changed_bits, 521)
}

fn avalanche_for_step_mutations_v1<F>(label: &'static str, _baseline: &StormExecutionInputsV1, output_fn: F) -> AvalancheMetricsV1
where
    F: Fn(u64) -> [u8; 66],
{
    let baseline_step = 0x0123_4567_89ab_cdefu64;
    let baseline_output = output_fn(baseline_step);
    let mut changed_bits = Vec::with_capacity(64);

    for bit in 0..64usize {
        let mutated_step = baseline_step ^ (1u64 << bit);
        let mutated_output = output_fn(mutated_step);
        changed_bits.push(hamming_distance_v1(&baseline_output, &mutated_output));
    }

    summarize_avalanche_v1(label, &changed_bits, 521)
}

fn summarize_avalanche_v1(label: &'static str, changed_bits: &[usize], output_bits: usize) -> AvalancheMetricsV1 {
    let min_changed_bits = *changed_bits.iter().min().unwrap();
    let max_changed_bits = *changed_bits.iter().max().unwrap();
    let avg_changed_bits =
        changed_bits.iter().copied().sum::<usize>() as f64 / changed_bits.len() as f64;
    AvalancheMetricsV1 {
        label,
        sample_count: changed_bits.len(),
        min_changed_bits,
        max_changed_bits,
        avg_changed_bits,
        avg_changed_fraction: avg_changed_bits / output_bits as f64,
    }
}

fn phase_d_metrics_v1<F>(
    label: &'static str,
    baseline_inputs: &StormExecutionInputsV1,
    mutator: F,
    bit_index: usize,
    baseline_trace: &[aura_intent_lineage_v1::StormState521V1],
) -> PhaseDMetricsV1
where
    F: Fn(&StormExecutionInputsV1, usize) -> StormExecutionInputsV1,
{
    let mutated_inputs = mutator(baseline_inputs, bit_index);
    let mutated_trace = build_storm_trace(&mutated_inputs);
    let distances = baseline_trace
        .iter()
        .zip(mutated_trace.iter())
        .map(|(left, right)| hamming_distance_v1(&left.encode_row_bytes(), &right.encode_row_bytes()))
        .collect::<Vec<_>>();

    PhaseDMetricsV1 {
        label,
        initial_distance_bits: distances[0],
        final_distance_bits: *distances.last().unwrap(),
        peak_distance_bits: *distances.iter().max().unwrap(),
        first_non_zero_step: distances
            .iter()
            .position(|distance| *distance > 0)
            .unwrap_or(distances.len() - 1),
    }
}

fn mutate_side_a_bit_v1(inputs: &StormExecutionInputsV1, bit_index: usize) -> StormExecutionInputsV1 {
    let mut mutated = *inputs;
    flip_bit_v1(&mut mutated.side_a, bit_index);
    mutated
}

fn mutate_side_b_bit_v1(inputs: &StormExecutionInputsV1, bit_index: usize) -> StormExecutionInputsV1 {
    let mut mutated = *inputs;
    flip_bit_v1(&mut mutated.side_b, bit_index);
    mutated
}

fn mutate_context_bit_v1(inputs: &StormExecutionInputsV1, bit_index: usize) -> StormExecutionInputsV1 {
    let mut mutated = *inputs;
    flip_bit_v1(
        &mut mutated.context_bytes_v1,
        context_mutable_absolute_bit_v1(bit_index),
    );
    mutated
}

fn evenly_spaced_bit_positions_v1(total_bits: usize, desired_samples: usize) -> Vec<usize> {
    let sample_count = desired_samples.min(total_bits);
    let mut positions = Vec::with_capacity(sample_count);
    let denominator = sample_count.max(1);
    for index in 0..sample_count {
        let position = index * total_bits / denominator;
        positions.push(position.min(total_bits - 1));
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

fn canonical_storm_inputs_v1(iteration_count: Option<u64>) -> StormExecutionInputsV1 {
    let fixture = load_storm_fixture_v1();
    StormExecutionInputsV1 {
        side_a: decode_fixed_hex::<STORM_SIDE_INPUT_LEN_V1>(&fixture.side_a_hex),
        side_b: decode_fixed_hex::<STORM_SIDE_INPUT_LEN_V1>(&fixture.side_b_hex),
        context_bytes_v1: decode_fixed_hex::<STORM_CONTEXT_V1_LEN>(&fixture.context_bytes_v1_hex),
        iteration_count: iteration_count.unwrap_or(fixture.iteration_count),
    }
}

fn load_storm_fixture_v1() -> StormFixtureV1 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn load_session_fixture_v1() -> SessionFixtureV1 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/session_encryption_v1/session_encryption_parity_vector_v1.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn deterministic_bytes_v1(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut output = Vec::with_capacity(len);
    for index in 0..len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let mixed = state.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(index as u64);
        output.push((mixed >> 56) as u8);
    }
    output
}

fn raw_hash521_encoded_v1(message: &[u8]) -> ([u8; 66], bool) {
    let h0 = sha3_512_with_suffix_v1(message, 0x00);
    let h1 = sha3_512_with_suffix_v1(message, 0x01);
    let extra_bits = (u16::from(h1[0]) << 1) | u16::from(h1[1] >> 7);
    let mut encoded = [0u8; 66];

    for bit_index in 0..512usize {
        let source_bit = (h0[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
        let target_bit_index = 7 + bit_index;
        encoded[target_bit_index / 8] |= source_bit << (7 - (target_bit_index % 8));
    }

    for bit_index in 0..9usize {
        let source_bit = ((extra_bits >> (8 - bit_index)) & 1) as u8;
        let target_bit_index = 7 + 512 + bit_index;
        encoded[target_bit_index / 8] |= source_bit << (7 - (target_bit_index % 8));
    }

    let hit_modulus = encoded == FIELD_MODULUS_521_V1;
    if hit_modulus {
        ([0u8; 66], true)
    } else {
        (encoded, false)
    }
}

fn sha3_512_with_suffix_v1(message: &[u8], suffix: u8) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    hasher.update([suffix]);
    hasher.finalize().into()
}

fn field_bit_v1(bytes: &[u8; 66], bit_index: usize) -> u8 {
    let target_bit_index = 7 + bit_index;
    (bytes[target_bit_index / 8] >> (7 - (target_bit_index % 8))) & 1
}

fn top_9_bits_v1(bytes: &[u8; 66]) -> u16 {
    (u16::from(bytes[0] & 0x01) << 8) | u16::from(bytes[1])
}

fn flip_bit_v1(bytes: &mut [u8], bit_index: usize) {
    let byte_index = bit_index / 8;
    let bit_in_byte = bit_index % 8;
    bytes[byte_index] ^= 1u8 << (7 - bit_in_byte);
}

fn context_mutable_bit_count_v1() -> usize {
    CONTEXT_MUTABLE_BYTE_RANGES_V1
        .iter()
        .map(|(_, len)| len * 8)
        .sum()
}

fn context_mutable_absolute_bit_v1(bit_index: usize) -> usize {
    let mut remaining = bit_index % context_mutable_bit_count_v1();
    for (start, len) in CONTEXT_MUTABLE_BYTE_RANGES_V1 {
        let range_bits = len * 8;
        if remaining < range_bits {
            return start * 8 + remaining;
        }
        remaining -= range_bits;
    }
    unreachable!("mutable context bit index must resolve inside the configured ranges")
}

fn hamming_distance_v1(left: &[u8], right: &[u8]) -> usize {
    assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right.iter())
        .map(|(lhs, rhs)| (*lhs ^ *rhs).count_ones() as usize)
        .sum()
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

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex_v1(bytes: &[u8]) -> String {
    let digest = <Sha256 as sha2::Digest>::digest(bytes);
    encode_hex(&digest)
}
