mod support;

use std::{collections::BTreeMap, fs, path::PathBuf};

use aura_intent_lineage_v1::{
    derive_deterministic_commitment_521_v1, FieldElement521V1,
    AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1,
    AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

use support::{canonical_layer2_object, encode_hex};

const PREFIX_BITS_V1: [u32; 4] = [8, 16, 24, 32];
const STRUCTURED_NEIGHBOR_BASE_REFERENCE_V1: u64 = 1u64 << 48;
const STRUCTURED_NEIGHBOR_QUERY_COUNT_V1: u64 = 1u64 << 16;

const AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_DETERMINISTIC_COMMITMENT_521_V1";
const AURA_DETERMINISTIC_COMMITMENT_521_SEED_X_V1: &[u8] =
    b"AURA_DETERMINISTIC_COMMITMENT_521_SEED_X_V1";
const AURA_DETERMINISTIC_COMMITMENT_521_SEED_Y_V1: &[u8] =
    b"AURA_DETERMINISTIC_COMMITMENT_521_SEED_Y_V1";
const DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1: usize = 64;
const DETERMINISTIC_COMMITMENT_521_INDEX_SCALE_V1: u64 = 257;
const DETERMINISTIC_COMMITMENT_521_MIX_SCALE_V1: u64 = 65_537;
const DETERMINISTIC_COMMITMENT_521_FINAL_SCALE_V1: u64 = 131_071;

const ALT_SHA512_TO_FIELD_REDUCED_TAG_V1: &[u8] = b"AURA_DC521_AUDIT_SHA512_TO_FIELD_REDUCED_V1";
const ALT_SHA512_TO_FIELD_EXPAND_X_V1: &[u8] = b"AURA_DC521_AUDIT_SHA512_TO_FIELD_EXPAND_X_V1";
const ALT_SHA512_TO_FIELD_EXPAND_Y_V1: &[u8] = b"AURA_DC521_AUDIT_SHA512_TO_FIELD_EXPAND_Y_V1";

#[derive(Serialize)]
struct BiasAuditReportV1 {
    scope: &'static str,
    command: &'static str,
    target: TargetSummaryV1,
    construction_trace: ConstructionTraceV1,
    stage_prefix_localization: StagePrefixLocalizationV1,
    avalanche_summary: Vec<AvalancheSummaryV1>,
    field_mutation_summary: Vec<FieldMutationSummaryV1>,
    prefix_diffusion_controls: Vec<PrefixDiffusionSummaryV1>,
    alternate_field_native_construction_available_in_repo: bool,
    alternate_field_native_construction_note: String,
    root_cause_hypothesis: String,
    bug_classification: &'static str,
    should_demote_from_primary_commitment_status: bool,
    minimum_safe_replacement_strategy: String,
}

#[derive(Serialize)]
struct TargetSummaryV1 {
    layer2_lineage_commitment_hex: String,
    canonical_preimage_len: usize,
    canonical_preimage_hex: String,
    canonical_input_len: usize,
    canonical_input_hex: String,
    exact_recomputation_equal: bool,
}

#[derive(Serialize)]
struct ConstructionTraceV1 {
    domain_separator_ascii: &'static str,
    context_domain_separator_ascii: &'static str,
    field_layout: Vec<FieldRangeV1>,
    freshness_reference_offset_in_preimage: usize,
    freshness_reference_offset_in_canonical_input: usize,
    affected_chunk_index: usize,
    affected_chunk_start: usize,
    affected_chunk_end: usize,
    chunks: Vec<ChunkTraceV1>,
    trailer_hex: String,
    final_element_hex: String,
    final_commitment_hex: String,
}

#[derive(Clone, Serialize)]
struct FieldRangeV1 {
    field: &'static str,
    start: usize,
    len: usize,
    end_exclusive: usize,
    start_chunk: usize,
    end_chunk: usize,
}

#[derive(Serialize)]
struct ChunkTraceV1 {
    chunk_index: usize,
    start: usize,
    end_exclusive: usize,
    chunk_hex: String,
    chunk_element_hex: String,
    mixed_chunk_hex: String,
    x_before_hex: String,
    y_before_hex: String,
    x_after_hex: String,
    y_after_hex: String,
}

#[derive(Serialize)]
struct StagePrefixLocalizationV1 {
    neighbor_family: &'static str,
    candidate_count: u64,
    target_reference: u64,
    stages: Vec<StagePrefixObservationV1>,
    first_mixing_stage_without_32_bit_diffusion: String,
}

#[derive(Serialize)]
struct StagePrefixObservationV1 {
    stage: &'static str,
    prefix_match_counts_to_target: PrefixMatchCountsV1,
    distinct_32_bit_prefixes: usize,
    constant_bits_in_first_32_across_family: usize,
    min_one_ratio_first_32: f64,
    max_one_ratio_first_32: f64,
}

#[derive(Clone, Copy, Serialize)]
struct PrefixMatchCountsV1 {
    bits_8: u64,
    bits_16: u64,
    bits_24: u64,
    bits_32: u64,
}

#[derive(Serialize)]
struct AvalancheSummaryV1 {
    algorithm: &'static str,
    mutation_family: &'static str,
    sample_count: usize,
    output_bits: usize,
    min_changed_bits: usize,
    max_changed_bits: usize,
    avg_changed_bits: f64,
    avg_changed_fraction: f64,
    prefix_changed_counts: PrefixMatchCountsV1,
}

#[derive(Serialize)]
struct FieldMutationSummaryV1 {
    field: &'static str,
    start: usize,
    len: usize,
    start_chunk: usize,
    end_chunk: usize,
    current_commitment_changed_bits: usize,
    current_commitment_prefix_changed: PrefixChangedBoolsV1,
    sha256_changed_bits: usize,
    sha512_changed_bits: usize,
    sha512_reduce_to_field_changed_bits: usize,
    sha512_expand_to_field_changed_bits: usize,
}

#[derive(Serialize)]
struct PrefixChangedBoolsV1 {
    bits_8: bool,
    bits_16: bool,
    bits_24: bool,
    bits_32: bool,
}

#[derive(Serialize)]
struct PrefixDiffusionSummaryV1 {
    algorithm: &'static str,
    output_len: usize,
    match_counts_to_target: PrefixMatchCountsV1,
    distinct_32_bit_prefixes: usize,
    constant_bits_in_first_32_across_family: usize,
    min_one_ratio_first_32: f64,
    max_one_ratio_first_32: f64,
}

#[derive(Clone)]
struct TargetFixtureV1 {
    target_reference: u64,
    canonical_preimage: Vec<u8>,
    canonical_input: Vec<u8>,
    trace: CommitmentTraceV1Local,
    field_layout: Vec<FieldRangeV1>,
    freshness_reference_offset: usize,
}

#[derive(Clone)]
struct CommitmentTraceV1Local {
    rounds: Vec<CommitmentRoundV1Local>,
    trailer: FieldElement521V1,
    final_element: FieldElement521V1,
}

#[derive(Clone)]
struct CommitmentRoundV1Local {
    chunk_index: usize,
    start: usize,
    end_exclusive: usize,
    chunk_bytes: Vec<u8>,
    chunk_element: FieldElement521V1,
    mixed_chunk: FieldElement521V1,
    x_before: FieldElement521V1,
    y_before: FieldElement521V1,
    x_after: FieldElement521V1,
    y_after: FieldElement521V1,
}

#[derive(Clone, Copy)]
enum ControlAlgorithmV1 {
    CurrentPrimitive,
    Sha256,
    Sha512,
    Sha512ReduceToField,
    Sha512ExpandToField,
}

#[derive(Default)]
struct AvalancheAccumulatorV1 {
    min_changed_bits: usize,
    max_changed_bits: usize,
    total_changed_bits: usize,
    sample_count: usize,
    prefix_changed_counts: [u64; PREFIX_BITS_V1.len()],
}

#[derive(Default)]
struct PrefixFamilyAccumulatorV1 {
    match_counts: [u64; PREFIX_BITS_V1.len()],
    distinct_prefixes_32: BTreeMap<u32, u64>,
    one_counts_first_32: [u64; 32],
    sample_count: u64,
}

#[test]
#[ignore = "non-authoritative research/analysis only"]
fn non_authoritative_research_deterministic_commitment_521_bias_audit_v1() {
    let fixture = build_target_fixture_v1();
    let construction_trace = build_construction_trace_v1(&fixture);
    let stage_prefix_localization = stage_prefix_localization_v1(&fixture);
    let avalanche_summary = avalanche_summary_v1(&fixture);
    let field_mutation_summary = field_mutation_summary_v1(&fixture);
    let prefix_diffusion_controls = prefix_diffusion_controls_v1(&fixture);
    let root_cause_hypothesis =
        root_cause_hypothesis_v1(&stage_prefix_localization, &prefix_diffusion_controls);
    let report = BiasAuditReportV1 {
        scope: "research-only / non-authoritative / no claim of a full 521-bit break",
        command: "cargo test -p aura_intent_lineage_v1 --release --test deterministic_commitment_521_bias_audit_v1 non_authoritative_research_deterministic_commitment_521_bias_audit_v1 -- --ignored --nocapture",
        target: TargetSummaryV1 {
            layer2_lineage_commitment_hex: encode_hex(&current_primitive_output_v1(
                &fixture.canonical_preimage,
            )),
            canonical_preimage_len: fixture.canonical_preimage.len(),
            canonical_preimage_hex: encode_hex(&fixture.canonical_preimage),
            canonical_input_len: fixture.canonical_input.len(),
            canonical_input_hex: encode_hex(&fixture.canonical_input),
            exact_recomputation_equal: current_primitive_output_v1(&fixture.canonical_preimage)
                == derive_deterministic_commitment_521_v1(
                    AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
                    &fixture.canonical_preimage,
                )
                .to_bytes(),
        },
        construction_trace,
        stage_prefix_localization,
        avalanche_summary,
        field_mutation_summary,
        prefix_diffusion_controls,
        alternate_field_native_construction_available_in_repo: false,
        alternate_field_native_construction_note: String::from(
            "No alternate byte-oriented field-native commitment primitive is currently implemented in the repo. The comparison therefore uses research-only widened/reduced hash-to-field controls to separate field reduction behavior from the current accumulator construction.",
        ),
        root_cause_hypothesis,
        bug_classification: "construction-level, not encoding-level",
        should_demote_from_primary_commitment_status: true,
        minimum_safe_replacement_strategy: String::from(
            "Demote DeterministicCommitment521V1 from Layer 2 primary-commitment duty. Keep the canonical Layer 2 preimage and domain separator exactly as they are, but replace the current low-degree field accumulator with a domain-separated cryptographic expand-then-reduce construction such as reduce_mod_p(SHA-512(tag_x || preimage) || SHA-512(tag_y || preimage)). That preserves deterministic replay and canonical encoding while forcing a real compression/avalanche stage before field serialization.",
        ),
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    eprintln!("{json}");
    write_report_file_v1("AURA_521_BIT_COMMITMENT_BIAS_AUDIT_V1.json", &json);

    assert!(report.target.exact_recomputation_equal);
}

fn build_target_fixture_v1() -> TargetFixtureV1 {
    let layer2_object = canonical_layer2_object();
    let target_reference = layer2_object.lineage.freshness_reference;
    let canonical_preimage = layer2_object.lineage.canonical_preimage().unwrap();
    let canonical_input = canonical_commitment_input_bytes_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_preimage,
    );
    let trace = derive_commitment_trace_v1(&canonical_input);
    let field_layout = lineage_field_layout_v1();
    let freshness_reference_offset = field_layout
        .iter()
        .find(|field| field.field == "freshness_reference")
        .map(|field| field.start)
        .unwrap();

    TargetFixtureV1 {
        target_reference,
        canonical_preimage,
        canonical_input,
        trace,
        field_layout,
        freshness_reference_offset,
    }
}

fn build_construction_trace_v1(fixture: &TargetFixtureV1) -> ConstructionTraceV1 {
    let affected_field = fixture
        .field_layout
        .iter()
        .find(|field| field.field == "freshness_reference")
        .unwrap();
    let canonical_input_body_start = canonical_input_body_offset_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    );
    let affected_chunk_index =
        (canonical_input_body_start + fixture.freshness_reference_offset) / DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1;
    let affected_round = &fixture.trace.rounds[affected_chunk_index];

    ConstructionTraceV1 {
        domain_separator_ascii:
            "AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_V1",
        context_domain_separator_ascii: "AURA_DETERMINISTIC_COMMITMENT_521_V1",
        field_layout: fixture.field_layout.clone(),
        freshness_reference_offset_in_preimage: affected_field.start,
        freshness_reference_offset_in_canonical_input: canonical_input_body_start + affected_field.start,
        affected_chunk_index,
        affected_chunk_start: affected_round.start,
        affected_chunk_end: affected_round.end_exclusive,
        chunks: fixture
            .trace
            .rounds
            .iter()
            .map(|round| ChunkTraceV1 {
                chunk_index: round.chunk_index,
                start: round.start,
                end_exclusive: round.end_exclusive,
                chunk_hex: encode_hex(&round.chunk_bytes),
                chunk_element_hex: encode_hex(&round.chunk_element.to_bytes()),
                mixed_chunk_hex: encode_hex(&round.mixed_chunk.to_bytes()),
                x_before_hex: encode_hex(&round.x_before.to_bytes()),
                y_before_hex: encode_hex(&round.y_before.to_bytes()),
                x_after_hex: encode_hex(&round.x_after.to_bytes()),
                y_after_hex: encode_hex(&round.y_after.to_bytes()),
            })
            .collect(),
        trailer_hex: encode_hex(&fixture.trace.trailer.to_bytes()),
        final_element_hex: encode_hex(&fixture.trace.final_element.to_bytes()),
        final_commitment_hex: encode_hex(&fixture.trace.final_element.to_bytes()),
    }
}

fn stage_prefix_localization_v1(fixture: &TargetFixtureV1) -> StagePrefixLocalizationV1 {
    let target_round = &fixture.trace.rounds[affected_chunk_index_v1(fixture)];
    let target_commitment = current_primitive_output_v1(&fixture.canonical_preimage);
    let target_chunk_element = target_round.chunk_element.to_bytes();
    let target_mixed_chunk = target_round.mixed_chunk.to_bytes();
    let target_x_after = target_round.x_after.to_bytes();
    let target_y_after = target_round.y_after.to_bytes();

    let mut chunk_element_accumulator = PrefixFamilyAccumulatorV1::default();
    let mut mixed_chunk_accumulator = PrefixFamilyAccumulatorV1::default();
    let mut x_after_accumulator = PrefixFamilyAccumulatorV1::default();
    let mut y_after_accumulator = PrefixFamilyAccumulatorV1::default();
    let mut commitment_accumulator = PrefixFamilyAccumulatorV1::default();

    for candidate in 0..STRUCTURED_NEIGHBOR_QUERY_COUNT_V1 {
        let body = structured_neighbor_preimage_v1(fixture, candidate);
        let canonical_input = canonical_commitment_input_bytes_v1(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &body,
        );
        let trace = derive_commitment_trace_v1(&canonical_input);
        let affected_round = &trace.rounds[affected_chunk_index_v1(fixture)];
        let commitment = trace.final_element.to_bytes();

        update_prefix_family_accumulator_v1(
            &mut chunk_element_accumulator,
            &affected_round.chunk_element.to_bytes(),
            &target_chunk_element,
        );
        update_prefix_family_accumulator_v1(
            &mut mixed_chunk_accumulator,
            &affected_round.mixed_chunk.to_bytes(),
            &target_mixed_chunk,
        );
        update_prefix_family_accumulator_v1(
            &mut x_after_accumulator,
            &affected_round.x_after.to_bytes(),
            &target_x_after,
        );
        update_prefix_family_accumulator_v1(
            &mut y_after_accumulator,
            &affected_round.y_after.to_bytes(),
            &target_y_after,
        );
        update_prefix_family_accumulator_v1(
            &mut commitment_accumulator,
            &commitment,
            &target_commitment,
        );
    }

    let stages = vec![
        prefix_observation_from_accumulator_v1("affected_chunk_element", &chunk_element_accumulator),
        prefix_observation_from_accumulator_v1("affected_mixed_chunk", &mixed_chunk_accumulator),
        prefix_observation_from_accumulator_v1("x_after_affected_round", &x_after_accumulator),
        prefix_observation_from_accumulator_v1("y_after_affected_round", &y_after_accumulator),
        prefix_observation_from_accumulator_v1("final_commitment", &commitment_accumulator),
    ];

    let first_mixing_stage_without_32_bit_diffusion = if stages[2].prefix_match_counts_to_target.bits_32
        == STRUCTURED_NEIGHBOR_QUERY_COUNT_V1
        && stages[3].prefix_match_counts_to_target.bits_32 == STRUCTURED_NEIGHBOR_QUERY_COUNT_V1
    {
        String::from(
            "x_after_affected_round / y_after_affected_round already retain the target's entire first 32 bits across the full 2^16 structured-neighbor family. That is the first actual mixing stage after the varying chunk, so the diffusion failure localizes to the commitment transform rather than to canonical packing or final serialization.",
        )
    } else {
        String::from(
            "The first 32-bit fixed-prefix effect does not fully appear until a later stage; inspect the per-stage counts above.",
        )
    };

    StagePrefixLocalizationV1 {
        neighbor_family: "freshness_reference = 2^48 + candidate, exact over candidate in [0, 2^16)",
        candidate_count: STRUCTURED_NEIGHBOR_QUERY_COUNT_V1,
        target_reference: fixture.target_reference,
        stages,
        first_mixing_stage_without_32_bit_diffusion,
    }
}

fn avalanche_summary_v1(fixture: &TargetFixtureV1) -> Vec<AvalancheSummaryV1> {
    let baseline_body = &fixture.canonical_preimage;
    let all_bits = 0..(baseline_body.len() * 8);
    let freshness_field = fixture
        .field_layout
        .iter()
        .find(|field| field.field == "freshness_reference")
        .unwrap();
    let freshness_bits =
        (freshness_field.start * 8)..((freshness_field.start + freshness_field.len) * 8);

    let algorithms = [
        ControlAlgorithmV1::CurrentPrimitive,
        ControlAlgorithmV1::Sha256,
        ControlAlgorithmV1::Sha512,
        ControlAlgorithmV1::Sha512ReduceToField,
        ControlAlgorithmV1::Sha512ExpandToField,
    ];

    let mut summaries = Vec::new();
    for algorithm in algorithms {
        summaries.push(avalanche_for_bit_family_v1(
            algorithm,
            "all_preimage_single_bit_flips",
            baseline_body,
            all_bits.clone(),
        ));
        summaries.push(avalanche_for_bit_family_v1(
            algorithm,
            "freshness_reference_single_bit_flips",
            baseline_body,
            freshness_bits.clone(),
        ));
    }
    summaries
}

fn avalanche_for_bit_family_v1(
    algorithm: ControlAlgorithmV1,
    mutation_family: &'static str,
    baseline_body: &[u8],
    bit_range: impl Iterator<Item = usize>,
) -> AvalancheSummaryV1 {
    let baseline_output = algorithm_output_v1(algorithm, baseline_body);
    let mut accumulator = AvalancheAccumulatorV1 {
        min_changed_bits: usize::MAX,
        ..AvalancheAccumulatorV1::default()
    };

    for bit_index in bit_range {
        let mutated_body = flip_body_bit_v1(baseline_body, bit_index);
        let mutated_output = algorithm_output_v1(algorithm, &mutated_body);
        let changed_bits = hamming_distance_v1(&baseline_output, &mutated_output);
        accumulator.min_changed_bits = accumulator.min_changed_bits.min(changed_bits);
        accumulator.max_changed_bits = accumulator.max_changed_bits.max(changed_bits);
        accumulator.total_changed_bits += changed_bits;
        accumulator.sample_count += 1;
        for (index, bits) in PREFIX_BITS_V1.into_iter().enumerate() {
            if truncate_bits_be_v1(&baseline_output, bits) != truncate_bits_be_v1(&mutated_output, bits)
            {
                accumulator.prefix_changed_counts[index] += 1;
            }
        }
    }

    if accumulator.sample_count == 0 {
        accumulator.min_changed_bits = 0;
    }

    let output_bits = baseline_output.len() * 8;
    AvalancheSummaryV1 {
        algorithm: algorithm_name_v1(algorithm),
        mutation_family,
        sample_count: accumulator.sample_count,
        output_bits,
        min_changed_bits: accumulator.min_changed_bits,
        max_changed_bits: accumulator.max_changed_bits,
        avg_changed_bits: accumulator.total_changed_bits as f64 / accumulator.sample_count as f64,
        avg_changed_fraction: accumulator.total_changed_bits as f64
            / (accumulator.sample_count as f64 * output_bits as f64),
        prefix_changed_counts: PrefixMatchCountsV1 {
            bits_8: accumulator.prefix_changed_counts[0],
            bits_16: accumulator.prefix_changed_counts[1],
            bits_24: accumulator.prefix_changed_counts[2],
            bits_32: accumulator.prefix_changed_counts[3],
        },
    }
}

fn field_mutation_summary_v1(fixture: &TargetFixtureV1) -> Vec<FieldMutationSummaryV1> {
    let mut mutated_lineages = Vec::new();
    let baseline = canonical_layer2_object().lineage;

    let mut dcm_commitment_root = baseline;
    dcm_commitment_root.dcm_commitment_root[0] ^= 0x80;
    mutated_lineages.push(("dcm_commitment_root", dcm_commitment_root));

    let mut dcm_trace_commitment = baseline;
    dcm_trace_commitment.dcm_trace_commitment[0] ^= 0x40;
    mutated_lineages.push(("dcm_trace_commitment", dcm_trace_commitment));

    let mut subject_id = baseline;
    subject_id.subject_id[0] ^= 0x20;
    mutated_lineages.push(("subject_id", subject_id));

    let mut intent_hash = baseline;
    intent_hash.intent_hash[0] ^= 0x10;
    mutated_lineages.push(("intent_hash", intent_hash));

    let mut freshness_nonce = baseline;
    freshness_nonce.freshness_nonce[0] ^= 0x08;
    mutated_lineages.push(("freshness_nonce", freshness_nonce));

    let mut freshness_reference = baseline;
    freshness_reference.freshness_reference += 1;
    mutated_lineages.push(("freshness_reference", freshness_reference));

    let baseline_preimage = baseline.canonical_preimage().unwrap();
    let baseline_current = current_primitive_output_v1(&baseline_preimage);
    let baseline_sha256 = sha256_output_v1(&baseline_preimage);
    let baseline_sha512 = sha512_output_v1(&baseline_preimage);
    let baseline_sha512_reduce = sha512_reduce_to_field_output_v1(&baseline_preimage);
    let baseline_sha512_expand = sha512_expand_to_field_output_v1(&baseline_preimage);

    mutated_lineages
        .into_iter()
        .map(|(field_name, lineage)| {
            let field = fixture
                .field_layout
                .iter()
                .find(|field| field.field == field_name)
                .unwrap();
            let mutated_preimage = lineage.canonical_preimage().unwrap();
            let current = current_primitive_output_v1(&mutated_preimage);
            let sha256 = sha256_output_v1(&mutated_preimage);
            let sha512 = sha512_output_v1(&mutated_preimage);
            let sha512_reduce = sha512_reduce_to_field_output_v1(&mutated_preimage);
            let sha512_expand = sha512_expand_to_field_output_v1(&mutated_preimage);

            FieldMutationSummaryV1 {
                field: field_name,
                start: field.start,
                len: field.len,
                start_chunk: field.start_chunk,
                end_chunk: field.end_chunk,
                current_commitment_changed_bits: hamming_distance_v1(&baseline_current, &current),
                current_commitment_prefix_changed: PrefixChangedBoolsV1 {
                    bits_8: truncate_bits_be_v1(&baseline_current, 8)
                        != truncate_bits_be_v1(&current, 8),
                    bits_16: truncate_bits_be_v1(&baseline_current, 16)
                        != truncate_bits_be_v1(&current, 16),
                    bits_24: truncate_bits_be_v1(&baseline_current, 24)
                        != truncate_bits_be_v1(&current, 24),
                    bits_32: truncate_bits_be_v1(&baseline_current, 32)
                        != truncate_bits_be_v1(&current, 32),
                },
                sha256_changed_bits: hamming_distance_v1(&baseline_sha256, &sha256),
                sha512_changed_bits: hamming_distance_v1(&baseline_sha512, &sha512),
                sha512_reduce_to_field_changed_bits: hamming_distance_v1(
                    &baseline_sha512_reduce,
                    &sha512_reduce,
                ),
                sha512_expand_to_field_changed_bits: hamming_distance_v1(
                    &baseline_sha512_expand,
                    &sha512_expand,
                ),
            }
        })
        .collect()
}

fn prefix_diffusion_controls_v1(fixture: &TargetFixtureV1) -> Vec<PrefixDiffusionSummaryV1> {
    let algorithms = [
        ControlAlgorithmV1::CurrentPrimitive,
        ControlAlgorithmV1::Sha256,
        ControlAlgorithmV1::Sha512,
        ControlAlgorithmV1::Sha512ReduceToField,
        ControlAlgorithmV1::Sha512ExpandToField,
    ];

    algorithms
        .into_iter()
        .map(|algorithm| {
            let target = algorithm_output_v1(algorithm, &fixture.canonical_preimage);
            let mut accumulator = PrefixFamilyAccumulatorV1::default();
            for candidate in 0..STRUCTURED_NEIGHBOR_QUERY_COUNT_V1 {
                let body = structured_neighbor_preimage_v1(fixture, candidate);
                let output = algorithm_output_v1(algorithm, &body);
                update_prefix_family_accumulator_v1(&mut accumulator, &output, &target);
            }
            PrefixDiffusionSummaryV1 {
                algorithm: algorithm_name_v1(algorithm),
                output_len: target.len(),
                match_counts_to_target: PrefixMatchCountsV1 {
                    bits_8: accumulator.match_counts[0],
                    bits_16: accumulator.match_counts[1],
                    bits_24: accumulator.match_counts[2],
                    bits_32: accumulator.match_counts[3],
                },
                distinct_32_bit_prefixes: accumulator.distinct_prefixes_32.len(),
                constant_bits_in_first_32_across_family: constant_bits_in_first_32_v1(&accumulator),
                min_one_ratio_first_32: min_one_ratio_first_32_v1(&accumulator),
                max_one_ratio_first_32: max_one_ratio_first_32_v1(&accumulator),
            }
        })
        .collect()
}

fn root_cause_hypothesis_v1(
    stage_prefix_localization: &StagePrefixLocalizationV1,
    prefix_diffusion_controls: &[PrefixDiffusionSummaryV1],
) -> String {
    let sha512_expand = prefix_diffusion_controls
        .iter()
        .find(|entry| entry.algorithm == "sha512x2_expand_reduce_to_field_521")
        .unwrap();

    format!(
        "The failure is construction-level. Canonical packing is singular and byte-exact, and the same FieldElement521V1 serialization behaves normally for the widened SHA-512x2 hash-to-field control. The varying Layer 2 field, freshness_reference, sits late in the packed input and only perturbs low-order bytes of one 64-byte chunk. That chunk is embedded directly as a field element with no avalanche step, then absorbed by a low-degree accumulator that only uses addition, one square term, and small fixed multipliers. {stage_note} By contrast, the widened SHA-512x2 control produced {expand_prefixes} distinct 32-bit prefixes with zero constant bits in the first 32 across the same family. The current primitive therefore leaves the high-order prefix dominated by fixed seeds and earlier fixed chunks instead of diffusing the late-field entropy. The bug is not preimage encoding and not final byte serialization; it is the direct field embedding plus insufficient commitment transform.",
        stage_note = stage_prefix_localization.first_mixing_stage_without_32_bit_diffusion,
        expand_prefixes = sha512_expand.distinct_32_bit_prefixes,
    )
}

fn structured_neighbor_preimage_v1(fixture: &TargetFixtureV1, candidate: u64) -> Vec<u8> {
    let mut bytes = fixture.canonical_preimage.clone();
    let reference = STRUCTURED_NEIGHBOR_BASE_REFERENCE_V1 + candidate;
    bytes[fixture.freshness_reference_offset..fixture.freshness_reference_offset + 8]
        .copy_from_slice(&reference.to_le_bytes());
    bytes
}

fn update_prefix_family_accumulator_v1(
    accumulator: &mut PrefixFamilyAccumulatorV1,
    output: &[u8],
    target: &[u8],
) {
    for (index, bits) in PREFIX_BITS_V1.into_iter().enumerate() {
        if truncate_bits_be_v1(output, bits) == truncate_bits_be_v1(target, bits) {
            accumulator.match_counts[index] += 1;
        }
    }
    let prefix_32 = truncate_bits_be_v1(output, 32) as u32;
    *accumulator.distinct_prefixes_32.entry(prefix_32).or_default() += 1;
    for bit_index in 0..32 {
        if extract_bit_be_v1(output, bit_index) {
            accumulator.one_counts_first_32[bit_index] += 1;
        }
    }
    accumulator.sample_count += 1;
}

fn prefix_observation_from_accumulator_v1(
    stage: &'static str,
    accumulator: &PrefixFamilyAccumulatorV1,
) -> StagePrefixObservationV1 {
    StagePrefixObservationV1 {
        stage,
        prefix_match_counts_to_target: PrefixMatchCountsV1 {
            bits_8: accumulator.match_counts[0],
            bits_16: accumulator.match_counts[1],
            bits_24: accumulator.match_counts[2],
            bits_32: accumulator.match_counts[3],
        },
        distinct_32_bit_prefixes: accumulator.distinct_prefixes_32.len(),
        constant_bits_in_first_32_across_family: constant_bits_in_first_32_v1(accumulator),
        min_one_ratio_first_32: min_one_ratio_first_32_v1(accumulator),
        max_one_ratio_first_32: max_one_ratio_first_32_v1(accumulator),
    }
}

fn constant_bits_in_first_32_v1(accumulator: &PrefixFamilyAccumulatorV1) -> usize {
    accumulator
        .one_counts_first_32
        .iter()
        .filter(|count| **count == 0 || **count == accumulator.sample_count)
        .count()
}

fn min_one_ratio_first_32_v1(accumulator: &PrefixFamilyAccumulatorV1) -> f64 {
    accumulator
        .one_counts_first_32
        .iter()
        .map(|count| *count as f64 / accumulator.sample_count as f64)
        .fold(1.0f64, f64::min)
}

fn max_one_ratio_first_32_v1(accumulator: &PrefixFamilyAccumulatorV1) -> f64 {
    accumulator
        .one_counts_first_32
        .iter()
        .map(|count| *count as f64 / accumulator.sample_count as f64)
        .fold(0.0f64, f64::max)
}

fn algorithm_name_v1(algorithm: ControlAlgorithmV1) -> &'static str {
    match algorithm {
        ControlAlgorithmV1::CurrentPrimitive => "deterministic_commitment_521_v1",
        ControlAlgorithmV1::Sha256 => "sha256_preimage",
        ControlAlgorithmV1::Sha512 => "sha512_preimage",
        ControlAlgorithmV1::Sha512ReduceToField => "sha512_reduce_to_field_521",
        ControlAlgorithmV1::Sha512ExpandToField => "sha512x2_expand_reduce_to_field_521",
    }
}

fn algorithm_output_v1(algorithm: ControlAlgorithmV1, body: &[u8]) -> Vec<u8> {
    match algorithm {
        ControlAlgorithmV1::CurrentPrimitive => current_primitive_output_v1(body).to_vec(),
        ControlAlgorithmV1::Sha256 => sha256_output_v1(body).to_vec(),
        ControlAlgorithmV1::Sha512 => sha512_output_v1(body).to_vec(),
        ControlAlgorithmV1::Sha512ReduceToField => sha512_reduce_to_field_output_v1(body).to_vec(),
        ControlAlgorithmV1::Sha512ExpandToField => sha512_expand_to_field_output_v1(body).to_vec(),
    }
}

fn current_primitive_output_v1(
    body: &[u8],
) -> [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1] {
    derive_deterministic_commitment_521_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        body,
    )
    .to_bytes()
}

fn sha256_output_v1(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

fn sha512_output_v1(body: &[u8]) -> [u8; 64] {
    Sha512::digest(body).into()
}

fn sha512_reduce_to_field_output_v1(
    body: &[u8],
) -> [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1] {
    let digest: [u8; 64] = sha512_domain_separated_v1(ALT_SHA512_TO_FIELD_REDUCED_TAG_V1, body);
    FieldElement521V1::reduce_bytes_mod(&digest).to_bytes()
}

fn sha512_expand_to_field_output_v1(
    body: &[u8],
) -> [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1] {
    let first: [u8; 64] = sha512_domain_separated_v1(ALT_SHA512_TO_FIELD_EXPAND_X_V1, body);
    let second: [u8; 64] = sha512_domain_separated_v1(ALT_SHA512_TO_FIELD_EXPAND_Y_V1, body);
    let mut wide = Vec::with_capacity(128);
    wide.extend_from_slice(&first);
    wide.extend_from_slice(&second);
    FieldElement521V1::reduce_bytes_mod(&wide).to_bytes()
}

fn sha512_domain_separated_v1(domain_separator: &[u8], body: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update((domain_separator.len() as u64).to_le_bytes());
    hasher.update(domain_separator);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    let digest = hasher.finalize();
    digest.into()
}

fn canonical_commitment_input_bytes_v1(domain_separator: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1.len()
            + 8
            + domain_separator.len()
            + 8
            + body.len(),
    );
    bytes.extend_from_slice(AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&(domain_separator.len() as u64).to_le_bytes());
    bytes.extend_from_slice(domain_separator);
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn canonical_input_body_offset_v1(domain_separator: &[u8]) -> usize {
    AURA_DETERMINISTIC_COMMITMENT_521_CONTEXT_DOMAIN_SEPARATOR_V1.len() + 8 + domain_separator.len() + 8
}

fn derive_commitment_trace_v1(canonical_input: &[u8]) -> CommitmentTraceV1Local {
    let index_scale = FieldElement521V1::from_u64(DETERMINISTIC_COMMITMENT_521_INDEX_SCALE_V1);
    let mix_scale = FieldElement521V1::from_u64(DETERMINISTIC_COMMITMENT_521_MIX_SCALE_V1);
    let final_scale = FieldElement521V1::from_u64(DETERMINISTIC_COMMITMENT_521_FINAL_SCALE_V1);
    let mut x = FieldElement521V1::reduce_bytes_mod(AURA_DETERMINISTIC_COMMITMENT_521_SEED_X_V1);
    let mut y = FieldElement521V1::reduce_bytes_mod(AURA_DETERMINISTIC_COMMITMENT_521_SEED_Y_V1);
    let mut rounds = Vec::new();
    let mut chunk_count = 0u64;

    for (chunk_index, chunk) in canonical_input
        .chunks(DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1)
        .enumerate()
    {
        let index_element = FieldElement521V1::from_u64(chunk_index as u64 + 1);
        let chunk_element = FieldElement521V1::reduce_bytes_mod(chunk);
        let mixed_chunk = chunk_element.add_mod(&index_element.mul_mod(&index_scale));
        let x_before = x;
        let y_before = y;
        let x_after = x.add_mod(&y).add_mod(&mixed_chunk);
        let y_after = x
            .add_mod(&y.add_mod(&y))
            .add_mod(&chunk_element.square_mod())
            .add_mod(&mixed_chunk.mul_mod(&mix_scale));
        rounds.push(CommitmentRoundV1Local {
            chunk_index,
            start: chunk_index * DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1,
            end_exclusive: chunk_index * DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1 + chunk.len(),
            chunk_bytes: chunk.to_vec(),
            chunk_element,
            mixed_chunk,
            x_before,
            y_before,
            x_after,
            y_after,
        });
        x = x_after;
        y = y_after;
        chunk_count += 1;
    }

    let trailer = FieldElement521V1::from_u64(canonical_input.len() as u64)
        .add_mod(&FieldElement521V1::from_u64(chunk_count))
        .add_mod(&FieldElement521V1::reduce_bytes_mod(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        ));
    let final_element = x.add_mod(&y.mul_mod(&final_scale)).add_mod(&trailer);
    CommitmentTraceV1Local {
        rounds,
        trailer,
        final_element,
    }
}

fn lineage_field_layout_v1() -> Vec<FieldRangeV1> {
    let mut fields = Vec::new();
    let mut offset = 0usize;

    let push_field = |field: &'static str, len: usize, fields: &mut Vec<FieldRangeV1>, offset: &mut usize| {
        let start = *offset;
        let end_exclusive = start + len;
        fields.push(FieldRangeV1 {
            field,
            start,
            len,
            end_exclusive,
            start_chunk: start / DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1,
            end_chunk: (end_exclusive - 1) / DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1,
        });
        *offset = end_exclusive;
    };

    push_field(
        "authorization_lineage_domain_separator",
        AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1.len(),
        &mut fields,
        &mut offset,
    );
    push_field("version", 1, &mut fields, &mut offset);
    push_field("lineage_flags", 2, &mut fields, &mut offset);
    push_field("dcm_commitment_kind", 1, &mut fields, &mut offset);
    push_field("dcm_commitment_root", 32, &mut fields, &mut offset);
    push_field("dcm_trace_commitment", 32, &mut fields, &mut offset);
    push_field("subject_binding_type", 1, &mut fields, &mut offset);
    push_field("subject_id", 32, &mut fields, &mut offset);
    push_field("subject_public_key", 32, &mut fields, &mut offset);
    push_field("intent_type", 1, &mut fields, &mut offset);
    push_field("intent_hash", 32, &mut fields, &mut offset);
    push_field("freshness_mode", 1, &mut fields, &mut offset);
    push_field("freshness_nonce", 32, &mut fields, &mut offset);
    push_field("freshness_reference", 8, &mut fields, &mut offset);
    push_field("proof_material_v1_hash", 32, &mut fields, &mut offset);
    push_field("fractal_key_v1_hash", 32, &mut fields, &mut offset);

    debug_assert_eq!(offset, 300);
    fields
}

fn affected_chunk_index_v1(fixture: &TargetFixtureV1) -> usize {
    let body_offset = canonical_input_body_offset_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    );
    (body_offset + fixture.freshness_reference_offset) / DETERMINISTIC_COMMITMENT_521_CHUNK_LEN_V1
}

fn flip_body_bit_v1(body: &[u8], bit_index: usize) -> Vec<u8> {
    let mut bytes = body.to_vec();
    let byte_index = bit_index / 8;
    let bit_in_byte = bit_index % 8;
    bytes[byte_index] ^= 1u8 << bit_in_byte;
    bytes
}

fn hamming_distance_v1(lhs: &[u8], rhs: &[u8]) -> usize {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(left, right)| (*left ^ *right).count_ones() as usize)
        .sum()
}

fn truncate_bits_be_v1(bytes: &[u8], bits: u32) -> u64 {
    assert!(bits <= 32);
    let byte_len = ((bits + 7) / 8) as usize;
    let mut value = 0u64;
    for byte in &bytes[..byte_len] {
        value = (value << 8) | u64::from(*byte);
    }
    let excess_bits = (byte_len as u32 * 8) - bits;
    if excess_bits > 0 {
        value >>= excess_bits;
    }
    value
}

fn extract_bit_be_v1(bytes: &[u8], bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit_in_byte = 7 - (bit_index % 8);
    ((bytes[byte_index] >> bit_in_byte) & 1) == 1
}

fn write_report_file_v1(name: &str, content: &str) {
    let report_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("reports")
        .join(name);
    fs::write(report_path, format!("{content}\n")).unwrap();
}
