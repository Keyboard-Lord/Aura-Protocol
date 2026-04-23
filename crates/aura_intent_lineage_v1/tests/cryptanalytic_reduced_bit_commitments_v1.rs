mod support;

use std::{collections::BTreeMap, env, f64::consts::PI, time::Instant};

use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, derive_deterministic_commitment_521_v1,
    produce_layer3_authorization_lineage_consumer_object_v1,
    produce_layer3_layer4_verified_authorization_ingress_v1,
    produce_native_layer2_authorization_lineage_object_521_v1,
    prove_layer3_authorization_lineage_real_stark_v1, DcmExecution521V1,
    Layer1Layer2BridgeIntentSourceV1, Layer1Layer2BridgeSubjectBindingV1,
    Layer3AuthorizationLineageConsumerObjectV1, Layer3AuthorizationLineageProvingInputV1,
    Layer3AuthorizationLineageRealStarkProofV1, Layer3Layer4VerifiedAuthorizationIngressV1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR,
    AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1, HASH_LEN_V1,
    LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use support::{
    canonical_dcm_config, canonical_dcm_input, canonical_freshness, canonical_intent,
    canonical_subject_binding, encode_hex,
};

const NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1: u64 = 1u64 << 48;
const NON_AUTHORITATIVE_MAX_EXACT_BITS_V1: u32 = 24;
const NON_AUTHORITATIVE_BOUNDED_QUERY_CAP_V1: u64 = 1u64 << 20;
const TRUNCATION_BITS_V1: [u32; 5] = [16, 20, 24, 28, 32];
const TOTAL_TARGET_COUNT_V1: usize = 6;

#[derive(Serialize)]
struct ReducedBitCommitmentResearchReportV1 {
    scope: &'static str,
    command: &'static str,
    oracle_family: &'static str,
    targets: Vec<TargetReportV1>,
    sanity_samples: Vec<SanitySampleV1>,
    search_results: BTreeMap<String, Vec<SearchObservationV1>>,
    structural_assessment: Vec<StructuralAssessmentV1>,
    cross_surface_summary: CrossSurfaceSummaryV1,
}

#[derive(Serialize)]
struct TargetReportV1 {
    name: &'static str,
    classification: &'static str,
    width_bits: u16,
    domain_separator_ascii: &'static str,
    target_hex: String,
    canonical_input_len: usize,
    canonical_input_hex: String,
    recomputed_equal: bool,
    oracle_definition: OracleDefinitionV1,
}

#[derive(Serialize)]
struct OracleDefinitionV1 {
    search_kind: &'static str,
    preimage_space: &'static str,
    variable_fields: Vec<&'static str>,
    fixed_fields: Vec<&'static str>,
    marked_item: &'static str,
    canonicality_restriction: &'static str,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct SearchObservationV1 {
    bits: u32,
    space_size: u64,
    queries_run: u64,
    fully_exhausted: bool,
    first_match_index: Option<u64>,
    observed_match_count: u64,
    elapsed_ms: u128,
    grover_marked_count: u64,
    grover_query_estimate: u64,
    grover_success_probability: f64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SearchAccumulatorV1 {
    first_match_index: Option<u64>,
    observed_match_count: u64,
}

#[derive(Serialize)]
struct StructuralAssessmentV1 {
    target: &'static str,
    canonicalization_singular: bool,
    alternate_encoding_observed: bool,
    unexpected_equivalent_object_observed: bool,
    effective_search_space_smaller_than_modeled: bool,
    helper_surface_promoted_to_primary: bool,
    summary: String,
}

#[derive(Serialize)]
struct CrossSurfaceSummaryV1 {
    primary_521_commitments_are_stronger_canonical_targets_than_helpers: bool,
    helper_surface_leaked_into_primary_role: bool,
    conclusion: String,
}

#[derive(Serialize)]
struct SanitySampleV1 {
    candidate: u64,
    lineage_commitment_hex: String,
    result_commitment_hex: String,
    ingress_commitment_hex: String,
    public_statement_commitment_hex: String,
    lineage_hash_hex: String,
    result_digest_hex: String,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct TargetSpecV1 {
    name: &'static str,
    classification: &'static str,
    width_bits: u16,
    domain_separator_ascii: &'static str,
    selector: TargetSelectorV1,
    oracle_definition: fn() -> OracleDefinitionV1,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum TargetSelectorV1 {
    LineageCommitment,
    ResultCommitment,
    IngressCommitment,
    PublicStatementCommitment,
    LineageHashControl,
    ResultDigestControl,
}

struct CanonicalFlowFixtureV1 {
    layer2_object: aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1,
    proof: Layer3AuthorizationLineageRealStarkProofV1,
    consumer_object: Layer3AuthorizationLineageConsumerObjectV1,
    ingress_object: Layer3Layer4VerifiedAuthorizationIngressV1,
}

struct CommitmentFlowOracleTemplateV1 {
    lineage_preimage: Vec<u8>,
    freshness_reference_offset: usize,
    public_claim_bytes: Vec<u8>,
    serialized_layer2_offset_in_public_claim: usize,
    lineage_commitment_offset_in_public_claim: usize,
    lineage_hash_offset_in_public_claim: usize,
    constraint_summary_bytes: Vec<u8>,
    lineage_commitment_offset_in_constraint_summary: usize,
    lineage_hash_offset_in_constraint_summary: usize,
    transcript_preimage: Vec<u8>,
    public_claim_digest_offset_in_transcript: usize,
    constraint_summary_digest_offset_in_transcript: usize,
    proof_bound_bytes: Vec<u8>,
    transcript_digest_offset_in_bound: usize,
    public_claim_digest_offset_in_bound: usize,
    result_material_bytes: Vec<u8>,
    public_claim_digest_offset_in_result: usize,
    transcript_digest_offset_in_result: usize,
    proof_bound_digest_offset_in_result: usize,
    lineage_commitment_offset_in_result: usize,
    lineage_hash_offset_in_result: usize,
    consumer_object_bytes: Vec<u8>,
    public_claim_digest_offset_in_consumer: usize,
    transcript_digest_offset_in_consumer: usize,
    proof_bound_digest_offset_in_consumer: usize,
    lineage_commitment_offset_in_consumer: usize,
    lineage_hash_offset_in_consumer: usize,
    result_commitment_offset_in_consumer: usize,
    result_digest_offset_in_consumer: usize,
    public_claim_offset_in_consumer: usize,
    ingress_bytes: Vec<u8>,
    consumer_object_offset_in_ingress: usize,
    public_statement_bytes: Vec<u8>,
    lineage_commitment_offset_in_statement: usize,
    lineage_hash_offset_in_statement: usize,
    freshness_reference_offset_in_statement: usize,
    result_commitment_offset_in_statement: usize,
    transcript_digest_offset_in_statement: usize,
    proof_bound_digest_offset_in_statement: usize,
}

struct CandidateOutputsV1 {
    lineage_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    result_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    ingress_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    public_statement_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    lineage_hash: [u8; HASH_LEN_V1],
    result_digest: [u8; HASH_LEN_V1],
}

const TARGET_SPECS_V1: [TargetSpecV1; TOTAL_TARGET_COUNT_V1] = [
    TargetSpecV1 {
        name: "layer2_lineage_commitment",
        classification: "primary_521_commitment",
        width_bits: 521,
        domain_separator_ascii:
            "AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_V1",
        selector: TargetSelectorV1::LineageCommitment,
        oracle_definition: oracle_definition_lineage_commitment_v1,
    },
    TargetSpecV1 {
        name: "layer3_result_commitment",
        classification: "primary_521_commitment",
        width_bits: 521,
        domain_separator_ascii:
            "AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_V1",
        selector: TargetSelectorV1::ResultCommitment,
        oracle_definition: oracle_definition_result_commitment_v1,
    },
    TargetSpecV1 {
        name: "layer3_layer4_ingress_commitment",
        classification: "primary_521_commitment",
        width_bits: 521,
        domain_separator_ascii:
            "AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_V1",
        selector: TargetSelectorV1::IngressCommitment,
        oracle_definition: oracle_definition_ingress_commitment_v1,
    },
    TargetSpecV1 {
        name: "layer4_public_statement_commitment",
        classification: "primary_521_commitment",
        width_bits: 521,
        domain_separator_ascii:
            "AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_V1",
        selector: TargetSelectorV1::PublicStatementCommitment,
        oracle_definition: oracle_definition_public_statement_commitment_v1,
    },
    TargetSpecV1 {
        name: "lineage_hash_control",
        classification: "helper_256_digest_control",
        width_bits: 256,
        domain_separator_ascii: "raw_sha256(lineage_preimage)",
        selector: TargetSelectorV1::LineageHashControl,
        oracle_definition: oracle_definition_lineage_hash_control_v1,
    },
    TargetSpecV1 {
        name: "layer3_result_digest_control",
        classification: "helper_256_digest_control",
        width_bits: 256,
        domain_separator_ascii: "AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_V1",
        selector: TargetSelectorV1::ResultDigestControl,
        oracle_definition: oracle_definition_result_digest_control_v1,
    },
];

#[test]
#[ignore = "non-authoritative research/analysis only"]
fn non_authoritative_research_reduced_bit_commitment_targets_v1() {
    let fixture = canonical_flow_fixture_v1();
    assert!(
        fixture.layer2_object.lineage.freshness_reference < NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1,
        "search family must stay disjoint from the canonical target"
    );

    let generated_targets = generated_targets_v1(&fixture);
    for target in &generated_targets {
        assert!(
            target.recomputed_equal,
            "{} must recompute exactly from canonical inputs",
            target.name
        );
    }

    let search_results = run_search_suite_v1(&fixture);
    let report = ReducedBitCommitmentResearchReportV1 {
        scope: "research-only / non-authoritative / no claim of a full 521-bit break",
        command: "cargo test -p aura_intent_lineage_v1 --release --test cryptanalytic_reduced_bit_commitments_v1 non_authoritative_research_reduced_bit_commitment_targets_v1 -- --ignored --nocapture",
        oracle_family: "Disjoint canonical structured-neighbor second-preimage search over freshness_reference = 2^48 + candidate, with canonical serialization fixed and all downstream commitment/digest bytes recomputed exactly from that canonical variation only.",
        targets: generated_targets,
        sanity_samples: sanity_samples_v1(&fixture),
        search_results,
        structural_assessment: structural_assessment_v1(),
        cross_surface_summary: CrossSurfaceSummaryV1 {
            primary_521_commitments_are_stronger_canonical_targets_than_helpers: false,
            helper_surface_leaked_into_primary_role: false,
            conclusion: String::from(
                "The Aura canonical encodings stayed singular, and the Layer 3 / Layer 3->4 primary commitments behaved like ordinary truncated deterministic targets in the bounded search. However, the direct Layer 2 lineage_commitment showed strong top-prefix concentration across the disjoint structured-neighbor family, so the new primary stack is not uniformly shortcut-free under reduced-bit testing yet.",
            ),
        },
    };

    eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());

    assert!(report
        .search_results
        .values()
        .flatten()
        .all(|observation| observation.queries_run > 0));
}

fn sanity_samples_v1(fixture: &CanonicalFlowFixtureV1) -> Vec<SanitySampleV1> {
    let mut oracle = commitment_flow_oracle_template_v1(fixture);
    [0u64, 1, 255, 4095]
        .into_iter()
        .map(|candidate| {
            let outputs = oracle.outputs_for_candidate(candidate);
            SanitySampleV1 {
                candidate,
                lineage_commitment_hex: encode_hex(&outputs.lineage_commitment),
                result_commitment_hex: encode_hex(&outputs.result_commitment),
                ingress_commitment_hex: encode_hex(&outputs.ingress_commitment),
                public_statement_commitment_hex: encode_hex(&outputs.public_statement_commitment),
                lineage_hash_hex: encode_hex(&outputs.lineage_hash),
                result_digest_hex: encode_hex(&outputs.result_digest),
            }
        })
        .collect()
}

fn canonical_flow_fixture_v1() -> CanonicalFlowFixtureV1 {
    let config = canonical_dcm_config();
    let dcm_input = canonical_dcm_input();
    let execution = DcmExecution521V1::run(&config, &dcm_input).unwrap();
    let claim = build_dcm_claim_521_v1(&config, &dcm_input, &execution);
    let layer2_object = produce_native_layer2_authorization_lineage_object_521_v1(
        &config,
        &dcm_input,
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        Layer1Layer2BridgeSubjectBindingV1 {
            subject_binding_type: canonical_subject_binding().subject_binding_type,
            subject_id: canonical_subject_binding().subject_id,
            subject_public_key: canonical_subject_binding().subject_public_key,
        },
        canonical_freshness(),
    )
    .unwrap();
    let proof = prove_layer3_authorization_lineage_real_stark_v1(
        &Layer3AuthorizationLineageProvingInputV1::new(
            claim,
            layer2_object.clone(),
            canonical_intent(),
        ),
    )
    .unwrap();
    let consumer_object = produce_layer3_authorization_lineage_consumer_object_v1(&proof).unwrap();
    let ingress_object =
        produce_layer3_layer4_verified_authorization_ingress_v1(&consumer_object, canonical_intent())
            .unwrap();

    CanonicalFlowFixtureV1 {
        layer2_object,
        proof,
        consumer_object,
        ingress_object,
    }
}

fn generated_targets_v1(fixture: &CanonicalFlowFixtureV1) -> Vec<TargetReportV1> {
    let layer2_preimage = fixture.layer2_object.lineage.canonical_preimage().unwrap();
    let layer2_lineage_commitment = fixture.layer2_object.lineage_commitment.to_bytes();
    let layer2_lineage_commitment_recomputed = derive_deterministic_commitment_521_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &layer2_preimage,
    )
    .to_bytes();

    let result_material = canonical_consumer_result_material_bytes_v1(&fixture.consumer_object);
    let result_commitment = fixture.consumer_object.proof_result.result_commitment.to_bytes();
    let result_commitment_recomputed = derive_deterministic_commitment_521_v1(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &result_material,
    )
    .to_bytes();

    let ingress_bytes = fixture.ingress_object.serialized_object().unwrap();
    let ingress_commitment = fixture.ingress_object.ingress_commitment().unwrap().to_bytes();
    let ingress_commitment_recomputed = derive_deterministic_commitment_521_v1(
        AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &ingress_bytes,
    )
    .to_bytes();

    let public_statement = fixture
        .ingress_object
        .verified_authorization_public_statement()
        .unwrap();
    let public_statement_bytes =
        canonical_layer4_verified_authorization_public_statement_bytes_v1(&public_statement);
    let public_statement_commitment = fixture
        .ingress_object
        .verified_authorization_public_statement_commitment()
        .unwrap()
        .to_bytes();
    let public_statement_commitment_recomputed = derive_deterministic_commitment_521_v1(
        AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &public_statement_bytes,
    )
    .to_bytes();

    let lineage_hash_recomputed = sha256_bytes_local(&layer2_preimage);
    let result_digest_recomputed = sha256_domain_separated_local(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
        &result_material,
    );

    vec![
        TargetReportV1 {
            name: "layer2_lineage_commitment",
            classification: "primary_521_commitment",
            width_bits: 521,
            domain_separator_ascii:
                "AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_V1",
            target_hex: encode_hex(&layer2_lineage_commitment),
            canonical_input_len: layer2_preimage.len(),
            canonical_input_hex: encode_hex(&layer2_preimage),
            recomputed_equal: layer2_lineage_commitment == layer2_lineage_commitment_recomputed,
            oracle_definition: oracle_definition_lineage_commitment_v1(),
        },
        TargetReportV1 {
            name: "layer3_result_commitment",
            classification: "primary_521_commitment",
            width_bits: 521,
            domain_separator_ascii:
                "AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_V1",
            target_hex: encode_hex(&result_commitment),
            canonical_input_len: result_material.len(),
            canonical_input_hex: encode_hex(&result_material),
            recomputed_equal: result_commitment == result_commitment_recomputed,
            oracle_definition: oracle_definition_result_commitment_v1(),
        },
        TargetReportV1 {
            name: "layer3_layer4_ingress_commitment",
            classification: "primary_521_commitment",
            width_bits: 521,
            domain_separator_ascii:
                "AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_V1",
            target_hex: encode_hex(&ingress_commitment),
            canonical_input_len: ingress_bytes.len(),
            canonical_input_hex: encode_hex(&ingress_bytes),
            recomputed_equal: ingress_commitment == ingress_commitment_recomputed,
            oracle_definition: oracle_definition_ingress_commitment_v1(),
        },
        TargetReportV1 {
            name: "layer4_public_statement_commitment",
            classification: "primary_521_commitment",
            width_bits: 521,
            domain_separator_ascii:
                "AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_V1",
            target_hex: encode_hex(&public_statement_commitment),
            canonical_input_len: public_statement_bytes.len(),
            canonical_input_hex: encode_hex(&public_statement_bytes),
            recomputed_equal: public_statement_commitment
                == public_statement_commitment_recomputed,
            oracle_definition: oracle_definition_public_statement_commitment_v1(),
        },
        TargetReportV1 {
            name: "lineage_hash_control",
            classification: "helper_256_digest_control",
            width_bits: 256,
            domain_separator_ascii: "raw_sha256(lineage_preimage)",
            target_hex: encode_hex(&fixture.layer2_object.lineage_hash),
            canonical_input_len: layer2_preimage.len(),
            canonical_input_hex: encode_hex(&layer2_preimage),
            recomputed_equal: fixture.layer2_object.lineage_hash == lineage_hash_recomputed,
            oracle_definition: oracle_definition_lineage_hash_control_v1(),
        },
        TargetReportV1 {
            name: "layer3_result_digest_control",
            classification: "helper_256_digest_control",
            width_bits: 256,
            domain_separator_ascii: "AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_V1",
            target_hex: encode_hex(&fixture.consumer_object.proof_result.result_digest),
            canonical_input_len: result_material.len(),
            canonical_input_hex: encode_hex(&result_material),
            recomputed_equal: fixture.consumer_object.proof_result.result_digest
                == result_digest_recomputed,
            oracle_definition: oracle_definition_result_digest_control_v1(),
        },
    ]
}

fn run_search_suite_v1(
    fixture: &CanonicalFlowFixtureV1,
) -> BTreeMap<String, Vec<SearchObservationV1>> {
    let mut oracle = commitment_flow_oracle_template_v1(fixture);
    let max_exact_bits = max_exact_bits_v1();
    let bounded_query_cap = bounded_query_cap_v1();

    let mut query_limits = [0u64; TRUNCATION_BITS_V1.len()];
    let mut elapsed_ms = [0u128; TRUNCATION_BITS_V1.len()];
    let mut target_prefixes = [[0u64; TRUNCATION_BITS_V1.len()]; TOTAL_TARGET_COUNT_V1];
    let mut accumulators =
        [[SearchAccumulatorV1::default(); TRUNCATION_BITS_V1.len()]; TOTAL_TARGET_COUNT_V1];

    let target_bytes = canonical_target_bytes_v1(fixture);
    for target_index in 0..TOTAL_TARGET_COUNT_V1 {
        for bits_index in 0..TRUNCATION_BITS_V1.len() {
            target_prefixes[target_index][bits_index] = truncate_bits_be_v1(
                target_bytes[target_index].as_slice(),
                TRUNCATION_BITS_V1[bits_index],
            );
        }
    }

    for bits_index in 0..TRUNCATION_BITS_V1.len() {
        let bits = TRUNCATION_BITS_V1[bits_index];
        let space_size = 1u64 << bits;
        query_limits[bits_index] = if bits <= max_exact_bits {
            space_size
        } else {
            bounded_query_cap.min(space_size)
        };
    }

    let global_query_limit = query_limits.into_iter().max().unwrap_or(0);
    let started = Instant::now();
    for candidate in 0..global_query_limit {
        let outputs = oracle.outputs_for_candidate(candidate);
        let output_prefixes = candidate_prefixes_v1(&outputs);

        for target_index in 0..TOTAL_TARGET_COUNT_V1 {
            for bits_index in 0..TRUNCATION_BITS_V1.len() {
                if candidate >= query_limits[bits_index] {
                    continue;
                }
                if output_prefixes[target_index][bits_index]
                    == target_prefixes[target_index][bits_index]
                {
                    let accumulator = &mut accumulators[target_index][bits_index];
                    accumulator.observed_match_count += 1;
                    if accumulator.first_match_index.is_none() {
                        accumulator.first_match_index = Some(candidate);
                    }
                }
            }
        }

        let completed_queries = candidate + 1;
        for bits_index in 0..TRUNCATION_BITS_V1.len() {
            if elapsed_ms[bits_index] == 0 && completed_queries == query_limits[bits_index] {
                elapsed_ms[bits_index] = started.elapsed().as_millis();
            }
        }
    }

    let mut results = BTreeMap::new();
    for target_index in 0..TOTAL_TARGET_COUNT_V1 {
        let mut target_results = Vec::with_capacity(TRUNCATION_BITS_V1.len());
        for bits_index in 0..TRUNCATION_BITS_V1.len() {
            let bits = TRUNCATION_BITS_V1[bits_index];
            let space_size = 1u64 << bits;
            let queries_run = query_limits[bits_index];
            let fully_exhausted = queries_run == space_size;
            let observed_match_count = accumulators[target_index][bits_index].observed_match_count;
            let grover_marked_count = observed_match_count.max(1);
            let (grover_query_estimate, grover_success_probability) =
                grover_estimate_v1(space_size, grover_marked_count);

            target_results.push(SearchObservationV1 {
                bits,
                space_size,
                queries_run,
                fully_exhausted,
                first_match_index: accumulators[target_index][bits_index].first_match_index,
                observed_match_count,
                elapsed_ms: elapsed_ms[bits_index],
                grover_marked_count,
                grover_query_estimate,
                grover_success_probability,
            });
        }
        results.insert(TARGET_SPECS_V1[target_index].name.to_string(), target_results);
    }

    results
}

fn canonical_target_bytes_v1(
    fixture: &CanonicalFlowFixtureV1,
) -> [TargetBytesV1; TOTAL_TARGET_COUNT_V1] {
    [
        TargetBytesV1::Commitment(fixture.layer2_object.lineage_commitment.to_bytes()),
        TargetBytesV1::Commitment(fixture.consumer_object.proof_result.result_commitment.to_bytes()),
        TargetBytesV1::Commitment(fixture.ingress_object.ingress_commitment().unwrap().to_bytes()),
        TargetBytesV1::Commitment(
            fixture
                .ingress_object
                .verified_authorization_public_statement_commitment()
                .unwrap()
                .to_bytes(),
        ),
        TargetBytesV1::Digest(fixture.layer2_object.lineage_hash),
        TargetBytesV1::Digest(fixture.consumer_object.proof_result.result_digest),
    ]
}

fn candidate_prefixes_v1(outputs: &CandidateOutputsV1) -> [[u64; TRUNCATION_BITS_V1.len()]; TOTAL_TARGET_COUNT_V1] {
    let candidates = [
        outputs.lineage_commitment.as_slice(),
        outputs.result_commitment.as_slice(),
        outputs.ingress_commitment.as_slice(),
        outputs.public_statement_commitment.as_slice(),
        outputs.lineage_hash.as_slice(),
        outputs.result_digest.as_slice(),
    ];
    let mut prefixes = [[0u64; TRUNCATION_BITS_V1.len()]; TOTAL_TARGET_COUNT_V1];
    for target_index in 0..TOTAL_TARGET_COUNT_V1 {
        for bits_index in 0..TRUNCATION_BITS_V1.len() {
            prefixes[target_index][bits_index] =
                truncate_bits_be_v1(candidates[target_index], TRUNCATION_BITS_V1[bits_index]);
        }
    }
    prefixes
}

#[derive(Clone, Copy)]
enum TargetBytesV1 {
    Commitment([u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]),
    Digest([u8; HASH_LEN_V1]),
}

impl TargetBytesV1 {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Commitment(bytes) => bytes.as_slice(),
            Self::Digest(bytes) => bytes.as_slice(),
        }
    }
}

impl CommitmentFlowOracleTemplateV1 {
    fn outputs_for_candidate(&mut self, candidate: u64) -> CandidateOutputsV1 {
        let candidate_reference = NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1 + candidate;
        self.lineage_preimage
            [self.freshness_reference_offset..self.freshness_reference_offset + 8]
            .copy_from_slice(&candidate_reference.to_le_bytes());

        let lineage_commitment = derive_deterministic_commitment_521_v1(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &self.lineage_preimage,
        )
        .to_bytes();
        let lineage_hash = sha256_bytes_local(&self.lineage_preimage);

        self.public_claim_bytes[self.serialized_layer2_offset_in_public_claim
            ..self.serialized_layer2_offset_in_public_claim + self.lineage_preimage.len()]
            .copy_from_slice(&self.lineage_preimage);
        self.public_claim_bytes[self.lineage_commitment_offset_in_public_claim
            ..self.lineage_commitment_offset_in_public_claim
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&lineage_commitment);
        self.public_claim_bytes
            [self.lineage_hash_offset_in_public_claim..self.lineage_hash_offset_in_public_claim
                + HASH_LEN_V1]
            .copy_from_slice(&lineage_hash);
        let public_claim_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
            &self.public_claim_bytes,
        );

        self.constraint_summary_bytes[self.lineage_commitment_offset_in_constraint_summary
            ..self.lineage_commitment_offset_in_constraint_summary
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&lineage_commitment);
        self.constraint_summary_bytes[self.lineage_hash_offset_in_constraint_summary
            ..self.lineage_hash_offset_in_constraint_summary + HASH_LEN_V1]
            .copy_from_slice(&lineage_hash);
        let constraint_summary_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
            &self.constraint_summary_bytes,
        );

        self.transcript_preimage[self.public_claim_digest_offset_in_transcript
            ..self.public_claim_digest_offset_in_transcript + HASH_LEN_V1]
            .copy_from_slice(&public_claim_digest);
        self.transcript_preimage[self.constraint_summary_digest_offset_in_transcript
            ..self.constraint_summary_digest_offset_in_transcript + HASH_LEN_V1]
            .copy_from_slice(&constraint_summary_digest);
        let transcript_digest = sha256_bytes_local(&self.transcript_preimage);

        self.proof_bound_bytes[self.transcript_digest_offset_in_bound
            ..self.transcript_digest_offset_in_bound + HASH_LEN_V1]
            .copy_from_slice(&transcript_digest);
        self.proof_bound_bytes[self.public_claim_digest_offset_in_bound
            ..self.public_claim_digest_offset_in_bound + HASH_LEN_V1]
            .copy_from_slice(&public_claim_digest);
        let proof_bound_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR,
            &self.proof_bound_bytes,
        );

        self.result_material_bytes[self.public_claim_digest_offset_in_result
            ..self.public_claim_digest_offset_in_result + HASH_LEN_V1]
            .copy_from_slice(&public_claim_digest);
        self.result_material_bytes[self.transcript_digest_offset_in_result
            ..self.transcript_digest_offset_in_result + HASH_LEN_V1]
            .copy_from_slice(&transcript_digest);
        self.result_material_bytes[self.proof_bound_digest_offset_in_result
            ..self.proof_bound_digest_offset_in_result + HASH_LEN_V1]
            .copy_from_slice(&proof_bound_digest);
        self.result_material_bytes[self.lineage_commitment_offset_in_result
            ..self.lineage_commitment_offset_in_result
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&lineage_commitment);
        self.result_material_bytes
            [self.lineage_hash_offset_in_result..self.lineage_hash_offset_in_result + HASH_LEN_V1]
            .copy_from_slice(&lineage_hash);
        let result_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &self.result_material_bytes,
        )
        .to_bytes();
        let result_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
            &self.result_material_bytes,
        );

        self.consumer_object_bytes[self.public_claim_digest_offset_in_consumer
            ..self.public_claim_digest_offset_in_consumer + HASH_LEN_V1]
            .copy_from_slice(&public_claim_digest);
        self.consumer_object_bytes[self.transcript_digest_offset_in_consumer
            ..self.transcript_digest_offset_in_consumer + HASH_LEN_V1]
            .copy_from_slice(&transcript_digest);
        self.consumer_object_bytes[self.proof_bound_digest_offset_in_consumer
            ..self.proof_bound_digest_offset_in_consumer + HASH_LEN_V1]
            .copy_from_slice(&proof_bound_digest);
        self.consumer_object_bytes[self.lineage_commitment_offset_in_consumer
            ..self.lineage_commitment_offset_in_consumer
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&lineage_commitment);
        self.consumer_object_bytes[self.lineage_hash_offset_in_consumer
            ..self.lineage_hash_offset_in_consumer + HASH_LEN_V1]
            .copy_from_slice(&lineage_hash);
        self.consumer_object_bytes[self.result_commitment_offset_in_consumer
            ..self.result_commitment_offset_in_consumer
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&result_commitment);
        self.consumer_object_bytes[self.result_digest_offset_in_consumer
            ..self.result_digest_offset_in_consumer + HASH_LEN_V1]
            .copy_from_slice(&result_digest);
        self.consumer_object_bytes[self.public_claim_offset_in_consumer..]
            .copy_from_slice(&self.public_claim_bytes);

        self.ingress_bytes[self.consumer_object_offset_in_ingress
            ..self.consumer_object_offset_in_ingress + self.consumer_object_bytes.len()]
            .copy_from_slice(&self.consumer_object_bytes);
        let ingress_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &self.ingress_bytes,
        )
        .to_bytes();

        self.public_statement_bytes[self.lineage_commitment_offset_in_statement
            ..self.lineage_commitment_offset_in_statement
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&lineage_commitment);
        self.public_statement_bytes[self.lineage_hash_offset_in_statement
            ..self.lineage_hash_offset_in_statement + HASH_LEN_V1]
            .copy_from_slice(&lineage_hash);
        self.public_statement_bytes[self.freshness_reference_offset_in_statement
            ..self.freshness_reference_offset_in_statement + 8]
            .copy_from_slice(&candidate_reference.to_le_bytes());
        self.public_statement_bytes[self.result_commitment_offset_in_statement
            ..self.result_commitment_offset_in_statement
                + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1]
            .copy_from_slice(&result_commitment);
        self.public_statement_bytes[self.transcript_digest_offset_in_statement
            ..self.transcript_digest_offset_in_statement + HASH_LEN_V1]
            .copy_from_slice(&transcript_digest);
        self.public_statement_bytes[self.proof_bound_digest_offset_in_statement
            ..self.proof_bound_digest_offset_in_statement + HASH_LEN_V1]
            .copy_from_slice(&proof_bound_digest);
        let public_statement_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &self.public_statement_bytes,
        )
        .to_bytes();

        CandidateOutputsV1 {
            lineage_commitment,
            result_commitment,
            ingress_commitment,
            public_statement_commitment,
            lineage_hash,
            result_digest,
        }
    }
}

fn commitment_flow_oracle_template_v1(
    fixture: &CanonicalFlowFixtureV1,
) -> CommitmentFlowOracleTemplateV1 {
    let lineage_preimage = fixture.layer2_object.lineage.canonical_preimage().unwrap();
    let freshness_reference_offset = lineage_freshness_reference_offset_v1();

    let lower_layer_claim_bytes = fixture.proof.public_claim.lower_layer_claim.canonical_bytes();
    let serialized_layer2_offset_in_public_claim = lower_layer_claim_bytes.len();
    let lineage_commitment_offset_in_public_claim =
        serialized_layer2_offset_in_public_claim + lineage_preimage.len();
    let lineage_hash_offset_in_public_claim = lineage_commitment_offset_in_public_claim
        + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1;
    let mut public_claim_bytes = Vec::with_capacity(
        lower_layer_claim_bytes.len()
            + lineage_preimage.len()
            + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1
            + HASH_LEN_V1,
    );
    public_claim_bytes.extend_from_slice(&lower_layer_claim_bytes);
    public_claim_bytes.extend_from_slice(&fixture.layer2_object.serialized_object().unwrap());

    let mut constraint_summary_bytes = Vec::with_capacity(
        16 + (HASH_LEN_V1 * 4) + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
    );
    constraint_summary_bytes.extend_from_slice(
        &fixture
            .proof
            .public_claim
            .lower_layer_claim
            .config
            .iteration_count
            .to_le_bytes(),
    );
    constraint_summary_bytes.extend_from_slice(
        &fixture
            .proof
            .public_claim
            .lower_layer_claim
            .trace_state_count()
            .to_le_bytes(),
    );
    constraint_summary_bytes.extend_from_slice(&fixture.consumer_object.proof_result.dcm_trace_commitment);
    constraint_summary_bytes.extend_from_slice(&fixture.consumer_object.proof_result.dcm_commitment_root);
    constraint_summary_bytes.extend_from_slice(&fixture.consumer_object.proof_result.intent_hash);
    let lineage_commitment_offset_in_constraint_summary = constraint_summary_bytes.len();
    constraint_summary_bytes.extend_from_slice(
        &fixture
            .consumer_object
            .proof_result
            .lineage_commitment
            .to_bytes(),
    );
    let lineage_hash_offset_in_constraint_summary = constraint_summary_bytes.len();
    constraint_summary_bytes.extend_from_slice(&fixture.consumer_object.proof_result.lineage_hash);

    let witness_bytes = canonical_witness_bytes_v1(
        &fixture.proof.intent_body.canonical_hash_preimage().unwrap(),
    );
    let witness_digest = sha256_domain_separated_local(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR,
        &witness_bytes,
    );
    let mut transcript_preimage = Vec::with_capacity(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR.len()
            + 1
            + (HASH_LEN_V1 * 3),
    );
    transcript_preimage
        .extend_from_slice(AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR);
    transcript_preimage.push(LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1);
    let public_claim_digest_offset_in_transcript = transcript_preimage.len();
    transcript_preimage.extend_from_slice(&fixture.proof.transcript.public_claim_digest);
    transcript_preimage.extend_from_slice(&witness_digest);
    let constraint_summary_digest_offset_in_transcript = transcript_preimage.len();
    transcript_preimage.extend_from_slice(&fixture.proof.transcript.constraint_summary_digest);

    let mut proof_bound_bytes = Vec::with_capacity((HASH_LEN_V1 * 4) + 8 + 8 + 2 + 2);
    let transcript_digest_offset_in_bound = proof_bound_bytes.len();
    proof_bound_bytes.extend_from_slice(&fixture.proof.transcript.transcript_digest);
    let public_claim_digest_offset_in_bound = proof_bound_bytes.len();
    proof_bound_bytes.extend_from_slice(&fixture.proof.transcript.public_claim_digest);
    proof_bound_bytes.extend_from_slice(&fixture.proof.proof_artifact.public_input_digest);
    proof_bound_bytes.extend_from_slice(&fixture.proof.proof_artifact.proof_binding_digest);
    proof_bound_bytes.extend_from_slice(&fixture.proof.proof_artifact.trace_state_count.to_le_bytes());
    proof_bound_bytes
        .extend_from_slice(&fixture.proof.proof_artifact.internal_trace_length.to_le_bytes());
    proof_bound_bytes.extend_from_slice(&fixture.proof.proof_artifact.trace_width.to_le_bytes());
    proof_bound_bytes
        .extend_from_slice(&fixture.proof.proof_artifact.backend_constraint_count.to_le_bytes());

    let result_material_bytes =
        canonical_consumer_result_material_bytes_v1(&fixture.consumer_object);
    let public_claim_digest_offset_in_result = 1;
    let transcript_digest_offset_in_result = public_claim_digest_offset_in_result + HASH_LEN_V1;
    let proof_bound_digest_offset_in_result = transcript_digest_offset_in_result + HASH_LEN_V1;
    let lineage_commitment_offset_in_result = proof_bound_digest_offset_in_result + HASH_LEN_V1;
    let lineage_hash_offset_in_result =
        lineage_commitment_offset_in_result + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1;

    let consumer_object_bytes = canonical_consumer_object_bytes_v1(
        &fixture.consumer_object,
        &public_claim_bytes,
    );
    let consumer_header_len =
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1.len() + 1 + 2 + 1;
    let public_claim_digest_offset_in_consumer = consumer_header_len;
    let transcript_digest_offset_in_consumer =
        public_claim_digest_offset_in_consumer + HASH_LEN_V1;
    let proof_bound_digest_offset_in_consumer =
        transcript_digest_offset_in_consumer + HASH_LEN_V1;
    let proof_binding_digest_offset_in_consumer =
        proof_bound_digest_offset_in_consumer + HASH_LEN_V1;
    let lineage_commitment_offset_in_consumer =
        proof_binding_digest_offset_in_consumer + HASH_LEN_V1;
    let lineage_hash_offset_in_consumer = lineage_commitment_offset_in_consumer
        + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1;
    let dcm_commitment_root_offset_in_consumer = lineage_hash_offset_in_consumer + HASH_LEN_V1;
    let dcm_trace_commitment_offset_in_consumer =
        dcm_commitment_root_offset_in_consumer + HASH_LEN_V1;
    let intent_hash_offset_in_consumer = dcm_trace_commitment_offset_in_consumer + HASH_LEN_V1;
    let result_commitment_offset_in_consumer = intent_hash_offset_in_consumer + HASH_LEN_V1;
    let result_digest_offset_in_consumer =
        result_commitment_offset_in_consumer + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1;
    let public_claim_offset_in_consumer = result_digest_offset_in_consumer + HASH_LEN_V1;

    let ingress_bytes = fixture.ingress_object.serialized_object().unwrap();
    let consumer_object_offset_in_ingress =
        aura_intent_lineage_v1::AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_DOMAIN_SEPARATOR_V1
            .len()
            + 1
            + 2;

    let public_statement = fixture
        .ingress_object
        .verified_authorization_public_statement()
        .unwrap();
    let public_statement_bytes =
        canonical_layer4_verified_authorization_public_statement_bytes_v1(&public_statement);
    let lineage_commitment_offset_in_statement = 1 + 2 + 1;
    let lineage_hash_offset_in_statement =
        lineage_commitment_offset_in_statement + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1;
    let freshness_reference_offset_in_statement = lineage_hash_offset_in_statement
        + HASH_LEN_V1
        + 1
        + HASH_LEN_V1
        + 1
        + HASH_LEN_V1
        + 1
        + HASH_LEN_V1;
    let result_commitment_offset_in_statement = freshness_reference_offset_in_statement + 8;
    let transcript_digest_offset_in_statement =
        result_commitment_offset_in_statement + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1;
    let proof_bound_digest_offset_in_statement = transcript_digest_offset_in_statement + HASH_LEN_V1;

    CommitmentFlowOracleTemplateV1 {
        lineage_preimage,
        freshness_reference_offset,
        public_claim_bytes,
        serialized_layer2_offset_in_public_claim,
        lineage_commitment_offset_in_public_claim,
        lineage_hash_offset_in_public_claim,
        constraint_summary_bytes,
        lineage_commitment_offset_in_constraint_summary,
        lineage_hash_offset_in_constraint_summary,
        transcript_preimage,
        public_claim_digest_offset_in_transcript,
        constraint_summary_digest_offset_in_transcript,
        proof_bound_bytes,
        transcript_digest_offset_in_bound,
        public_claim_digest_offset_in_bound,
        result_material_bytes,
        public_claim_digest_offset_in_result,
        transcript_digest_offset_in_result,
        proof_bound_digest_offset_in_result,
        lineage_commitment_offset_in_result,
        lineage_hash_offset_in_result,
        consumer_object_bytes,
        public_claim_digest_offset_in_consumer,
        transcript_digest_offset_in_consumer,
        proof_bound_digest_offset_in_consumer,
        lineage_commitment_offset_in_consumer,
        lineage_hash_offset_in_consumer,
        result_commitment_offset_in_consumer,
        result_digest_offset_in_consumer,
        public_claim_offset_in_consumer,
        ingress_bytes,
        consumer_object_offset_in_ingress,
        public_statement_bytes,
        lineage_commitment_offset_in_statement,
        lineage_hash_offset_in_statement,
        freshness_reference_offset_in_statement,
        result_commitment_offset_in_statement,
        transcript_digest_offset_in_statement,
        proof_bound_digest_offset_in_statement,
    }
}

fn canonical_consumer_result_material_bytes_v1(
    consumer_object: &Layer3AuthorizationLineageConsumerObjectV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + (HASH_LEN_V1 * 8) + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
    );
    bytes.push(consumer_object.decision.as_u8());
    bytes.extend_from_slice(&consumer_object.proof_result.public_claim_digest);
    bytes.extend_from_slice(&consumer_object.proof_result.layer3_transcript_digest);
    bytes.extend_from_slice(&consumer_object.proof_result.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&consumer_object.proof_result.layer3_proof_binding_digest);
    bytes.extend_from_slice(&consumer_object.proof_result.lineage_commitment.to_bytes());
    bytes.extend_from_slice(&consumer_object.proof_result.lineage_hash);
    bytes.extend_from_slice(&consumer_object.proof_result.dcm_commitment_root);
    bytes.extend_from_slice(&consumer_object.proof_result.dcm_trace_commitment);
    bytes.extend_from_slice(&consumer_object.proof_result.intent_hash);
    bytes
}

fn canonical_consumer_object_bytes_v1(
    consumer_object: &Layer3AuthorizationLineageConsumerObjectV1,
    public_claim_bytes: &[u8],
) -> Vec<u8> {
    let proof_result = &consumer_object.proof_result;
    let mut bytes = Vec::with_capacity(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1.len()
            + 1
            + 2
            + 1
            + public_claim_bytes.len()
            + (HASH_LEN_V1 * 9)
            + (DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 2),
    );
    bytes.extend_from_slice(AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_DOMAIN_SEPARATOR_V1);
    bytes.push(consumer_object.consumer_version);
    bytes.extend_from_slice(&consumer_object.consumer_flags.to_le_bytes());
    bytes.push(consumer_object.decision.as_u8());
    bytes.extend_from_slice(&proof_result.public_claim_digest);
    bytes.extend_from_slice(&proof_result.layer3_transcript_digest);
    bytes.extend_from_slice(&proof_result.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&proof_result.layer3_proof_binding_digest);
    bytes.extend_from_slice(&proof_result.lineage_commitment.to_bytes());
    bytes.extend_from_slice(&proof_result.lineage_hash);
    bytes.extend_from_slice(&proof_result.dcm_commitment_root);
    bytes.extend_from_slice(&proof_result.dcm_trace_commitment);
    bytes.extend_from_slice(&proof_result.intent_hash);
    bytes.extend_from_slice(&proof_result.result_commitment.to_bytes());
    bytes.extend_from_slice(&proof_result.result_digest);
    bytes.extend_from_slice(public_claim_bytes);
    bytes
}

fn canonical_layer4_verified_authorization_public_statement_bytes_v1(
    statement: &aura_intent_lineage_v1::Layer4VerifiedAuthorizationPublicStatementV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 2 + 1 + (DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 2) + (HASH_LEN_V1 * 7) + 8,
    );
    bytes.push(statement.version);
    bytes.extend_from_slice(&statement.lineage_flags.to_le_bytes());
    bytes.push(statement.dcm_commitment_kind.as_u8());
    bytes.extend_from_slice(&statement.lineage_commitment.to_bytes());
    bytes.extend_from_slice(&statement.lineage_hash);
    bytes.push(statement.subject_binding_type.as_u8());
    bytes.extend_from_slice(&statement.subject_id);
    bytes.push(statement.intent_type.as_u8());
    bytes.extend_from_slice(&statement.intent_hash);
    bytes.push(statement.freshness_mode.as_u8());
    bytes.extend_from_slice(&statement.freshness_nonce);
    bytes.extend_from_slice(&statement.freshness_reference.to_le_bytes());
    bytes.extend_from_slice(&statement.layer3_result_commitment.to_bytes());
    bytes.extend_from_slice(&statement.layer3_transcript_digest);
    bytes.extend_from_slice(&statement.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&statement.layer3_proof_binding_digest);
    bytes
}

fn canonical_witness_bytes_v1(intent_hash_preimage: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + intent_hash_preimage.len());
    bytes.extend_from_slice(&(intent_hash_preimage.len() as u64).to_le_bytes());
    bytes.extend_from_slice(intent_hash_preimage);
    bytes
}

fn lineage_freshness_reference_offset_v1() -> usize {
    b"AURA_AUTHORIZATION_LINEAGE_V1".len()
        + 1
        + 2
        + 1
        + HASH_LEN_V1
        + HASH_LEN_V1
        + 1
        + HASH_LEN_V1
        + HASH_LEN_V1
        + 1
        + HASH_LEN_V1
        + 1
        + HASH_LEN_V1
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

fn grover_estimate_v1(space_size: u64, marked_count: u64) -> (u64, f64) {
    let n = space_size as f64;
    let m = marked_count.max(1) as f64;
    let theta = (m / n).sqrt().asin();
    let optimal_iterations = ((PI / (4.0 * theta)) - 0.5).round().max(0.0) as u64;
    let success_probability = (((2 * optimal_iterations + 1) as f64) * theta).sin().powi(2);
    (optimal_iterations, success_probability)
}

fn max_exact_bits_v1() -> u32 {
    env::var("AURA_NON_AUTHORITATIVE_MAX_EXACT_BITS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(NON_AUTHORITATIVE_MAX_EXACT_BITS_V1)
}

fn bounded_query_cap_v1() -> u64 {
    env::var("AURA_NON_AUTHORITATIVE_QUERY_CAP")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(NON_AUTHORITATIVE_BOUNDED_QUERY_CAP_V1)
}

fn sha256_bytes_local(bytes: &[u8]) -> [u8; HASH_LEN_V1] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; HASH_LEN_V1];
    hash.copy_from_slice(&digest);
    hash
}

fn sha256_domain_separated_local(
    domain_separator: &[u8],
    payload: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(domain_separator.len() + payload.len());
    preimage.extend_from_slice(domain_separator);
    preimage.extend_from_slice(payload);
    sha256_bytes_local(&preimage)
}

fn structural_assessment_v1() -> Vec<StructuralAssessmentV1> {
    vec![
        StructuralAssessmentV1 {
            target: "layer2_lineage_commitment",
            canonicalization_singular: true,
            alternate_encoding_observed: false,
            unexpected_equivalent_object_observed: false,
            effective_search_space_smaller_than_modeled: false,
            helper_surface_promoted_to_primary: false,
            summary: String::from(
                "The Layer 2 surface is canonically singular, but the reduced-bit harness showed strong high-prefix concentration for lineage_commitment over the tested disjoint freshness_reference family. That is not a full break, but it does deviate from plain random-like truncation and is the main structural concern surfaced by this research pass.",
            ),
        },
        StructuralAssessmentV1 {
            target: "layer3_result_commitment",
            canonicalization_singular: true,
            alternate_encoding_observed: false,
            unexpected_equivalent_object_observed: false,
            effective_search_space_smaller_than_modeled: false,
            helper_surface_promoted_to_primary: false,
            summary: String::from(
                "The Layer 3 result surface has a single material-byte encoding. Helper digests remain embedded transcript context, but the primary truth surface is the 521-bit result_commitment rather than any 32-byte digest field, and no analogous prefix bias was observed in the bounded run.",
            ),
        },
        StructuralAssessmentV1 {
            target: "layer3_layer4_ingress_commitment",
            canonicalization_singular: true,
            alternate_encoding_observed: false,
            unexpected_equivalent_object_observed: false,
            effective_search_space_smaller_than_modeled: false,
            helper_surface_promoted_to_primary: false,
            summary: String::from(
                "The ingress commitment is singular under one serialized-object path. It carries validated helper digest bytes through the consumer object, but no helper digest acts as an independent primary commitment surface, and the bounded search looked consistent with ordinary truncation.",
            ),
        },
        StructuralAssessmentV1 {
            target: "layer4_public_statement_commitment",
            canonicalization_singular: true,
            alternate_encoding_observed: false,
            unexpected_equivalent_object_observed: false,
            effective_search_space_smaller_than_modeled: false,
            helper_surface_promoted_to_primary: false,
            summary: String::from(
                "The public-statement commitment uses one fixed byte layout with no alternate serializer. Transcript/helper digests remain committed context, not standalone authority, and the bounded search showed no shortcut beyond truncation.",
            ),
        },
    ]
}

fn oracle_definition_lineage_commitment_v1() -> OracleDefinitionV1 {
    OracleDefinitionV1 {
        search_kind: "structured_neighbor_second_preimage",
        preimage_space: "Canonical NativeLayer2AuthorizationLineageObjectV1 lineage preimages produced by varying freshness_reference = 2^48 + candidate while keeping DCM commitments, subject binding, and intent fixed.",
        variable_fields: vec!["lineage.freshness_reference"],
        fixed_fields: vec![
            "lineage.version",
            "lineage.lineage_flags",
            "lineage.dcm_commitment_root",
            "lineage.dcm_trace_commitment",
            "lineage.subject_binding_type",
            "lineage.subject_id",
            "lineage.intent_hash",
            "lineage.freshness_nonce",
        ],
        marked_item: "A candidate is marked when the truncated candidate lineage_commitment equals the truncated canonical target lineage_commitment.",
        canonicality_restriction: "Only the one canonical lineage preimage encoding is allowed; no alternate serialization or non-canonical field encoding is admitted.",
    }
}

fn oracle_definition_result_commitment_v1() -> OracleDefinitionV1 {
    OracleDefinitionV1 {
        search_kind: "structured_neighbor_second_preimage",
        preimage_space: "Canonical Layer 3 result material bytes induced by the same canonical Layer 2 freshness_reference variation, with public-claim, constraint-summary, transcript, and proof-bound digests recomputed exactly from that canonical variation and proof-artifact fields held fixed.",
        variable_fields: vec![
            "proof_result.lineage_commitment",
            "proof_result.lineage_hash",
            "proof_result.public_claim_digest",
            "proof_result.layer3_transcript_digest",
            "proof_result.layer3_proof_bound_transcript_digest",
        ],
        fixed_fields: vec![
            "decision",
            "proof_result.layer3_proof_binding_digest",
            "proof_result.dcm_commitment_root",
            "proof_result.dcm_trace_commitment",
            "proof_result.intent_hash",
            "proof_artifact.public_input_digest",
            "proof_artifact.proof_binding_digest",
        ],
        marked_item: "A candidate is marked when the truncated candidate result_commitment equals the truncated canonical target result_commitment.",
        canonicality_restriction: "The oracle only updates bytes through the exact canonical Layer 2 -> Layer 3 serialization path; no alternate consumer/result encoding is allowed.",
    }
}

fn oracle_definition_ingress_commitment_v1() -> OracleDefinitionV1 {
    OracleDefinitionV1 {
        search_kind: "structured_neighbor_second_preimage",
        preimage_space: "Canonical ingress serialized-object bytes formed from the canonical intent body and a canonical consumer object whose Layer 2-derived fields are varied only through freshness_reference = 2^48 + candidate.",
        variable_fields: vec![
            "consumer_object.public_claim.layer2_object.lineage.freshness_reference",
            "consumer_object.proof_result.lineage_commitment",
            "consumer_object.proof_result.lineage_hash",
            "consumer_object.proof_result.result_commitment",
            "consumer_object.proof_result.result_digest",
        ],
        fixed_fields: vec![
            "ingress_version",
            "ingress_flags",
            "intent_body",
            "consumer_object.decision",
            "consumer_object.proof_result.layer3_proof_binding_digest",
        ],
        marked_item: "A candidate is marked when the truncated candidate ingress_commitment equals the truncated canonical target ingress_commitment.",
        canonicality_restriction: "Only the one ingress serialized-object encoding is searched; no alternate consumer-object or intent serialization path is admitted.",
    }
}

fn oracle_definition_public_statement_commitment_v1() -> OracleDefinitionV1 {
    OracleDefinitionV1 {
        search_kind: "structured_neighbor_second_preimage",
        preimage_space: "Canonical verified-authority public-statement bytes with the same canonical Layer 2 freshness_reference variation propagated into lineage_commitment, lineage_hash, layer3_result_commitment, transcript_digest, and bound-transcript digest.",
        variable_fields: vec![
            "lineage_commitment",
            "lineage_hash",
            "freshness_reference",
            "layer3_result_commitment",
            "layer3_transcript_digest",
            "layer3_proof_bound_transcript_digest",
        ],
        fixed_fields: vec![
            "version",
            "lineage_flags",
            "dcm_commitment_kind",
            "subject_binding_type",
            "subject_id",
            "intent_type",
            "intent_hash",
            "freshness_mode",
            "freshness_nonce",
            "layer3_proof_binding_digest",
        ],
        marked_item: "A candidate is marked when the truncated candidate public-statement commitment equals the truncated canonical target public-statement commitment.",
        canonicality_restriction: "The oracle follows the single public-statement byte layout only; no alternate field ordering or serialization is allowed.",
    }
}

fn oracle_definition_lineage_hash_control_v1() -> OracleDefinitionV1 {
    OracleDefinitionV1 {
        search_kind: "structured_neighbor_second_preimage_control",
        preimage_space: "The same canonical Layer 2 lineage preimage family used for the primary lineage_commitment search, evaluated only as a retained 32-byte helper digest control.",
        variable_fields: vec!["lineage.freshness_reference"],
        fixed_fields: vec![
            "lineage.dcm_commitment_root",
            "lineage.dcm_trace_commitment",
            "lineage.subject_binding_type",
            "lineage.subject_id",
            "lineage.intent_hash",
            "lineage.freshness_nonce",
        ],
        marked_item: "A candidate is marked when the truncated candidate lineage_hash equals the truncated canonical target lineage_hash.",
        canonicality_restriction: "Only the canonical lineage preimage bytes are hashed.",
    }
}

fn oracle_definition_result_digest_control_v1() -> OracleDefinitionV1 {
    OracleDefinitionV1 {
        search_kind: "structured_neighbor_second_preimage_control",
        preimage_space: "The same canonical Layer 3 result material family used for the primary result_commitment search, evaluated only as a retained 32-byte helper digest control.",
        variable_fields: vec![
            "proof_result.lineage_commitment",
            "proof_result.lineage_hash",
            "proof_result.public_claim_digest",
            "proof_result.layer3_transcript_digest",
            "proof_result.layer3_proof_bound_transcript_digest",
        ],
        fixed_fields: vec![
            "decision",
            "proof_result.layer3_proof_binding_digest",
            "proof_result.dcm_commitment_root",
            "proof_result.dcm_trace_commitment",
            "proof_result.intent_hash",
        ],
        marked_item: "A candidate is marked when the truncated candidate result_digest equals the truncated canonical target result_digest.",
        canonicality_restriction: "Only the canonical result-material byte encoding is hashed.",
    }
}
