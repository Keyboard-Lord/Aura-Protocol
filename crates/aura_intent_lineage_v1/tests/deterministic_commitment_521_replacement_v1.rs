mod support;

use std::collections::BTreeSet;

use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, derive_deterministic_commitment_521_v1,
    produce_layer3_authorization_lineage_consumer_object_v1,
    produce_layer3_layer4_verified_authorization_ingress_v1,
    produce_native_layer2_authorization_lineage_object_521_v1,
    prove_layer3_authorization_lineage_real_stark_v1, DcmExecution521V1,
    FieldElement521V1, Layer1Layer2BridgeIntentSourceV1, Layer1Layer2BridgeSubjectBindingV1,
    Layer3AuthorizationLineageConsumerObjectV1, Layer3AuthorizationLineageProvingInputV1,
    Layer3AuthorizationLineageRealStarkProofV1, Layer3Layer4VerifiedAuthorizationIngressV1,
    AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
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
use sha2::{Digest, Sha256};

use support::{
    canonical_dcm_config, canonical_dcm_input, canonical_freshness, canonical_intent,
    canonical_subject_binding,
};

const STRUCTURED_NEIGHBOR_BASE_REFERENCE_V1: u64 = 1u64 << 48;
const STRUCTURED_NEIGHBOR_COUNT_V1: u64 = 1u64 << 12;
const PREFIX_BITS_V1: [u32; 4] = [8, 16, 24, 32];

const LEGACY_CONTEXT_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_DETERMINISTIC_COMMITMENT_521_V1";
const LEGACY_SEED_X_V1: &[u8] = b"AURA_DETERMINISTIC_COMMITMENT_521_SEED_X_V1";
const LEGACY_SEED_Y_V1: &[u8] = b"AURA_DETERMINISTIC_COMMITMENT_521_SEED_Y_V1";
const LEGACY_CHUNK_LEN_V1: usize = 64;
const LEGACY_INDEX_SCALE_V1: u64 = 257;
const LEGACY_MIX_SCALE_V1: u64 = 65_537;
const LEGACY_FINAL_SCALE_V1: u64 = 131_071;

#[derive(Clone)]
struct CanonicalFlowFixtureV1 {
    layer2_object: aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1,
    proof: Layer3AuthorizationLineageRealStarkProofV1,
    consumer_object: Layer3AuthorizationLineageConsumerObjectV1,
    ingress_object: Layer3Layer4VerifiedAuthorizationIngressV1,
}

struct CommitmentFlowOracleTemplateV1 {
    lineage_preimage: Vec<u8>,
    freshness_reference_offset: usize,
    lower_layer_claim_bytes: Vec<u8>,
    iteration_count: u64,
    trace_state_count: u64,
    dcm_trace_commitment: [u8; HASH_LEN_V1],
    dcm_commitment_root: [u8; HASH_LEN_V1],
    intent_hash: [u8; HASH_LEN_V1],
    witness_digest: [u8; HASH_LEN_V1],
    proof_artifact_public_input_digest: [u8; HASH_LEN_V1],
    proof_artifact_proof_binding_digest: [u8; HASH_LEN_V1],
    proof_artifact_trace_state_count: u64,
    proof_artifact_internal_trace_length: u64,
    proof_artifact_trace_width: u16,
    proof_artifact_backend_constraint_count: u16,
    consumer_version: u8,
    consumer_flags: u16,
    decision: u8,
    ingress_version: u8,
    ingress_flags: u16,
    intent_hash_preimage: Vec<u8>,
    statement_version: u8,
    statement_lineage_flags: u16,
    statement_dcm_commitment_kind: u8,
    statement_subject_binding_type: u8,
    statement_subject_id: [u8; HASH_LEN_V1],
    statement_intent_type: u8,
    statement_freshness_mode: u8,
    statement_freshness_nonce: [u8; HASH_LEN_V1],
}

struct CandidateOutputsV1 {
    lineage_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    result_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    ingress_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    public_statement_commitment: [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
}

#[derive(Default)]
struct PrefixAccumulatorV1 {
    match_counts: [u64; PREFIX_BITS_V1.len()],
    distinct_prefixes_32: BTreeSet<u32>,
    one_counts_first_32: [u64; 32],
    sample_count: u64,
}

#[derive(Default)]
struct AvalancheAccumulatorV1 {
    total_new_changed_bits: usize,
    total_legacy_changed_bits: usize,
    new_prefix_changed_counts: [u64; PREFIX_BITS_V1.len()],
    legacy_prefix_changed_counts: [u64; PREFIX_BITS_V1.len()],
    sample_count: usize,
}

#[test]
fn replacement_primitive_recomputes_all_primary_commitment_surfaces_exactly() {
    let fixture = canonical_flow_fixture_v1();
    let lineage_preimage = fixture.layer2_object.lineage.canonical_preimage().unwrap();
    let result_material = canonical_consumer_result_primary_material_bytes_v1(&fixture.consumer_object);
    let consumer_material =
        canonical_consumer_object_primary_material_bytes_v1(&fixture.consumer_object);
    let ingress_material = canonical_ingress_primary_material_bytes_v1(&fixture.ingress_object);
    let public_statement = fixture
        .ingress_object
        .verified_authorization_public_statement()
        .unwrap();
    let public_statement_bytes = canonical_layer4_verified_authorization_public_statement_primary_material_bytes_v1(
        &fixture.ingress_object,
        &public_statement,
    );

    assert_eq!(
        fixture.layer2_object.lineage_commitment,
        derive_deterministic_commitment_521_v1(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &lineage_preimage,
        )
    );
    assert_eq!(
        fixture.consumer_object.proof_result.result_commitment,
        derive_deterministic_commitment_521_v1(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &result_material,
        )
    );
    assert_eq!(
        fixture.consumer_object.consumer_commitment().unwrap(),
        derive_deterministic_commitment_521_v1(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &consumer_material,
        )
    );
    assert_eq!(
        fixture.ingress_object.ingress_commitment().unwrap(),
        derive_deterministic_commitment_521_v1(
            AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &ingress_material,
        )
    );
    assert_eq!(
        fixture
            .ingress_object
            .verified_authorization_public_statement_commitment()
            .unwrap(),
        derive_deterministic_commitment_521_v1(
            AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &public_statement_bytes,
        )
    );
}

#[test]
fn replacement_primitive_improves_freshness_reference_one_bit_avalanche_over_legacy_control() {
    let object = support::canonical_layer2_object();
    let baseline_preimage = object.lineage.canonical_preimage().unwrap();
    let baseline_new = derive_deterministic_commitment_521_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &baseline_preimage,
    )
    .to_bytes();
    let baseline_legacy = legacy_deterministic_commitment_521_v1(
        AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &baseline_preimage,
    );

    let mut accumulator = AvalancheAccumulatorV1::default();
    let freshness_reference_offset = lineage_freshness_reference_offset_v1();
    for bit_offset in 0..64usize {
        let mut mutated_preimage = baseline_preimage.clone();
        let absolute_bit = freshness_reference_offset * 8 + bit_offset;
        let byte_index = absolute_bit / 8;
        let bit_in_byte = absolute_bit % 8;
        mutated_preimage[byte_index] ^= 1u8 << bit_in_byte;

        let mutated_new = derive_deterministic_commitment_521_v1(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &mutated_preimage,
        )
        .to_bytes();
        let mutated_legacy = legacy_deterministic_commitment_521_v1(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &mutated_preimage,
        );

        accumulator.total_new_changed_bits += hamming_distance_v1(&baseline_new, &mutated_new);
        accumulator.total_legacy_changed_bits +=
            hamming_distance_v1(&baseline_legacy, &mutated_legacy);
        accumulator.sample_count += 1;

        for (index, bits) in PREFIX_BITS_V1.into_iter().enumerate() {
            if truncate_bits_be_v1(&baseline_new, bits) != truncate_bits_be_v1(&mutated_new, bits) {
                accumulator.new_prefix_changed_counts[index] += 1;
            }
            if truncate_bits_be_v1(&baseline_legacy, bits)
                != truncate_bits_be_v1(&mutated_legacy, bits)
            {
                accumulator.legacy_prefix_changed_counts[index] += 1;
            }
        }
    }

    let avg_new =
        accumulator.total_new_changed_bits as f64 / accumulator.sample_count as f64;
    let avg_legacy =
        accumulator.total_legacy_changed_bits as f64 / accumulator.sample_count as f64;

    assert!(
        avg_new > avg_legacy + 80.0,
        "expected large avalanche improvement, got new={avg_new:.2}, legacy={avg_legacy:.2}"
    );
    assert!(
        accumulator.new_prefix_changed_counts[1] >= 56,
        "new primitive should diffuse the first 16 bits for most flips, got {} / 64",
        accumulator.new_prefix_changed_counts[1]
    );
    assert!(
        accumulator.new_prefix_changed_counts[2] >= 56,
        "new primitive should diffuse the first 24 bits for most flips, got {} / 64",
        accumulator.new_prefix_changed_counts[2]
    );
    assert!(
        accumulator.new_prefix_changed_counts[3] >= 56,
        "new primitive should diffuse the first 32 bits for most flips, got {} / 64",
        accumulator.new_prefix_changed_counts[3]
    );
    assert_eq!(
        accumulator.legacy_prefix_changed_counts[3], 0,
        "legacy comparison control should reproduce the historical 32-bit prefix lock"
    );
}

#[test]
fn replacement_primitive_resists_top_prefix_concentration_across_primary_surfaces() {
    let fixture = canonical_flow_fixture_v1();
    let mut oracle = commitment_flow_oracle_template_v1(&fixture);
    let targets = oracle.outputs_for_target();

    let mut lineage_accumulator = PrefixAccumulatorV1::default();
    let mut result_accumulator = PrefixAccumulatorV1::default();
    let mut ingress_accumulator = PrefixAccumulatorV1::default();
    let mut statement_accumulator = PrefixAccumulatorV1::default();

    for candidate in 0..STRUCTURED_NEIGHBOR_COUNT_V1 {
        let outputs = oracle.outputs_for_candidate(candidate);
        update_prefix_accumulator_v1(
            &mut lineage_accumulator,
            &outputs.lineage_commitment,
            &targets.lineage_commitment,
        );
        update_prefix_accumulator_v1(
            &mut result_accumulator,
            &outputs.result_commitment,
            &targets.result_commitment,
        );
        update_prefix_accumulator_v1(
            &mut ingress_accumulator,
            &outputs.ingress_commitment,
            &targets.ingress_commitment,
        );
        update_prefix_accumulator_v1(
            &mut statement_accumulator,
            &outputs.public_statement_commitment,
            &targets.public_statement_commitment,
        );
    }

    assert_field_native_prefix_diffusion_v1("layer2_lineage_commitment", &lineage_accumulator);
    assert_field_native_prefix_diffusion_v1("layer3_result_commitment", &result_accumulator);
    assert_field_native_prefix_diffusion_v1(
        "layer3_layer4_ingress_commitment",
        &ingress_accumulator,
    );
    assert_field_native_prefix_diffusion_v1(
        "layer4_public_statement_commitment",
        &statement_accumulator,
    );
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

impl CommitmentFlowOracleTemplateV1 {
    fn outputs_for_target(&mut self) -> CandidateOutputsV1 {
        self.outputs_for_candidate_inner(self.target_reference_bytes_v1())
    }

    fn outputs_for_candidate(&mut self, candidate: u64) -> CandidateOutputsV1 {
        self.outputs_for_candidate_inner(
            (STRUCTURED_NEIGHBOR_BASE_REFERENCE_V1 + candidate).to_le_bytes(),
        )
    }

    fn outputs_for_candidate_inner(&mut self, freshness_reference_bytes: [u8; 8]) -> CandidateOutputsV1 {
        self.lineage_preimage
            [self.freshness_reference_offset..self.freshness_reference_offset + 8]
            .copy_from_slice(&freshness_reference_bytes);

        let lineage_commitment = derive_deterministic_commitment_521_v1(
            AURA_NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &self.lineage_preimage,
        )
        .to_bytes();
        let lineage_hash = sha256_bytes_local(&self.lineage_preimage);

        let layer2_primary_bytes =
            canonical_layer2_primary_bytes_from_parts_v1(&self.lineage_preimage, &lineage_commitment);
        let public_claim_bytes = canonical_layer3_public_claim_bytes_from_parts_v1(
            &self.lower_layer_claim_bytes,
            &self.lineage_preimage,
            &lineage_commitment,
            &lineage_hash,
        );
        let public_claim_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
            &public_claim_bytes,
        );

        let constraint_summary_bytes = canonical_constraint_summary_bytes_from_parts_v1(
            self.iteration_count,
            self.trace_state_count,
            &self.dcm_trace_commitment,
            &self.dcm_commitment_root,
            &self.intent_hash,
            &lineage_commitment,
            &lineage_hash,
        );
        let constraint_summary_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
            &constraint_summary_bytes,
        );

        let transcript_preimage = canonical_transcript_preimage_v1(
            &public_claim_digest,
            &self.witness_digest,
            &constraint_summary_digest,
        );
        let transcript_digest = sha256_bytes_local(&transcript_preimage);

        let proof_bound_bytes = canonical_proof_bound_bytes_v1(
            &transcript_digest,
            &public_claim_digest,
            &self.proof_artifact_public_input_digest,
            &self.proof_artifact_proof_binding_digest,
            self.proof_artifact_trace_state_count,
            self.proof_artifact_internal_trace_length,
            self.proof_artifact_trace_width,
            self.proof_artifact_backend_constraint_count,
        );
        let proof_bound_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR,
            &proof_bound_bytes,
        );

        let result_material_bytes = canonical_consumer_result_primary_material_bytes_from_parts_v1(
            self.decision,
            &self.lower_layer_claim_bytes,
            &layer2_primary_bytes,
            &transcript_digest,
            &proof_bound_digest,
            &self.proof_artifact_proof_binding_digest,
        );
        let result_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &result_material_bytes,
        )
        .to_bytes();

        let consumer_material_bytes = canonical_consumer_object_primary_material_bytes_from_parts_v1(
            self.consumer_version,
            self.consumer_flags,
            self.decision,
            &result_commitment,
            &self.lower_layer_claim_bytes,
            &layer2_primary_bytes,
        );
        let consumer_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_OBJECT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &consumer_material_bytes,
        )
        .to_bytes();

        let ingress_material_bytes = canonical_ingress_primary_material_bytes_from_parts_v1(
            self.ingress_version,
            self.ingress_flags,
            &lineage_commitment,
            &result_commitment,
            &consumer_commitment,
            &layer2_primary_bytes,
            &self.intent_hash_preimage,
        );
        let ingress_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER3_LAYER4_VERIFIED_AUTHORIZATION_INGRESS_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &ingress_material_bytes,
        )
        .to_bytes();

        let public_statement_bytes =
            canonical_public_statement_primary_material_bytes_from_parts_v1(
                self.statement_version,
                self.statement_lineage_flags,
                self.statement_dcm_commitment_kind,
                &lineage_commitment,
                self.statement_subject_binding_type,
                &self.statement_subject_id,
                self.statement_intent_type,
                &self.intent_hash,
                self.statement_freshness_mode,
                &self.statement_freshness_nonce,
                u64::from_le_bytes(freshness_reference_bytes),
                &result_commitment,
                &ingress_commitment,
            );
        let public_statement_commitment = derive_deterministic_commitment_521_v1(
            AURA_LAYER4_VERIFIED_AUTHORIZATION_PUBLIC_STATEMENT_COMMITMENT_DOMAIN_SEPARATOR_V1,
            &public_statement_bytes,
        )
        .to_bytes();

        CandidateOutputsV1 {
            lineage_commitment,
            result_commitment,
            ingress_commitment,
            public_statement_commitment,
        }
    }

    fn target_reference_bytes_v1(&self) -> [u8; 8] {
        let offset = self.freshness_reference_offset;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.lineage_preimage[offset..offset + 8]);
        bytes
    }
}

fn commitment_flow_oracle_template_v1(
    fixture: &CanonicalFlowFixtureV1,
) -> CommitmentFlowOracleTemplateV1 {
    let lineage_preimage = fixture.layer2_object.lineage.canonical_preimage().unwrap();
    let freshness_reference_offset = lineage_freshness_reference_offset_v1();

    CommitmentFlowOracleTemplateV1 {
        lineage_preimage,
        freshness_reference_offset,
        lower_layer_claim_bytes: fixture
            .proof
            .public_claim
            .lower_layer_claim
            .canonical_bytes()
            .to_vec(),
        iteration_count: fixture.proof.public_claim.lower_layer_claim.config.iteration_count,
        trace_state_count: fixture.proof.public_claim.lower_layer_claim.trace_state_count(),
        dcm_trace_commitment: fixture.consumer_object.proof_result.dcm_trace_commitment,
        dcm_commitment_root: fixture.consumer_object.proof_result.dcm_commitment_root,
        intent_hash: fixture.consumer_object.proof_result.intent_hash,
        witness_digest: sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR,
            &canonical_witness_bytes_v1(&fixture.proof.intent_body.canonical_hash_preimage().unwrap()),
        ),
        proof_artifact_public_input_digest: fixture.proof.proof_artifact.public_input_digest,
        proof_artifact_proof_binding_digest: fixture.proof.proof_artifact.proof_binding_digest,
        proof_artifact_trace_state_count: fixture.proof.proof_artifact.trace_state_count,
        proof_artifact_internal_trace_length: fixture.proof.proof_artifact.internal_trace_length,
        proof_artifact_trace_width: fixture.proof.proof_artifact.trace_width,
        proof_artifact_backend_constraint_count: fixture
            .proof
            .proof_artifact
            .backend_constraint_count,
        consumer_version: fixture.consumer_object.consumer_version,
        consumer_flags: fixture.consumer_object.consumer_flags,
        decision: fixture.consumer_object.decision.as_u8(),
        ingress_version: fixture.ingress_object.ingress_version,
        ingress_flags: fixture.ingress_object.ingress_flags,
        intent_hash_preimage: fixture
            .ingress_object
            .intent_body
            .canonical_hash_preimage()
            .unwrap(),
        statement_version: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .version,
        statement_lineage_flags: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .lineage_flags,
        statement_dcm_commitment_kind: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .dcm_commitment_kind
            .as_u8(),
        statement_subject_binding_type: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .subject_binding_type
            .as_u8(),
        statement_subject_id: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .subject_id,
        statement_intent_type: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .intent_type
            .as_u8(),
        statement_freshness_mode: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .freshness_mode
            .as_u8(),
        statement_freshness_nonce: fixture
            .ingress_object
            .verified_authorization_public_statement()
            .unwrap()
            .freshness_nonce,
    }
}

fn canonical_consumer_result_primary_material_bytes_v1(
    consumer_object: &Layer3AuthorizationLineageConsumerObjectV1,
) -> Vec<u8> {
    let lower_layer_claim_bytes = consumer_object.public_claim.lower_layer_claim.canonical_bytes();
    let layer2_primary_bytes = canonical_layer2_primary_bytes_from_parts_v1(
        &consumer_object
            .public_claim
            .layer2_object
            .lineage
            .canonical_preimage()
            .unwrap(),
        &consumer_object
            .public_claim
            .layer2_object
            .lineage_commitment
            .to_bytes(),
    );
    canonical_consumer_result_primary_material_bytes_from_parts_v1(
        consumer_object.decision.as_u8(),
        &lower_layer_claim_bytes,
        &layer2_primary_bytes,
        &consumer_object.proof_result.layer3_transcript_digest,
        &consumer_object.proof_result.layer3_proof_bound_transcript_digest,
        &consumer_object.proof_result.layer3_proof_binding_digest,
    )
}

fn canonical_consumer_object_primary_material_bytes_v1(
    consumer_object: &Layer3AuthorizationLineageConsumerObjectV1,
) -> Vec<u8> {
    let lower_layer_claim_bytes = consumer_object.public_claim.lower_layer_claim.canonical_bytes();
    let layer2_primary_bytes = canonical_layer2_primary_bytes_from_parts_v1(
        &consumer_object
            .public_claim
            .layer2_object
            .lineage
            .canonical_preimage()
            .unwrap(),
        &consumer_object
            .public_claim
            .layer2_object
            .lineage_commitment
            .to_bytes(),
    );
    canonical_consumer_object_primary_material_bytes_from_parts_v1(
        consumer_object.consumer_version,
        consumer_object.consumer_flags,
        consumer_object.decision.as_u8(),
        &consumer_object.proof_result.result_commitment.to_bytes(),
        &lower_layer_claim_bytes,
        &layer2_primary_bytes,
    )
}

fn canonical_ingress_primary_material_bytes_v1(
    ingress_object: &Layer3Layer4VerifiedAuthorizationIngressV1,
) -> Vec<u8> {
    let layer2_primary_bytes = canonical_layer2_primary_bytes_from_parts_v1(
        &ingress_object
            .consumer_object
            .public_claim
            .layer2_object
            .lineage
            .canonical_preimage()
            .unwrap(),
        &ingress_object
            .consumer_object
            .public_claim
            .layer2_object
            .lineage_commitment
            .to_bytes(),
    );
    canonical_ingress_primary_material_bytes_from_parts_v1(
        ingress_object.ingress_version,
        ingress_object.ingress_flags,
        &ingress_object
            .consumer_object
            .public_claim
            .layer2_object
            .lineage_commitment
            .to_bytes(),
        &ingress_object
            .consumer_object
            .proof_result
            .result_commitment
            .to_bytes(),
        &ingress_object
            .consumer_object
            .consumer_commitment()
            .unwrap()
            .to_bytes(),
        &layer2_primary_bytes,
        &ingress_object.intent_body.canonical_hash_preimage().unwrap(),
    )
}

fn canonical_layer4_verified_authorization_public_statement_primary_material_bytes_v1(
    ingress_object: &Layer3Layer4VerifiedAuthorizationIngressV1,
    statement: &aura_intent_lineage_v1::Layer4VerifiedAuthorizationPublicStatementV1,
) -> Vec<u8> {
    canonical_public_statement_primary_material_bytes_from_parts_v1(
        statement.version,
        statement.lineage_flags,
        statement.dcm_commitment_kind.as_u8(),
        &statement.lineage_commitment.to_bytes(),
        statement.subject_binding_type.as_u8(),
        &statement.subject_id,
        statement.intent_type.as_u8(),
        &statement.intent_hash,
        statement.freshness_mode.as_u8(),
        &statement.freshness_nonce,
        statement.freshness_reference,
        &statement.layer3_result_commitment.to_bytes(),
        &ingress_object.ingress_commitment().unwrap().to_bytes(),
    )
}

fn canonical_layer2_primary_bytes_from_parts_v1(
    lineage_preimage: &[u8],
    lineage_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(lineage_preimage.len() + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1);
    bytes.extend_from_slice(lineage_preimage);
    bytes.extend_from_slice(lineage_commitment);
    bytes
}

fn canonical_layer3_public_claim_bytes_from_parts_v1(
    lower_layer_claim_bytes: &[u8],
    lineage_preimage: &[u8],
    lineage_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    lineage_hash: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        lower_layer_claim_bytes.len()
            + lineage_preimage.len()
            + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1
            + HASH_LEN_V1,
    );
    bytes.extend_from_slice(lower_layer_claim_bytes);
    bytes.extend_from_slice(lineage_preimage);
    bytes.extend_from_slice(lineage_commitment);
    bytes.extend_from_slice(lineage_hash);
    bytes
}

fn canonical_constraint_summary_bytes_from_parts_v1(
    iteration_count: u64,
    trace_state_count: u64,
    dcm_trace_commitment: &[u8; HASH_LEN_V1],
    dcm_commitment_root: &[u8; HASH_LEN_V1],
    intent_hash: &[u8; HASH_LEN_V1],
    lineage_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    lineage_hash: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        16 + (HASH_LEN_V1 * 4) + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1,
    );
    bytes.extend_from_slice(&iteration_count.to_le_bytes());
    bytes.extend_from_slice(&trace_state_count.to_le_bytes());
    bytes.extend_from_slice(dcm_trace_commitment);
    bytes.extend_from_slice(dcm_commitment_root);
    bytes.extend_from_slice(intent_hash);
    bytes.extend_from_slice(lineage_commitment);
    bytes.extend_from_slice(lineage_hash);
    bytes
}

fn canonical_transcript_preimage_v1(
    public_claim_digest: &[u8; HASH_LEN_V1],
    witness_digest: &[u8; HASH_LEN_V1],
    constraint_summary_digest: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR.len()
            + 1
            + (HASH_LEN_V1 * 3),
    );
    bytes.extend_from_slice(AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR);
    bytes.push(LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1);
    bytes.extend_from_slice(public_claim_digest);
    bytes.extend_from_slice(witness_digest);
    bytes.extend_from_slice(constraint_summary_digest);
    bytes
}

fn canonical_proof_bound_bytes_v1(
    transcript_digest: &[u8; HASH_LEN_V1],
    public_claim_digest: &[u8; HASH_LEN_V1],
    public_input_digest: &[u8; HASH_LEN_V1],
    proof_binding_digest: &[u8; HASH_LEN_V1],
    trace_state_count: u64,
    internal_trace_length: u64,
    trace_width: u16,
    backend_constraint_count: u16,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((HASH_LEN_V1 * 4) + 8 + 8 + 2 + 2);
    bytes.extend_from_slice(transcript_digest);
    bytes.extend_from_slice(public_claim_digest);
    bytes.extend_from_slice(public_input_digest);
    bytes.extend_from_slice(proof_binding_digest);
    bytes.extend_from_slice(&trace_state_count.to_le_bytes());
    bytes.extend_from_slice(&internal_trace_length.to_le_bytes());
    bytes.extend_from_slice(&trace_width.to_le_bytes());
    bytes.extend_from_slice(&backend_constraint_count.to_le_bytes());
    bytes
}

fn canonical_consumer_result_primary_material_bytes_from_parts_v1(
    decision: u8,
    lower_layer_claim_bytes: &[u8],
    layer2_primary_bytes: &[u8],
    layer3_transcript_digest: &[u8; HASH_LEN_V1],
    layer3_proof_bound_transcript_digest: &[u8; HASH_LEN_V1],
    layer3_proof_binding_digest: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + lower_layer_claim_bytes.len() + layer2_primary_bytes.len() + (HASH_LEN_V1 * 3),
    );
    bytes.push(decision);
    bytes.extend_from_slice(lower_layer_claim_bytes);
    bytes.extend_from_slice(layer2_primary_bytes);
    bytes.extend_from_slice(layer3_transcript_digest);
    bytes.extend_from_slice(layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(layer3_proof_binding_digest);
    bytes
}

fn canonical_consumer_object_primary_material_bytes_from_parts_v1(
    consumer_version: u8,
    consumer_flags: u16,
    decision: u8,
    result_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    lower_layer_claim_bytes: &[u8],
    layer2_primary_bytes: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1
            + 2
            + 1
            + DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1
            + lower_layer_claim_bytes.len()
            + layer2_primary_bytes.len(),
    );
    bytes.push(consumer_version);
    bytes.extend_from_slice(&consumer_flags.to_le_bytes());
    bytes.push(decision);
    bytes.extend_from_slice(result_commitment);
    bytes.extend_from_slice(lower_layer_claim_bytes);
    bytes.extend_from_slice(layer2_primary_bytes);
    bytes
}

fn canonical_ingress_primary_material_bytes_from_parts_v1(
    ingress_version: u8,
    ingress_flags: u16,
    lineage_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    result_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    consumer_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    layer2_primary_bytes: &[u8],
    intent_hash_preimage: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1
            + 2
            + (DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 3)
            + layer2_primary_bytes.len()
            + intent_hash_preimage.len(),
    );
    bytes.push(ingress_version);
    bytes.extend_from_slice(&ingress_flags.to_le_bytes());
    bytes.extend_from_slice(lineage_commitment);
    bytes.extend_from_slice(result_commitment);
    bytes.extend_from_slice(consumer_commitment);
    bytes.extend_from_slice(layer2_primary_bytes);
    bytes.extend_from_slice(intent_hash_preimage);
    bytes
}

fn canonical_public_statement_primary_material_bytes_from_parts_v1(
    statement_version: u8,
    statement_lineage_flags: u16,
    statement_dcm_commitment_kind: u8,
    lineage_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    statement_subject_binding_type: u8,
    statement_subject_id: &[u8; HASH_LEN_V1],
    statement_intent_type: u8,
    intent_hash: &[u8; HASH_LEN_V1],
    statement_freshness_mode: u8,
    statement_freshness_nonce: &[u8; HASH_LEN_V1],
    freshness_reference: u64,
    result_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    ingress_commitment: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 2 + 1 + (DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1 * 3) + (HASH_LEN_V1 * 3) + 8,
    );
    bytes.push(statement_version);
    bytes.extend_from_slice(&statement_lineage_flags.to_le_bytes());
    bytes.push(statement_dcm_commitment_kind);
    bytes.extend_from_slice(lineage_commitment);
    bytes.push(statement_subject_binding_type);
    bytes.extend_from_slice(statement_subject_id);
    bytes.push(statement_intent_type);
    bytes.extend_from_slice(intent_hash);
    bytes.push(statement_freshness_mode);
    bytes.extend_from_slice(statement_freshness_nonce);
    bytes.extend_from_slice(&freshness_reference.to_le_bytes());
    bytes.extend_from_slice(result_commitment);
    bytes.extend_from_slice(ingress_commitment);
    bytes
}

fn canonical_witness_bytes_v1(intent_hash_preimage: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + intent_hash_preimage.len());
    bytes.extend_from_slice(&(intent_hash_preimage.len() as u64).to_le_bytes());
    bytes.extend_from_slice(intent_hash_preimage);
    bytes
}

fn lineage_freshness_reference_offset_v1() -> usize {
    AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1.len()
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

fn update_prefix_accumulator_v1(
    accumulator: &mut PrefixAccumulatorV1,
    output: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
    target: &[u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1],
) {
    for (index, bits) in PREFIX_BITS_V1.into_iter().enumerate() {
        if truncate_bits_be_v1(output, bits) == truncate_bits_be_v1(target, bits) {
            accumulator.match_counts[index] += 1;
        }
    }
    accumulator
        .distinct_prefixes_32
        .insert(truncate_bits_be_v1(output, 32) as u32);
    for bit_index in 0..32usize {
        if extract_bit_be_v1(output, bit_index) {
            accumulator.one_counts_first_32[bit_index] += 1;
        }
    }
    accumulator.sample_count += 1;
}

fn assert_field_native_prefix_diffusion_v1(surface: &str, accumulator: &PrefixAccumulatorV1) {
    assert!(
        accumulator.match_counts[0] < (STRUCTURED_NEIGHBOR_COUNT_V1 * 3 / 4),
        "{surface} still shows excessive first-byte concentration: {} / {} matches",
        accumulator.match_counts[0],
        STRUCTURED_NEIGHBOR_COUNT_V1
    );
    assert!(
        accumulator.match_counts[1] < 64,
        "{surface} still shows excessive 16-bit concentration: {} matches",
        accumulator.match_counts[1]
    );
    assert!(
        accumulator.match_counts[2] <= 8,
        "{surface} still shows excessive 24-bit concentration: {} matches",
        accumulator.match_counts[2]
    );
    assert!(
        accumulator.match_counts[3] <= 1,
        "{surface} still shows excessive 32-bit concentration: {} matches",
        accumulator.match_counts[3]
    );
    assert!(
        accumulator.distinct_prefixes_32.len() > 3800,
        "{surface} produced too few distinct 32-bit prefixes: {}",
        accumulator.distinct_prefixes_32.len()
    );
    assert!(
        constant_bits_in_first_32_v1(accumulator) <= 8,
        "{surface} retained too many constant bits in the first 32: {}",
        constant_bits_in_first_32_v1(accumulator)
    );
}

fn constant_bits_in_first_32_v1(accumulator: &PrefixAccumulatorV1) -> usize {
    accumulator
        .one_counts_first_32
        .iter()
        .filter(|count| **count == 0 || **count == accumulator.sample_count)
        .count()
}

fn legacy_deterministic_commitment_521_v1(
    domain_separator: &[u8],
    body: &[u8],
) -> [u8; DETERMINISTIC_COMMITMENT_521_BYTE_LEN_V1] {
    let canonical_input = legacy_canonical_commitment_input_bytes_v1(domain_separator, body);
    let index_scale = FieldElement521V1::from_u64(LEGACY_INDEX_SCALE_V1);
    let mix_scale = FieldElement521V1::from_u64(LEGACY_MIX_SCALE_V1);
    let final_scale = FieldElement521V1::from_u64(LEGACY_FINAL_SCALE_V1);
    let mut x = FieldElement521V1::reduce_bytes_mod(LEGACY_SEED_X_V1);
    let mut y = FieldElement521V1::reduce_bytes_mod(LEGACY_SEED_Y_V1);
    let mut chunk_count = 0u64;

    for (index, chunk) in canonical_input.chunks(LEGACY_CHUNK_LEN_V1).enumerate() {
        let index_element = FieldElement521V1::from_u64(index as u64 + 1);
        let chunk_element = FieldElement521V1::reduce_bytes_mod(chunk);
        let mixed_chunk = chunk_element.add_mod(&index_element.mul_mod(&index_scale));
        let next_x = x.add_mod(&y).add_mod(&mixed_chunk);
        let next_y = x
            .add_mod(&y.add_mod(&y))
            .add_mod(&chunk_element.square_mod())
            .add_mod(&mixed_chunk.mul_mod(&mix_scale));
        x = next_x;
        y = next_y;
        chunk_count += 1;
    }

    let trailer = FieldElement521V1::from_u64(canonical_input.len() as u64)
        .add_mod(&FieldElement521V1::from_u64(chunk_count))
        .add_mod(&FieldElement521V1::reduce_bytes_mod(domain_separator));
    x.add_mod(&y.mul_mod(&final_scale))
        .add_mod(&trailer)
        .to_bytes()
}

fn legacy_canonical_commitment_input_bytes_v1(domain_separator: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        LEGACY_CONTEXT_DOMAIN_SEPARATOR_V1.len() + 8 + domain_separator.len() + 8 + body.len(),
    );
    bytes.extend_from_slice(LEGACY_CONTEXT_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&(domain_separator.len() as u64).to_le_bytes());
    bytes.extend_from_slice(domain_separator);
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(body);
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
