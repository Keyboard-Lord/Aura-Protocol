use std::{env, f64::consts::PI, time::Instant};

use aura_intent_lineage_v1::{
    produce_layer3_authorization_lineage_consumer_object_v1,
    produce_native_layer2_authorization_lineage_object_521_v1,
    prove_layer3_authorization_lineage_real_stark_v1, AuraLayer4FeePolicyKindV1,
    AuraLayer4IntentBodyV1, AuraLayer4OperationBodyV1, AuraLayer4TxKindV1, DcmConfig521V1,
    DcmExecution521V1, DcmInput521V1, FreshnessModeV1,
    Layer1Layer2BridgeFreshnessV1, Layer1Layer2BridgeIntentSourceV1,
    Layer1Layer2BridgeSubjectBindingV1, Layer3AuthorizationLineageProvingInputV1,
    SubjectBindingTypeV1,
    ValueTransferOperationV1, AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR,
    LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1,
};
use sha2::{Digest, Sha256};

use super::{
    accepted_canonical_pipeline_report, accepted_canonical_pipeline_request, encode_hex,
};
use super::super::{
    canonical_pipeline_request_from_report_v1, CanonicalPipelineReportV1,
    CanonicalPipelineRequestV1, LocalStateV1,
    CANONICAL_PIPELINE_REQUEST_BINDING_DOMAIN_SEPARATOR_V1,
    CANONICAL_PIPELINE_REPORT_DIGEST_DOMAIN_SEPARATOR_V1,
    CANONICAL_PIPELINE_SCHEMA_VERSION_V1,
};

const NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1: u64 = 1u64 << 48;
const NON_AUTHORITATIVE_MAX_EXACT_BITS_V1: u32 = 24;
const NON_AUTHORITATIVE_BOUNDED_QUERY_CAP_V1: u64 = 1u64 << 20;

#[derive(Clone, Debug)]
struct GeneratedTargetV1 {
    name: &'static str,
    digest_hex: String,
    canonical_input_hex: String,
    canonical_input_len: usize,
}

#[derive(Clone, Debug)]
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

struct Layer2OracleTemplateV1 {
    lineage_preimage: Vec<u8>,
    freshness_reference_offset: usize,
}

struct ReportOracleTemplateV1 {
    request_binding_preimage: Vec<u8>,
    previous_head_hash_offset: usize,
    report_digest_preimage: Vec<u8>,
    request_binding_hash_offset: usize,
}

struct ConsumerResultOracleTemplateV1 {
    lineage_preimage: Vec<u8>,
    freshness_reference_offset: usize,
    public_claim_bytes: Vec<u8>,
    serialized_layer2_offset: usize,
    constraint_summary_bytes: Vec<u8>,
    lineage_hash_offset_in_constraint_summary: usize,
    transcript_preimage: Vec<u8>,
    public_claim_digest_offset_in_transcript: usize,
    constraint_digest_offset_in_transcript: usize,
    proof_bound_bytes: Vec<u8>,
    transcript_digest_offset_in_bound: usize,
    public_claim_digest_offset_in_bound: usize,
    result_bytes: Vec<u8>,
    public_claim_digest_offset_in_result: usize,
    transcript_digest_offset_in_result: usize,
    bound_digest_offset_in_result: usize,
    lineage_hash_offset_in_result: usize,
}

#[test]
#[ignore = "non-authoritative research/analysis only"]
fn non_authoritative_research_reduced_bit_hash_targets_v1() {
    let report = accepted_canonical_pipeline_report();
    let request = accepted_canonical_pipeline_request();

    let active_target = active_report_digest_target_v1(&report);
    let canonical_request = canonical_pipeline_request_from_report_v1(&report)
        .expect("report should reconstruct its canonical request");
    let report_recomputed =
        sha256_bytes_local(&canonical_report_digest_preimage_bytes_v1(&report));
    assert_eq!(
        report_recomputed,
        report.head_transition_summary.report_digest,
        "active report digest must independently recompute from canonical report bytes"
    );
    assert_eq!(canonical_request, request);

    let canonical_layer2_object = canonical_layer2_object_v1();
    let layer2_preimage = canonical_layer2_object
        .lineage
        .canonical_preimage()
        .expect("canonical layer2 preimage should serialize");
    let layer2_recomputed = sha256_bytes_local(&layer2_preimage);
    assert_eq!(
        layer2_recomputed, canonical_layer2_object.lineage_hash,
        "layer2 lineage hash must recompute from canonical preimage bytes"
    );
    let layer2_target = GeneratedTargetV1 {
        name: "native_layer2_lineage_hash",
        digest_hex: encode_hex(&canonical_layer2_object.lineage_hash),
        canonical_input_hex: encode_hex(&layer2_preimage),
        canonical_input_len: layer2_preimage.len(),
    };

    let (canonical_proof, canonical_consumer) = canonical_layer3_consumer_v1();
    let consumer_result_preimage = canonical_consumer_result_preimage_bytes_v1(&canonical_consumer);
    let consumer_result_recomputed = sha256_domain_separated_local(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
        &consumer_result_preimage,
    );
    assert_eq!(
        consumer_result_recomputed,
        canonical_consumer.proof_result.result_digest,
        "layer3 consumer result digest must recompute from frozen result preimage bytes"
    );
    let consumer_target = GeneratedTargetV1 {
        name: "layer3_consumer_result_digest",
        digest_hex: encode_hex(&canonical_consumer.proof_result.result_digest),
        canonical_input_hex: encode_hex(&consumer_result_preimage),
        canonical_input_len: consumer_result_preimage.len(),
    };

    let report_fixture_binding_changes_digest = {
        let mut report_variant = report.clone();
        report_variant.fixture_name.push_str("_transport_variant");
        sha256_bytes_local(&canonical_report_digest_preimage_bytes_v1(&report_variant))
            != report.head_transition_summary.report_digest
    };

    let report_search = run_search_suite_v1(
        &active_target,
        &mut report_oracle_template_v1(&report),
        |oracle, candidate| oracle.digest_for_candidate(candidate),
    );
    let layer2_search = run_search_suite_v1(
        &layer2_target,
        &mut layer2_oracle_template_v1(&canonical_layer2_object),
        |oracle, candidate| oracle.digest_for_candidate(candidate),
    );
    let consumer_search = run_search_suite_v1(
        &consumer_target,
        &mut consumer_result_oracle_template_v1(&canonical_proof, &canonical_consumer),
        |oracle, candidate| oracle.digest_for_candidate(candidate),
    );

    eprintln!("AURA reduced-bit cryptanalytic evaluation (non-authoritative research only)");
    print_target_v1(&active_target);
    print_target_v1(&layer2_target);
    print_target_v1(&consumer_target);
    eprintln!(
        "active_report_digest fixture_name_transport_binding_changes_digest={report_fixture_binding_changes_digest}"
    );
    print_search_suite_v1(active_target.name, &report_search);
    print_search_suite_v1(layer2_target.name, &layer2_search);
    print_search_suite_v1(consumer_target.name, &consumer_search);

    assert!(report_fixture_binding_changes_digest);
    assert!(report_search
        .iter()
        .chain(layer2_search.iter())
        .chain(consumer_search.iter())
        .all(|observation| observation.queries_run > 0));
    assert!(report_search
        .iter()
        .chain(layer2_search.iter())
        .chain(consumer_search.iter())
        .filter(|observation| observation.fully_exhausted)
        .all(|observation| observation.queries_run == observation.space_size));
}

impl GeneratedTargetV1 {
    fn digest_bytes(&self) -> [u8; 32] {
        decode_hex_32_local(&self.digest_hex)
    }
}

impl Layer2OracleTemplateV1 {
    fn digest_for_candidate(&mut self, candidate: u64) -> [u8; 32] {
        self.lineage_preimage[self.freshness_reference_offset..self.freshness_reference_offset + 8]
            .copy_from_slice(&(NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1 + candidate).to_le_bytes());
        sha256_bytes_local(&self.lineage_preimage)
    }
}

impl ReportOracleTemplateV1 {
    fn digest_for_candidate(&mut self, candidate: u64) -> [u8; 32] {
        let mut previous_head_hash = [0u8; 32];
        previous_head_hash.copy_from_slice(
            &self.request_binding_preimage
                [self.previous_head_hash_offset..self.previous_head_hash_offset + 32],
        );
        previous_head_hash[0] ^= 0x80;
        previous_head_hash[24..32]
            .copy_from_slice(&(NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1 + candidate).to_le_bytes());
        self.request_binding_preimage
            [self.previous_head_hash_offset..self.previous_head_hash_offset + 32]
            .copy_from_slice(&previous_head_hash);

        let request_binding_hash = sha256_bytes_local(&self.request_binding_preimage);
        self.report_digest_preimage
            [self.request_binding_hash_offset..self.request_binding_hash_offset + 32]
            .copy_from_slice(&request_binding_hash);
        sha256_bytes_local(&self.report_digest_preimage)
    }
}

impl ConsumerResultOracleTemplateV1 {
    fn digest_for_candidate(&mut self, candidate: u64) -> [u8; 32] {
        self.lineage_preimage[self.freshness_reference_offset..self.freshness_reference_offset + 8]
            .copy_from_slice(&(NON_AUTHORITATIVE_SEARCH_BASE_REFERENCE_V1 + candidate).to_le_bytes());

        let lineage_hash = sha256_bytes_local(&self.lineage_preimage);

        self.public_claim_bytes[self.serialized_layer2_offset
            ..self.serialized_layer2_offset + self.lineage_preimage.len()]
            .copy_from_slice(&self.lineage_preimage);
        self.public_claim_bytes[self.serialized_layer2_offset + self.lineage_preimage.len()
            ..self.serialized_layer2_offset + self.lineage_preimage.len() + 32]
            .copy_from_slice(&lineage_hash);
        let public_claim_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_PUBLIC_DOMAIN_SEPARATOR,
            &self.public_claim_bytes,
        );

        self.constraint_summary_bytes[self.lineage_hash_offset_in_constraint_summary
            ..self.lineage_hash_offset_in_constraint_summary + 32]
            .copy_from_slice(&lineage_hash);
        let constraint_summary_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_CONSTRAINTS_DOMAIN_SEPARATOR,
            &self.constraint_summary_bytes,
        );

        self.transcript_preimage[self.public_claim_digest_offset_in_transcript
            ..self.public_claim_digest_offset_in_transcript + 32]
            .copy_from_slice(&public_claim_digest);
        self.transcript_preimage[self.constraint_digest_offset_in_transcript
            ..self.constraint_digest_offset_in_transcript + 32]
            .copy_from_slice(&constraint_summary_digest);
        let transcript_digest = sha256_bytes_local(&self.transcript_preimage);

        self.proof_bound_bytes[self.transcript_digest_offset_in_bound
            ..self.transcript_digest_offset_in_bound + 32]
            .copy_from_slice(&transcript_digest);
        self.proof_bound_bytes[self.public_claim_digest_offset_in_bound
            ..self.public_claim_digest_offset_in_bound + 32]
            .copy_from_slice(&public_claim_digest);
        let proof_bound_digest = sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_REAL_STARK_BINDING_DOMAIN_SEPARATOR,
            &self.proof_bound_bytes,
        );

        self.result_bytes[self.public_claim_digest_offset_in_result
            ..self.public_claim_digest_offset_in_result + 32]
            .copy_from_slice(&public_claim_digest);
        self.result_bytes[self.transcript_digest_offset_in_result
            ..self.transcript_digest_offset_in_result + 32]
            .copy_from_slice(&transcript_digest);
        self.result_bytes[self.bound_digest_offset_in_result
            ..self.bound_digest_offset_in_result + 32]
            .copy_from_slice(&proof_bound_digest);
        self.result_bytes[self.lineage_hash_offset_in_result
            ..self.lineage_hash_offset_in_result + 32]
            .copy_from_slice(&lineage_hash);

        sha256_domain_separated_local(
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
            &self.result_bytes,
        )
    }
}

fn active_report_digest_target_v1(report: &CanonicalPipelineReportV1) -> GeneratedTargetV1 {
    let preimage = canonical_report_digest_preimage_bytes_v1(report);
    GeneratedTargetV1 {
        name: "active_canonical_report_digest",
        digest_hex: encode_hex(&report.head_transition_summary.report_digest),
        canonical_input_hex: encode_hex(&preimage),
        canonical_input_len: preimage.len(),
    }
}

fn canonical_intent_v1() -> AuraLayer4IntentBodyV1 {
    AuraLayer4IntentBodyV1 {
        intent_version: 1,
        intent_flags: 0,
        rollup_id: [0x11; 32],
        tx_kind: AuraLayer4TxKindV1::ValueTransfer,
        sender_account_id: [0x22; 32],
        sender_nonce: 7,
        validity_flags: 0x000c,
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
        not_before_batch_number: 120,
        not_after_batch_number: 125,
        fee_policy_kind: AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
        max_fee_native: 500,
        client_context_commitment: [0u8; 32],
        operation_body: AuraLayer4OperationBodyV1::ValueTransfer(ValueTransferOperationV1 {
            recipient_account_id: [0x33; 32],
            amount: 2500,
        }),
    }
}

fn canonical_dcm_config_v1() -> DcmConfig521V1 {
    DcmConfig521V1 { iteration_count: 5 }
}

fn canonical_dcm_input_v1() -> DcmInput521V1 {
    DcmInput521V1::from_u64(3, 7)
}

fn canonical_subject_binding_v1() -> Layer1Layer2BridgeSubjectBindingV1 {
    Layer1Layer2BridgeSubjectBindingV1 {
        subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
        subject_id: [0x55; 32],
        subject_public_key: None,
    }
}

fn canonical_freshness_v1() -> Layer1Layer2BridgeFreshnessV1 {
    Layer1Layer2BridgeFreshnessV1 {
        freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
        freshness_nonce: [0x66; 32],
        freshness_reference: 4242,
    }
}

fn canonical_layer2_object_v1() -> aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1 {
    produce_native_layer2_authorization_lineage_object_521_v1(
        &canonical_dcm_config_v1(),
        &canonical_dcm_input_v1(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent_v1()),
        canonical_subject_binding_v1(),
        canonical_freshness_v1(),
    )
    .expect("canonical layer2 object should produce")
}

fn canonical_layer3_consumer_v1(
) -> (
    aura_intent_lineage_v1::Layer3AuthorizationLineageRealStarkProofV1,
    aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1,
) {
    let config = canonical_dcm_config_v1();
    let dcm_input = canonical_dcm_input_v1();
    let execution = DcmExecution521V1::run(&config, &dcm_input)
        .expect("canonical DCM execution should succeed");
    let claim = aura_intent_lineage_v1::build_dcm_claim_521_v1(&config, &dcm_input, &execution);
    let layer2_object = canonical_layer2_object_v1();
    let intent = canonical_intent_v1();
    let proving_input = Layer3AuthorizationLineageProvingInputV1::new(claim, layer2_object, intent);
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&proving_input)
        .expect("canonical layer3 proof should succeed");
    let consumer = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    (proof, consumer)
}

fn canonical_consumer_result_preimage_bytes_v1(
    consumer: &aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + (32 * 8));
    bytes.push(consumer.decision.as_u8());
    bytes.extend_from_slice(&consumer.proof_result.public_claim_digest);
    bytes.extend_from_slice(&consumer.proof_result.layer3_transcript_digest);
    bytes.extend_from_slice(&consumer.proof_result.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&consumer.proof_result.layer3_proof_binding_digest);
    bytes.extend_from_slice(&consumer.proof_result.lineage_hash);
    bytes.extend_from_slice(&consumer.proof_result.dcm_commitment_root);
    bytes.extend_from_slice(&consumer.proof_result.dcm_trace_commitment);
    bytes.extend_from_slice(&consumer.proof_result.intent_hash);
    bytes
}

fn canonical_report_digest_preimage_bytes_v1(report: &CanonicalPipelineReportV1) -> Vec<u8> {
    assert!(
        report.attestation_summary.is_none()
            && report.attestation_proof_summary.is_none()
            && report.provenance_summary.is_none(),
        "sample-specific report digest builder expects the accepted execution report path"
    );

    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_REPORT_DIGEST_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&report.pipeline_schema_version.to_le_bytes());
    push_len_prefixed_v1(&mut bytes, report.pipeline_id.as_bytes());
    push_len_prefixed_v1(&mut bytes, report.fixture_name.as_bytes());
    push_len_prefixed_v1(&mut bytes, report.proof_system.as_fixture_str().as_bytes());
    push_len_prefixed_v1(&mut bytes, report.expected_result.as_fixture_str().as_bytes());
    push_len_prefixed_v1(&mut bytes, report.actual_result.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&report.pre_state_root);
    push_optional_hash_v1(&mut bytes, report.executed_post_state_root);
    push_optional_hash_v1(&mut bytes, report.settlement_committed_state_root);
    bytes.extend_from_slice(&report.request_audit.request_binding_hash);
    bytes.extend_from_slice(
        &report
            .ledger_summary
            .ledger_state_commitment
            .pre_ledger_state_commitment,
    );
    bytes.extend_from_slice(
        &report
            .ledger_summary
            .ledger_state_commitment
            .post_ledger_state_commitment,
    );
    bytes.extend_from_slice(&report.accounting_summary.burn_record.account_id);
    bytes.extend_from_slice(&report.accounting_summary.burn_record.pre_balance.to_le_bytes());
    bytes.extend_from_slice(&report.accounting_summary.burn_record.post_balance.to_le_bytes());
    bytes.extend_from_slice(&report.accounting_summary.burn_record.burned_amount.to_le_bytes());
    bytes.extend_from_slice(&report.wallet_binding_summary.wallet_binding_digest);
    bytes.extend_from_slice(&report.token_anchor_summary.token_anchor_digest);
    push_len_prefixed_v1(
        &mut bytes,
        report
            .status_explanation
            .failure_reason_code
            .as_str()
            .as_bytes(),
    );
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    if let Some(public_inputs) = &report.public_inputs {
        bytes.push(1);
        bytes.extend_from_slice(&public_inputs.public_inputs_hash);
    } else {
        bytes.push(0);
    }
    if let Some(proof_artifact) = &report.proof_artifact {
        bytes.push(1);
        bytes.extend_from_slice(&proof_artifact.proof_binding_digest);
    } else {
        bytes.push(0);
    }
    bytes
}

fn report_request_binding_preimage_bytes_v1(
    request: &CanonicalPipelineRequestV1,
) -> (Vec<u8>, usize) {
    assert!(
        request.attestation.is_none(),
        "sample-specific request binding builder expects the accepted execution request path"
    );

    let ordered_accounts = LocalStateV1::new(request.accounts.clone())
        .expect("canonical request accounts should validate")
        .ordered_accounts();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_REQUEST_BINDING_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&CANONICAL_PIPELINE_SCHEMA_VERSION_V1.to_le_bytes());
    push_len_prefixed_v1(&mut bytes, request.pipeline_id.as_bytes());
    push_len_prefixed_v1(&mut bytes, request.proof_system.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&request.economic.economic_policy_version.to_le_bytes());
    push_len_prefixed_v1(&mut bytes, request.economic.request_kind.as_str().as_bytes());
    push_len_prefixed_v1(&mut bytes, request.economic.burn_intent.as_str().as_bytes());
    bytes.extend_from_slice(&request.accounting.accounting_policy_version.to_le_bytes());
    push_len_prefixed_v1(&mut bytes, request.accounting.payment_intent.as_str().as_bytes());
    push_len_prefixed_v1(
        &mut bytes,
        request.accounting.settlement_intent.as_str().as_bytes(),
    );
    bytes.extend_from_slice(&request.ledger.ledger_policy_version.to_le_bytes());
    bytes.extend_from_slice(&request.ledger.payer_account_id);
    bytes.extend_from_slice(&request.ledger.total_supply.to_le_bytes());
    bytes.extend_from_slice(&request.ledger.burned_supply.to_le_bytes());
    push_ledger_accounts_v1(&mut bytes, &request.ledger.accounts);
    bytes.extend_from_slice(&request.head.settlement_head_version.to_le_bytes());
    let previous_head_hash_offset = bytes.len();
    bytes.extend_from_slice(&request.head.previous_head_hash);
    bytes.extend_from_slice(&request.head.head_sequence_number.to_le_bytes());
    bytes.extend_from_slice(&request.wallet_binding.wallet_binding_version.to_le_bytes());
    bytes.extend_from_slice(&request.wallet_binding.account_id);
    push_len_prefixed_v1(&mut bytes, request.wallet_binding.wallet_address.as_bytes());
    bytes.extend_from_slice(&request.token_anchor.token_policy_version.to_le_bytes());
    push_len_prefixed_v1(&mut bytes, request.token_anchor.network_mode.as_str().as_bytes());
    push_len_prefixed_v1(
        &mut bytes,
        request.token_anchor.settlement_anchor_type.as_str().as_bytes(),
    );
    push_optional_external_balance_reference_v1(
        &mut bytes,
        request.token_anchor.external_balance_reference.as_ref(),
    );
    bytes.push(u8::from(request.token_anchor.enforce_external_match));
    match request.token_anchor.expected_external_balance {
        Some(balance) => {
            bytes.push(1);
            bytes.extend_from_slice(&balance.to_le_bytes());
        }
        None => bytes.push(0),
    }
    bytes.push(0);
    bytes.extend_from_slice(&request.rollup_id);
    push_genesis_accounts_v1(&mut bytes, &ordered_accounts);
    bytes.extend_from_slice(&request.batch_number.to_le_bytes());
    bytes.extend_from_slice(&request.parent_batch_commitment);
    push_transactions_v1(&mut bytes, &request.transactions);
    push_len_prefixed_v1(&mut bytes, request.fixture_name.as_bytes());
    push_optional_tamper_v1(&mut bytes, request.tamper_public_inputs.as_ref());
    push_optional_tamper_v1(&mut bytes, request.tamper_proof_binding_digest.as_ref());
    push_len_prefixed_v1(&mut bytes, request.expected_result.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&request.economic.declared_fee_units.to_le_bytes());
    (bytes, previous_head_hash_offset)
}

fn layer2_oracle_template_v1(
    layer2_object: &aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1,
) -> Layer2OracleTemplateV1 {
    Layer2OracleTemplateV1 {
        lineage_preimage: layer2_object
            .lineage
            .canonical_preimage()
            .expect("canonical layer2 preimage should serialize"),
        freshness_reference_offset: lineage_freshness_reference_offset_v1(),
    }
}

fn report_oracle_template_v1(report: &CanonicalPipelineReportV1) -> ReportOracleTemplateV1 {
    let request = canonical_pipeline_request_from_report_v1(report)
        .expect("report should reconstruct its canonical request");
    let (request_binding_preimage, previous_head_hash_offset) =
        report_request_binding_preimage_bytes_v1(&request);
    let mut report_digest_preimage = canonical_report_digest_preimage_bytes_v1(report);
    let request_binding_hash_offset = report_digest_request_binding_hash_offset_v1(report);
    report_digest_preimage[request_binding_hash_offset..request_binding_hash_offset + 32]
        .copy_from_slice(&report.request_audit.request_binding_hash);
    ReportOracleTemplateV1 {
        request_binding_preimage,
        previous_head_hash_offset,
        report_digest_preimage,
        request_binding_hash_offset,
    }
}

fn consumer_result_oracle_template_v1(
    canonical_proof: &aura_intent_lineage_v1::Layer3AuthorizationLineageRealStarkProofV1,
    canonical_consumer: &aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1,
) -> ConsumerResultOracleTemplateV1 {
    let lineage_preimage = canonical_proof
        .public_claim
        .layer2_object
        .lineage
        .canonical_preimage()
        .expect("canonical lineage preimage should serialize");
    let lower_layer_claim_bytes = canonical_proof.public_claim.lower_layer_claim.canonical_bytes();
    let serialized_layer2_offset = lower_layer_claim_bytes.len();
    let mut public_claim_bytes =
        Vec::with_capacity(lower_layer_claim_bytes.len() + lineage_preimage.len() + 32);
    public_claim_bytes.extend_from_slice(&lower_layer_claim_bytes);
    public_claim_bytes.extend_from_slice(&lineage_preimage);
    public_claim_bytes.extend_from_slice(&canonical_proof.public_claim.layer2_object.lineage_hash);

    let mut constraint_summary_bytes = Vec::with_capacity(16 + (32 * 4));
    constraint_summary_bytes.extend_from_slice(
        &canonical_proof
            .public_claim
            .lower_layer_claim
            .config
            .iteration_count
            .to_le_bytes(),
    );
    constraint_summary_bytes.extend_from_slice(
        &canonical_proof
            .public_claim
            .lower_layer_claim
            .trace_state_count()
            .to_le_bytes(),
    );
    constraint_summary_bytes
        .extend_from_slice(&canonical_consumer.proof_result.dcm_trace_commitment);
    constraint_summary_bytes
        .extend_from_slice(&canonical_consumer.proof_result.dcm_commitment_root);
    constraint_summary_bytes.extend_from_slice(&canonical_consumer.proof_result.intent_hash);
    let lineage_hash_offset_in_constraint_summary = constraint_summary_bytes.len();
    constraint_summary_bytes.extend_from_slice(&canonical_consumer.proof_result.lineage_hash);

    let intent_preimage = canonical_proof
        .intent_body
        .canonical_hash_preimage()
        .expect("canonical intent preimage should serialize");
    let witness_digest = sha256_domain_separated_local(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_WITNESS_DOMAIN_SEPARATOR,
        &canonical_witness_bytes_v1(&intent_preimage),
    );

    let mut transcript_preimage = Vec::with_capacity(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR.len() + 1 + (32 * 3),
    );
    transcript_preimage
        .extend_from_slice(AURA_LAYER3_AUTHORIZATION_LINEAGE_V1_TRANSCRIPT_DOMAIN_SEPARATOR);
    transcript_preimage.push(LAYER3_AUTHORIZATION_LINEAGE_PROOF_TRANSCRIPT_VERSION_V1);
    let public_claim_digest_offset_in_transcript = transcript_preimage.len();
    transcript_preimage.extend_from_slice(&canonical_proof.transcript.public_claim_digest);
    transcript_preimage.extend_from_slice(&witness_digest);
    let constraint_digest_offset_in_transcript = transcript_preimage.len();
    transcript_preimage.extend_from_slice(&canonical_proof.transcript.constraint_summary_digest);

    let mut proof_bound_bytes = Vec::with_capacity((32 * 4) + 8 + 8 + 2 + 2);
    let transcript_digest_offset_in_bound = proof_bound_bytes.len();
    proof_bound_bytes.extend_from_slice(&canonical_proof.transcript.transcript_digest);
    let public_claim_digest_offset_in_bound = proof_bound_bytes.len();
    proof_bound_bytes.extend_from_slice(&canonical_proof.transcript.public_claim_digest);
    proof_bound_bytes.extend_from_slice(&canonical_proof.proof_artifact.public_input_digest);
    proof_bound_bytes.extend_from_slice(&canonical_proof.proof_artifact.proof_binding_digest);
    proof_bound_bytes
        .extend_from_slice(&canonical_proof.proof_artifact.trace_state_count.to_le_bytes());
    proof_bound_bytes.extend_from_slice(
        &canonical_proof
            .proof_artifact
            .internal_trace_length
            .to_le_bytes(),
    );
    proof_bound_bytes.extend_from_slice(&canonical_proof.proof_artifact.trace_width.to_le_bytes());
    proof_bound_bytes.extend_from_slice(
        &canonical_proof
            .proof_artifact
            .backend_constraint_count
            .to_le_bytes(),
    );

    let result_bytes = canonical_consumer_result_preimage_bytes_v1(canonical_consumer);
    let public_claim_digest_offset_in_result = 1;
    let transcript_digest_offset_in_result = public_claim_digest_offset_in_result + 32;
    let bound_digest_offset_in_result = transcript_digest_offset_in_result + 32;
    let lineage_hash_offset_in_result = bound_digest_offset_in_result + 64;

    ConsumerResultOracleTemplateV1 {
        lineage_preimage,
        freshness_reference_offset: lineage_freshness_reference_offset_v1(),
        public_claim_bytes,
        serialized_layer2_offset,
        constraint_summary_bytes,
        lineage_hash_offset_in_constraint_summary,
        transcript_preimage,
        public_claim_digest_offset_in_transcript,
        constraint_digest_offset_in_transcript,
        proof_bound_bytes,
        transcript_digest_offset_in_bound,
        public_claim_digest_offset_in_bound,
        result_bytes,
        public_claim_digest_offset_in_result,
        transcript_digest_offset_in_result,
        bound_digest_offset_in_result,
        lineage_hash_offset_in_result,
    }
}

fn run_search_suite_v1<T, F>(
    target: &GeneratedTargetV1,
    oracle_template: &mut T,
    mut oracle: F,
) -> Vec<SearchObservationV1>
where
    F: FnMut(&mut T, u64) -> [u8; 32],
{
    [16u32, 20, 24, 28, 32]
        .into_iter()
        .map(|bits| {
            let space_size = 1u64 << bits;
            let query_limit = if bits <= max_exact_bits_v1() {
                space_size
            } else {
                bounded_query_cap_v1().min(space_size)
            };
            let target_bits = truncate_digest_bits_be_v1(&target.digest_bytes(), bits);
            let started = Instant::now();
            let mut first_match_index = None;
            let mut observed_match_count = 0u64;

            for candidate in 0..query_limit {
                let digest = oracle(oracle_template, candidate);
                if truncate_digest_bits_be_v1(&digest, bits) == target_bits {
                    observed_match_count += 1;
                    if first_match_index.is_none() {
                        first_match_index = Some(candidate);
                    }
                }
            }

            let fully_exhausted = query_limit == space_size;
            let grover_marked_count = if observed_match_count == 0 {
                1
            } else {
                observed_match_count
            };
            let (grover_query_estimate, grover_success_probability) =
                grover_estimate_v1(space_size, grover_marked_count);

            SearchObservationV1 {
                bits,
                space_size,
                queries_run: query_limit,
                fully_exhausted,
                first_match_index,
                observed_match_count,
                elapsed_ms: started.elapsed().as_millis(),
                grover_marked_count,
                grover_query_estimate,
                grover_success_probability,
            }
        })
        .collect()
}

fn print_target_v1(target: &GeneratedTargetV1) {
    eprintln!(
        "target={} digest={} canonical_input_len={} canonical_input_hex={}",
        target.name, target.digest_hex, target.canonical_input_len, target.canonical_input_hex
    );
}

fn print_search_suite_v1(name: &str, observations: &[SearchObservationV1]) {
    for observation in observations {
        eprintln!(
            "target={} bits={} space_size={} complete={} queries_run={} first_match_index={} observed_match_count={} grover_marked_count={} grover_query_estimate={} grover_success_probability={:.6} elapsed_ms={}",
            name,
            observation.bits,
            observation.space_size,
            observation.fully_exhausted,
            observation.queries_run,
            observation
                .first_match_index
                .map(|value| value.to_string())
                .unwrap_or_else(|| String::from("none")),
            observation.observed_match_count,
            observation.grover_marked_count,
            observation.grover_query_estimate,
            observation.grover_success_probability,
            observation.elapsed_ms
        );
    }
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

fn truncate_digest_bits_be_v1(digest: &[u8; 32], bits: u32) -> u64 {
    assert!(bits <= 32);
    let byte_len = usize::try_from((bits + 7) / 8).expect("bit length should fit usize");
    let mut value = 0u64;
    for byte in &digest[..byte_len] {
        value = (value << 8) | u64::from(*byte);
    }
    let excess_bits = (u32::try_from(byte_len).unwrap() * 8) - bits;
    if excess_bits > 0 {
        value >>= excess_bits;
    }
    value
}

fn canonical_witness_bytes_v1(intent_hash_preimage: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + intent_hash_preimage.len());
    bytes.extend_from_slice(
        &u64::try_from(intent_hash_preimage.len())
            .expect("intent preimage length should fit u64")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(intent_hash_preimage);
    bytes
}

fn lineage_freshness_reference_offset_v1() -> usize {
    b"AURA_AUTHORIZATION_LINEAGE_V1".len()
        + 1
        + 2
        + 1
        + 32
        + 32
        + 1
        + 32
        + 32
        + 1
        + 32
        + 1
        + 32
}

fn report_digest_request_binding_hash_offset_v1(report: &CanonicalPipelineReportV1) -> usize {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_REPORT_DIGEST_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&report.pipeline_schema_version.to_le_bytes());
    push_len_prefixed_v1(&mut bytes, report.pipeline_id.as_bytes());
    push_len_prefixed_v1(&mut bytes, report.fixture_name.as_bytes());
    push_len_prefixed_v1(&mut bytes, report.proof_system.as_fixture_str().as_bytes());
    push_len_prefixed_v1(&mut bytes, report.expected_result.as_fixture_str().as_bytes());
    push_len_prefixed_v1(&mut bytes, report.actual_result.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&report.pre_state_root);
    push_optional_hash_v1(&mut bytes, report.executed_post_state_root);
    push_optional_hash_v1(&mut bytes, report.settlement_committed_state_root);
    bytes.len()
}

fn push_len_prefixed_v1(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(
        &u64::try_from(value.len())
            .expect("length should fit u64")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value);
}

fn push_optional_hash_v1(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(hash) => {
            bytes.push(1);
            bytes.extend_from_slice(&hash);
        }
        None => bytes.push(0),
    }
}

fn push_optional_tamper_v1(
    bytes: &mut Vec<u8>,
    tamper: Option<&super::super::ByteTamperFixtureV1>,
) {
    match tamper {
        Some(tamper) => {
            bytes.push(1);
            bytes.extend_from_slice(
                &u64::try_from(tamper.byte_offset)
                    .expect("tamper offset should fit u64")
                    .to_le_bytes(),
            );
            bytes.push(tamper.xor_with);
        }
        None => bytes.push(0),
    }
}

fn push_ledger_accounts_v1(
    bytes: &mut Vec<u8>,
    accounts: &[super::super::CanonicalPipelineLedgerAccountV1],
) {
    bytes.extend_from_slice(
        &u64::try_from(accounts.len())
            .expect("ledger account length should fit u64")
            .to_le_bytes(),
    );
    for account in accounts {
        bytes.extend_from_slice(&account.account_id);
        bytes.extend_from_slice(&account.balance.to_le_bytes());
    }
}

fn push_genesis_accounts_v1(
    bytes: &mut Vec<u8>,
    accounts: &[super::super::LocalAccountV1],
) {
    bytes.extend_from_slice(
        &u64::try_from(accounts.len())
            .expect("genesis account length should fit u64")
            .to_le_bytes(),
    );
    for account in accounts {
        bytes.extend_from_slice(&account.account_id);
        bytes.extend_from_slice(&account.balance.to_le_bytes());
        bytes.extend_from_slice(&account.nonce.to_le_bytes());
    }
}

fn push_transactions_v1(
    bytes: &mut Vec<u8>,
    transactions: &[super::super::TransferTransactionV1],
) {
    bytes.extend_from_slice(
        &u64::try_from(transactions.len())
            .expect("transaction length should fit u64")
            .to_le_bytes(),
    );
    for transaction in transactions {
        bytes.extend_from_slice(&transaction.tx_version.to_le_bytes());
        bytes.extend_from_slice(&transaction.sender_account_id);
        bytes.extend_from_slice(&transaction.recipient_account_id);
        bytes.extend_from_slice(&transaction.sender_nonce.to_le_bytes());
        bytes.extend_from_slice(&transaction.amount.to_le_bytes());
    }
}

fn push_optional_external_balance_reference_v1(
    bytes: &mut Vec<u8>,
    reference: Option<&super::super::CanonicalPipelineExternalBalanceReferenceV1>,
) {
    match reference {
        Some(reference) => {
            bytes.push(1);
            push_len_prefixed_v1(bytes, reference.reference_id.as_bytes());
            match reference.observed_balance {
                Some(balance) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&balance.to_le_bytes());
                }
                None => bytes.push(0),
            }
            match reference.observed_slot {
                Some(slot) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&slot.to_le_bytes());
                }
                None => bytes.push(0),
            }
            bytes.push(u8::from(reference.connected));
        }
        None => bytes.push(0),
    }
}

fn sha256_bytes_local(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_domain_separated_local(domain_separator: &[u8], body: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(domain_separator.len() + body.len());
    bytes.extend_from_slice(domain_separator);
    bytes.extend_from_slice(body);
    sha256_bytes_local(&bytes)
}

fn decode_hex_32_local(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "expected 32-byte hex string");
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble_v1(pair[0]);
        let low = decode_nibble_v1(pair[1]);
        bytes[index] = (high << 4) | low;
    }
    bytes
}

fn decode_nibble_v1(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}
