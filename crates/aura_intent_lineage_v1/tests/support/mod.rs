// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
#![allow(dead_code)]

use std::{fs, path::PathBuf};

use aura_intent_lineage_v1::{
    assemble_layer3_proof_claim_v1, build_storm_claim_v1,
    produce_native_layer2_authorization_lineage_object_521_v1,
    run_native_layer1_layer2_bridge_521_v1, run_native_layer1_layer2_bridge_v1,
    AuraLayer4FeePolicyKindV1, AuraLayer4IntentBodyV1, AuraLayer4OperationBodyV1,
    AuraLayer4TxKindV1, AuthorizationEnvelopeAuthKindV1,
    AuthorizationEnvelopeLineageTransportKindV1, AuthorizationEnvelopeV1,
    AuthorizationEnvelopeValidityBoundsV1, AuthorizationLineageV1, DcmCommitmentKindV1,
    DcmConfig521V1, DcmConfigV1, DcmInput521V1, DcmInputV1, DcmState521V1, DcmStateV1,
    FreshnessModeV1, IntentTypeV1, Layer1Layer2BridgeErrorV1, Layer1Layer2BridgeFreshnessV1,
    Layer1Layer2BridgeIntentSourceV1, Layer1Layer2BridgeSubjectBindingV1,
    Layer1Layer2BridgeSuccess521V1, Layer1Layer2BridgeSuccessV1, Layer3ClaimConstructionInputV1,
    NativeLayer2AuthorizationLineageObjectV1, ProofClaimAssemblyV1, StormContextV1,
    StormExecutionInputsV1, SubjectBindingTypeV1, ValueTransferOperationV1,
    STORM_CONTEXT_V1_VERSION,
};
use serde::{de::DeserializeOwned, Deserialize};

pub const LEGACY_CANONICAL_DCM_COMMITMENT_ROOT_HEX: &str =
    "2c0c509e2214ac9781e366cfa6e907efd2b86404133cf8937089fb7c2e245db4";
pub const LEGACY_CANONICAL_DCM_TRACE_COMMITMENT_HEX: &str =
    "c7121d768249c01a14011efbd60bcc29356a31da250079bb2a951abb6bb82829";
pub const LEGACY_CANONICAL_LINEAGE_HASH_HEX: &str =
    "99f1dbcba102eaa9965125ce3d582c45b1379a687905f670108c3caab7d24b18";
pub const CANONICAL_DCM_COMMITMENT_ROOT_HEX: &str =
    "7b64c5bd4f5d157daf7100494c9ae4d48237a16e11476357f090ad839d4159ef";
pub const CANONICAL_DCM_TRACE_COMMITMENT_HEX: &str =
    "76dbd2f074da73a6e98119e7c06633a72633845fa210d181e86e4ab7a0c7f44a";
pub const CANONICAL_INTENT_HASH_HEX: &str =
    "7fbb895d47d0231a4b63d6637409833956fb9d19fa399624d0076ed8824bb288";
pub const CANONICAL_LINEAGE_HASH_HEX: &str =
    "bc64085ed18453334994cde906cf53409c284f3f5b877a2a161d79940d71cde5";
pub const CANONICAL_TRANSCRIPT_PUBLIC_CLAIM_DIGEST_HEX: &str =
    "5ba572533a7990841af919db06b7edbe6bf438aa2e51b6de32d03b0dd58d5bee";
pub const CANONICAL_TRANSCRIPT_WITNESS_DIGEST_HEX: &str =
    "401aa0d5b470a921881b26e9aecc167d80e03b0abd5f44f895b9597e662e48a7";
pub const CANONICAL_TRANSCRIPT_CONSTRAINT_SUMMARY_DIGEST_HEX: &str =
    "f094c6bfb4550e0695c16962eea31b816b4ca45377d184ef3fbef0a12262c15b";
pub const CANONICAL_TRANSCRIPT_DIGEST_HEX: &str =
    "e7b69f421b531127f350e4e4f55a83b81ddea81f97e6df807e13b7bb4642d4cd";
pub const CANONICAL_PROOF_SESSION_ID_HEX: &str =
    "685662562c56b0be001fdb267b2369711adc821d21aa748ab80f06e3ba57aabc";
pub const LEGACY_CANONICAL_TRACE_STATES_V1: [DcmStateV1; 6] = [
    DcmStateV1 { x: 3, y: 7 },
    DcmStateV1 { x: 10, y: 17 },
    DcmStateV1 { x: 27, y: 44 },
    DcmStateV1 { x: 71, y: 18 },
    DcmStateV1 { x: 89, y: 10 },
    DcmStateV1 { x: 2, y: 12 },
];

#[derive(Debug, Deserialize)]
pub struct IntentFixtureFile {
    pub contract: String,
    pub fixture_name: String,
    pub domain_separator_ascii: String,
    pub intent: IntentFixtureIntent,
    pub expected_serialized_body_hex: String,
    pub expected_hash_preimage_hex: String,
    pub expected_intent_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct IntentRejectFixtureFile {
    pub contract: String,
    pub fixture_name: String,
    pub expected_reject_reason: String,
    pub intent: IntentFixtureIntent,
}

#[derive(Debug, Deserialize)]
pub struct IntentFixtureIntent {
    pub intent_version: u8,
    pub intent_flags: u16,
    pub rollup_id_hex: String,
    pub tx_kind: String,
    pub sender_account_id_hex: String,
    pub sender_nonce: u64,
    pub validity_flags: u16,
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    pub not_before_batch_number: u64,
    pub not_after_batch_number: u64,
    pub fee_policy_kind: String,
    pub max_fee_native: u64,
    pub client_context_commitment_hex: String,
    pub operation_body: ValueTransferFixtureBody,
}

#[derive(Debug, Deserialize)]
pub struct ValueTransferFixtureBody {
    pub recipient_account_id_hex: String,
    pub amount: u64,
}

#[derive(Debug, Deserialize)]
pub struct LineageFixtureFile {
    pub contract: String,
    pub fixture_name: String,
    pub domain_separator_ascii: Option<String>,
    pub lineage: LineageFixtureLineage,
    pub expected_lineage_preimage_hex: Option<String>,
    pub expected_serialized_object_hex: Option<String>,
    pub expected_lineage_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct LineageRejectFixtureFile {
    pub contract: String,
    pub fixture_name: String,
    pub expected_reject_reason: String,
    pub lineage: LineageFixtureLineage,
}

#[derive(Debug, Deserialize)]
pub struct LineageFixtureLineage {
    pub version: u8,
    pub lineage_flags: u16,
    pub dcm_commitment_kind: String,
    pub dcm_commitment_root_hex: String,
    pub dcm_trace_commitment_hex: String,
    pub subject_binding_type: String,
    pub subject_id_hex: String,
    pub subject_public_key_hex: String,
    pub intent_type: String,
    pub intent_hash_hex: String,
    pub freshness_mode: String,
    pub freshness_nonce_hex: String,
    pub freshness_reference: u64,
    pub proof_material_v1_hash_hex: String,
    pub fractal_key_v1_hash_hex: String,
}

pub fn legacy_canonical_dcm_config() -> DcmConfigV1 {
    DcmConfigV1 {
        modulus: 97,
        iteration_count: 5,
    }
}

pub fn legacy_canonical_dcm_input() -> DcmInputV1 {
    DcmInputV1 { x0: 3, y0: 7 }
}

pub fn legacy_changed_dcm_input() -> DcmInputV1 {
    DcmInputV1 { x0: 4, y0: 7 }
}

pub fn canonical_dcm_config() -> DcmConfig521V1 {
    DcmConfig521V1 { iteration_count: 5 }
}

pub fn canonical_dcm_input() -> DcmInput521V1 {
    DcmInput521V1::from_u64(3, 7)
}

pub fn changed_dcm_input() -> DcmInput521V1 {
    DcmInput521V1::from_u64(4, 7)
}

pub fn canonical_trace_states_v1() -> [DcmState521V1; 6] {
    [
        DcmState521V1::from_u64(3, 7),
        DcmState521V1::from_u64(10, 17),
        DcmState521V1::from_u64(27, 44),
        DcmState521V1::from_u64(71, 115),
        DcmState521V1::from_u64(186, 301),
        DcmState521V1::from_u64(487, 788),
    ]
}

pub fn canonical_intent() -> AuraLayer4IntentBodyV1 {
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

pub fn canonical_subject_binding() -> Layer1Layer2BridgeSubjectBindingV1 {
    Layer1Layer2BridgeSubjectBindingV1 {
        subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
        subject_id: [0x55; 32],
        subject_public_key: None,
    }
}

pub fn canonical_freshness() -> Layer1Layer2BridgeFreshnessV1 {
    Layer1Layer2BridgeFreshnessV1 {
        freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
        freshness_nonce: [0x66; 32],
        freshness_reference: 4242,
    }
}

pub fn legacy_canonical_bridge_result(
) -> Result<Layer1Layer2BridgeSuccessV1, Layer1Layer2BridgeErrorV1> {
    run_native_layer1_layer2_bridge_v1(
        &legacy_canonical_dcm_config(),
        &legacy_canonical_dcm_input(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
}

pub fn canonical_bridge_result() -> Result<Layer1Layer2BridgeSuccess521V1, Layer1Layer2BridgeErrorV1>
{
    run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config(),
        &canonical_dcm_input(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
}

pub fn layer3_input_for_dcm_input(dcm_input: DcmInput521V1) -> Layer3ClaimConstructionInputV1 {
    let intent = canonical_intent();
    let bridge = run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config(),
        &dcm_input,
        Layer1Layer2BridgeIntentSourceV1::IntentBody(intent),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap();
    let lower_layer_claim = canonical_storm_claim_for_bridge(&bridge, intent);

    Layer3ClaimConstructionInputV1::from_native_bridge_with_storm_claim(
        canonical_dcm_config(),
        dcm_input,
        lower_layer_claim,
        intent,
        bridge,
    )
}

pub fn canonical_layer3_input() -> Layer3ClaimConstructionInputV1 {
    layer3_input_for_dcm_input(canonical_dcm_input())
}

pub fn layer3_assembly_for_dcm_input(dcm_input: DcmInput521V1) -> ProofClaimAssemblyV1 {
    assemble_layer3_proof_claim_v1(&layer3_input_for_dcm_input(dcm_input)).unwrap()
}

pub fn layer2_object_for_dcm_input(
    dcm_input: DcmInput521V1,
) -> NativeLayer2AuthorizationLineageObjectV1 {
    produce_native_layer2_authorization_lineage_object_521_v1(
        &canonical_dcm_config(),
        &dcm_input,
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap()
}

pub fn canonical_layer2_object() -> NativeLayer2AuthorizationLineageObjectV1 {
    layer2_object_for_dcm_input(canonical_dcm_input())
}

pub fn canonical_layer3_assembly() -> ProofClaimAssemblyV1 {
    layer3_assembly_for_dcm_input(canonical_dcm_input())
}

pub fn canonical_storm_execution_inputs(
    intent: AuraLayer4IntentBodyV1,
    iteration_count: u64,
) -> StormExecutionInputsV1 {
    let freshness = canonical_freshness();
    let subject = canonical_subject_binding();
    let intent_hash = intent.intent_hash().unwrap();

    StormExecutionInputsV1 {
        side_a: [0x91; 110],
        side_b: [0x19; 110],
        context_bytes_v1: StormContextV1 {
            context_version: STORM_CONTEXT_V1_VERSION,
            network_id: [0x77; 32],
            intent_hash,
            freshness_nonce: freshness.freshness_nonce,
            valid_from: intent.not_before_batch_number,
            valid_until: intent.not_after_batch_number,
            controller_id: subject.subject_id,
            route_tag: [0x88; 32],
        }
        .to_bytes(),
        iteration_count,
    }
}

pub fn canonical_storm_claim_for_bridge(
    bridge: &Layer1Layer2BridgeSuccess521V1,
    intent: AuraLayer4IntentBodyV1,
) -> aura_intent_lineage_v1::StormClaim521V1 {
    let inputs = canonical_storm_execution_inputs(intent, bridge.dcm_claim.config.iteration_count);
    build_storm_claim_v1(
        &inputs,
        bridge.dcm_claim.commitment_root,
        bridge.dcm_execution.trace_commitment,
    )
}

pub fn canonical_inline_envelope(
    lineage: AuthorizationLineageV1,
    lineage_hash: [u8; 32],
) -> AuthorizationEnvelopeV1 {
    AuthorizationEnvelopeV1 {
        auth_version: 1,
        auth_kind: AuthorizationEnvelopeAuthKindV1::AuthorizationLineageV1ExactIntent,
        controlled_account_id: [0xaa; 32],
        envelope_validity_bounds: AuthorizationEnvelopeValidityBoundsV1 {
            validity_flags: 0,
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 0,
            not_before_batch_number: 0,
            not_after_batch_number: 0,
        },
        lineage_transport_kind:
            AuthorizationEnvelopeLineageTransportKindV1::InlineAuthorizationLineageV1,
        lineage_hash,
        inline_authorization_lineage_v1: Some(lineage),
    }
}

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/layer4_v1")
        .join(name)
}

pub fn load_fixture<T: DeserializeOwned>(name: &str) -> T {
    let path = fixture_path(name);
    let contents = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read fixture {}: {error}", path.display());
    });
    serde_json::from_str(&contents).unwrap_or_else(|error| {
        panic!("failed to parse fixture {}: {error}", path.display());
    })
}

pub fn build_intent(fixture: &IntentFixtureIntent) -> AuraLayer4IntentBodyV1 {
    AuraLayer4IntentBodyV1 {
        intent_version: fixture.intent_version,
        intent_flags: fixture.intent_flags,
        rollup_id: hex32(&fixture.rollup_id_hex),
        tx_kind: parse_tx_kind(&fixture.tx_kind),
        sender_account_id: hex32(&fixture.sender_account_id_hex),
        sender_nonce: fixture.sender_nonce,
        validity_flags: fixture.validity_flags,
        not_before_unix_seconds: fixture.not_before_unix_seconds,
        not_after_unix_seconds: fixture.not_after_unix_seconds,
        not_before_batch_number: fixture.not_before_batch_number,
        not_after_batch_number: fixture.not_after_batch_number,
        fee_policy_kind: parse_fee_policy_kind(&fixture.fee_policy_kind),
        max_fee_native: fixture.max_fee_native,
        client_context_commitment: hex32(&fixture.client_context_commitment_hex),
        operation_body: AuraLayer4OperationBodyV1::ValueTransfer(ValueTransferOperationV1 {
            recipient_account_id: hex32(&fixture.operation_body.recipient_account_id_hex),
            amount: fixture.operation_body.amount,
        }),
    }
}

pub fn build_lineage(fixture: &LineageFixtureLineage) -> AuthorizationLineageV1 {
    AuthorizationLineageV1 {
        version: fixture.version,
        lineage_flags: fixture.lineage_flags,
        dcm_commitment_kind: parse_dcm_commitment_kind(&fixture.dcm_commitment_kind),
        dcm_commitment_root: hex32(&fixture.dcm_commitment_root_hex),
        dcm_trace_commitment: hex32(&fixture.dcm_trace_commitment_hex),
        subject_binding_type: parse_subject_binding_type(&fixture.subject_binding_type),
        subject_id: hex32(&fixture.subject_id_hex),
        subject_public_key: hex32(&fixture.subject_public_key_hex),
        intent_type: parse_intent_type(&fixture.intent_type),
        intent_hash: hex32(&fixture.intent_hash_hex),
        freshness_mode: parse_freshness_mode(&fixture.freshness_mode),
        freshness_nonce: hex32(&fixture.freshness_nonce_hex),
        freshness_reference: fixture.freshness_reference,
        proof_material_v1_hash: hex32(&fixture.proof_material_v1_hash_hex),
        fractal_key_v1_hash: hex32(&fixture.fractal_key_v1_hash_hex),
    }
}

pub fn hex32(hex: &str) -> [u8; 32] {
    let bytes = decode_hex(hex);
    assert_eq!(
        bytes.len(),
        32,
        "expected 32 decoded bytes, got {}",
        bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex length must be even");
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        bytes.push((decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]));
    }
    bytes
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_nibble(nibble: u8) -> u8 {
    match nibble {
        b'0'..=b'9' => nibble - b'0',
        b'a'..=b'f' => nibble - b'a' + 10,
        b'A'..=b'F' => nibble - b'A' + 10,
        _ => panic!("invalid hex nibble: {nibble}"),
    }
}

fn parse_tx_kind(value: &str) -> AuraLayer4TxKindV1 {
    match value {
        "VALUE_TRANSFER" => AuraLayer4TxKindV1::ValueTransfer,
        "ACCOUNT_CREATE" => AuraLayer4TxKindV1::AccountCreate,
        "ACCOUNT_UPDATE" => AuraLayer4TxKindV1::AccountUpdate,
        "SYSTEM_OPERATION_RESERVED_REJECT" => AuraLayer4TxKindV1::SystemOperationReservedReject,
        _ => panic!("unsupported tx_kind fixture value: {value}"),
    }
}

fn parse_fee_policy_kind(value: &str) -> AuraLayer4FeePolicyKindV1 {
    match value {
        "MAX_FEE_PER_TX_NATIVE" => AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
        _ => panic!("unsupported fee_policy_kind fixture value: {value}"),
    }
}

fn parse_dcm_commitment_kind(value: &str) -> DcmCommitmentKindV1 {
    match value {
        "DCM_ROOT_COMMITMENT_V1" => DcmCommitmentKindV1::DcmRootCommitmentV1,
        "LEGACY_V1_COMPATIBILITY_ONLY" => DcmCommitmentKindV1::LegacyV1CompatibilityOnly,
        _ => panic!("unsupported dcm_commitment_kind fixture value: {value}"),
    }
}

fn parse_subject_binding_type(value: &str) -> SubjectBindingTypeV1 {
    match value {
        "RAW_ED25519_PUBLIC_KEY_32" => SubjectBindingTypeV1::RawEd25519PublicKey32,
        "EXTERNAL_SUBJECT_ID_32" => SubjectBindingTypeV1::ExternalSubjectId32,
        _ => panic!("unsupported subject_binding_type fixture value: {value}"),
    }
}

fn parse_intent_type(value: &str) -> IntentTypeV1 {
    match value {
        "OPAQUE_INTENT_HASH_32" => IntentTypeV1::OpaqueIntentHash32,
        "AURA_LAYER4_INTENT_HASH_V1" => IntentTypeV1::AuraLayer4IntentHashV1,
        "LEGACY_V1_CHALLENGE_CONTEXT" => IntentTypeV1::LegacyV1ChallengeContext,
        _ => panic!("unsupported intent_type fixture value: {value}"),
    }
}

fn parse_freshness_mode(value: &str) -> FreshnessModeV1 {
    match value {
        "NONCE_ONLY" => FreshnessModeV1::NonceOnly,
        "NONCE_PLUS_UNIX_TIME_SECONDS" => FreshnessModeV1::NoncePlusUnixTimeSeconds,
        "NONCE_PLUS_SLOT_NUMBER" => FreshnessModeV1::NoncePlusSlotNumber,
        "LEGACY_V1_CHALLENGE_FRESHNESS" => FreshnessModeV1::LegacyV1ChallengeFreshness,
        _ => panic!("unsupported freshness_mode fixture value: {value}"),
    }
}
