#[path = "support/economic_v1.rs"]
mod support;
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_l2_local_chain_v0::economic_meter::{
    debit_economic_ledger_v1, economic_ledger_commitment_v1,
};
use aura_sdk_v1::{
    authorization::{decode_hex_v2, encode_hex_v2},
    economic::{
        head::{EconomicHeadV2, EconomicOutcomeV1},
        EconomicConsentV1, EconomicLimitsV1, EconomicWorkV1,
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NETWORK: BitcoinNetworkV1 = BitcoinNetworkV1::Regtest;
fn limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: 100_000,
        max_meter_bytes: 90_000,
        max_iterations: 100,
    }
}
fn evidence() -> Value {
    let (work, consent, authorization, _, _) = support::sample();
    let post = debit_economic_ledger_v1(&work.meter.ledger, work.burn_units().unwrap()).unwrap();
    let genesis = EconomicHeadV2::genesis();
    let outcomes = [
        EconomicOutcomeV1::Accepted,
        EconomicOutcomeV1::ExecutionRejected,
        EconomicOutcomeV1::VerificationRejected,
        EconomicOutcomeV1::SettlementRejected,
    ];
    let heads: Vec<_> = outcomes
        .into_iter()
        .map(|outcome| {
            json!({"outcome": format!("{outcome:?}"),
        "head": genesis.advance(NETWORK, &work, outcome, &post).unwrap()})
        })
        .collect();
    json!({"network": "regtest", "secret_key_hex": format!("{}03", "00".repeat(31)),
        "work_hex": encode_hex_v2(&work.canonical_bytes().unwrap()), "meter_hex": encode_hex_v2(&work.meter.canonical_bytes().unwrap()),
        "burn_units": work.burn_units().unwrap().to_string(), "consent": consent, "authorization": authorization,
        "signing_digest_hex": encode_hex_v2(&EconomicConsentV1::signing_digest(NETWORK, &work, &authorization).unwrap()),
        "pre_ledger_commitment_hex": encode_hex_v2(&economic_ledger_commitment_v1(&work.meter.ledger).unwrap()),
        "post_ledger_commitment_hex": encode_hex_v2(&economic_ledger_commitment_v1(&post).unwrap()), "genesis": genesis, "heads": heads })
}

#[test]
fn frozen_work_consent_debit_and_all_four_head_vectors() {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../fixtures/economic_admission_v1/contract_vector.json"
    ))
    .unwrap();
    assert_eq!(evidence(), expected);
    let (work, consent, auth, _, _) = support::sample();
    consent
        .verify_admission_signatures(NETWORK, &work, &auth)
        .unwrap();
    let bytes = work.canonical_bytes().unwrap();
    assert_eq!(EconomicWorkV1::decode(&bytes, limits()).unwrap(), work);
    let previous_auth: Value = serde_json::from_str(include_str!(
        "../../../fixtures/authorization_v2/authorization_vector_v2.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::to_value(auth).unwrap(),
        previous_auth["authorization"]
    );
}

#[test]
fn every_work_byte_and_signed_reference_is_bound() {
    let (work, consent, auth, _, _) = support::sample();
    let original = work.canonical_bytes().unwrap();
    for i in 0..original.len() {
        let mut bytes = original.clone();
        bytes[i] ^= 1;
        if let Ok(changed) = EconomicWorkV1::decode(&bytes, limits()) {
            assert!(
                consent
                    .verify_admission_signatures(NETWORK, &changed, &auth)
                    .is_err(),
                "byte {i}"
            );
        }
    }
    assert!(consent
        .verify_admission_signatures(BitcoinNetworkV1::Mainnet, &work, &auth)
        .is_err());
    let mut changed = auth.clone();
    changed.proof_hash_hex = "aa".repeat(32);
    assert!(consent
        .verify_admission_signatures(NETWORK, &work, &changed)
        .is_err());
    for field in [
        "subject_binding",
        "freshness_binding",
        "intent_commitment_hex",
    ] {
        let mut value = serde_json::to_value(&auth).unwrap();
        value["authorization_lineage"][field] = "01".repeat(32).into();
        let changed = serde_json::from_value(value).unwrap();
        assert!(consent
            .verify_admission_signatures(NETWORK, &work, &changed)
            .is_err());
    }
}

#[test]
fn framing_shape_and_resource_limits_fail_before_admission() {
    let (work, consent, _, _, _) = support::sample();
    let bytes = work.canonical_bytes().unwrap();
    for n in 0..bytes.len() {
        assert!(EconomicWorkV1::decode(&bytes[..n], limits()).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(EconomicWorkV1::decode(&extra, limits()).is_err());
    let mut overflow = bytes.clone();
    let start = b"AURA_ECONOMIC_WORK_REQUEST_V1".len();
    overflow[start..start + 8].fill(0xff);
    assert!(EconomicWorkV1::decode(&overflow, limits()).is_err());
    let mut bound = limits();
    bound.max_iterations = 2;
    assert!(EconomicWorkV1::decode(&bytes, bound).is_err());
    bound = limits();
    bound.max_meter_bytes = 10;
    assert!(EconomicWorkV1::decode(&bytes, bound).is_err());
    bound = limits();
    bound.max_work_bytes = 10;
    assert!(EconomicWorkV1::decode(&bytes, bound).is_err());
    for field in ["economic_consent_version", "signature_hex"] {
        let mut v = serde_json::to_value(&consent).unwrap();
        v.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<EconomicConsentV1>(v).is_err());
    }
    let mut v = serde_json::to_value(&consent).unwrap();
    v["proof_hash_hex"] = "00".repeat(32).into();
    assert!(serde_json::from_value::<EconomicConsentV1>(v).is_err());
    let mut bad = consent.clone();
    bad.economic_consent_version = "v2".into();
    assert!(bad.validate_shape().is_err());
    bad = consent;
    bad.signature_hex.make_ascii_uppercase();
    assert!(bad.validate_shape().is_err());
}

#[test]
fn consent_and_signature_checks_do_not_assert_proof_authorization() {
    let (work, _, mut auth, _, _) = support::sample();
    auth.proof_hash_hex = "ee".repeat(32); // Valid signatures for a reference unrelated to the actual proof.
    let secp = secp256k1::Secp256k1::new();
    auth.signature_hex = encode_hex_v2(
        secp.sign_schnorr_no_aux_rand(&auth.signing_digest(NETWORK).unwrap(), &support::keypair())
            .as_ref(),
    );
    let consent = support::sign(&work, &auth);
    consent
        .verify_admission_signatures(NETWORK, &work, &auth)
        .unwrap();
    let mut changed = auth;
    changed.signature_hex = "00".repeat(64);
    assert!(consent
        .verify_admission_signatures(NETWORK, &work, &changed)
        .is_err());
}

#[test]
fn head_rejects_stale_linkage_bad_debit_genesis_and_sequence_overflow() {
    let (work, _, _, _, _) = support::sample();
    let post = debit_economic_ledger_v1(&work.meter.ledger, work.burn_units().unwrap()).unwrap();
    let genesis = EconomicHeadV2::genesis();
    let head = genesis
        .advance(NETWORK, &work, EconomicOutcomeV1::Accepted, &post)
        .unwrap();
    assert_eq!(head.validate().unwrap(), 1);
    assert!(head
        .advance(NETWORK, &work, EconomicOutcomeV1::Accepted, &post)
        .is_err());
    assert!(genesis
        .advance(
            NETWORK,
            &work,
            EconomicOutcomeV1::Accepted,
            &work.meter.ledger
        )
        .is_err());
    let mut bad = genesis.clone();
    bad.current_head_hash_hex = "11".repeat(32);
    assert!(bad.validate().is_err());
    for n in ["", "00", "01", "+1", "-1", "1.0", "18446744073709551616"] {
        bad = head.clone();
        bad.head_sequence_number = n.into();
        assert!(bad.validate().is_err());
    }
    let mut max = head.clone();
    max.head_sequence_number = u64::MAX.to_string();
    let c = decode_hex_v2::<32>(&max.canonical_head_commitment_hex).unwrap();
    let mut pre = b"AURA_ECONOMIC_HEAD_V1".to_vec();
    pre.extend_from_slice(&2u32.to_le_bytes());
    pre.extend_from_slice(&u64::MAX.to_le_bytes());
    pre.extend_from_slice(&c);
    max.current_head_hash_hex = encode_hex_v2(&Sha256::digest(pre));
    assert_eq!(max.validate().unwrap(), u64::MAX);
    assert!(max
        .advance(NETWORK, &work, EconomicOutcomeV1::Accepted, &post)
        .unwrap_err()
        .to_string()
        .contains("overflow"));
    assert!(debit_economic_ledger_v1(&work.meter.ledger, 1_000_001).is_err());
}
