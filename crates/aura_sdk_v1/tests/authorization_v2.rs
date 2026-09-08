#[path = "support/authorization_v2.rs"] mod support;
use aura_sdk_v1::authorization::{AuthorizerJournalV2, AuthorizationEnvelopeV2, AuthorizationDispositionV2, encode_hex_v2};
use aura_bitcoin_v1::BitcoinNetworkV1;
use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}, process::Command};
const NETWORK: BitcoinNetworkV1 = BitcoinNetworkV1::Regtest;
fn path() -> PathBuf { std::env::temp_dir().join(format!("aura-authorizer-{}-{}.db", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn resign(envelope: &mut AuthorizationEnvelopeV2) {
    use secp256k1::{Secp256k1, SecretKey, Keypair};
    let secp = Secp256k1::new(); let mut key = [0;32]; key[31] = 3;
    let pair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(key).unwrap());
    envelope.signature_hex = encode_hex_v2(secp.sign_schnorr_with_aux_rand(&envelope.signing_digest(NETWORK).unwrap(), &pair, &[1;32]).as_ref());
}
#[test]
fn shared_vector_matches_existing_proof_and_material_bytes() {
    let vector: serde_json::Value = serde_json::from_str(include_str!("../../../fixtures/authorization_v2/authorization_vector_v2.json")).unwrap();
    let (envelope, _, proof) = support::sample(0x11);
    assert_eq!(serde_json::to_value(&envelope).unwrap(), vector["authorization"]);
    assert_eq!(encode_hex_v2(&proof.proof_bytes), vector["proof_bytes_hex"]);
    assert_eq!(encode_hex_v2(&envelope.signing_digest(NETWORK).unwrap()), vector["signing_digest_hex"]);
    envelope.verify_signature(NETWORK).unwrap();
    assert!(envelope.verify_signature(BitcoinNetworkV1::Mainnet).is_err());
}
#[test]
fn strict_wire_rejects_legacy_and_noncanonical_objects() {
    let (envelope, _, _) = support::sample(0x11);
    let mut value = serde_json::to_value(&envelope).unwrap();
    value["intent_id_hex"] = "44".repeat(32).into();
    assert!(serde_json::from_value::<AuthorizationEnvelopeV2>(value).is_err());
    let mut wrong = envelope.clone(); wrong.authorization_version = "v1".into();
    assert!(wrong.validate_shape().is_err());
    wrong = envelope.clone(); wrong.authorization_lineage.subject_binding = "ff".repeat(32);
    assert!(wrong.validate_shape().is_err());
    wrong = envelope; wrong.signature_hex = wrong.signature_hex.to_uppercase();
    assert!(wrong.validate_shape().is_err());
}
#[test]
fn signature_proof_material_and_lineage_failures_do_not_reserve_nonce() {
    let file = path(); let mut journal = AuthorizerJournalV2::create(&file).unwrap();
    let (envelope, claim, proof) = support::sample(0x11);
    let mut wrong = envelope.clone(); wrong.signature_hex = "00".repeat(64);
    assert!(journal.accept(NETWORK, &wrong, &claim, &proof, 10).is_err());
    wrong = envelope.clone(); wrong.proof_hash_hex = "ff".repeat(32); resign(&mut wrong);
    assert!(journal.accept(NETWORK, &wrong, &claim, &proof, 10).unwrap_err().to_string().contains("material binding"));
    wrong = envelope.clone(); wrong.authorization_lineage.freshness_binding = "ee".repeat(32);
    assert!(journal.accept(NETWORK, &wrong, &claim, &proof, 10).unwrap_err().to_string().contains("lineage mismatch"));
    wrong = envelope.clone(); wrong.authorization_lineage.intent_commitment_hex = "ee".repeat(32); resign(&mut wrong);
    assert!(journal.accept(NETWORK, &wrong, &claim, &proof, 10).is_err());
    let mut bad_proof = proof.clone(); bad_proof.proof_bytes[20] ^= 1;
    assert!(journal.accept(NETWORK, &envelope, &claim, &bad_proof, 10).is_err());
    assert!(journal.accept(NETWORK, &envelope, &claim, &proof, 2).is_err());
    assert_eq!(journal.accept(NETWORK, &envelope, &claim, &proof, 10).unwrap().disposition(), AuthorizationDispositionV2::Reserved);
    drop(journal); std::fs::remove_file(file).unwrap();
}
#[test]
fn restart_retry_resigning_and_different_action_replay() {
    let file = path();
    let (mut envelope, claim, proof) = support::sample(0x11);
    let mut journal = AuthorizerJournalV2::create(&file).unwrap();
    assert_eq!(journal.accept(NETWORK, &envelope, &claim, &proof, 10).unwrap().disposition(), AuthorizationDispositionV2::Reserved);
    drop(journal);
    assert!(Command::new(std::env::current_exe().unwrap()).args(["--exact", "journal_process_worker"])
        .env("AURA_TEST_JOURNAL_PATH", &file).status().unwrap().success());
    let mut journal = AuthorizerJournalV2::open(&file).unwrap();
    resign(&mut envelope);
    assert_eq!(journal.accept(NETWORK, &envelope, &claim, &proof, 10).unwrap().disposition(), AuthorizationDispositionV2::SameActionRetry);
    let (other, other_claim, other_proof) = support::sample(0x12);
    assert!(journal.accept(NETWORK, &other, &other_claim, &other_proof, 10).unwrap_err().to_string().contains("different action"));
    drop(journal); std::fs::remove_file(file).unwrap();
}
#[test]
fn journal_process_worker() {
    if let Some(file) = std::env::var_os("AURA_TEST_JOURNAL_PATH") {
        let (envelope, claim, proof) = support::sample(0x11);
        let mut journal = AuthorizerJournalV2::open(std::path::Path::new(&file)).unwrap();
        assert_eq!(journal.accept(NETWORK, &envelope, &claim, &proof, 10).unwrap().disposition(), AuthorizationDispositionV2::SameActionRetry);
    }
}
#[test]
fn journal_creation_is_explicit_and_corruption_requires_recovery() {
    let file = path();
    assert!(AuthorizerJournalV2::open(&file).is_err()); assert!(!file.exists());
    let journal = AuthorizerJournalV2::create(&file).unwrap(); drop(journal);
    assert!(AuthorizerJournalV2::create(&file).is_err());
    std::fs::write(&file, b"damaged").unwrap();
    assert!(AuthorizerJournalV2::open(&file).is_err());
    std::fs::remove_file(file).unwrap();
}
#[test]
fn competing_connections_cannot_accept_different_actions_with_same_nonce() {
    use std::sync::{Arc, Barrier};
    let file = path(); drop(AuthorizerJournalV2::create(&file).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [0x11,0x12].into_iter().map(|side| {
        let file = file.clone(); let barrier = barrier.clone();
        std::thread::spawn(move || {
            let mut journal = AuthorizerJournalV2::open(&file).unwrap();
            let (e,c,p) = support::sample(side); barrier.wait();
            journal.accept(NETWORK, &e, &c, &p, 10).is_ok()
        })
    }).collect();
    assert_eq!(handles.into_iter().map(|h| h.join().unwrap() as usize).sum::<usize>(),1);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn canonical_proof_decode_preserves_artifact_and_rejects_malformed_lengths() {
    use aura_intent_lineage_v1::decode_storm_air_real_artifact_v1;
    let (_, claim, proof) = support::sample(0x11);
    let (decoded_claim, decoded) = decode_storm_air_real_artifact_v1(proof.proof_bytes.clone()).unwrap();
    assert_eq!(decoded_claim, claim);
    assert_eq!(decoded, proof);
    let mut malformed = proof.proof_bytes.clone(); malformed[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_storm_air_real_artifact_v1(malformed).is_err());
    let mut overflow = proof.proof_bytes.clone(); overflow[10..18].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_storm_air_real_artifact_v1(overflow).is_err());
    let mut trailing = proof.proof_bytes.clone(); trailing.push(0);
    assert!(decode_storm_air_real_artifact_v1(trailing).is_err());
    assert!(decode_storm_air_real_artifact_v1(proof.proof_bytes[..20].to_vec()).is_err());
}
