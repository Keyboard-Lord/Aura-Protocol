use aura_c3_merkle_host::*;
use aura_compute_merkle_v1::*;
use risc0_zkvm::{
    sha::Digest, FakeReceipt, InnerReceipt, Receipt, ReceiptClaim, VerificationError,
};
fn journal() -> [u8; JOURNAL_LEN] {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../vectors/batch-v1.json")).unwrap();
    hex::decode(v["cases"][2]["journal_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn structural() -> Vec<u8> {
    let mut b = OUTPUT_DOMAIN.to_vec();
    b.extend(journal());
    b.extend([0; 32]);
    b.extend(0u32.to_le_bytes());
    b.extend([0; CONTROL_DEPTH * 32]);
    b.extend(33u32.to_le_bytes());
    b.extend([0; 128]);
    // The seal stores the lift po2 as a raw u32 (upstream writes
    // BabyBearElem::new_raw(program.po2)), not a Montgomery element.
    b.extend(18u32.to_le_bytes());
    b
}
#[test]
fn controlled_construction_reaches_real_verifier_and_fake_seal_rejects() {
    check_verifier_pin().unwrap();
    let err = verify_output(&structural(), &journal(), Digest::ZERO).unwrap_err();
    assert!(
        err.is::<VerificationError>(),
        "must reach upstream verification, not fail local construction: {err:#}"
    );
}
#[test]
fn malformed_sizes_domains_journals_and_recursion_size_reject() {
    let b = structural();
    for n in [0, 1, OUTPUT_HEADER_LEN - 1, b.len() - 1] {
        assert!(verify_output(&b[..n], &journal(), Digest::ZERO).is_err());
    }
    for i in [
        0,
        OUTPUT_DOMAIN.len(),
        OUTPUT_DOMAIN.len() + JOURNAL_DOMAIN.len(),
        OUTPUT_HEADER_LEN - 4,
        OUTPUT_HEADER_LEN + 128,
    ] {
        let mut bad = b.clone();
        bad[i] ^= 1;
        assert!(verify_output(&bad, &journal(), Digest::ZERO).is_err());
    }
    let mut bad = b.clone();
    bad.push(0);
    assert!(verify_output(&bad, &journal(), Digest::ZERO).is_err());
    let mut wrong = journal();
    wrong[JOURNAL_DOMAIN.len()] ^= 1;
    assert!(verify_output(&b, &wrong, Digest::ZERO).is_err());
}
#[test]
fn out_of_profile_lift_po2_rejects_before_upstream_verification() {
    let b = structural();
    // Seal word 32 is the raw lift po2; the approved profile covers 12..=24.
    for po2 in [0u32, 11, 25, u32::MAX] {
        let mut bad = b.clone();
        bad[OUTPUT_HEADER_LEN + 128..OUTPUT_HEADER_LEN + 132]
            .copy_from_slice(&po2.to_le_bytes());
        let err = verify_output(&bad, &journal(), Digest::ZERO).unwrap_err();
        assert!(
            !err.is::<VerificationError>(),
            "po2 {po2} must reject at the profile bound, not upstream: {err:#}"
        );
    }
}
#[test]
fn development_receipt_cannot_enter_output_codec() {
    let j = journal();
    let r = Receipt::new(
        InnerReceipt::Fake(FakeReceipt::new(ReceiptClaim::ok(Digest::ZERO, j.to_vec()))),
        j.to_vec(),
    );
    assert!(encode_output(&r, &j, Digest::ZERO).is_err());
}
