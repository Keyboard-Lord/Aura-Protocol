use aura_compute_merkle_v1::*;
use sha2::{Digest, Sha256};
fn h(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}
fn cases() -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../workloads/merkle_risc0_v1/vectors/batch-v1.json"
    ))
    .unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}
fn bytes(v: &serde_json::Value, k: &str) -> Vec<u8> {
    v[k].as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn independent_python_vectors_and_order() {
    let vectors = cases();
    for v in &vectors {
        let b = bytes(v, "input_hex");
        let batch = Batch::parse(&b).unwrap();
        batch.verify(h).unwrap();
        assert_eq!(
            batch.input_commitment(h).as_slice(),
            bytes(v, "input_commitment_hex")
        );
        assert_eq!(
            batch
                .journal(bytes(v, "job_commitment_hex").try_into().unwrap(), h)
                .as_slice(),
            bytes(v, "journal_hex")
        );
    }
    assert_ne!(
        bytes(&vectors[2], "input_commitment_hex"),
        bytes(&vectors[3], "input_commitment_hex")
    );
}
#[test]
fn each_input_byte_mutation_rejects_membership_or_changes_commitment() {
    let b = bytes(&cases()[2], "input_hex");
    let original = Batch::parse(&b).unwrap().input_commitment(h);
    for i in 0..b.len() {
        let mut bad = b.clone();
        bad[i] ^= 1;
        if let Ok(p) = Batch::parse(&bad) {
            assert!(
                p.verify(h).is_err() || p.input_commitment(h) != original,
                "offset {i}"
            );
        }
    }
    for i in [
        INPUT_DOMAIN.len() + 5,
        INPUT_HEADER_LEN,
        INPUT_HEADER_LEN + 4,
        INPUT_HEADER_LEN + 36,
        INPUT_HEADER_LEN + 68,
    ] {
        let mut bad = b.clone();
        bad[i] ^= 1;
        assert!(Batch::parse(&bad).and_then(|p| p.verify(h)).is_err());
    }
}
#[test]
fn bounds_truncation_trailing_and_tree_index() {
    let b = bytes(&cases()[2], "input_hex");
    for n in 0..b.len() {
        assert!(Batch::parse(&b[..n]).is_err());
    }
    let mut bad = b.clone();
    bad.push(0);
    assert!(Batch::parse(&bad).is_err());
    for count in [0u32, 65, u32::MAX] {
        let mut bad = b.clone();
        bad[INPUT_DOMAIN.len()..INPUT_DOMAIN.len() + 4].copy_from_slice(&count.to_le_bytes());
        assert!(Batch::parse(&bad).is_err());
    }
    let mut bad = b.clone();
    bad[INPUT_DOMAIN.len() + 4] = 33;
    assert!(Batch::parse(&bad).is_err());
    let mut bad = b.clone();
    bad[INPUT_HEADER_LEN..INPUT_HEADER_LEN + 4].copy_from_slice(&8u32.to_le_bytes());
    assert!(Batch::parse(&bad).is_err());
}
#[test]
fn maximum_dimensions_are_bounded_and_well_defined() {
    // All index bits participate at depth 32. Repeated assertions are not deduplicated.
    let leaf = [17u8; 32];
    let index = u32::MAX;
    let sibling = [23u8; 32];
    let mut l = vec![0];
    l.extend(leaf);
    let mut root = h(&l);
    for _ in 0..32 {
        let mut p = vec![1];
        p.extend(sibling);
        p.extend(root);
        root = h(&p);
    }
    let mut b = INPUT_DOMAIN.to_vec();
    b.extend(64u32.to_le_bytes());
    b.push(32);
    b.extend(root);
    for _ in 0..64 {
        b.extend(index.to_le_bytes());
        b.extend(leaf);
        for _ in 0..32 {
            b.extend(sibling);
        }
    }
    assert_eq!(b.len(), MAX_INPUT_LEN);
    Batch::parse(&b).unwrap().verify(h).unwrap();
}
#[test]
fn flat_proof_parser_rejects_unbounded_shapes() {
    let mut b = OUTPUT_DOMAIN.to_vec();
    b.extend(bytes(&cases()[2], "journal_hex"));
    b.extend([0; 32]);
    b.extend(0u32.to_le_bytes());
    b.extend([0; CONTROL_DEPTH * 32]);
    b.extend(1u32.to_le_bytes());
    b.extend([0; 4]);
    assert!(ProofView::parse(&b).is_ok()); // Structural fixture only, not a valid proof.
    for n in 0..b.len() {
        assert!(ProofView::parse(&b[..n]).is_err());
    }
    let mut bad = b.clone();
    bad.push(0);
    assert!(ProofView::parse(&bad).is_err());
    for words in [0u32, MAX_SEAL_WORDS as u32 + 1, u32::MAX] {
        let mut bad = b.clone();
        bad[OUTPUT_HEADER_LEN - 4..OUTPUT_HEADER_LEN].copy_from_slice(&words.to_le_bytes());
        assert!(ProofView::parse(&bad).is_err());
    }
    let mut bad = b.clone();
    let p = OUTPUT_DOMAIN.len() + JOURNAL_LEN + 32;
    bad[p..p + 4].copy_from_slice(&256u32.to_le_bytes());
    assert!(ProofView::parse(&bad).is_err());
    let mut bad = b.clone();
    bad[0] ^= 1;
    assert!(ProofView::parse(&bad).is_err());
    let mut bad = b;
    bad[OUTPUT_DOMAIN.len()] ^= 1;
    assert!(ProofView::parse(&bad).is_err());
}
