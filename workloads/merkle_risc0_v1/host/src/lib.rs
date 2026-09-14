//! Candidate-specific succinct verifier. No untrusted upstream receipt deserialization.
use anyhow::{ensure, Result};
use aura_compute_merkle_v1::*;
use risc0_zkvm::{
    sha::{Digest, Impl, Sha256},
    InnerReceipt, MaybePruned, Receipt, ReceiptClaim, SuccinctReceipt,
    SuccinctReceiptVerifierParameters,
};

pub const REVISION: &str = "3bbcd44d6459b9ef6ac0df3846dc9215514934e8";
pub const CONTROL_ROOT: &str = "517f405d5dbda85b2dc15f3ab6f8a05170bde64980ef594a8e9fd923febe1a03";
pub const VERIFIER_PARAMETERS: &str =
    "556eeddcc0b9c119d11a3c8303bfba3dc380cbf6291951baf4206627497cc862";
pub fn sha256(b: &[u8]) -> Hash {
    Impl::hash_bytes(b).as_bytes().try_into().unwrap()
}

pub fn check_verifier_pin() -> Result<()> {
    use risc0_zkvm::sha::Digestible;
    let p = SuccinctReceiptVerifierParameters::default();
    ensure!(
        p.control_root.to_string() == CONTROL_ROOT && p.digest().to_string() == VERIFIER_PARAMETERS,
        "verifier parameter drift"
    );
    Ok(())
}

fn digest(b: &[u8]) -> Digest {
    Digest::from_bytes(b.try_into().expect("caller provides exactly 32 bytes"))
}

/// Verify exactly the expected fixed guest, successful halt, journal and no assumptions.
/// This candidate API takes an ImageID while the guest is being built; registration
/// must bind it to the frozen reviewed image, never a requester-supplied image.
pub fn verify_output(
    output: &[u8],
    expected_journal: &[u8; JOURNAL_LEN],
    image: Digest,
) -> Result<Receipt> {
    check_verifier_pin()?;
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "dev-mode environment rejected"
    );
    let p = ProofView::parse(output).map_err(anyhow::Error::msg)?;
    ensure!(p.journal == expected_journal, "job/input/journal binding");
    // Pin the succinct recursion circuit's po2 before any upstream verifier work.
    // The first 32 words are globals, followed by a BabyBear Montgomery element.
    ensure!(p.seal.len() >= 33 * 4, "short recursion seal");
    let po2 = u32::from_le_bytes(p.seal[128..132].try_into().unwrap());
    ensure!(
        po2 == risc0_core::field::baby_bear::Elem::new(18).as_u32_montgomery(),
        "unsupported recursion size"
    );
    // Claim and parameters have exactly one local construction, not caller-controlled variants.
    // The pinned upstream exposes neither a constructor for this non-exhaustive
    // type nor its MerkleProof type. Construct only this bounded in-memory value;
    // no JSON input/output API exists. In particular, recursive claim data is made
    // locally, never decoded from the customer. This cannot select Fake/Composite.
    let inner: SuccinctReceipt<ReceiptClaim> = serde_json::from_value(serde_json::json!({
        "seal": p.seal.chunks_exact(4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect::<Vec<_>>(),
        "control_id": digest(&p.control_id),
        "claim": MaybePruned::Value(ReceiptClaim::ok(image, expected_journal.to_vec())),
        "hashfn": "poseidon2",
        "verifier_parameters": digest(&hex::decode(VERIFIER_PARAMETERS)?),
        "control_inclusion_proof": { "index": p.control_index, "digests": p.control_path.chunks_exact(32).map(digest).collect::<Vec<_>>() },
    }))?;
    let receipt = Receipt::new(InnerReceipt::Succinct(inner), expected_journal.to_vec());
    std::panic::catch_unwind(|| receipt.verify(image))
        .map_err(|_| anyhow::anyhow!("upstream verifier panic rejected"))??;
    Ok(receipt)
}

/// Encode only a genuine, already verified fixed-profile succinct receipt.
pub fn encode_output(
    receipt: &Receipt,
    journal: &[u8; JOURNAL_LEN],
    image: Digest,
) -> Result<Vec<u8>> {
    check_verifier_pin()?;
    let r = receipt.inner.succinct()?;
    ensure!(
        receipt.journal.bytes == journal
            && r.hashfn == "poseidon2"
            && r.verifier_parameters.to_string() == VERIFIER_PARAMETERS,
        "wrong receipt profile"
    );
    ensure!(
        r.control_inclusion_proof.digests.len() == CONTROL_DEPTH
            && r.control_inclusion_proof.index < 1 << CONTROL_DEPTH,
        "control path bounds"
    );
    ensure!(
        !r.seal.is_empty() && r.seal.len() <= MAX_SEAL_WORDS,
        "seal bounds"
    );
    std::panic::catch_unwind(|| receipt.verify(image))
        .map_err(|_| anyhow::anyhow!("upstream verifier panic rejected"))??;
    let mut b = Vec::with_capacity(OUTPUT_HEADER_LEN + r.seal.len() * 4);
    b.extend_from_slice(OUTPUT_DOMAIN);
    b.extend_from_slice(journal);
    b.extend_from_slice(r.control_id.as_bytes());
    b.extend_from_slice(&r.control_inclusion_proof.index.to_le_bytes());
    for d in &r.control_inclusion_proof.digests {
        b.extend_from_slice(d.as_bytes());
    }
    b.extend_from_slice(&(r.seal.len() as u32).to_le_bytes());
    for word in &r.seal {
        b.extend_from_slice(&word.to_le_bytes());
    }
    ProofView::parse(&b).map_err(anyhow::Error::msg)?;
    Ok(b)
}
