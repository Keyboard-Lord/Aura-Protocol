//! Candidate-specific succinct verifier. No upstream receipt deserialization.
use anyhow::{ensure, Result};
use aura_compute_merkle_v1::*;
use risc0_zkvm::{sha::{Digest, Impl, Sha256}, Receipt, ReceiptClaim, InnerReceipt, SuccinctReceipt, MerkleProof, SuccinctReceiptVerifierParameters};

pub const REVISION: &str = "3bbcd44d6459b9ef6ac0df3846dc9215514934e8";
pub const CONTROL_ROOT: &str = "517f405d5dbda85b2dc15f3ab6f8a05170bde64980ef594a8e9fd923febe1a03";
pub const VERIFIER_PARAMETERS: &str = "556eeddcc0b9c119d11a3c8303bfba3dc380cbf6291951baf4206627497cc862";
pub fn sha256(b: &[u8]) -> Hash { Impl::hash_bytes(b).as_bytes().try_into().unwrap() }

pub fn check_verifier_pin() -> Result<()> {
    use risc0_zkvm::sha::Digestible;
    let p = SuccinctReceiptVerifierParameters::default();
    ensure!(p.control_root.to_string() == CONTROL_ROOT && p.digest().to_string() == VERIFIER_PARAMETERS, "verifier parameter drift");
    Ok(())
}

fn digest(b: &[u8]) -> Digest {
    Digest::from_bytes(b.try_into().expect("caller provides exactly 32 bytes"))
}

/// Verify exactly the expected fixed guest, successful halt, journal and no assumptions.
/// This candidate API takes an ImageID while the guest is being built; registration
/// must bind it to the frozen reviewed image, never a requester-supplied image.
pub fn verify_output(output: &[u8], expected_journal: &[u8; JOURNAL_LEN], image: Digest) -> Result<Receipt> {
    check_verifier_pin()?;
    ensure!(std::env::var_os("RISC0_DEV_MODE").is_none(), "dev-mode environment rejected");
    let p = ProofView::parse(output).map_err(anyhow::Error::msg)?;
    ensure!(p.journal == expected_journal, "job/input/journal binding");
    // Claim and parameters have exactly one local construction, not caller-controlled variants.
    let inner = SuccinctReceipt {
        seal: p.seal.chunks_exact(4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect(),
        control_id: digest(&p.control_id),
        claim: ReceiptClaim::ok(image, expected_journal.to_vec()).into(),
        hashfn: "poseidon2".into(),
        verifier_parameters: VERIFIER_PARAMETERS.parse()?,
        control_inclusion_proof: MerkleProof { index: p.control_index, digests: p.control_path.chunks_exact(32).map(digest).collect() },
    };
    let receipt = Receipt::new(InnerReceipt::Succinct(inner), expected_journal.to_vec());
    receipt.verify(image)?;
    Ok(receipt)
}

/// Encode only a genuine, already verified fixed-profile succinct receipt.
pub fn encode_output(receipt: &Receipt, journal: &[u8; JOURNAL_LEN], image: Digest) -> Result<Vec<u8>> {
    check_verifier_pin()?;
    receipt.verify(image)?;
    let r = receipt.inner.succinct()?;
    ensure!(receipt.journal.bytes == journal && r.hashfn == "poseidon2" && r.verifier_parameters.to_string() == VERIFIER_PARAMETERS, "wrong receipt profile");
    ensure!(r.control_inclusion_proof.digests.len() == CONTROL_DEPTH && r.control_inclusion_proof.index < 1 << CONTROL_DEPTH, "control path bounds");
    ensure!(!r.seal.is_empty() && r.seal.len() <= MAX_SEAL_WORDS, "seal bounds");
    let mut b = Vec::with_capacity(OUTPUT_HEADER_LEN + r.seal.len()*4);
    b.extend_from_slice(OUTPUT_DOMAIN); b.extend_from_slice(journal);
    b.extend_from_slice(r.control_id.as_bytes());
    b.extend_from_slice(&r.control_inclusion_proof.index.to_le_bytes());
    for d in &r.control_inclusion_proof.digests { b.extend_from_slice(d.as_bytes()); }
    b.extend_from_slice(&(r.seal.len() as u32).to_le_bytes());
    for word in &r.seal { b.extend_from_slice(&word.to_le_bytes()); }
    ProofView::parse(&b).map_err(anyhow::Error::msg)?;
    Ok(b)
}
