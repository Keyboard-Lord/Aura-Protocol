//! C3 fixed workload relation. Candidate contract until the complete C3 freeze gate.
//! Hardware-independent, allocation-bounded, and shared verbatim by guest and host.
#![no_std]
extern crate alloc;
use alloc::vec::Vec;

pub const INPUT_DOMAIN: &[u8] = b"AURA_C3_MERKLE_INPUT_V1";
pub const JOURNAL_DOMAIN: &[u8] = b"AURA_C3_MERKLE_JOURNAL_V1";
pub const OUTPUT_DOMAIN: &[u8] = b"AURA_C3_RISC0_SUCCINCT_V1";
pub const MAX_BATCH: usize = 64;
pub const MAX_DEPTH: usize = 32;
pub const INPUT_HEADER_LEN: usize = INPUT_DOMAIN.len() + 4 + 1 + 32;
pub const MAX_INPUT_LEN: usize = INPUT_HEADER_LEN + MAX_BATCH * (36 + 32 * MAX_DEPTH);
pub const JOURNAL_LEN: usize = JOURNAL_DOMAIN.len() + 32 * 3 + 4;
pub const MAX_SEAL_WORDS: usize = 262_144;
// Exact upstream allowed-code Merkle tree depth, pinned with the verifier profile.
pub const CONTROL_DEPTH: usize = 8;
pub const OUTPUT_HEADER_LEN: usize = OUTPUT_DOMAIN.len() + JOURNAL_LEN + 32 + 4 + CONTROL_DEPTH * 32 + 4;
pub const MAX_OUTPUT_LEN: usize = OUTPUT_HEADER_LEN + 4 * MAX_SEAL_WORDS;

pub type Hash = [u8; 32];
pub type Result<T> = core::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug)]
pub struct Batch<'a> {
    bytes: &'a [u8],
    pub count: u32,
    pub depth: u8,
    pub root: Hash,
}

impl<'a> Batch<'a> {
    /// No allocation, normalization, sorting, implicit direction bits or padding.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < INPUT_HEADER_LEN || bytes.len() > MAX_INPUT_LEN || !bytes.starts_with(INPUT_DOMAIN) {
            return Err("invalid batch framing");
        }
        let p = INPUT_DOMAIN.len();
        let count = u32::from_le_bytes(bytes[p..p+4].try_into().unwrap());
        let depth = bytes[p+4];
        if count == 0 || count as usize > MAX_BATCH || depth as usize > MAX_DEPTH {
            return Err("batch limits");
        }
        let stride = 36 + 32 * depth as usize;
        if bytes.len() != INPUT_HEADER_LEN + count as usize * stride {
            return Err("noncanonical batch length");
        }
        for row in bytes[INPUT_HEADER_LEN..].chunks_exact(stride) {
            let index = u32::from_le_bytes(row[..4].try_into().unwrap());
            if depth < 32 && index >= (1u32 << depth) { return Err("index outside tree"); }
        }
        Ok(Self { bytes, count, depth, root: bytes[p+5..p+37].try_into().unwrap() })
    }

    /// Complete binary tree: leaf = SHA256(00 || value[32]);
    /// parent = SHA256(01 || left[32] || right[32]). Paths run leaf to root.
    /// Bit h of the unsigned leaf index chooses right (1) or left (0) at height h.
    pub fn verify(&self, sha256: impl Fn(&[u8]) -> Hash) -> Result<()> {
        for row in self.bytes[INPUT_HEADER_LEN..].chunks_exact(36 + 32 * self.depth as usize) {
            let index = u32::from_le_bytes(row[..4].try_into().unwrap());
            let mut leaf = [0;33]; leaf[1..].copy_from_slice(&row[4..36]);
            let mut node = sha256(&leaf);
            for (h, sibling) in row[36..].chunks_exact(32).enumerate() {
                let mut preimage = [0;65]; preimage[0] = 1;
                if index & (1 << h) == 0 {
                    preimage[1..33].copy_from_slice(&node); preimage[33..].copy_from_slice(sibling);
                } else {
                    preimage[1..33].copy_from_slice(sibling); preimage[33..].copy_from_slice(&node);
                }
                node = sha256(&preimage);
            }
            if node != self.root { return Err("membership failed"); }
        }
        Ok(())
    }

    /// Byte-for-byte C1 input content framing. The SDK remains the C1 owner;
    /// cross-owner regression vectors check this guest-compatible specialization.
    pub fn input_commitment(&self, sha256: impl Fn(&[u8]) -> Hash) -> Hash {
        let mut b = Vec::with_capacity(21 + 8 + self.bytes.len());
        b.extend_from_slice(b"AURA_COMPUTE_INPUT_V1");
        b.extend_from_slice(&(self.bytes.len() as u64).to_le_bytes());
        b.extend_from_slice(self.bytes);
        sha256(&b)
    }

    /// The caller must verify membership first. This layout contains no proof or telemetry.
    pub fn journal(&self, job: Hash, sha256: impl Fn(&[u8]) -> Hash) -> [u8; JOURNAL_LEN] {
        let mut b = [0; JOURNAL_LEN]; let p = JOURNAL_DOMAIN.len();
        b[..p].copy_from_slice(JOURNAL_DOMAIN);
        b[p..p+32].copy_from_slice(&job);
        b[p+32..p+64].copy_from_slice(&self.input_commitment(sha256));
        b[p+64..p+96].copy_from_slice(&self.root);
        b[p+96..].copy_from_slice(&self.count.to_le_bytes());
        b
    }
}

/// Flat succinct-only representation. Bounded borrowed parsing precedes allocating
/// any upstream proof object. No enums, recursive claims, strings, or bincode.
pub struct ProofView<'a> {
    pub journal: &'a [u8],
    pub control_id: Hash,
    pub control_index: u32,
    pub control_path: &'a [u8],
    pub seal: &'a [u8],
}
impl<'a> ProofView<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self> {
        if b.len() < OUTPUT_HEADER_LEN || b.len() > MAX_OUTPUT_LEN || !b.starts_with(OUTPUT_DOMAIN) {
            return Err("invalid proof framing");
        }
        let mut p = OUTPUT_DOMAIN.len();
        let journal = &b[p..p+JOURNAL_LEN]; p += JOURNAL_LEN;
        if !journal.starts_with(JOURNAL_DOMAIN) { return Err("invalid journal domain"); }
        let n = u32::from_le_bytes(journal[JOURNAL_LEN-4..].try_into().unwrap());
        if n == 0 || n as usize > MAX_BATCH { return Err("journal batch limits"); }
        let control_id = b[p..p+32].try_into().unwrap(); p += 32;
        let control_index = u32::from_le_bytes(b[p..p+4].try_into().unwrap()); p += 4;
        if control_index >= 1 << CONTROL_DEPTH { return Err("control index bounds"); }
        let control_path = &b[p..p+CONTROL_DEPTH*32]; p += CONTROL_DEPTH*32;
        let words = u32::from_le_bytes(b[p..p+4].try_into().unwrap()) as usize; p += 4;
        if words == 0 || words > MAX_SEAL_WORDS || b.len() != p + words*4 { return Err("seal bounds or length"); }
        Ok(Self { journal, control_id, control_index, control_path, seal: &b[p..] })
    }
}
