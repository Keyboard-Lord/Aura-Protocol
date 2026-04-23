//! RESEARCH / SUPPORTING ONLY
//!
//! This crate contains standalone research overlays for the lower-layer cat-map runtime/proof
//! spine in `aura_intent_lineage_v1`.
//!
//! The overlays here are an upstream bounded-input overlay that emits only `(x0, y0)` and does
//! not modify active protocol.
//!
//! They MUST NOT:
//! - alter canonical request/report pipeline behavior
//! - alter cat-map transition logic
//! - alter AIR/public input schema
//! - alter settlement, burn, or attestation semantics

#[cfg(feature = "active_integration")]
compile_error!(
    "RESEARCH / SUPPORTING crate aura_intent_lineage_research_v1 does not modify active protocol and cannot compile into the single authoritative pipeline without explicit protocol upgrade."
);

use sha2::{Digest, Sha256};

pub use aura_intent_lineage_v1::{
    DcmInput521V1, FieldElement521V1, FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
    HASH_LEN_V1,
};

mod research_dodecahedral_graph_v1;
mod research_ema_network_v1;
mod research_ema_seed_bridge_v1;

pub use research_dodecahedral_graph_v1::*;
pub use research_ema_network_v1::*;
pub use research_ema_seed_bridge_v1::*;

pub(crate) fn sha256_domain_separated(domain_separator: &[u8], bytes: &[u8]) -> [u8; HASH_LEN_V1] {
    let mut hasher = Sha256::new();
    hasher.update(domain_separator);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; HASH_LEN_V1] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
