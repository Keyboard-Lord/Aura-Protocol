//! RESEARCH / SUPPORTING ONLY — SEED BRIDGE
//!
//! The layer is RESEARCH / SUPPORTING and does not modify:
//! - canonical request/report pipeline
//! - cat-map transition
//! - AIR/prover boundaries
//! - settlement, burn, attestation, wallet binding, or UDOT authority
//!
//! This seed bridge is an upstream bounded-input overlay whose only permitted active boundary is
//! `(x0, y0)` emission as an upstream initialization input.
//!
//! Bridge Contract:
//! - Canonically serialize the 20-node EMA state
//! - Derive two domain-separated SHA-256 hashes
//! - Reduce each hash mod (2^521 - 1)
//! - Emit (x0, y0)
//!
//! This output is the ONLY interface to the existing cat-map execution.
//! The cat-map transition, AIR, proof system, and canonical request/report pipeline remain
//! unchanged.

use crate::research_ema_network_v1::{
    run_research_ema_network_v1, ResearchEmaAlphaV1, ResearchEmaNetworkStateV1,
    ResearchEmaRoundInputsV1,
};
use crate::{sha256_domain_separated, DcmInput521V1, FieldElement521V1, HASH_LEN_V1};

pub const AURA_RESEARCH_EMA_SEED_BRIDGE_X_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_RESEARCH_EMA_SEED_BRIDGE_X_V1";
pub const AURA_RESEARCH_EMA_SEED_BRIDGE_Y_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_RESEARCH_EMA_SEED_BRIDGE_Y_V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchEmaSeedBridgeV1 {
    pub network_state: ResearchEmaNetworkStateV1,
    pub canonical_network_state: Vec<u8>,
    pub x_hash: [u8; HASH_LEN_V1],
    pub y_hash: [u8; HASH_LEN_V1],
    pub dcm_input: DcmInput521V1,
}

pub fn bridge_research_ema_network_state_to_seed_v1(
    network_state: &ResearchEmaNetworkStateV1,
) -> ResearchEmaSeedBridgeV1 {
    let canonical_network_state = network_state.canonical_bytes();
    let x_hash = sha256_domain_separated(
        AURA_RESEARCH_EMA_SEED_BRIDGE_X_DOMAIN_SEPARATOR_V1,
        &canonical_network_state,
    );
    let y_hash = sha256_domain_separated(
        AURA_RESEARCH_EMA_SEED_BRIDGE_Y_DOMAIN_SEPARATOR_V1,
        &canonical_network_state,
    );
    let x0 = FieldElement521V1::reduce_bytes_mod(&x_hash);
    let y0 = FieldElement521V1::reduce_bytes_mod(&y_hash);

    ResearchEmaSeedBridgeV1 {
        network_state: network_state.clone(),
        canonical_network_state,
        x_hash,
        y_hash,
        dcm_input: DcmInput521V1 { x0, y0 },
    }
}

pub fn bridge_research_ema_network_state_to_dcm_input_521_v1(
    network_state: &ResearchEmaNetworkStateV1,
) -> DcmInput521V1 {
    bridge_research_ema_network_state_to_seed_v1(network_state).dcm_input
}

pub fn compile_research_ema_seed_bridge_v1(
    alpha: ResearchEmaAlphaV1,
    rounds: &[ResearchEmaRoundInputsV1],
) -> ResearchEmaSeedBridgeV1 {
    let network_state = run_research_ema_network_v1(alpha, rounds);
    bridge_research_ema_network_state_to_seed_v1(&network_state)
}
