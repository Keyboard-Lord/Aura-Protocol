//! RESEARCH / SUPPORTING ONLY
//!
//! The layer is RESEARCH / SUPPORTING and does not modify:
//! - canonical request/report pipeline
//! - cat-map transition
//! - AIR/prover boundaries
//! - settlement, burn, attestation, wallet binding, or UDOT authority
//!
//! This EMA surface is an upstream bounded-input overlay whose only permitted active boundary is
//! `(x0, y0)` emission as an upstream initialization input.
//!
//! This module defines EMA update rules over the fixed 20-node graph.
//! Outputs are bounded and deterministic.

use core::{array, fmt};

use crate::research_dodecahedral_graph_v1::{
    RESEARCH_DODECAHEDRAL_EMA_CANONICAL_ADJACENCY_V1, RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1,
    RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1,
};
use crate::{
    sha256_bytes, FieldElement521V1, FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
    HASH_LEN_V1,
};

pub const RESEARCH_EMA_NETWORK_SERIALIZATION_VERSION_V1: u8 = 1;
pub const RESEARCH_EMA_NETWORK_STATE_HEADER_BYTE_LEN_V1: usize = 1 + 1 + 1 + 8 + 8 + 8;
pub const RESEARCH_EMA_NODE_CANONICAL_BYTE_LEN_V1: usize =
    1 + FIELD_ELEMENT_521_BYTE_LEN_V1 + HASH_LEN_V1;
pub const RESEARCH_EMA_NETWORK_STATE_CANONICAL_BYTE_LEN_V1: usize =
    RESEARCH_EMA_NETWORK_STATE_HEADER_BYTE_LEN_V1
        + RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1 * RESEARCH_EMA_NODE_CANONICAL_BYTE_LEN_V1;

pub const AURA_RESEARCH_EMA_WEIGHT_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_RESEARCH_EMA_WEIGHT_V1";
pub const AURA_RESEARCH_EMA_LINEAGE_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_RESEARCH_EMA_LINEAGE_V1";
pub const AURA_RESEARCH_EMA_GENESIS_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_RESEARCH_EMA_GENESIS_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResearchEmaAlphaV1 {
    pub numerator: u64,
    pub denominator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResearchEmaAlphaErrorV1 {
    ZeroDenominator,
    ZeroNumerator,
    NumeratorExceedsDenominator { numerator: u64, denominator: u64 },
}

impl fmt::Display for ResearchEmaAlphaErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDenominator => write!(f, "alpha denominator must be non-zero"),
            Self::ZeroNumerator => write!(f, "alpha must be in (0, 1]"),
            Self::NumeratorExceedsDenominator {
                numerator,
                denominator,
            } => write!(
                f,
                "alpha numerator must not exceed denominator: {numerator}/{denominator}"
            ),
        }
    }
}

impl std::error::Error for ResearchEmaAlphaErrorV1 {}

impl ResearchEmaAlphaV1 {
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, ResearchEmaAlphaErrorV1> {
        if denominator == 0 {
            return Err(ResearchEmaAlphaErrorV1::ZeroDenominator);
        }
        if numerator == 0 {
            return Err(ResearchEmaAlphaErrorV1::ZeroNumerator);
        }
        if numerator > denominator {
            return Err(ResearchEmaAlphaErrorV1::NumeratorExceedsDenominator {
                numerator,
                denominator,
            });
        }

        Ok(Self {
            numerator,
            denominator,
        })
    }

    fn field_coefficients(self) -> (FieldElement521V1, FieldElement521V1) {
        let denominator_inverse = field_inverse_v1(FieldElement521V1::from_u64(self.denominator));
        let alpha = FieldElement521V1::from_u64(self.numerator).mul_mod(&denominator_inverse);
        let one_minus_alpha = FieldElement521V1::from_u64(self.denominator - self.numerator)
            .mul_mod(&denominator_inverse);
        let neighbor_average = one_minus_alpha.mul_mod(&field_inverse_v1(
            FieldElement521V1::from_u64(RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1 as u64),
        ));

        (alpha, neighbor_average)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchEmaRoundInputsV1 {
    pub shards: [Vec<u8>; RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1],
}

impl ResearchEmaRoundInputsV1 {
    pub fn empty() -> Self {
        Self {
            shards: array::from_fn(|_| Vec::new()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResearchEmaNodeStateV1 {
    pub weight: FieldElement521V1,
    pub lineage_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchEmaNetworkStateV1 {
    pub alpha: ResearchEmaAlphaV1,
    pub completed_rounds: u64,
    pub nodes: [ResearchEmaNodeStateV1; RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1],
}

impl ResearchEmaNetworkStateV1 {
    pub fn node(&self, node_index: usize) -> Option<&ResearchEmaNodeStateV1> {
        self.nodes.get(node_index)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RESEARCH_EMA_NETWORK_STATE_CANONICAL_BYTE_LEN_V1);
        bytes.push(RESEARCH_EMA_NETWORK_SERIALIZATION_VERSION_V1);
        bytes.push(RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1 as u8);
        bytes.push(RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1 as u8);
        bytes.extend_from_slice(&self.completed_rounds.to_le_bytes());
        bytes.extend_from_slice(&self.alpha.numerator.to_le_bytes());
        bytes.extend_from_slice(&self.alpha.denominator.to_le_bytes());

        for (node_index, node) in self.nodes.iter().enumerate() {
            bytes.push(node_index as u8);
            bytes.extend_from_slice(&node.weight.to_bytes());
            bytes.extend_from_slice(&node.lineage_hash);
        }

        bytes
    }
}

pub fn initialize_research_ema_network_state_v1(
    alpha: ResearchEmaAlphaV1,
) -> ResearchEmaNetworkStateV1 {
    ResearchEmaNetworkStateV1 {
        alpha,
        completed_rounds: 0,
        nodes: array::from_fn(|node_index| ResearchEmaNodeStateV1 {
            weight: FieldElement521V1::zero(),
            lineage_hash: derive_research_ema_genesis_hash_v1(node_index),
        }),
    }
}

pub fn apply_research_ema_round_v1(
    state: &ResearchEmaNetworkStateV1,
    round: &ResearchEmaRoundInputsV1,
) -> ResearchEmaNetworkStateV1 {
    let (alpha_coefficient, neighbor_average_coefficient) = state.alpha.field_coefficients();
    let next_nodes = array::from_fn(|node_index| {
        let neighbors = RESEARCH_DODECAHEDRAL_EMA_CANONICAL_ADJACENCY_V1[node_index];
        let local_weight = derive_research_ema_weight_v1(&round.shards[node_index]);
        let neighbor_weight_sum = neighbors
            .into_iter()
            .fold(FieldElement521V1::zero(), |acc, neighbor_index| {
                acc.add_mod(&state.nodes[neighbor_index].weight)
            });
        let ordered_neighbor_hashes =
            neighbors.map(|neighbor_index| state.nodes[neighbor_index].lineage_hash);

        ResearchEmaNodeStateV1 {
            weight: alpha_coefficient
                .mul_mod(&local_weight)
                .add_mod(&neighbor_average_coefficient.mul_mod(&neighbor_weight_sum)),
            lineage_hash: derive_research_ema_lineage_hash_v1(
                &round.shards[node_index],
                &ordered_neighbor_hashes,
            ),
        }
    });

    ResearchEmaNetworkStateV1 {
        alpha: state.alpha,
        completed_rounds: state
            .completed_rounds
            .checked_add(1)
            .expect("research EMA round count overflow"),
        nodes: next_nodes,
    }
}

pub fn run_research_ema_network_v1(
    alpha: ResearchEmaAlphaV1,
    rounds: &[ResearchEmaRoundInputsV1],
) -> ResearchEmaNetworkStateV1 {
    let mut state = initialize_research_ema_network_state_v1(alpha);
    for round in rounds {
        state = apply_research_ema_round_v1(&state, round);
    }
    state
}

pub fn derive_research_ema_weight_v1(shard: &[u8]) -> FieldElement521V1 {
    let shard_bytes = canonical_research_ema_shard_bytes_v1(shard);
    let mut preimage =
        Vec::with_capacity(AURA_RESEARCH_EMA_WEIGHT_DOMAIN_SEPARATOR_V1.len() + shard_bytes.len());
    preimage.extend_from_slice(AURA_RESEARCH_EMA_WEIGHT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&shard_bytes);
    FieldElement521V1::reduce_bytes_mod(&preimage)
}

pub fn derive_research_ema_lineage_hash_v1(
    shard: &[u8],
    ordered_neighbor_hashes: &[[u8; HASH_LEN_V1]; RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1],
) -> [u8; HASH_LEN_V1] {
    let shard_bytes = canonical_research_ema_shard_bytes_v1(shard);
    let mut preimage = Vec::with_capacity(
        AURA_RESEARCH_EMA_LINEAGE_DOMAIN_SEPARATOR_V1.len()
            + shard_bytes.len()
            + ordered_neighbor_hashes.len() * HASH_LEN_V1,
    );
    preimage.extend_from_slice(AURA_RESEARCH_EMA_LINEAGE_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&shard_bytes);
    for hash in ordered_neighbor_hashes {
        preimage.extend_from_slice(hash);
    }
    sha256_bytes(&preimage)
}

fn canonical_research_ema_shard_bytes_v1(shard: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + shard.len());
    bytes.extend_from_slice(&(shard.len() as u64).to_le_bytes());
    bytes.extend_from_slice(shard);
    bytes
}

fn derive_research_ema_genesis_hash_v1(node_index: usize) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(AURA_RESEARCH_EMA_GENESIS_DOMAIN_SEPARATOR_V1.len() + 1);
    preimage.extend_from_slice(AURA_RESEARCH_EMA_GENESIS_DOMAIN_SEPARATOR_V1);
    preimage.push(node_index as u8);
    sha256_bytes(&preimage)
}

fn field_inverse_v1(value: FieldElement521V1) -> FieldElement521V1 {
    assert!(!value.is_zero(), "field inverse for zero is undefined");

    let mut exponent = FIELD_MODULUS_521_V1;
    exponent[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] =
        exponent[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1].saturating_sub(2);
    field_pow_v1(value, &exponent)
}

fn field_pow_v1(
    base: FieldElement521V1,
    exponent: &[u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
) -> FieldElement521V1 {
    let mut result = FieldElement521V1::one();
    for byte in exponent {
        for bit_index in (0..8).rev() {
            result = result.square_mod();
            if (byte >> bit_index) & 1 == 1 {
                result = result.mul_mod(&base);
            }
        }
    }
    result
}
