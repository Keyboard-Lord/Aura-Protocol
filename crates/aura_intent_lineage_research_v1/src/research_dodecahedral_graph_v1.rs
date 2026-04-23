//! RESEARCH / SUPPORTING ONLY
//!
//! The layer is RESEARCH / SUPPORTING and does not modify:
//! - canonical request/report pipeline
//! - cat-map transition
//! - AIR/prover boundaries
//! - settlement, burn, attestation, wallet binding, or UDOT authority
//!
//! This dodecahedral EMA topology is an upstream bounded-input overlay whose only permitted active
//! boundary is `(x0, y0)` emission as an upstream initialization input.
//!
//! This module defines the fixed 20-node topology and canonical neighbor ordering.
//! Ordering is consensus-critical for deterministic seed derivation.

pub const RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1: usize = 20;
pub const RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1: usize = 3;

/// Canonical zero-based adjacency for the generalized Petersen labeling `G(10,2)`.
///
/// Nodes `0..=9` are the outer cycle and nodes `10..=19` are the inner star.
/// Each neighbor list is frozen in ascending node-index order.
pub const RESEARCH_DODECAHEDRAL_EMA_CANONICAL_ADJACENCY_V1: [[usize;
    RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1];
    RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1] = [
    [1, 9, 10],
    [0, 2, 11],
    [1, 3, 12],
    [2, 4, 13],
    [3, 5, 14],
    [4, 6, 15],
    [5, 7, 16],
    [6, 8, 17],
    [7, 9, 18],
    [0, 8, 19],
    [0, 12, 18],
    [1, 13, 19],
    [2, 10, 14],
    [3, 11, 15],
    [4, 12, 16],
    [5, 13, 17],
    [6, 14, 18],
    [7, 15, 19],
    [8, 10, 16],
    [9, 11, 17],
];

pub fn research_dodecahedral_neighbors_v1(
    node_index: usize,
) -> Option<[usize; RESEARCH_DODECAHEDRAL_EMA_NODE_DEGREE_V1]> {
    RESEARCH_DODECAHEDRAL_EMA_CANONICAL_ADJACENCY_V1
        .get(node_index)
        .copied()
}
