// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Cat-map trace commitment scaffold for the 521-bit AIR path.
//! This module builds a deterministic Merkle-style tree over pair-state rows.
//! It is a research scaffold only and not a final production commitment scheme.

use core::fmt;

use crate::{sha256_domain_separated, DcmAirTraceV1, DcmState521V1, HASH_LEN_V1};

pub const STARK_TRACE_COMMITMENT_VERSION_V1: u8 = 1;
pub const AURA_DCM_STARK_TRACE_V1_LEAF_DOMAIN_SEPARATOR: &[u8] = b"AURA_DCM_STARK_TRACE_V1_LEAF";
pub const AURA_DCM_STARK_TRACE_V1_NODE_DOMAIN_SEPARATOR: &[u8] = b"AURA_DCM_STARK_TRACE_V1_NODE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarkTraceCommitmentV1 {
    pub commitment_version: u8,
    pub leaf_count: u64,
    pub tree_height: u64,
    pub root: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkTraceMerkleOpeningV1 {
    pub row_index: u64,
    pub row_value: DcmState521V1,
    pub sibling_hashes: Vec<[u8; HASH_LEN_V1]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkTraceCommitmentTreeV1 {
    trace: DcmAirTraceV1,
    levels: Vec<Vec<[u8; HASH_LEN_V1]>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StarkTraceCommitmentErrorV1 {
    EmptyTrace,
    RowIndexOutOfRange { row_index: u64, row_count: u64 },
    OpeningPathLengthMismatch { expected: u64, actual: u64 },
}

impl fmt::Display for StarkTraceCommitmentErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "trace commitment requires a non-empty trace"),
            Self::RowIndexOutOfRange {
                row_index,
                row_count,
            } => write!(
                f,
                "row index out of range for trace commitment opening: index {row_index}, row_count {row_count}"
            ),
            Self::OpeningPathLengthMismatch { expected, actual } => write!(
                f,
                "opening path length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for StarkTraceCommitmentErrorV1 {}

pub fn build_stark_trace_commitment_tree_v1(
    trace: &DcmAirTraceV1,
) -> Result<StarkTraceCommitmentTreeV1, StarkTraceCommitmentErrorV1> {
    if trace.row_count() == 0 {
        return Err(StarkTraceCommitmentErrorV1::EmptyTrace);
    }

    let mut current_level = Vec::with_capacity(trace.rows().len());
    for (row_index, row_value) in trace.rows().iter().enumerate() {
        current_level.push(hash_trace_leaf_v1(row_index as u64, row_value));
    }

    let mut levels = Vec::with_capacity(8);
    levels.push(current_level.clone());

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut pair_index = 0usize;
        while pair_index < current_level.len() {
            let left = current_level[pair_index];
            let right = if pair_index + 1 < current_level.len() {
                current_level[pair_index + 1]
            } else {
                current_level[pair_index]
            };
            next_level.push(hash_trace_node_v1(&left, &right));
            pair_index += 2;
        }
        levels.push(next_level.clone());
        current_level = next_level;
    }

    Ok(StarkTraceCommitmentTreeV1 {
        trace: trace.clone(),
        levels,
    })
}

impl StarkTraceCommitmentTreeV1 {
    pub fn commitment(&self) -> StarkTraceCommitmentV1 {
        StarkTraceCommitmentV1 {
            commitment_version: STARK_TRACE_COMMITMENT_VERSION_V1,
            leaf_count: self.trace.row_count(),
            tree_height: derive_stark_trace_tree_height_from_leaf_count_v1(self.trace.row_count()),
            root: *self
                .levels
                .last()
                .expect("non-empty trace commitment tree must have a root")
                .first()
                .expect("non-empty trace commitment tree root level must contain one node"),
        }
    }

    pub fn open_row(
        &self,
        row_index: u64,
    ) -> Result<StarkTraceMerkleOpeningV1, StarkTraceCommitmentErrorV1> {
        if row_index >= self.trace.row_count() {
            return Err(StarkTraceCommitmentErrorV1::RowIndexOutOfRange {
                row_index,
                row_count: self.trace.row_count(),
            });
        }

        let row_value = self
            .trace
            .row(row_index as usize)
            .expect("row_index validated against trace row count");
        let mut sibling_hashes = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut current_index = row_index as usize;

        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let sibling_index = if current_index % 2 == 0 {
                if current_index + 1 < level.len() {
                    current_index + 1
                } else {
                    current_index
                }
            } else {
                current_index - 1
            };
            sibling_hashes.push(level[sibling_index]);
            current_index /= 2;
        }

        Ok(StarkTraceMerkleOpeningV1 {
            row_index,
            row_value,
            sibling_hashes,
        })
    }
}

pub(crate) fn derive_stark_trace_tree_height_from_leaf_count_v1(mut leaf_count: u64) -> u64 {
    let mut tree_height = 0u64;
    while leaf_count > 1 {
        leaf_count = leaf_count.div_ceil(2);
        tree_height += 1;
    }
    tree_height
}

pub(crate) fn verify_stark_trace_merkle_opening_v1(
    commitment: &StarkTraceCommitmentV1,
    opening: &StarkTraceMerkleOpeningV1,
) -> Result<[u8; HASH_LEN_V1], StarkTraceCommitmentErrorV1> {
    if opening.sibling_hashes.len() as u64 != commitment.tree_height {
        return Err(StarkTraceCommitmentErrorV1::OpeningPathLengthMismatch {
            expected: commitment.tree_height,
            actual: opening.sibling_hashes.len() as u64,
        });
    }
    if opening.row_index >= commitment.leaf_count {
        return Err(StarkTraceCommitmentErrorV1::RowIndexOutOfRange {
            row_index: opening.row_index,
            row_count: commitment.leaf_count,
        });
    }

    let mut current_hash = hash_trace_leaf_v1(opening.row_index, &opening.row_value);
    let mut current_index = opening.row_index as usize;

    for sibling_hash in &opening.sibling_hashes {
        current_hash = if current_index % 2 == 0 {
            hash_trace_node_v1(&current_hash, sibling_hash)
        } else {
            hash_trace_node_v1(sibling_hash, &current_hash)
        };
        current_index /= 2;
    }

    Ok(current_hash)
}

fn hash_trace_leaf_v1(row_index: u64, row_value: &DcmState521V1) -> [u8; HASH_LEN_V1] {
    let row_bytes = row_value.canonical_bytes();
    let mut payload = Vec::with_capacity(8 + row_bytes.len());
    payload.extend_from_slice(&row_index.to_le_bytes());
    payload.extend_from_slice(&row_bytes);
    sha256_domain_separated(AURA_DCM_STARK_TRACE_V1_LEAF_DOMAIN_SEPARATOR, &payload)
}

fn hash_trace_node_v1(
    left_child: &[u8; HASH_LEN_V1],
    right_child: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut payload = Vec::with_capacity(HASH_LEN_V1 * 2);
    payload.extend_from_slice(left_child);
    payload.extend_from_slice(right_child);
    sha256_domain_separated(AURA_DCM_STARK_TRACE_V1_NODE_DOMAIN_SEPARATOR, &payload)
}
