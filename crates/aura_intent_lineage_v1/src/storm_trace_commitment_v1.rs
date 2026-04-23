//! Canonical trace commitment rules for the storm lower layer.

use sha3::{Digest, Sha3_256};

use crate::{StormState521V1, STORM_STATE_521_ROW_BYTE_LEN_V1};

pub type StormTraceRootV1 = [u8; 32];

pub fn storm_leaf_hash(row_bytes: &[u8; STORM_STATE_521_ROW_BYTE_LEN_V1]) -> [u8; 32] {
    sha3_256_bytes(row_bytes)
}

pub fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    sha3_256_bytes(&bytes)
}

pub fn compute_storm_trace_root(trace: &[StormState521V1]) -> [u8; 32] {
    let rows = trace
        .iter()
        .map(StormState521V1::encode_row_bytes)
        .collect::<Vec<_>>();
    compute_storm_trace_root_from_rows(&rows)
}

pub fn compute_storm_trace_root_from_rows(
    rows: &[[u8; STORM_STATE_521_ROW_BYTE_LEN_V1]],
) -> [u8; 32] {
    assert!(
        !rows.is_empty(),
        "storm trace must contain at least the initial state"
    );

    let mut level = rows.iter().map(storm_leaf_hash).collect::<Vec<_>>();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level
                .last()
                .expect("non-empty Merkle level must have a last element");
            level.push(last);
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(merkle_parent(&pair[0], &pair[1]));
        }
        level = next;
    }

    level[0]
}

fn sha3_256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use crate::FieldElement521V1;

    use super::{compute_storm_trace_root, merkle_parent, storm_leaf_hash};
    use crate::StormState521V1;

    #[test]
    fn storm_leaf_hash_is_deterministic() {
        let state = StormState521V1 {
            x: FieldElement521V1::from_u64(1),
            y: FieldElement521V1::from_u64(2),
        };
        let row_bytes = state.encode_row_bytes();

        assert_eq!(storm_leaf_hash(&row_bytes), storm_leaf_hash(&row_bytes));
    }

    #[test]
    fn odd_leaf_levels_duplicate_the_last_leaf() {
        let leaf = [0x11; 32];
        assert_eq!(merkle_parent(&leaf, &leaf), merkle_parent(&leaf, &leaf));
    }

    #[test]
    fn trace_root_changes_when_trace_changes() {
        let first = [
            StormState521V1 {
                x: FieldElement521V1::from_u64(1),
                y: FieldElement521V1::from_u64(2),
            },
            StormState521V1 {
                x: FieldElement521V1::from_u64(3),
                y: FieldElement521V1::from_u64(4),
            },
        ];
        let second = [
            first[0],
            StormState521V1 {
                x: FieldElement521V1::from_u64(3),
                y: FieldElement521V1::from_u64(5),
            },
        ];

        assert_ne!(compute_storm_trace_root(&first), compute_storm_trace_root(&second));
    }
}
