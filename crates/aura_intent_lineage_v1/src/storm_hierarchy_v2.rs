//! Experimental hierarchy over an unchanged V1 trace. Not a canonical wire or proof.
use crate::{
    aura_hash521_v1, build_storm_trace, compute_storm_trace_root, validate_context_bytes_v1,
    FieldElement521V1, StormContextErrorV1, StormExecutionErrorV1, StormExecutionInputsV1,
    StormState521V1, STORM_CONTEXT_V1_LEN,
};
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;

pub const STORM_EPOCH_TRANSITIONS_V2: u64 = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StormEpochV2 {
    pub epoch_index: u64,
    pub start_step: u64,
    pub transition_count: u64,
    pub initial_state: StormState521V1,
    pub final_state: StormState521V1,
    pub epoch_trace_root: [u8; 32],
    pub epoch_commitment: [u8; 32],
    pub macro_state_before: FieldElement521V1,
    pub macro_state_after: FieldElement521V1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StormHierarchyV2 {
    pub iteration_count: u64,
    pub epoch_count: u64,
    pub epochs: Vec<StormEpochV2>,
    pub initial_macro_state: FieldElement521V1,
    pub final_macro_state: FieldElement521V1,
    pub hierarchy_root: [u8; 32],
}

#[derive(Debug)]
pub enum StormHierarchyErrorV2 {
    EmptyTrace,
    EmptyHierarchy,
    InvalidContext(StormContextErrorV1),
    InvalidExecution(StormExecutionErrorV1),
}
impl core::fmt::Display for StormHierarchyErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StormHierarchyErrorV2 {}

/// Runs the existing V1 micro recurrence, then derives only experimental outputs.
pub fn execute_storm_hierarchy_v2(
    inputs: &StormExecutionInputsV1,
) -> Result<StormHierarchyV2, StormHierarchyErrorV2> {
    inputs
        .validate()
        .map_err(StormHierarchyErrorV2::InvalidExecution)?;
    build_storm_hierarchy_v2(&inputs.context_bytes_v1, &build_storm_trace(inputs))
}

/// Overlays a nonempty trace. This function commits the supplied rows; it does not
/// prove they follow the V1 recurrence. Adjacent epochs share their boundary row.
pub fn build_storm_hierarchy_v2(
    context: &[u8; STORM_CONTEXT_V1_LEN],
    trace: &[StormState521V1],
) -> Result<StormHierarchyV2, StormHierarchyErrorV2> {
    validate_context_bytes_v1(context).map_err(StormHierarchyErrorV2::InvalidContext)?;
    let initial = trace.first().ok_or(StormHierarchyErrorV2::EmptyTrace)?;
    let iteration_count = (trace.len() - 1) as u64;
    let epoch_count = if iteration_count == 0 {
        1
    } else {
        (iteration_count - 1) / STORM_EPOCH_TRANSITIONS_V2 + 1
    };
    let initial_macro_state = hash_field(
        b"AURA_STORM_MACRO_INIT_V2",
        &[context, &initial.encode_row_bytes()],
    );
    let mut z = initial_macro_state;
    let mut epochs = Vec::with_capacity(epoch_count as usize);
    for epoch_index in 0..epoch_count {
        let start_step = epoch_index * STORM_EPOCH_TRANSITIONS_V2;
        let transition_count = (iteration_count - start_step).min(STORM_EPOCH_TRANSITIONS_V2);
        let rows = &trace[start_step as usize..=(start_step + transition_count) as usize];
        let initial_state = rows[0];
        let final_state = rows[rows.len() - 1];
        let epoch_trace_root = compute_storm_trace_root(rows);
        let epoch_commitment = hash256(
            b"AURA_STORM_EPOCH_COMMITMENT_V2",
            &[
                &epoch_index.to_le_bytes(),
                &start_step.to_le_bytes(),
                &transition_count.to_le_bytes(),
                &initial_state.encode_row_bytes(),
                &final_state.encode_row_bytes(),
                &epoch_trace_root,
            ],
        );
        let after = macro_step_v2(&z, &final_state, context, epoch_index);
        epochs.push(StormEpochV2 {
            epoch_index,
            start_step,
            transition_count,
            initial_state,
            final_state,
            epoch_trace_root,
            epoch_commitment,
            macro_state_before: z,
            macro_state_after: after,
        });
        z = after;
    }
    let commitments: Vec<_> = epochs.iter().map(|e| e.epoch_commitment).collect();
    Ok(StormHierarchyV2 {
        iteration_count,
        epoch_count,
        epochs,
        initial_macro_state,
        final_macro_state: z,
        hierarchy_root: compute_hierarchy_root_v2(&commitments)?,
    })
}

fn macro_constants_v2() -> &'static (FieldElement521V1, FieldElement521V1) {
    static CONSTANTS: OnceLock<(FieldElement521V1, FieldElement521V1)> = OnceLock::new();
    CONSTANTS.get_or_init(|| {
        (
            aura_hash521_v1(b"AURA_STORM_MACRO_ALPHA_V2"),
            aura_hash521_v1(b"AURA_STORM_MACRO_BETA_V2"),
        )
    })
}

fn macro_step_v2(
    z: &FieldElement521V1,
    end: &StormState521V1,
    context: &[u8; STORM_CONTEXT_V1_LEN],
    k: u64,
) -> FieldElement521V1 {
    let (alpha, beta) = macro_constants_v2();
    let rho = hash_field(b"AURA_STORM_MACRO_RHO_V2", &[context, &k.to_le_bytes()]);
    z.square_mod()
        .add_mod(&alpha.mul_mod(&end.x))
        .add_mod(&beta.mul_mod(&end.y))
        .add_mod(&rho)
}

/// Ordered, domain-separated experimental Merkle tree. Duplicates the last node
/// on odd levels; zero padding and empty hierarchies are not defined.
pub fn compute_hierarchy_root_v2(
    commitments: &[[u8; 32]],
) -> Result<[u8; 32], StormHierarchyErrorV2> {
    if commitments.is_empty() {
        return Err(StormHierarchyErrorV2::EmptyHierarchy);
    }
    let mut level: Vec<_> = commitments
        .iter()
        .map(|c| hash256(b"AURA_STORM_HIERARCHY_LEAF_V2", &[c]))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                hash256(
                    b"AURA_STORM_HIERARCHY_PARENT_V2",
                    &[&pair[0], pair.get(1).unwrap_or(&pair[0])],
                )
            })
            .collect();
    }
    Ok(level[0])
}
fn hash256(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn hash_field(domain: &[u8], parts: &[&[u8]]) -> FieldElement521V1 {
    let mut bytes = domain.to_vec();
    for part in parts {
        bytes.extend_from_slice(part);
    }
    aura_hash521_v1(&bytes)
}
