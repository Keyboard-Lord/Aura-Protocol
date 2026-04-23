# AURA_TRACE_LAYOUT_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L2`  
**Purpose:** Define the ordered trace rows and state encoding  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — TRACE FORMAT**
> This document defines the canonical trace row format (132 bytes: x||y).
> Row order is exact and immutable. No row may be removed or reordered.

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/storm_state_v1.rs`
- Rust: `crates/aura_intent_lineage_v1/src/storm_claim_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormStateV1.ts`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormClaimV1.ts`

## Row Rule

Each state row is:

`row_bytes_n = x_bytes_66_be || y_bytes_66_be`

Row width is exactly 132 bytes.

## Ordering Rule

Row order is exact:

`row_0, row_1, ..., row_iteration_count`

`row_0` is the derived initial state.

`row_iteration_count` is the derived final state.

## Claim Boundary

`StormClaim521V1` carries:

- `version`
- `modulus_id`
- `iteration_count`
- `side_A`
- `side_B`
- `context_bytes_v1`
- `initial_state`
- `final_state`
- `TRACE_ROOT`

`StormClaim521V1` MUST NOT carry:

- `legacy_commitment_root`
- `legacy_trace_commitment`
- any other compatibility alias for `TRACE_ROOT`

If legacy trace or commitment material exists upstream, it MUST be consumed by a non-canonical
normalization adapter and deterministically re-expressed as canonical storm inputs before claim
construction.
