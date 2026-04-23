# AURA_CONTINUOUS_SETTLEMENT_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L4`  
**Purpose:** Define local settlement head progression  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — HEAD DERIVATION**
> This document defines canonical settlement head derivation from prior head.
> Previous-head and sequence fields are derived, not caller-supplied.

Implementation:

- Rust: `crates/aura_l2_local_chain_v0`
- TypeScript: `packages/aura_sdk_v0_ts/src/index.ts`
- Frozen fixtures: `fixtures/l2_canonical_pipeline_v1/continuous_chain_v1/*`

## Head Input

Canonical transition input is:

- `prior_head`
- `settlement_report`

`previous_head_hash_hex` and `head_sequence_number` are derived from `prior_head`.

Canonical transition objects do not accept caller-supplied head linkage fields.

## Transition Rule

A valid transition MUST:

- use `settlement_head_version = 1`
- derive `previous_head_hash_hex = prior_head.current_head_hash_hex`
- derive `head_sequence_number = prior_head.head_sequence_number + 1`
- produce one `current_head_hash_hex`
- produce one `canonical_head_commitment_hex`

## Construction Rule

Any object that directly supplies `previous_head_hash_hex` or `head_sequence_number` is
non-canonical.

Sequence mismatch and previous-head mismatch are therefore unrepresentable inside canonical
settlement construction.

`authority_mode = stateless_non_authoritative` is fixed in the emitted summary.
