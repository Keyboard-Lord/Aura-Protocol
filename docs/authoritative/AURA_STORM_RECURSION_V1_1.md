# AURA_STORM_RECURSION_V1_1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L1`  
**Purpose:** Define STORM_V1_1 recurrence formulas  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — STORM EXECUTION LAYER**
> This document defines the canonical STORM recurrence used by the active protocol.
> The quadratic recurrence formulas herein are the sole active execution semantics.
> Note: The "Arnold cat map" (linear) described in research materials is NOT active.

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/storm_execution_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormExecutionV1.ts`

## Inputs

`STORM_V1_1` accepts exactly:

- `side_A`: 110 bytes
- `side_B`: 110 bytes
- `context_bytes_v1`: 209 bytes
- `iteration_count`: `u64`

`context_bytes_v1` is valid only when:

- byte `0` is `0x01`
- bytes `33..65` equal `SHA3-512("AURA_STORM_EXECUTION_V1")[0..32]`

## State Rule

`s_0 = (x_0, y_0)`

For each `n` in `[0, iteration_count - 1]`:

`x_(n+1) = x_n^2 - y_n^2 + a + phi_n mod (2^521 - 1)`

`y_(n+1) = 2*x_n*y_n + b + psi_n mod (2^521 - 1)`

The canonical trace is:

`T = [s_0, s_1, ..., s_iteration_count]`

No row may be removed, inferred, or reordered.

## Determinism

The same inputs MUST reproduce the same:

- `initial_state`
- `final_state`
- ordered trace

Determinism is forward-only; the transition is not injective. For fixed step
injections and parameters, `(x, y)` and `(-x, -y)` produce the same successor
because both squared terms and the product `x*y` are unchanged. These states are
distinct whenever `(x, y) != (0, 0)` in this odd-characteristic field. A final
state alone therefore does not uniquely identify a predecessor or an arbitrary
trace. Validation must retain the prescribed input binding and ordered trace
commitment. This corrects a uniqueness claim; it does not change the recurrence.

## Locked Validation

- `fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json`
- `crates/aura_intent_lineage_v1/tests/storm_execution_v1.rs`
- `packages/aura_sdk_v1_ts/src/stormExecutionV1.test.ts`
- `packages/aura_sdk_v1_ts/tests/storm_parity_v1.test.ts`

## Fail-Closed Enforcement

**MUST:** Any deviation from the canonical STORM recurrence results in immediate fail-closed rejection.

Specific rejections:

- Invalid context bytes → `STORM_CONTEXT_INVALID` → reject
- Non-canonical field encoding → `FIELD_ENCODING_INVALID` → reject  
- Modified recurrence formula → `STORM_CLAIM_INVALID` → reject
- Entropy injection mismatch → `EntropyMismatch` → reject
- Trace step missing or reordered → `TraceInvalid` → reject

No partial verification. No relaxed constraints. No bypass.
