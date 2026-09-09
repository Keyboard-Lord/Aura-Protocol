# AURA_DERIVATION_FUNCTIONS_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L1`  
**Purpose:** Define AURA_HASH521_V1 and domain-separated Storm derivations  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — PARAMETER DERIVATION**
> This document defines how Storm parameters (x0, y0, a, b, phi_n, psi_n) are derived.
> All domain separators are ASCII and exact. No alternate separators are valid.

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/storm_hash521_v1.rs`
- Rust: `crates/aura_intent_lineage_v1/src/storm_execution_v1.rs`
- Rust: `crates/aura_intent_lineage_v1/src/storm_context_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormHash521V1.ts`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormExecutionV1.ts`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormContextV1.ts`

## Shared hash primitive

`AURA_HASH521_V1` uses the single SHA3-512 reduction defined by
[AURA_HASH_V2](AURA_HASH_V2.md). Its Rust/TypeScript API suffix is retained; there
is no second parameter-only hash algorithm. Earlier text describing two hashes,
512+9-bit packing and suffix bytes `0x00`/`0x01` does not match the existing
implementation or frozen vectors and is superseded. No implementation bytes change.

## Storm Derivations

All domain separators are ASCII and exact.

`x0   = AURA_HASH521_V1("AURA_X0_V1"       || side_A)`

`y0   = AURA_HASH521_V1("AURA_Y0_V1"       || side_B)`

`a    = AURA_HASH521_V1("AURA_C_A_V1"      || context_bytes_v1)`

`b    = AURA_HASH521_V1("AURA_C_B_V1"      || context_bytes_v1)`

`phi_n = AURA_HASH521_V1("AURA_STORM_X_V1" || side_A || side_B || context_bytes_v1 || u64_le(n))`

`psi_n = AURA_HASH521_V1("AURA_STORM_Y_V1" || side_A || side_B || context_bytes_v1 || u64_le(n))`

No alternate separator is valid.

No alternate step encoding is valid.
