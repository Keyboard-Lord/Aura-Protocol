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

## `AURA_HASH521_V1` — Storm Parameter Derivation ONLY

**CRITICAL DISTINCTION:** This construction is for Storm parameter derivation ONLY, not for the canonical identity surface.

For the **identity surface**, see ROOT AUTHORITY (AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md):
- `H_521(m) = Reduce_N(SHA3-512(m))` — simple direct reduction

For **Storm parameter derivation** (`AURA_HASH521_V1`), the construction is:

- `h0 = SHA3-512(msg || 0x00)`
- `h1 = SHA3-512(msg || 0x01)`
- take 512 bits from `h0`
- take the first 9 bits of `h1`, MSB first
- pack 521 bits into a 66-byte big-endian field element
- if the packed value equals `2^521 - 1`, map to zero

**Rationale:** Storm parameter derivation requires 521 bits of entropy from domain-separated inputs. The identity surface uses the simpler direct reduction. Both use SHA3-512 exclusively.

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
