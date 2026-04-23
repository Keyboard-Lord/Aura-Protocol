# AURA_PROVER_BINDING_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L2`  
**Purpose:** Define proof binding to storm inputs, states, and trace commitment  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — PROVER BINDING**
> This document defines how public inputs bind to Storm claims and trace roots.
> The cryptographic binding between compact public inputs and canonical claim is enforced.

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/storm_claim_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormClaimV1.ts`

## Compact Public Inputs

`StormPublicInputs521V1` is:

- `version`
- `modulus_id`
- `iteration_count`
- `side_a_hash`
- `side_b_hash`
- `context_hash`
- `initial_state`
- `final_state`
- `TRACE_ROOT`

## Hash Rules

**HASH USAGE:** Prover binding uses SHA3-256 for compact public input hashes per the Cryptographic Hash Usage Matrix.

**Rationale:**
- Side/context hashes are 256-bit commitments to raw bytes
- These are DISTINCT from the 521-bit identity surface
- SHA3-256 provides adequate collision resistance for binding purposes
- Public inputs remain compact (256-bit hashes vs 521-bit field elements)

**MUST:** All prover binding hashes use SHA3-256 exclusively.

`side_a_hash  = SHA3-256("AURA_STORM_SIDE_A_HASH_V1" || side_A)`

`side_b_hash  = SHA3-256("AURA_STORM_SIDE_B_HASH_V1" || side_B)`

`context_hash = SHA3-256("AURA_STORM_CONTEXT_HASH_V1" || context_bytes_v1)`

The hashes bind raw bytes only. The canonical identity surface (H_521) uses SHA3-512 per ROOT AUTHORITY.

## Binding Rule

A valid proof binding is constructed only from canonical `StormClaim521V1`.

It MUST reproduce:

- the derived initial state
- the derived final state
- the derived `TRACE_ROOT`
- the three compact hashes above

`PROVER_BINDING_INVALID` applies only when:

- the canonical storm claim is malformed
- the compact public inputs cannot be reproduced from the canonical claim
- the proof/public-input/trace cryptographic binding is broken

Cross-representation drift is not a canonical failure mode because canonical proof objects expose
only one claim representation.
