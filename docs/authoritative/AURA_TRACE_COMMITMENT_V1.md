# AURA_TRACE_COMMITMENT_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L2`  
**Purpose:** Define TRACE_ROOT commitment  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — TRACE COMMITMENT**
> This document defines the canonical Merkle commitment over the ordered trace.
> Uses SHA3-256 for Merkle construction. No sorting. No zero padding.

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/storm_trace_commitment_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormTraceCommitmentV1.ts`

## Leaf Rule

`leaf_n = SHA3-256(row_bytes_n)`

## Parent Rule

`parent = SHA3-256(left || right)`

## Hash Choice Rationale

**CRITICAL:** Trace commitment uses SHA3-256 (not SHA3-512) per the Cryptographic Hash Usage Matrix.

**Rationale:**
- Trace commitment produces a 256-bit Merkle root (sufficient for collision resistance)
- SHA3-256 provides adequate security with smaller proof sizes
- The trace commitment is DISTINCT from the 521-bit identity surface
- Identity surface uses SHA3-512 (521-bit output reduced to field)
- Trace commitment uses SHA3-256 (256-bit Merkle construction)

**MUST:** All trace commitment operations use SHA3-256 exclusively. No mixing of hash primitives.

## Odd-Level Rule

If a level has odd cardinality, duplicate the last node before hashing parents.

## Root Rule

`TRACE_ROOT` is the final 32-byte root produced from the ordered leaves.

No domain separator is inserted at the leaf layer.

No domain separator is inserted at the parent layer.

No sorting is valid.

No zero padding is valid.
