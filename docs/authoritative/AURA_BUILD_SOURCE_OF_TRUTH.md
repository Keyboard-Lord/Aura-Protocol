# AURA_BUILD_SOURCE_OF_TRUTH

**Classification:** `ROOT AUTHORITY`  
**Layer:** `META`  
**Purpose:** Define the exact canonical document authority set and the authority order  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — DOCUMENT REGISTRY**
> This file owns the canonical documentation topology. It defines which documents
> are authoritative, their order of precedence, and their classification status.

There is exactly one canonical pipeline.

## Root Authority

The following document defines the core protocol specification and governs all
protocol mathematics (hash, field, STORM, proof, settlement):

- `AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md` — **ROOT AUTHORITY**

When this document conflicts with any other authoritative document on core protocol
semantics, this document governs. All protocol truth flows from this root.

## Canonical Set

The canonical documentation set is exactly the 21 files under `docs/authoritative/`.

No file outside `docs/authoritative/` defines:

- how the system works
- what is authoritative
- what is implemented
- what is deprecated

`README.md`, package `README.md` files, fixture notes, and code comments are implementation metadata only.

This index file owns set membership and authority order.

## Authority Order

This file defines document order. Authority order resolves references only.

The 20 protocol-definition documents are fixed in this order:

0. `AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md` — **ROOT AUTHORITY** (protocol specification)
1. `AURA_HASH_V2.md` — **ACTIVE AUTHORITY** (canonical 521-bit identity)
2. `AURA_STORM_RECURSION_V1_1.md` — **ACTIVE AUTHORITY**
3. `AURA_FIELD_ARITHMETIC_V1.md` — **ACTIVE AUTHORITY**
4. `AURA_DERIVATION_FUNCTIONS_V1.md` — **ACTIVE AUTHORITY**
5. `AURA_TRACE_LAYOUT_V1.md` — **ACTIVE AUTHORITY**
6. `AURA_TRACE_COMMITMENT_V1.md` — **ACTIVE AUTHORITY**
7. `AURA_STARK_SPEC_V1.md` — **ACTIVE AUTHORITY**
8. `AURA_PROVER_BINDING_V1.md` — **ACTIVE AUTHORITY**
9. `AURA_CANONICAL_PIPELINE_V1.md` — **ACTIVE AUTHORITY**
10. `AURA_REPORT_CONTRACT_V1.md` — **ACTIVE AUTHORITY**
11. `AURA_LEDGER_AND_BURN_V1.md` — **ACTIVE AUTHORITY**
12. `AURA_AUTHORIZATION_LINEAGE_V1.md` — **ACTIVE AUTHORITY**
13. `AURA_CONTINUOUS_SETTLEMENT_V1.md` — **ACTIVE AUTHORITY**
14. `AURA_UDOT_SPEC_V1.md` — **ACTIVE AUTHORITY**
15. `AURA_ARTIFACT_STRUCTURE_V1.md` — **ACTIVE AUTHORITY**
16. `AURA_INVARIANTS_V1.md` — **VALIDATION**
17. `AURA_FAILURE_CLASSES_V1.md` — **VALIDATION**
18. `AURA_VECTOR_MATRIX_V1.md` — **VALIDATION**
19. `AURA_HARDENING_LOG_V1.md` — **VALIDATION**
20. `AURA_HASH_V1.md` — **FROZEN LEGACY**

**Resolution Rule:** When documents conflict, the lower-numbered document governs.

It does not permit duplicated definitions.

## Ownership Rule

Each concept has exactly one owning document and one canonical form.

In particular:

- proof boundary fields are owned by `AURA_STARK_SPEC_V1.md`
- proof binding semantics are owned by `AURA_PROVER_BINDING_V1.md`
- pipeline stage structure is owned by `AURA_CANONICAL_PIPELINE_V1.md`
- settlement wire fields are owned by `AURA_REPORT_CONTRACT_V1.md`
- authorization lineage encoding is owned by `AURA_AUTHORIZATION_LINEAGE_V1.md`
- continuous head derivation is owned by `AURA_CONTINUOUS_SETTLEMENT_V1.md`
- UDOT canonical form is owned by `AURA_UDOT_SPEC_V1.md`
- artifact derivation ownership is defined by `AURA_ARTIFACT_STRUCTURE_V1.md`

Other documents may reference these concepts, but they MUST NOT restate alternate field lists,
parallel representations, or compatibility forms.

## Active Boundary

Active behavior is limited to:

- `HASH_V2` (521-bit SHA3-512-based identity)
- `MESSAGE_ROOT`
- `STORM_V1_1`
- `TRACE_ROOT`
- the canonical `StarkProofEnvelopeV1` wire
- the canonical `SolanaSettlementRequestWireV1` wire
- the local ledger, burn, and settlement fixtures still exercised by `scripts/verify_active_foundation.sh`

`PROOF_MATERIAL_V2` is a repository name only.

`PROOF_MATERIAL_V2` MUST NOT define active behavior.

## Cryptographic Hash Usage Matrix

The protocol uses hash functions with EXACTLY these semantics:

| Layer | Hash Function | Purpose | Document |
|-------|---------------|---------|----------|
| **L0 Identity** | **SHA3-512** | Canonical identity surface: `H_521(m) = Reduce_N(SHA3-512(m))` | ROOT AUTHORITY |
| **L0 Text** | SHA3-512 | Text mode canonicalization verification | HASH_V2 |
| **L1 Storm Init** | SHA3-512 | `y0 = Reduce_N(SHA3-512(x0 || "init"))` | ROOT AUTHORITY |
| **L1 Storm Params** | SHA3-512 | Parameter derivation with domain separation (bit-packing) | DERIVATION_FUNCTIONS_V1 |
| **L1 Storm Injection** | SHA3-512 | Entropy: `(φ_n, ψ_n)` from `StormV1()` | ROOT AUTHORITY |
| **L2 Trace Commitment** | **SHA3-256** | Merkle leaf/parent hashing: `leaf_n = SHA3-256(row_bytes)` | TRACE_COMMITMENT_V1 |
| **L2 Prover Binding** | **SHA3-256** | Side/context hashes for compact public inputs | PROVER_BINDING_V1 |
| **L3 Proof Envelope** | SHA3-512 | Final artifact derivation (post-proof) | ROOT AUTHORITY |
| **L3 Export Hash** | SHA3-512 | External compatibility: `EXPORT_HASH = SHA3-512(...)` | HASH_V2 |
| **L5 UDOT** | **SHA-256** | Glyph derivation from proof_hash (presentation only) | UDOT_SPEC_V1 |
| **Legacy V1** | SHA-256 | Historical identity (FROZEN) | HASH_V1 |

**CRITICAL RULES:**
- Identity surface MUST use SHA3-512 ONLY
- Trace commitment MUST use SHA3-256 per TRACE_COMMITMENT_V1
- Merkle construction MUST use SHA3-256 for leaf/parent hashing
- UDOT uses SHA-256 for presentation-layer glyph derivation (non-canonical)
- Any deviation from this matrix results in fail-closed rejection

## Compression Rule

Every concept MUST live in exactly one document.

Cross-reference is allowed.

Redefinition, duplicated definitions, and parallel representations are invalid.
