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

The canonical documentation set is exactly the 25 files under `docs/authoritative/`.

No file outside `docs/authoritative/` defines:

- normative protocol behavior
- canonical document membership or precedence
- protocol conformance requirements
- protocol deprecation policy

`README.md`, package `README.md` files, fixture notes, and code comments are implementation metadata only.

This index file owns set membership and authority order.

## Specification and Implementation Evidence

This registry defines intended protocol authority. The current checked-out source,
fixtures, and executed tests establish implementation state. A specification's
`ACTIVE AUTHORITY` label does not establish that its requirements are implemented.
Implementation metadata may describe that evidence and identify discrepancies;
it must not introduce alternate normative definitions.

The approved Bitcoin OP_RETURN codec, Core transport, BIP340 authorization and
durable nonce journal are implemented. The active workspace excludes the Solana
program and submission clients, retained in a separate explicit legacy workspace.
Rust and TypeScript share neutral bound-material preparation and the fixed V2
UDOT bundle. Historical nested proof and settlement envelopes remain legacy
evidence rather than alternate canonical wires.

End-to-end economic integration remains incomplete: the local ledger/burn runner
and the Storm authorization/Bitcoin path have no approved common economic
admission contract. Their separate passing checks do not establish one completed
economic pipeline. Preserve existing cryptographic and economic behavior while
resolving that boundary; do not infer new hash or charging semantics from migration.

Research, historical evidence, and unapproved proposals do not acquire authority
through titles such as "final", "canonical", or "source of truth". Proposals remain
non-authoritative until explicitly approved and incorporated into the owning
documents with corresponding implementation and validation.

## Authority Order

This file defines document order. Authority order resolves references only.

The 25 authoritative documents are fixed in this order:

0. `AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md` — **ROOT AUTHORITY** (protocol specification)
1. `AURA CANONICAL INGESTION LAYER (CIL) SPECIFICATION V1.md` — **ACTIVE AUTHORITY**
2. `AURA_HASH_V2.md` — **ACTIVE AUTHORITY** (canonical 521-bit identity)
3. `AURA_STORM_RECURSION_V1_1.md` — **ACTIVE AUTHORITY**
4. `AURA_FIELD_ARITHMETIC_V1.md` — **ACTIVE AUTHORITY**
5. `AURA_DERIVATION_FUNCTIONS_V1.md` — **ACTIVE AUTHORITY**
6. `AURA_TRACE_LAYOUT_V1.md` — **ACTIVE AUTHORITY**
7. `AURA_TRACE_COMMITMENT_V1.md` — **ACTIVE AUTHORITY**
8. `AURA_STARK_SPEC_V1.md` — **ACTIVE AUTHORITY**
9. `AURA_PROVER_BINDING_V1.md` — **ACTIVE AUTHORITY**
10. `AURA_CANONICAL_PIPELINE_V1.md` — **ACTIVE AUTHORITY**
11. `AURA_REPORT_CONTRACT_V1.md` — **ACTIVE AUTHORITY**
12. `AURA_LEDGER_AND_BURN_V1.md` — **ACTIVE AUTHORITY**
13. `AURA_AUTHORIZATION_LINEAGE_V1.md` — **ACTIVE AUTHORITY**
14. `AURA_CONTINUOUS_SETTLEMENT_V1.md` — **ACTIVE AUTHORITY**
15. `AURA_UDOT_SPEC_V1.md` — **ACTIVE AUTHORITY**
16. `AURA_ARTIFACT_STRUCTURE_V1.md` — **ACTIVE AUTHORITY**
17. `AURA_INVARIANTS_V1.md` — **VALIDATION**
18. `AURA_FAILURE_CLASSES_V1.md` — **VALIDATION**
19. `AURA_VECTOR_MATRIX_V1.md` — **VALIDATION**
20. `AURA_HARDENING_LOG_V1.md` — **VALIDATION**
21. `AURA_HASH_V1.md` — **FROZEN LEGACY**
22. `AURA_UDOT_UNICODE_LAYER_V3.md` — **SUPPORTING**
23. `AURA_AURAFARMING_NODES.md` — **RESEARCH / SUPPORTING**
24. `AURA_BUILD_SOURCE_OF_TRUTH.md` — **ROOT AUTHORITY / META**

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
- the existing canonical Storm witness-backend proof bytes owned by `AURA_STARK_SPEC_V1.md`
- the canonical BIP340 `AuthorizationEnvelopeV2` boundary
- the canonical `BitcoinAnchorRequestV1` wire
- the local ledger, burn, and settlement fixtures still exercised by `scripts/verify_active_foundation.sh`

`PROOF_MATERIAL_V2` is a repository name only.

`PROOF_MATERIAL_V2` MUST NOT define active behavior.

## Cryptographic ownership map

This registry identifies owners; it does not restate competing preimages.

| Concept | Construction | Owner |
| --- | --- | --- |
| Active field-valued hash primitive | Single SHA3-512, big-endian field reduction | `AURA_HASH_V2.md` |
| Storm initialization, parameters and forcing | The same primitive with exact caller domain/payload bytes | `AURA_DERIVATION_FUNCTIONS_V1.md` |
| Ordered trace commitment | SHA3-256 leaves and parents | `AURA_TRACE_COMMITMENT_V1.md` |
| Compact input binding | Domain-separated SHA3-256 | `AURA_PROVER_BINDING_V1.md` |
| Proof material and FractalKey proof reference | Existing SHA256 canonical-byte hashing | `AURA_ARTIFACT_STRUCTURE_V1.md` |
| BIP340 authorization message | Tagged SHA256 | `AURA_AUTHORIZATION_LINEAGE_V1.md` |
| UDOT presentation | Existing SHA256 glyph derivation | `AURA_UDOT_SPEC_V1.md` |
| Preserved historical message hash | Existing SHA256 framing | `AURA_HASH_V1.md` |

There is no active `EXPORT_HASH` alternate proof identifier or separate 512+9-bit
parameter hash construction. Research hashes do not enter canonical admission.

## Compression Rule

Every concept MUST live in exactly one document.

Cross-reference is allowed.

Redefinition, duplicated definitions, and parallel representations are invalid.
