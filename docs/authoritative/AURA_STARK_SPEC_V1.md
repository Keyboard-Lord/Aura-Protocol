# AURA_STARK_SPEC_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L2`  
**Purpose:** Define the active STARK proving and wire boundary  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — STARK PROOF SYSTEM**
> This document defines the canonical STARK proof envelope and wire format.
> Proof objects MUST conform to StarkProofEnvelopeV1 exactly.

Implementation:

- Rust proving surface: `crates/aura_intent_lineage_v1/src/stark_prover_v1.rs`
- Rust verification surface: `crates/aura_intent_lineage_v1/src/stark_verifier_v1.rs`
- TypeScript wire surface: `packages/aura_sdk_v1_ts/src/index.ts`
- Frozen wire fixture: `fixtures/v1/canonical_pipeline_v1/stark_proof_envelope_v1.json`

## Rust Proof Boundary

Rust owns proof session production and acceptance.

Rust proof generation is not transported as raw proof bytes in the canonical JSON wire.

## Canonical JSON Proof Object

The canonical external proof object is `StarkProofEnvelopeV1`:

- `proof_version`
- `proof_session_id_hex`
- `proof_hash_hex`
- `storm_claim`

Unexpected fields are invalid.

Canonical proof objects MUST NOT carry:

- `legacy_dcm_claim`
- `authorization_intent`
- any other parallel claim or nested upstream object

## Compatibility Boundary

Legacy DCM claims, if accepted at all, are ingestion-only inputs.

A non-canonical one-way adapter MAY deterministically map a legacy DCM input into `storm_claim`
before canonical pipeline entry.

The adapter output is only `storm_claim`.

No canonical object may carry both legacy and canonical claim representations simultaneously.

## Binding Rule

`storm_claim` is the sole proof-bound claim at the canonical boundary.

`proof_hash_hex` is the sole downstream proof reference.

No equivalence checks between parallel claims exist because parallel claims are non-canonical.

## Fail-Closed Enforcement

**MUST:** Any proof boundary deviation results in immediate fail-closed rejection.

Specific rejections:

- Malformed proof envelope → `PROVER_BINDING_INVALID` → reject
- Legacy DCM claim present → reject
- Parallel claim representation → reject
- Unexpected fields → reject
- Proof verification failure → `ProofInvalid` → reject + burn

STARK proof MUST verify against canonical public inputs. No bypass. No partial verification.
