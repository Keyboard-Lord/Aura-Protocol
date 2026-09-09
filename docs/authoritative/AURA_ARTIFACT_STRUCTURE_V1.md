# AURA_ARTIFACT_STRUCTURE_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L5`  
**Purpose:** Define artifact derivation chain  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — ARTIFACT DERIVATION**
> This document defines the canonical artifact derivation chain.
> Each artifact is a pure function of its inputs. No optional fields permitted.

Implementation:

- Rust: `prepare_bound_proof_material_v1` in `crates/aura_sdk_v1/src/lib.rs`
- TypeScript: `prepareBoundProofMaterialV1` in `packages/aura_sdk_v1_ts/src/sdkCoreV1.ts`
- Frozen preparation fixtures: `fixtures/v1/canonical_prepare/*`

Both return `PreparedBoundProofMaterialV1` using subject and freshness binding bytes.
Preparation binds bytes; it does not verify an Aura proof or grant authorization.
The [authorization owner](AURA_AUTHORIZATION_LINEAGE_V1.md) supplies and validates
the approved identity and nonce. Historical account-oriented preparation names
are accessible only through explicit `legacy` entry points.

## Artifact Chain

The artifact chain is exact:

1. build `ProofMaterialV1`
2. derive `proof_material_hash`
3. build `FractalKeyV1`
4. derive `proof_hash`
5. derive `UdotBundleV2` directly from `proof_hash`

## `ProofMaterialV1` — Auxiliary Binding Layer

**LAYER CLARIFICATION:** This is an auxiliary binding layer, not the canonical identity surface.
The canonical identity surface is `H_521` per ROOT AUTHORITY.

`ProofMaterialV1` binds proof components:

- `SHA256(proof_blob_bytes)`
- `SHA256(public_inputs_bytes)`
- `SHA256(verification_key_bytes)`

Then:

`proof_material_hash = SHA256(proof_material.canonical_bytes())`

Canonical bytes are `"AURA_PROOF_MATERIAL_V1" || version_u8 || type_u16_le ||
proof_blob_hash32 || public_inputs_hash32 || verification_key_hash32`. Version is 1
and type is 1. The domain occurs exactly once. All hashes above are 32 bytes.
The [authorization owner](AURA_AUTHORIZATION_LINEAGE_V1.md) selects the existing
active backend's proof, public-input and verification-key bytes.

This corrects earlier SHA3-512 documentation against the existing Rust/TypeScript
implementations and frozen vectors; it does not change material hashing.

## `FractalKeyV1` — Proof Reference Binding

`FractalKeyV1` uses exactly three ordered components:

1. subject binding
2. challenge binding
3. proof material hash

Then:

`proof_hash = SHA256(fractal_key.canonical_bytes())`

Canonical bytes are `"AURA_FRACTAL_KEY_V1" || version_u8 || component_count_u8 ||
component_1 || component_2 || component_3`. Version is 1 and count is 3. Each
component is `type_u16_le || payload32`, with types 1, 2, 3 in the order above.
The domain occurs exactly once. The 32-byte result and all serialization bytes
remain unchanged by the Bitcoin migration. The existing challenge component now
binds the nonce under the approved authorization contract.

**CRITICAL:** `proof_hash` is the canonical proof reference used by UDOT and settlement layers.

## Canonical UDOT Bundle

The fixed `UdotBundleV2` representation, derivation and validation rules are owned
once by [the UDOT specification](AURA_UDOT_SPEC_V1.md). This layer supplies the
canonical proof reference to that owner.

`PROOF_MATERIAL_V2` is outside the active artifact chain.
