# AURA_AUTHORIZATION_LINEAGE_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L4`  
**Purpose:** Define the canonical authorization identity binding  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — AUTHORIZATION BINDING**
> This document defines the six-field canonical authorization lineage encoding.
> No alternate lineage representations are valid in the active pipeline.

Implementation:

- Rust: `crates/aura_sdk_v1/src/authorization.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/index.ts`
- Validation fixtures: `fixtures/v1/canonical_pipeline_v1/authorization_intent_v1.json`
- Compatibility fixtures: `fixtures/layer4_v1/*.json`

## Canonical Envelope

`AuthorizationIntentEnvelopeV1` is:

- `intent_version`
- `intent_id_hex`
- `proof_hash_hex`
- `authorization_lineage`

## Canonical Lineage

`authorization_lineage` is:

- `subject_binding_type = submitter-pubkey-base58`
- `subject_binding`
- `intent_type = opaque-intent-hash-32`
- `intent_commitment_hex = intent_id_hex`
- `freshness_binding_type = challenge-pubkey-base58`
- `freshness_binding`

Unexpected fields are invalid.

Canonical authorization objects MUST NOT embed:

- `submit_proof_request`
- any proof envelope
- any settlement object

## Single-Encoding Rule

The six-field `authorization_lineage` binding above is the only canonical lineage encoding.

Legacy 521-bit lineage fixtures are non-canonical ingestion inputs only.

All upstream lineage inputs MUST be normalized into the canonical lineage encoding before pipeline
entry.
