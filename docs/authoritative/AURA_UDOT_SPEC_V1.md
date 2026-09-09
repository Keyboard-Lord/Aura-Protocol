# AURA_UDOT_SPEC_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L5`  
**Purpose:** Define UDOT derivation, glyph alphabets, and transport rules  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — REPRESENTATION LAYER**
> This document defines the canonical UDOT v2 representation format.
> UDOT is derived from proof_hash_hex and is non-canonical for settlement.
> V2 is fixed; v1-legacy is excluded from active pipeline.

Implementation:

- Rust: `crates/aura_udot_v2/src/v2.rs`
- Rust bundle: `crates/aura_sdk_v1/src/udot_bundle_v2.rs`
- TypeScript bundle and existing derivation: `packages/aura_sdk_v1_ts/src/sdkCoreV1.ts`
- Canonical bundle vectors: `fixtures/udot_v2/bundles.json`
- Preserved glyph and historical compatibility vectors: `fixtures/v1/udot_v1/test_vectors.json`

## Canonical Version Rule

Canonical UDOT is fixed to version 2.

`v1-legacy` is excluded from all canonical pipeline paths.

Any version branching happens strictly before canonical derivation.

Canonical UDOT objects do not carry a version discriminator.

## V2 Derivation

**HASH USAGE:** UDOT uses SHA-256 for glyph derivation per the Cryptographic Hash Usage Matrix (BUILD_SOURCE_OF_TRUTH). This is acceptable because UDOT is a **presentation layer only** — not part of the canonical identity or settlement path.

Given a 32-byte `proof_hash_bytes`:

- `seal_line  = first 16 nibbles of SHA-256("AURA_UDOT_SEAL_LINE_V1" || proof_hash_bytes)`
- `crest      = first  8 nibbles of SHA-256("AURA_UDOT_SEAL_V1"      || proof_hash_bytes)`
- `matrix_sequence = all 64 nibbles of proof_hash_bytes`, high nibble first in byte order

The matrix sequence directly encodes the proof reference and can be decoded back
to its exact bytes. It is not a matrix-domain hash. This corrects earlier prose
against the existing Rust/TypeScript implementations and frozen vectors without
changing glyph outputs. The proof reference is derived by the existing FractalKey
construction owned by [the artifact specification](AURA_ARTIFACT_STRUCTURE_V1.md).

V2 nibble-to-glyph order is exact:

`◦ ◌ ∘ ○ ⟡ ◎ • ∙ ◈ ◇ ◆ ㅁ ■ □ ▣ ▤`

`matrix_form` is the 8x8 LF-delimited rendering of `matrix_sequence` and is presentation-only.

## Canonical Bundle Rule

`UdotBundleV2` is:

- `proof_hash_hex`
- `seal_line`
- `crest`
- `matrix_sequence`

There is no `aura_hash_hex` field.

If glyphs must be recomputed, they are recomputed from `proof_hash_hex`; they are never accepted
as an independent parallel representation of the same value.

`generate_udot_bundle_v2` / `generateUdotBundleV2` require canonical lowercase
32-byte hexadecimal. `validate_udot_bundle_v2` / `validateUdotBundleV2` additionally
require the expected proof reference and recompute all three glyph strings.
Missing, extra, malformed, versioned or aliased fields are rejected. Parsing shape
alone does not validate binding. Versioned historical SDK wrappers remain under
the explicit `legacy` namespace; they do not enter this canonical boundary.
