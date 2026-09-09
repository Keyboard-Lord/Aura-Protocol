# AURA_HASH_V2

**Classification:** `ACTIVE AUTHORITY`
**Layer:** `L0`
**Purpose:** Own the active field-valued hash primitive
**Status:** `ACTIVE`

The document name is a protocol label. The existing implementation APIs are
`aura_hash521_v1` in Rust and `auraHash521V1` in TypeScript; their names and bytes
are preserved. This document does not introduce an `AURA_HASH521_V2` implementation
or a separate parameter-hash algorithm.

## Construction

For the exact supplied bytes m:

`H_521(m) = Reduce_p(SHA3-512(m)), p = 2^521 - 1`

Interpret the 64-byte digest as a big-endian integer and reduce modulo p using the
canonical field implementation. Encode the result as the existing 66-byte
big-endian field representation. There is exactly one SHA3-512 invocation and no
implicit domain, length, suffix, normalization or concatenation inside this primitive.
The digest is smaller than p; the output is a field encoding of a 512-bit digest,
not a claim of 521 bits of hash entropy.

Implementation:

- `crates/aura_intent_lineage_v1/src/storm_hash521_v1.rs`
- `packages/aura_sdk_v1_ts/src/stormHash521V1.ts`

[Storm derivations](AURA_DERIVATION_FUNCTIONS_V1.md) own their exact caller-provided
domains and payloads. Do not add internal hash framing or a second derivation path.
Field encodings and rejection rules remain under [field arithmetic](AURA_FIELD_ARITHMETIC_V1.md).

## Message and proof boundaries

The preserved message canonicalization helpers and historical `HASH_V1` framing
remain defined by their existing owner and fixtures. Their existence does not imply
an implemented generic `MESSAGE_ROOT -> Storm side_A/side_B` conversion. Active
Storm execution takes its explicit fixed-width sides and context.

The pipeline is owned by [AURA_CANONICAL_PIPELINE_V1](AURA_CANONICAL_PIPELINE_V1.md).
This primitive is not a replacement for proof-material hashing, FractalKey's
32-byte `proof_hash`, trace commitments, public-input commitments, BIP340 signature
hashing or UDOT derivation. Each has a separate purpose and owner. No optional
`EXPORT_HASH` or alternate proof identifier enters canonical authorization or anchoring.

Earlier descriptions of a double-hash expansion, implicit Storm binding from a
message root, and an already implemented succinct STARK pipeline are superseded
by the actual primitive and owning pipeline/proof contracts. This is documentation
alignment; it changes no cryptographic implementation or frozen output.

## Validation

The existing Storm hash tests and shared Storm execution parity vector pin the
primitive and its callers. The existing hash/message-root hardening gate additionally
protects historical message framing and text canonicalization. Both sets of bytes
remain preserved; passing one does not authorize replacing the other.
