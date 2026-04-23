# AURA_HASH_V1

**Classification:** `FROZEN LEGACY`  
**Layer:** `L0`  
**Purpose:** Define V1 canonical message bytes and MESSAGE_ROOT (historical)  
**Status:** `FROZEN`

> **FROZEN LEGACY — NON-AUTHORITATIVE FOR ACTIVE PROTOCOL**
> This document defines the V1 identity surface based on SHA-256.
> The active protocol uses AURA_HASH_V2 (521-bit SHA3-512-based identity).
> This document is retained for historical reference and V1 compatibility only.
> Do not use for new implementations.

## Historical Classification
- Original: AUTHORITATIVE (V1 protocol)
- Current: FROZEN LEGACY
- Superseded by: AURA_HASH_V2.md

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/aura_hash_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/auraHashV1.ts`

## Identity Rule

`HASH_V1` is the sole canonical identity function.

`MESSAGE_ROOT = HASH_V1(message_bytes)`

No lower layer may add framing, alternate prefixes, alternate hashes, or alternate normalization.

## Raw Byte Rule

`canonical_message_bytes_v1 = u64_le(len(message_bytes)) || message_bytes`

`HASH_V1(message_bytes) = SHA-256("AURA_HASH_V1" || canonical_message_bytes_v1)`

The length prefix is exact:

- unsigned `u64`
- little-endian
- always present

## Text Rule

Text mode is optional.

Text mode is exact:

1. decode UTF-8
2. normalize to NFC
3. replace `\r\n` with `\n`
4. replace `\r` with `\n`
5. reject `U+FEFF`
6. encode UTF-8
7. pass the resulting bytes into `HASH_V1`

Whitespace is preserved.

Trimming is invalid.

## Rejection

Reject only:

- message length outside `u64`
- invalid UTF-8 in text mode
- `U+FEFF` in text mode

## Locked Validation

- `fixtures/v1/aura_hash_v1/canonical_message_hash_v1.json`
- `crates/aura_intent_lineage_v1/tests/aura_hash_v1.rs`
- `crates/aura_intent_lineage_v1/tests/aura_text_canonicalization_profile_v1.rs`
- `packages/aura_sdk_v1_ts/tests/aura_hash_v1.test.ts`
- `packages/aura_sdk_v1_ts/tests/aura_text_canonicalization_profile_v1.test.ts`
