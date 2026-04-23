# AURA_FIELD_ARITHMETIC_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L1`  
**Purpose:** Define canonical field encoding and arithmetic  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — FIELD ARITHMETIC**
> This document defines the canonical 521-bit field (N = 2^521 - 1) and its encoding.
> All field operations MUST use this modulus and 66-byte big-endian encoding.

Implementation:

- Rust: `crates/aura_intent_lineage_v1/src/field_521_v1.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/stormHash521V1.ts`

## Modulus

The field modulus is:

`p = 2^521 - 1`

## Encoding

A field element is exactly 66 bytes, big-endian.

Encoding is valid only when:

- the top 7 bits of byte `0` are zero
- the value is strictly less than `p`
- the byte string is canonical

## Operations

The canonical operations are:

- addition mod `p`
- subtraction mod `p`
- multiplication mod `p`
- squaring mod `p`
- reduction of arbitrary byte strings by repeated radix-256 folding

No alternate modulus is valid.

No alternate byte width is valid.

## Fail-Closed Enforcement

**MUST:** Any field operation producing an out-of-range value results in immediate fail-closed rejection.

Specific rejections:

- Value >= 2^521 - 1 → `FIELD_ENCODING_INVALID` → reject
- Non-canonical 66-byte encoding → `FIELD_ENCODING_INVALID` → reject
- Top 7 bits of byte 0 non-zero → `FIELD_ENCODING_INVALID` → reject
- Alternate modulus attempted → reject
- Non-66-byte width → reject

All operations MUST reduce modulo N = 2^521 - 1. No exceptions.
