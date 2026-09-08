# AURA_HARDENING_LOG_V1

**Classification:** `VALIDATION`  
**Purpose:** Record the enforced locks that remain active  
**Status:** `ACTIVE`

> **VALIDATION — ACTIVE SECURITY LOCKS**
> This document records required protocol locks and verified hardening changes.
> A required lock is not evidence that every implementation surface enforces it.
> Derived from: AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md (root authority)

## Locks

- `LOCK-01`: `HASH_V2` is the sole active canonical identity function (521-bit SHA3-512-based). `HASH_V1` is FROZEN LEGACY.
- `LOCK-02`: Text normalization is NFC + LF with BOM rejection only.
- `LOCK-03`: `STORM_V1_1` uses fixed side lengths, fixed context length, and the fixed execution-domain bytes.
- `LOCK-04`: `TRACE_ROOT` uses ordered SHA3-256 Merkle reduction with duplicate-last odd-level handling.
- `LOCK-05`: Storm proof binding uses side hashes, context hash, boundary states, and `TRACE_ROOT`.
- `LOCK-06`: The canonical proof wire carries exactly one claim representation and no legacy compatibility fields.
- `LOCK-07`: The canonical final object carries only `proof_hash_hex` as its upstream proof reference.
- `LOCK-08`: Canonical UDOT is v2-only, derived directly from `proof_hash_hex`, and carries no `aura_hash_hex` alias or canonical `matrix_form`.
- `LOCK-09`: Local settlement burns the full amount on every terminal outcome.
- `LOCK-10`: Continuous settlement head linkage is derived from the prior head, so previous-head and sequence mismatches are unrepresentable in canonical construction.

## Verified implementation hardening

- Storm TypeScript execution rejects non-`bigint` iteration counts before replay,
  and step encoding rejects non-`bigint` indices. Both retain their existing u64
  range. Previously, JavaScript coercion could accept `NaN`, fractional numbers,
  or numeric strings, including through claim/public-input validation. Regression
  coverage lives in `packages/aura_sdk_v1_ts/src/stormExecutionV1.test.ts` and
  `src/stormClaimV1.test.ts`, included in the Storm hardening script. Existing
  Rust/TypeScript Storm parity vectors remain unchanged and pass.
