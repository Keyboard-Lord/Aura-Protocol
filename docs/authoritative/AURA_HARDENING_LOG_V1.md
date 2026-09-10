# AURA_HARDENING_LOG_V1

**Classification:** `VALIDATION`  
**Purpose:** Record the enforced locks that remain active  
**Status:** `ACTIVE`

> **VALIDATION — ACTIVE SECURITY LOCKS**
> This document records required protocol locks and verified hardening changes.
> A required lock is not evidence that every implementation surface enforces it.
> Derived from: AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md (root authority)

## Locks

- `LOCK-01`: Preserve the purpose-specific hash owners and frozen message/field encodings. H_521 does not replace SHA256 proof/material/signature/head bindings.
- `LOCK-02`: Text normalization is NFC + LF with BOM rejection only.
- `LOCK-03`: `STORM_V1_1` uses fixed side lengths, fixed context length, and the fixed execution-domain bytes.
- `LOCK-04`: `TRACE_ROOT` uses ordered SHA3-256 Merkle reduction with duplicate-last odd-level handling.
- `LOCK-05`: Storm proof binding uses side hashes, context hash, boundary states, and `TRACE_ROOT`.
- `LOCK-06`: The canonical proof wire carries one fixed V1 claim and witness encoding. Its historical trailing commitment slots retain their existing bytes; no alternate claim or compatibility alias is added.
- `LOCK-07`: The canonical final object carries only `proof_hash_hex` as its upstream proof reference.
- `LOCK-08`: Canonical UDOT is v2-only, derived directly from `proof_hash_hex`, and carries no `aura_hash_hex` alias or canonical `matrix_form`.
- `LOCK-09`: Every admitted terminal economic outcome retains its full authenticated burn. Pre-admission failures do not charge; idempotent retry never burns again.
- `LOCK-10`: Head V2 construction derives linkage from durable prior state. Stale metered linkage is rejected before charging; callers cannot construct an independent successor.
- `LOCK-11`: Economic debit/attempt ownership and terminal authorization/head/outbox updates are atomic. Reorgs change Bitcoin confirmation, never economic or authorization reservations.

## Verified implementation hardening

- Storm TypeScript execution rejects non-`bigint` iteration counts before replay,
  and step encoding rejects non-`bigint` indices. Both retain their existing u64
  range. Previously, JavaScript coercion could accept `NaN`, fractional numbers,
  or numeric strings, including through claim/public-input validation. Regression
  coverage lives in `packages/aura_sdk_v1_ts/src/stormExecutionV1.test.ts` and
  `src/stormClaimV1.test.ts`, included in the Storm hardening script. Existing
  Rust/TypeScript Storm parity vectors remain unchanged and pass.
