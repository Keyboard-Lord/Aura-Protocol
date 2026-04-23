<!-- DOC_STATUS_HEADER_START -->
> Status: RESEARCH / SUPPORTING
> Concept: AURA PATCH NOTES
> Scope Boundary: Supporting third-party patch-note material only. It documents vendored dependency context and does not define Aura protocol authority.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as supporting context only. Candidate, future, audit, or comparison language in the body is non-authoritative unless promoted elsewhere.
> Implementation State: Supporting, research, audit, planning, or non-authoritative.
<!-- DOC_STATUS_HEADER_END -->

This vendored `solana-client v1.18.26` copy is pinned by the root `[patch.crates-io]`
section in `/Users/mcrae/Desktop/AURA/Cargo.toml`.

Aura-local patch set:

- `src/send_and_confirm_transactions_in_parallel.rs`
  - changed `collect::<Result<_>>()?` to `collect::<Result<()>>()?`
  - reason: remove the Rust 2024 never-type fallback future-incompat warning from the canonical verifier path without changing the frozen Solana dependency line
