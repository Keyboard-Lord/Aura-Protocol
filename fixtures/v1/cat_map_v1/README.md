<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: Cat Map V1 Fixtures
> Scope Boundary: Current contract for the fixture directory and replay/parity expectations named by this document only. It does not widen protocol authority beyond those fixtures.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# Cat Map V1 Fixtures

Classification: `DEPRECATED`

These fixtures pin a superseded lower-layer cat-map runtime.

This fixture surface is deprecated and does not modify:

- canonical request/report pipeline
- cat-map transition
- AIR/prover boundaries
- settlement, burn, attestation, wallet binding, or UDOT authority

They are intended for:

- Rust lower-layer tests in `crates/aura_intent_lineage_v1/tests`
- TypeScript parity tests that consume the same fixture bundle

They are not active canonical pipeline authority and not frozen Aura v1 baseline authority.
