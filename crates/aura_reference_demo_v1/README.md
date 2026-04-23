<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: Aura Reference Demo v1
> Scope Boundary: Current contract for the implemented package surface named by this document only. It does not redefine repository-wide protocol meaning outside that package.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# Aura Reference Demo v1

Classification: `IMPLEMENTATION`

This crate is a deterministic Rust reference demo for the frozen Aura v1 flow.

It demonstrates:

- off-chain `ProofMaterialV1` preparation
- off-chain `FractalKeyV1` preparation
- `proof_hash` derivation
- canonical `submit_proof` instruction assembly
- canonical signed transaction assembly

It belongs to the frozen Aura v1 baseline and does not participate in the active implemented canonical pipeline.
