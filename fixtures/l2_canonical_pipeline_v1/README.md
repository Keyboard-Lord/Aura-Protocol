<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: Aura Canonical Pipeline V1 Fixtures
> Scope Boundary: Current contract for the fixture directory and replay/parity expectations named by this document only. It does not widen protocol authority beyond those fixtures.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# Aura Canonical Pipeline V1 Fixtures

Classification: `DEPRECATED`

This directory is a deprecated request/report fixture surface from the previous authority model.

Root authority for this layer is:

- `bash scripts/verify_active_foundation.sh`
- `bash scripts/run_canonical_pipeline_v1.sh`

The one underlying implemented request/report executor is:

- `cargo run -p aura_l2_local_chain_v0 -- --output json run-canonical-pipeline <request.json>`

That is the only active request -> pipeline -> report path.

Included here:

- accepted execution request/report pins
- accepted attestation request/report pins
- fail-closed rejection fixtures on the same path
- ledger replay fixtures on the same path
- mixed execution/attestation replay fixtures on the same path
- `continuous_chain_v1/` long-chain authoritative-persistence fixtures on the same path

Not canonical authority:

- `fixtures/l2_local_v1`
- `fixtures/l2_proof_vectors_v1`

Those remain compatibility or reproducibility surfaces only.
