<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: Continuous Canonical Chain V1 Fixtures
> Scope Boundary: Current contract for the fixture directory and replay/parity expectations named by this document only. It does not widen protocol authority beyond those fixtures.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# Continuous Canonical Chain V1 Fixtures

Classification: `DEPRECATED`

This corpus exercises a deprecated pipeline under a previous authority model.

Canonical use:

- run these fixtures in order with `--head-state <path>`
- authoritative head persistence advances on every report except `settlement_head_mismatch`
- settlement rejection or verification rejection still burns deterministically and still emits a canonical report
- only accepted execution commits a new state root; rejected settlement leaves the prior committed state in place

Non-authoritative use:

- running these fixtures stateless is allowed for support and diagnostics
- stateless results must not be mistaken for authoritative head truth

Sequence order:

1. `step01_execution_accept_request.json`
2. `step02_head_mismatch_reject_request.json`
3. `step03_execution_accept_request.json`
4. `step04_anchor_mismatch_reject_request.json`
5. `step05_attestation_accept_request.json`
6. `step06_disconnected_anchor_accept_request.json`
7. `step07_replay_reject_request.json`
8. `step08_stark_attestation_accept_request.json`
9. `step09_attestation_anchor_reject_request.json`
10. `step10_execution_accept_request.json`
11. `step11_tampered_stark_attestation_reject_request.json`
12. `step12_attestation_accept_request.json`
