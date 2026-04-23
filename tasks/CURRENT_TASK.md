<!-- DOC_STATUS_HEADER_START -->
> Status: RESEARCH / SUPPORTING
> Concept: Current Task
> Scope Boundary: Supporting task-tracking material only. It records local work state and does not define repository or protocol authority.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as supporting context only. Candidate, future, audit, or comparison language in the body is non-authoritative unless promoted elsewhere.
> Implementation State: Supporting, research, audit, planning, or non-authoritative.
<!-- DOC_STATUS_HEADER_END -->

# Current Task

## Title
Realign the Repository to Aura Core Stack v1

## Phase
Architecture realignment and consistency pass

## Objective
Re-establish Aura as a four-layer system rooted in the DCM core, correct the repository doctrine and public-facing docs first, then align repo surfaces and metadata to that doctrine without mutating frozen Aura v1 semantics.

## Architect Context
Aura's root identity begins at Layer 1 with the DCM core. Proof material / authorization lineage is Layer 2. The ZK / STARK proving layer is Layer 3. Stateful execution, Merkle state, and Solana settlement are Layer 4. The existing Aura v1 baseline remains frozen and valid as an implemented vertical slice, but it is not the whole architectural identity of Aura.

## Allowed Changes
- create or update doctrine and placeholder-spec docs for Layers 1 through 4
- update README and architecture-facing docs
- update subordinate Layer 4 L2/stateful docs so they no longer claim Aura as merely an L2
- update historical or compatibility docs so they no longer act as conflicting architecture authorities
- update non-breaking crate/package metadata, README text, and module-level docs for alignment
- update `reports/LAST_RUN.md`
- update `tasks/CURRENT_TASK.md`

## Forbidden Changes
- no fabrication of a fully implemented DCM system
- no fabrication of a full STARK prover or verifier
- no silent mutation of frozen Aura v1 semantics
- no breaking schema or API changes under the frozen v1 baseline
- no unsupported security guarantees

## Required Inputs
- `docs/AURA_CORE_STACK_V1.md`
- `docs/FOUNDATION_BASELINE_V1.md`
- `docs/AURA_L2_FOUNDATION_SCOPE_V1.md`
- `docs/AURA_L2_SEQUENCER_DATA_MODEL_V1.md`
- `docs/AURA_L2_STATE_TRANSITION_RULES_V1.md`
- `docs/AURA_L2_AUTHORIZATION_RULES_V1.md`

## Required Deliverables
- authoritative four-layer stack doctrine
- Layer 1, Layer 2, and Layer 3 placeholder/spec docs
- updated top-level README
- aligned Layer 4 docs and repo-facing metadata

## Acceptance Criteria
- the repository clearly presents Aura as a four-layer system
- DCM is restored as Layer 1 and Aura's foundational identity
- proof / authorization lineage is clearly Layer 2
- ZK / STARK proving is clearly Layer 3
- stateful infrastructure / Merkle state / Solana settlement is clearly Layer 4
- frozen Aura v1 semantics remain intact
- unimplemented lower layers are called out explicitly rather than implied

## Validation Requirements
- docs consistency review
- root Rust test pass
- standalone crate Rust test pass
- TypeScript package test pass

## Output Discipline
- update `reports/LAST_RUN.md`
- keep the pass docs-first and consistency-first
- prefer explicit non-goals over speculative protocol claims
