# AURA_MINER_PROTOCOL_V1

**Classification: APPROVED DESIGN DECISION / NOT ACTIVE PROTOCOL AUTHORITY.**
**Status: DESIGN AND IMPLEMENTATION COMPLETE — D1–D6 APPROVED; M0–M7 DONE.**
Baseline: completed Bitcoin migration at `f64fb4f`, including its economic integration.
Design approval: 2026-09-10. Implementation status updated: 2026-09-11.
The Rust/TS job/profile boundary, Rust local mining, durable coordination and
sponsor-funded Bitcoin publication are implemented and adversarially regtest-validated.
Frozen cryptographic outputs are unchanged. M7 incorporates the approved miner
definitions into their existing authoritative owner. The review below is internal, not an
independent cryptographic audit or proof of economic security.

## 1. Approved architecture and decision boundary

Build V1 as **coordinated, sponsor-funded Storm computation mining** over the existing
economic journal. Miners compete to find a fully verified, nonce-bound Storm proof
whose existing `proof_hash`, interpreted as an unsigned big-endian integer, meets
the signed job target. One journal selects one admitted contender per round; only
an Accepted contender is a winner. Bitcoin publishes the same proof reference.

This provides a concrete PoC/PoW eligibility rule, not permissionless consensus.
The journal operator remains trusted for job release, ordering, availability and
reward custody. The frozen baseline neither rolls back admitted burns nor selects
among independently maintained economic forks. Introducing cumulative-work fork
choice would require a separately approved replicated state/authorization model.

V1's useful task is narrowly **customer-requested nonce-conditioned Storm trajectory
generation**, for consumers that want those trajectories themselves. It is not a
claim that Storm proves arbitrary application work, that all losing trials are
useful, or that a commercial customer exists. A fixed-answer external job cannot
simultaneously remain unchanged and have its entire Storm trace varied by every
mining nonce. Splitting off cheap nonce hashing would establish hash work instead
of the intended Storm work. That alternative is not this proposal.

On 2026-09-10 the user replied **“yes approved”** to the explicit request to approve
decisions D1–D6 as the V1 design contract. Section 13 records that approval. These
requirements define the approved implementation design and do not supersede the
active protocol owners. M2–M5 are implemented and M6 acceptance has passed; section
11 links their evidence and M7 owner/operational reconciliation.

## 2. Current-state dependency map

| Existing owner | Miner dependency / implication |
| --- | --- |
| [Storm execution](../crates/aura_intent_lineage_v1/src/storm_execution_v1.rs), [derivations](../docs/authoritative/AURA_DERIVATION_FUNCTIONS_V1.md) | Sides determine initial state; the complete context determines parameters and every step's forcing. Nonce changes can affect computation without changing recurrence. |
| [Proof boundary](../docs/authoritative/AURA_STARK_SPEC_V1.md), [binding](../docs/authoritative/AURA_PROVER_BINDING_V1.md) | Canonical claim plus full witness; Rust verifies by replay. No succinctness, ZK, runtime measurement or proof of exclusive miner execution. |
| [Artifact owner](../docs/authoritative/AURA_ARTIFACT_STRUCTURE_V1.md) | Exactly one material → FractalKey → `proof_hash` path. Outer subject/nonce must match the verified context. |
| [Economic W](../crates/aura_sdk_v1/src/economic.rs), [meter](../crates/aura_l2_local_chain_v0/src/economic_meter.rs) | W carries exact M plus the Storm tuple. Burn uses M, not iteration count or Bitcoin fees. Existing full-verification tariff remains fixed. |
| [Journal](../crates/aura_sdk_v1/src/economic/journal.rs), [ledger rules](../docs/authoritative/AURA_LEDGER_AND_BURN_V1.md) | One admitted attempt per ledger/head; debit before service execution; every terminal outcome retains its burn and advances the head. No Aura reward-credit operation exists here. |
| [Authorization](../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md) | Miner is controller/payer/subject; both existing signatures required. Successful reservation follows actual proof/material/lineage verification. |
| [Head V2](../docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md) | Commits exact W, predecessor, outcome and debit snapshots. It is a durable linear economic history, not a PoW chain-selection mechanism. |
| [Bitcoin publication](../docs/authoritative/AURA_REPORT_CONTRACT_V1.md) | OP_RETURN contains only the existing proof reference. Reorgs revoke confirmation, not economic or authorization history. |
| [Archived Aurafarming research](../docs/research_assets/AURA_AURAFARMING_NODES_RESEARCH_V0_2.md), [hierarchy experiment](AURA_STORM_HIERARCHY_V2_EXPERIMENT.md) | Research only. Twenty-node topology, EMA forgetting and proof-convergence claims do not establish consensus, proof soundness or rewards. Hierarchical V2 does not feed macro state back into micro execution and is not needed here. |

The production path remains W → admission/debit → Storm → TRACE_ROOT → proof →
material → proof_hash → Authorization V2 → Head V2/outbox → Bitcoin. Private miner
evaluation uses these same computational primitives; it cannot settle, reserve
authorization or create an alternate production path.

## 3–10. Promoted contract

The approved definitions were incorporated into the existing
[Aurafarming / Miner V1 owner](../docs/authoritative/AURA_AURAFARMING_NODES.md)
during M7. This decision record retains rationale, approval history and evidence;
it no longer repeats the canonical job/profile or lifecycle definitions.

| Definition | Single owning section |
| --- | --- |
| Exact J, signature, intent and context profile | [Mining inputs](../docs/authoritative/AURA_AURAFARMING_NODES.md#2-exact-approved-mining-inputs) |
| PoC, PoW, eligibility and winner predicates | [Predicates](../docs/authoritative/AURA_AURAFARMING_NODES.md#3-exact-poc-and-pow-predicates) |
| Useful task, scarcity and limits | [Usefulness](../docs/authoritative/AURA_AURAFARMING_NODES.md#4-usefulness-and-computational-scarcity) |
| Explicit consecutive policy epochs | [Difficulty policy](../docs/authoritative/AURA_AURAFARMING_NODES.md#5-difficulty-and-adjustment-model) |
| Round lifecycle and head competition | [Lifecycle](../docs/authoritative/AURA_AURAFARMING_NODES.md#6-lifecycle-accounting-and-head-competition) |
| Sponsor reward and combined publication | [Reward policy](../docs/authoritative/AURA_AURAFARMING_NODES.md#7-reward-model-and-bitcoin-interaction) |
| Existing commitment boundaries | [Commitments](../docs/authoritative/AURA_AURAFARMING_NODES.md#8-what-is-committed-and-what-is-not) |
| Threat assumptions | [Threat review](../docs/authoritative/AURA_AURAFARMING_NODES.md#9-threat-review) |

## 11. Design evidence and limits

Reproduce the bounded probe:

```sh
cargo build -p aura_sdk_v1 --offline --bin aura-authorizer
node reports/miner_protocol_v1/design_probe.mjs
```

[Captured output](miner_protocol_v1/design_probe.json) records N=64 nonce changes
affecting both parameters, all 64 forcing pairs and TRACE_ROOT; exact W round-trip;
M/job commitment sensitivity; the N=0 trace-reuse counterexample; target endpoint
checks; and a concrete cheap outer-nonce rebinding that passes TS signature/material
checks but is rejected by the full existing Rust authorizer. It reproduces the
existing frozen authorization proof_hash before attempting that attack.

The probe is executable design evidence, not full miner security validation or a
production winner state machine. It remains unchanged and reproduced byte-identical
output during M2 closure. Atomic integration/reward tests are now covered by
M4–M6 evidence below; deployment calibration is not established by that probe.

M2 is implemented in [Rust](../crates/aura_sdk_v1/src/miner.rs) and
[TypeScript](../packages/aura_sdk_v1_ts/src/minerV1.ts). The
[shared frozen codec/profile evidence](../fixtures/miner_v1/README.md) pins J,
decoding, commitments, signature digest/signature, I, route, context, W and target
comparison using exact bytes. Focused tests cover every job/signature/work byte,
malformed inputs, trusted policy, limits, stale heads and profile bindings. Nine
Rust and ten TypeScript miner tests pass, together with targeted SDK checks and
existing authorization/economic/claim regressions. Profile and low-hash filters
remain distinct from actual PoC verification and durable authorization acceptance.

M3 is implemented in [Rust local search](../crates/aura_sdk_v1/src/miner_search.rs).
[M3 evidence](AURA_MINER_M3_EVIDENCE.md) records actual proof verification and
material/FractalKey binding, deterministic search/limits, existing-object vectors,
nonce/reuse experiments and measured N scaling. It also records the user's explicit
section 8 clarification: target remains bound through J/I/context; multiple
diagnostic thresholds compare the same completed hashes only. M3 has no admission,
winner, reward, head or Bitcoin publication effects. No new proof wire was introduced.

M4 composes durable round ownership and reward obligations into the existing
economic journal. [M4 evidence](AURA_MINER_M4_EVIDENCE.md) records server re-verification,
atomic debit/finalization, funded opening, guarded wallet-lock release, race/retry/
crash recovery and unchanged baseline regressions.

M5 adds persisted payment versions, combined reward/anchor publication and fresh
chain observations to the same journal. [M5 evidence](AURA_MINER_M5_EVIDENCE.md)
records Core-backed funding preflight, exact reward/input/anchor checks, explicit
fee replacement, process/Core restart, broadcast-crash and regtest reorg recovery.
No canonical Aura wire changed; no monetary activation is implied.

M6's [adversarial evidence](AURA_MINER_M6_EVIDENCE.md) and
[reproducible acceptance gate](../scripts/verify_miner_program_v1.mjs) cover actual
proof/rebinding attacks, concurrent contenders/retries, economic and publication
crashes, corrupt storage, replacement and reorg. All 11 stages passed, including
frozen Rust/TS regressions and 17 explicit Core attack cases. Missing payment
history and inconsistent observations now fail the owning journal's audit.
A complete internally consistent journal rollback remains undetectable from that
journal alone; M7 documents backup provenance and publication reconciliation.

[M7 readiness](AURA_MINER_M7_READINESS.md) records owner promotion, the operations
guide, two narrow approved-contract corrections and the final 11-stage acceptance
run. Production monetary activation remains separately gated.

## 12. Frozen components and minimal implementation DAG

No modification required to HASH_V2, field arithmetic, Storm initialization/
recurrence, trace encoding/Merkle reduction, claim/proof bytes, material hashing,
FractalKey, proof_hash, Authorization V2 envelope/signing, economic consent/W/M
encodings, burn constants/supply invariant, Head V2 formula/genesis, UDOT or Bitcoin
OP_RETURN. No hierarchical/macro Storm change is required.

The job/profile codec (M2), local search (M3), and transactionally composed
round/winner/reward records (M4), and reward publication (M5) are complete. Core
retains transaction encoding/signing and the same journal owns payment history.
No alternate settlement API was introduced. Adversarial acceptance, existing-owner
reconciliation and operational documentation are complete through M7.

| Slice | Dependencies | Bounded work and stop criterion |
| --- | --- | --- |
| M0 — design evidence | Baseline | This proposal and probe; frozen dependency map established. DONE. |
| M1 — semantic approval | M0 | User explicitly approved D1–D6 on 2026-09-10. DONE. |
| M2 — job/profile parity | M1 | DONE. Rust/TS job codec/signature, context binding and strict limits; shared frozen bytes, every-byte mutations, target endianness/endpoints, zero-N/slot/VK/route rejection. |
| M3 — miner computation | M2 | DONE. Existing Storm/proof/material owners; secure and deterministic research nonce modes, bounded search/cancellation/expiry, full local PoC and exact target predicate. Frozen existing-object vector, reuse/security tests and N=8–128 measurements. |
| M4 — coordinator composition | M3 (master-goal execution order) | DONE. Same SQLite admission/finalization owner plus policy/job/snapshot/funding/round/reward records. All four outcomes, race/retry, expiry, process-exit recovery and injected rollback tests passed. Original non-mining regressions unchanged. |
| M5 — reward publication | M4 | DONE. Core fee/dust/funding preflight; exact payout + unchanged anchor; persisted transactions and conflicting fee replacements. Regtest preparation/Core restart, broadcast-crash recovery, fee rejection and reorg passed without another entitlement or burn. |
| M6 — adversarial integration | M3, M5 | DONE. Full gate passed: real candidate/debit/proof/winner/head/outbox/payout/anchor, mutation/rebinding attacks, races/retries, seven economic crash boundaries, corrupt storage and 17 Core attack cases. Frozen outputs unchanged; consistent whole-journal rollback limitation explicit. |
| M7 — authority and activation | M6 | DONE. Approved definitions promoted into the existing owner; old Aurafarming research archived; measured limits, funding, backup provenance, monitoring/recovery and deployment boundaries documented. Epoch/challenge reconciliation and final gate passed. Monetary deployment remains separately authorized. |

M0–M7 are DONE. No next node remains in this program. Implementation and operational
documentation readiness do not authorize live monetary activation.

The existing Aurafarming document owns miner job/competition semantics; pipeline,
ledger/head/report owners cross-reference it for their integration obligations.
No parallel authoritative spec or duplicate frozen formula was introduced.

## 13. Approved decisions and remaining conditions

All six decisions below are **APPROVED** by the user's 2026-09-10 response. The
alternatives remain unselected; they are not optional modes within this contract.

| ID | Approved V1 decision | Unselected alternative and consequence |
| --- | --- | --- |
| D1 | Coordinated sponsored mining, one journal and first admitted contender; lock ordinary admissions during bounded open rounds; admitted failures close the round without rollback. | Permissionless cumulative-work consensus requires a new replicated economic state, fork/rollback and authorization-history contract. It cannot be slipped above frozen Head V2. |
| D2 | Customer-requested nonce-conditioned Storm trajectories; exact J/I/context profile in the linked owner; existing proof_hash is the sole difficulty value. | Fixed-answer application computation requires another verified task relation or separate hash work. Do not claim the present Storm trace proves it. |
| D3 | Epoch-fixed N/T and bounds, explicit operator adjustment between epochs, no automatic retarget. | Automatic adjustment needs agreed timing/history and manipulation rules. No arbitrary release parameters or security claims are approved by the probe's example. |
| D4 | Private losing trials pay compute cost only; pre-admission rejects pay no Aura burn; every admitted outcome retains the unchanged burn; only Accepted wins. | Charging every private trial is unenforceable without metered admission per trial, which would serialize search and advance heads on losers. A subsidy/fee change needs a new economic decision. |
| D5 | Positive pre-funded sponsor BTC rewards, custodial dedicated outpoint, exact miner-key payout alongside unchanged OP_RETURN; no Aura issuance or burn recycling. | Aura-denominated issuance/transfers require new reward/ledger conservation rules. Trustless Bitcoin escrow needs a separate reviewed construction. |
| D6 | Add atomic miner scheduling/winner/reward metadata and route enforcement to the existing coordinator; preserve formats; implement/test on regtest before separately approving monetary activation. | A standalone miner settlement endpoint would create a competing canonical path and is rejected. |

Approval of D1–D6 establishes the bounded implementation design, not proof of Storm
hardness, customer utility, fair ordering or funded mainnet readiness. M2 enforces
the job/profile boundary, M3 performs local verified mining, M4 adds durable
coordination, M5 publishes sponsor-funded rewards with the existing anchor, and M6
validates the combined path against the recorded adversarial cases.
There are no unresolved semantic
decisions within the approved coordinated V1 scope. Numerical deployment policy
must be measured and explicitly configured under D3; monetary activation remains
separately gated by D6. A change to these approved semantics requires a new decision.

The design-only goal is complete: dependencies, exact predicates, lifecycle,
economics, head/Bitcoin boundaries, threat review and implementation DAG are ready.
M2–M7 implementation validation and operational documentation are complete;
live monetary activation still requires separate approval.
