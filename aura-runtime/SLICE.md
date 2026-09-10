# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
State: COMPLETE — DESIGN ONLY
Last updated: 2026-09-10

## Outer mission

Design and validate AURA_MINER_PROTOCOL_V1 above the completed Bitcoin migration.
Deliver a coherent Storm PoC/PoW design, explicit security/economic boundaries,
approval of protocol-changing decisions and a bounded implementation DAG. Miner
network implementation is not required for this design goal.

## Frozen baseline and retained evidence

- Current baseline: `f64fb4f`, completed Bitcoin economic integration.
- Prior completion record: `reports/AURA_BITCOIN_ECONOMIC_MILESTONE_COMPLETION_V1.md`.
- Existing W, burn, Storm/trace/proof/material/FractalKey, Authorization V2,
  Head V2, UDOT and Bitcoin OP_RETURN semantics remain unchanged.
- No re-audit or rerun of the completed migration gate. The miner dependencies
  were inspected narrowly; all proposal/probe work is outside active protocol code.
- Root-local execution. No delegated workers or runtime/profile changes.

## Design owner and DAG

`reports/AURA_MINER_PROTOCOL_V1.md` records the approved design, its exact candidate
formulas, threat review, alternatives and D1–D6 decisions. The user replied
“yes approved” to the explicit D1–D6 design-contract question on 2026-09-10.
It is not active protocol authority; the existing authoritative owners remain frozen.

| ID | State | Dependency | Scope / stop criterion |
| --- | --- | --- | --- |
| M0 | DONE | Frozen baseline | Current owner map, coherent recommendation, bounded probe and internal threat review. |
| M1 | DONE | M0 | User approved D1–D6: coordinated rounds, workload/input profile, difficulty policy, accounting, rewards, atomic integration. |
| M2 | READY | M1 | Future job/profile Rust/TS codec and negative parity vectors. |
| M3 | BLOCKED | M2 | Future miner computation through existing owners, resource and attack measurements. |
| M4 | BLOCKED | M2 | Future atomic round scheduling/winner/reward records in the existing coordinator. |
| M5 | BLOCKED | M4 | Future reward-aware Bitcoin publication and recovery. |
| M6 | BLOCKED | M3, M5 | Future adversarial full integration and frozen-output regression. |
| M7 | BLOCKED | M6 | Future owner promotion and measured activation limits; monetary deployment separately approved. |

M2–M7 are the implementation DAG for a subsequent milestone. M2 is dependency-ready;
the design-only goal does not require implementing it. Approval establishes the
contract without changing active protocol behavior or authorizing monetary deployment.

## Current evidence

- `cargo build -p aura_sdk_v1 --offline --bin aura-authorizer`: passed.
- `node reports/miner_protocol_v1/design_probe.mjs`: passed; captured result in
  `reports/miner_protocol_v1/design_probe.json`.
- Probe verifies deterministic N=64 execution, all forcing pairs changing with a
  nonce, exact existing W round-trip, M/job binding, target endpoints and the
  zero-step trace-reuse counterexample using existing owners.
- Concrete attack evidence: 34 cheap outer-nonce rebindings of one frozen proof
  found a low hash. TS signature/material checks accept it; the full Rust authorizer
  rejects `proof context and authorization lineage mismatch` and emits no anchor.
- This does not prove sequential hardness, non-amortization, commercial utility,
  production difficulty, miner consensus, or parity for an unimplemented miner layer.
- No active implementation, old frozen vector, canonical document or Bitcoin wire
  was modified. Only proposal/evidence and this mission register were added/updated.

## Completion audit

The live design and captured executable evidence were checked against all requested
deliverables. Section references below are to the single design document; they do
not duplicate its definitions.

| Requested deliverable | Evidence / result |
| --- | --- |
| 1. Current-state dependency map | Section 2 maps the relevant frozen owners and their miner implications. |
| 2. AURA_MINER_PROTOCOL_V1 proposal | The named document now records the approved design and implementation boundary. |
| 3. Exact PoC definition | Section 4 requires full input-bound witness verification and existing material/FractalKey binding. |
| 4. Exact PoW predicate | Sections 3–4 fix all inputs and require big-endian proof_hash <= T after PoC. Probe covers target endpoints and cheap-rebinding rejection. |
| 5. Candidate lifecycle | Section 7 covers admission, every terminal outcome, retry, expiry and crash recovery. |
| 6. Difficulty / adjustment | Section 6 defines fixed per-epoch parameters and explicit operator epoch changes; no automatic retarget. |
| 7. Rewards / economics | Sections 7–8 preserve burn rules and select pre-funded sponsor BTC, eligibility and replay-safe payout. |
| 8. Head / fork choice | Sections 7 and 9 define one coordinated contender, no rollback, and explicit rejection of independent fork merging. |
| 9. Bitcoin interaction | Sections 8–9 retain OP_RETURN, specify payout/replacement/reorg behavior and distinguish on/off-chain commitments. |
| 10. Threat model | Section 10 reviews grinding, precomputation, bypass, nonce reuse, manipulation, withholding, duplicate work, state splits and reorgs with residual assumptions. |
| 11. Frozen components | Section 12 enumerates preserved primitives, encodings and state invariants. |
| 12. Minimal additions | Section 12 limits changes to miner profile/search, atomic metadata/guards and reward-aware transport. |
| 13. Implementation DAG | Section 12 gives eight dependency-ordered slices with concrete stop criteria; M2 is next. |
| 14. Unresolved approval decisions | Section 13 records explicit user approval of D1–D6; none remain within the approved V1 scope. |

The internal security review and bounded probe support design completion, not a
hardness theorem, independent audit or runtime miner certification. Deployment
calibration, full new-layer parity, adversarial integration and monetary activation
remain explicit implementation gates. The completed Bitcoin baseline is untouched.

## Stop condition

Design goal satisfied. Stop here; the next implementation slice is M2 under the
approved contract. No further design polishing or migration re-audit is required.
