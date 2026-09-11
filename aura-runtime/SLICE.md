# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
State: IN PROGRESS — SLICE 9 / M3 ONLY
Last updated: 2026-09-10

## Outer mission

Implement bounded local Storm mining (M3) using existing proof/material owners,
measure its cost and test nonce/proof reuse. M2 remains complete and frozen.
The section 8 clarification below is explicitly APPROVED; implementation resumed
with all frozen job/context bindings unchanged.
Do not begin M4 coordination, rewards, Bitcoin payout or consensus work.

## M3 section 8 clarification — APPROVED

Slice 9 section 8 requests that "target does not influence Storm execution itself."
Frozen M2 includes target in J; `SHA256(J)` enters I, which enters the Storm context
and forcing. Thus changing a signed job's target changes its prescribed computation.
Removing that dependency would change approved semantics and frozen M2 vectors.

A bounded read-only probe used the frozen M2 job/M/nonce at N=64 and changed only
target byte 31 with XOR 1 (target suffix `ff` to `fe`). Existing TS owners produced:

| Observation | Original target | Changed target |
| --- | --- | --- |
| Intent | `5994eae5caeffc538a06181638cb7e34482a88e4c5688499ca7d6b8d675486de` | `b84e3de4cbac449ca5e9db8545c6870b0f3f5501f092b119072eb7ca0d8ad79d` |
| TRACE_ROOT | `ee6c8a09cfae529d4e85e6d3b0553fdad69c4ad8fcd3690ef93ba6ff31db049d` | `4d5d90e331490b48cf6616bb7c15237d3cbc1bbb652edd0ddfab22bae42dfc54` |

The first forcing value also changed. This compares prescribed computations; the
modified job was not submitted as signed/authorized work. No production code,
canonical document or frozen fixture was changed, and no M3 implementation or
benchmark has been completed.

The user explicitly approved this clarification: preserve all frozen bindings. Test that applying a
comparison threshold to an already completed proof does not alter that proof or
execution; evaluate multiple diagnostic thresholds over the same fixed-job sample.
Only the signed job's own target establishes qualification. A differently signed
target defines a different job/computation. Diagnostic thresholds never replace
the signed job target for local qualification. This resolves USER_DECISION without
changing M2 or the miner protocol.

## Frozen baseline and retained evidence

- Frozen Bitcoin baseline: `f64fb4f`, completed economic integration. Slice 7 already
  contained the Rust/TS miner codec/profile implementations; M2 closure verified
  those implementations and required no production code changes.
- Prior completion record: `reports/AURA_BITCOIN_ECONOMIC_MILESTONE_COMPLETION_V1.md`.
- Existing W, burn, Storm/trace/proof/material/FractalKey, Authorization V2,
  Head V2, UDOT and Bitcoin OP_RETURN semantics remain unchanged.
- No re-audit or rerun of the completed migration gate. The miner dependencies
  were inspected narrowly. New M2 test fixtures/evidence do not replace old fixtures.
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
| M2 | DONE | M1 | Exact Rust/TS job/profile bytes, negative parity and target cases frozen; SDK and regression checks passed. |
| M3 | IN PROGRESS | M2 | Approved section 8 clarification; bounded local execution, verification and measurements only. |
| M4 | BLOCKED | M2 | Future atomic round scheduling/winner/reward records in the existing coordinator. |
| M5 | BLOCKED | M4 | Future reward-aware Bitcoin publication and recovery. |
| M6 | BLOCKED | M3, M5 | Future adversarial full integration and frozen-output regression. |
| M7 | BLOCKED | M6 | Future owner promotion and measured activation limits; monetary deployment separately approved. |

M3 is the sole active node. M4 is held for a later slice in this execution
plan even though its technical M2 dependency is complete. The approved dependency
graph is unchanged. No miner design promotion or monetary activation is implied.

## Retained M2 closure evidence

- [M2 frozen vectors and reproduction commands](../fixtures/miner_v1/README.md):
  471-byte J, job/signing/intent commitments, detached signature, route, context,
  exact M/W; all 471 job-byte and 64 signature-byte mutations, every W byte,
  strict framing, six valid variants, eleven malformed patches, eight target cases,
  trusted policy/limits, stale-head, payer/intent/nonce/route and claim-profile tests.
- `cargo test -p aura_sdk_v1 --offline --test miner_v1`: 9 passed.
- `node --test packages/aura_sdk_v1_ts/src/minerV1.test.ts`: 10 passed.
- `cargo check -p aura_sdk_v1 --offline --lib`: passed. Native TypeScript syntax and
  package-root module compilation/import checks passed; no separate TS build is configured.
- Existing `economic_contract_v1` / `authorization_v2`: 13 Rust tests passed.
  Existing `economicV1.test.ts` / `stormClaimV1.test.ts`: 7 TS tests passed.
- `cargo build -p aura_sdk_v1 --offline --bin aura-authorizer`: passed.
- `node reports/miner_protocol_v1/design_probe.mjs`: passed; output matched the
  existing `reports/miner_protocol_v1/design_probe.json` byte-for-byte.
- Probe verifies deterministic N=64 execution, all forcing pairs changing with a
  nonce, exact existing W round-trip, M/job binding, target endpoints and the
  zero-step trace-reuse counterexample using existing owners.
- Concrete attack evidence: 34 cheap outer-nonce rebindings of one frozen proof
  found a low hash. TS signature/material checks accept it; the full Rust authorizer
  rejects `proof context and authorization lineage mismatch` and emits no anchor.
- This does not prove sequential hardness, non-amortization, commercial utility,
  production difficulty or miner consensus. M2 codec/profile parity is frozen;
  runtime candidate/proof parity and measurements remain M3 work.
- No production implementation, old frozen vector, authoritative document or Bitcoin
  wire was modified in M2 closure. Changes are focused tests, new fixture evidence,
  SDK implementation metadata, design status and this register.

## Retained design completion audit (M0/M1)

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
| 13. Implementation DAG | Section 12 gives eight dependency-ordered slices; M2 is now DONE and M3 is next. |
| 14. Unresolved approval decisions | Section 13 records explicit user approval of D1–D6; none remain within the approved V1 scope. |

The internal security review and bounded probe support design completion, not a
hardness theorem, independent audit or runtime miner certification. Deployment
calibration, runtime candidate/proof parity, adversarial integration and monetary activation
remain explicit implementation gates. The completed Bitcoin baseline is untouched.

## Stop condition

M2 is DONE. Complete M3's bounded search, actual PoC, security experiments,
measurements and targeted regressions, then mark M3 DONE / M4 READY and stop.
M4–M7 remain unimplemented. No migration re-audit or change to frozen M2 is needed.
