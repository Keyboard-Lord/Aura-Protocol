# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: approved Aura Miner Protocol V1, master goal M3–M7
Current milestone: M6 IN PROGRESS
Last updated: 2026-09-11
Next node: M7 (BLOCKED until M6 closes)

## Mission and frozen baseline

Finish the miner program one dependency-ordered milestone at a time. Report and
stop at each node boundary. The master goal completes only after M7. No monetary
activation is authorized by implementation completion.

Completed Bitcoin migration/economic baseline: `f64fb4f`. Preserve existing HASH_V2,
field arithmetic, Storm initialization/recurrence, TRACE_ROOT, proof bytes,
ProofMaterial/FractalKey/proof_hash, Authorization V2, W/M, burn, Head V2, UDOT,
Bitcoin OP_RETURN and frozen M2 codecs/vectors. No migration re-audit without a
concrete dependency defect. Root-local execution; no runtime/profile changes.

Design owner: [AURA_MINER_PROTOCOL_V1](../reports/AURA_MINER_PROTOCOL_V1.md), approved
D1–D6, not yet active protocol authority. Prior Bitcoin completion evidence:
[completion record](../reports/AURA_BITCOIN_ECONOMIC_MILESTONE_COMPLETION_V1.md).

## DAG

| ID | State | Execution dependency | Scope / stop criterion |
| --- | --- | --- | --- |
| M0 | DONE | Bitcoin baseline | Approved design foundation and bounded threat probe. |
| M1 | DONE | M0 | D1–D6 explicitly approved. |
| M2 | DONE | M1 | Frozen 471-byte job/profile Rust/TS parity and negative coverage. |
| M3 | DONE | M2 | Bounded local verified mining, deterministic search, security experiments and measured N scaling. |
| M4 | DONE | M3 | One durable round owner composed into the existing economic coordinator; atomic contender/debit/authorization/head/winner/reward-obligation state and recovery tests. |
| M5 | DONE | M4 | Sponsor-funded reward plus unchanged Bitcoin anchor; regtest publication/replacement/reorg recovery. |
| M6 | IN PROGRESS | M5 | Reproducible adversarial full-system acceptance gate and frozen-output regressions. |
| M7 | BLOCKED | M6 | Existing-owner promotion, measured operational limits and activation readiness; live monetary deployment separately approved. |

This order follows the user's master goal. M4 composes round ownership into the existing economic transaction owner.

## Current evidence

[M5 implementation / Core evidence](../reports/AURA_MINER_M5_EVIDENCE.md).
[Captured regtest result](../reports/miner_protocol_v1/m5_regtest_results.json).
Prior: [M4](../reports/AURA_MINER_M4_EVIDENCE.md), [M3 measurements](../reports/AURA_MINER_M3_EVIDENCE.md).

- Existing journal owns signed payment history and fresh observations. Every
  version spends the reserved outpoint and preserves the exact reward and anchor.
- Core preflight rejects dust, insufficient funding and excessive fee before open.
  Signed payment persists before send; fee replacement is explicit and conflicting.
- Core 29 regtest passed: local mining/admission, exact combined payout, process/Core
  restart, lock restoration, broadcast-crash recovery, replacement, confirmation,
  reorg/reconfirmation and retry without another burn/winner/obligation.
- Fixture result: 214 vbytes; fees 428/2140 sat at 2/10 sat/vB; 10,000 sat reward;
  one winner, one obligation, two payment versions, unchanged 48-unit Aura burn.
- 21 miner journal/publication, 34 Rust M2/economic/auth and 19 TS miner/Bitcoin
  test entries passed; SDK library/binary/example compile passed.
- Frozen Aura owners, M2/M3 fixtures, Bitcoin anchor and authoritative docs unchanged.

## Decisions and limitations

Section 8 clarification is explicitly APPROVED: signed target remains in J/I/Storm
binding. Diagnostic thresholds only compare already-computed hashes and never
replace the signed target. The original decision evidence is retained in the M3
report. No unresolved semantic decision blocks M6.

The current system is coordinated witness-backed PoC plus a target predicate,
not production-ready mining, permissionless consensus, succinct/ZK proving,
physical/sequential hardness or calibrated economic security. Funding is custodial;
wallet locks are restored on publication recovery, while ambiguous locks/spends
require operator reconciliation. Policy N/T, reward, duration and fee budget are explicit, uncalibrated inputs.
No monetary activation is authorized.

## Stop condition

M5 acceptance is satisfied. M6 adversarial validation is in progress; M7 remains BLOCKED.
M6 must extend the reproducible miner regtest into the approved adversarial
full-system gate; do not claim M6 completion from M5's bounded acceptance evidence.
