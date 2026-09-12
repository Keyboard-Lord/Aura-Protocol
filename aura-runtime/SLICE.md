# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: approved Aura Miner Protocol V1, master goal M3–M7
Current milestone: M7 DONE — MASTER PROGRAM COMPLETE
Last updated: 2026-09-11
Next node: none

## Mission and frozen baseline

Finish the miner program one dependency-ordered milestone at a time. Report and
stop at each node boundary. The master goal completes only after M7. No monetary
activation is authorized by implementation completion.

Completed Bitcoin migration/economic baseline: `f64fb4f`. Preserve existing HASH_V2,
field arithmetic, Storm initialization/recurrence, TRACE_ROOT, proof bytes,
ProofMaterial/FractalKey/proof_hash, Authorization V2, W/M, burn, Head V2, UDOT,
Bitcoin OP_RETURN and frozen M2 codecs/vectors. No migration re-audit without a
concrete dependency defect. Root-local execution; no runtime/profile changes.

Protocol owner: [coordinated Miner V1](../docs/authoritative/AURA_AURAFARMING_NODES.md).
[Design decision history](../reports/AURA_MINER_PROTOCOL_V1.md) retains approved
D1–D6 and evidence, not duplicate authority. Prior Bitcoin completion evidence:
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
| M6 | DONE | M5 | Reproducible adversarial full-system acceptance gate and frozen-output regressions. |
| M7 | DONE | M6 | Existing-owner promotion, measured operational limits and activation readiness; live monetary deployment separately approved. |

This order follows the user's master goal. M4 composes round ownership into the existing economic transaction owner.

## Current evidence

[M7 completion audit](../reports/AURA_MINER_M7_READINESS.md),
[operations guide](../docs/AURA_MINER_OPERATIONS_V1.md),
[full acceptance gate](../scripts/verify_miner_program_v1.mjs),
[captured final result](../reports/miner_protocol_v1/m7_acceptance_results.json).
Prior: [M6](../reports/AURA_MINER_M6_EVIDENCE.md), [M5](../reports/AURA_MINER_M5_EVIDENCE.md),
[M4](../reports/AURA_MINER_M4_EVIDENCE.md), [M3 measurements](../reports/AURA_MINER_M3_EVIDENCE.md).

- All 11 final gate stages passed: 186 top-level Rust test entries (including child
  helpers), 58 TS tests, affected SDK compile and 17 explicit Core attack cases.
- M7 reconciled approved epoch-zero/consecutive rotation and post-snapshot challenge
  generation; two focused tests and the complete adversarial gate passed afterward.
- The existing Aurafarming owner now defines Miner V1. Prior network research is
  preserved verbatim outside authority; the design report cross-references the owner.
- Operations guide covers API ownership, measured limits, funding, journal/backup
  requirements, monitoring, recovery, security assumptions and activation boundary.
- Main Core scenario: 214 vbytes, fees 428/2140 sat, reward 10,000 sat, one winner,
  one obligation, two conflicting versions, unchanged 48-unit Aura burn.
- Frozen cryptographic outputs, M2/M3 vectors and Bitcoin anchor unchanged.
  Authoritative changes promote only the already-approved miner integration.

## Decisions and limitations

Section 8 clarification is explicitly APPROVED: signed target remains in J/I/Storm
binding. Diagnostic thresholds only compare already-computed hashes and never
replace the signed target. The original decision evidence is retained in the M3
report. No unresolved implementation decision remains in M0–M7. Deployment
parameters and monetary activation remain separate explicit decisions.

A complete internally consistent old database cannot detect its own rollback.
The explicit simulation records this limit: latest-backup provenance and external
publication reconciliation are required before restore. The operations guide
records those requirements; no external anti-rollback authority was introduced.

The implementation-ready system is coordinated witness-backed PoC plus a target
predicate, not permissionless consensus, succinct/ZK proving, physical/sequential
hardness or calibrated economic security. Funding is custodial;
wallet locks are restored on publication recovery, while ambiguous locks/spends
require operator reconciliation. Policy N/T, reward, duration and fee budget are explicit, uncalibrated inputs.
No monetary activation is authorized.

## Stop condition

M0–M7 acceptance is satisfied. Stop the master program. No next node, live monetary
deployment, automatic retarget or permissionless-consensus work is authorized.
