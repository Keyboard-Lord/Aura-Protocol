# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: approved Aura Miner Protocol V1, master goal M3–M7
Current milestone: M4 COMPLETE
Last updated: 2026-09-11
Next READY node: M5 (not started)

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
| M5 | READY | M4 | Sponsor-funded reward plus unchanged Bitcoin anchor; regtest publication/replacement/reorg recovery. |
| M6 | BLOCKED | M5 | Reproducible adversarial full-system acceptance gate and frozen-output regressions. |
| M7 | BLOCKED | M6 | Existing-owner promotion, measured operational limits and activation readiness; live monetary deployment separately approved. |

This order follows the user's master goal. M4 composes round ownership into the existing economic transaction owner.

## Current evidence

[M4 implementation and validation](../reports/AURA_MINER_M4_EVIDENCE.md).
[M3 closure and measurements](../reports/AURA_MINER_M3_EVIDENCE.md).

- Existing economic journal owns policy epochs, signed funded jobs, pinned
  snapshots, one contender, terminal rounds and unique reward obligations.
- Round acquisition/debit and authorization/Head V2/winner/reward/outbox commit
  atomically. Server regenerates and verifies the existing canonical proof.
- 19 focused M4 test entries passed, including process-exit recovery, races,
  retries, fake-low/rebound proof references, expiry, all existing failure burns,
  injected transaction failures, corruption and guarded funding-lock release.
- Existing regressions passed: journal 12, economic contract 5, authorization 8,
  Rust M2 9, Rust M3 13, TS M2/M3 11. SDK library/binary/example check passed.
- Frozen M2/M3 fixtures and existing cryptographic/economic/Bitcoin owners are
  unchanged. No canonical bytes or authoritative documents changed.
- Core funding adapter was validated with deterministic RPC mocks. No payout,
  transaction construction, broadcast or regtest work was performed in M4.

## Decisions and limitations

Section 8 clarification is explicitly APPROVED: signed target remains in J/I/Storm
binding. Diagnostic thresholds only compare already-computed hashes and never
replace the signed target. The original decision evidence is retained in the M3
report. No unresolved semantic decision blocks M4.

The current system is coordinated witness-backed PoC plus a target predicate,
not production-ready mining, permissionless consensus, succinct/ZK proving,
physical/sequential hardness or calibrated economic security. Funding is custodial;
wallet restart/re-lock and ambiguous external-lock reconciliation require operator
care. Policy N/T, reward, duration and fee budget are explicit, uncalibrated inputs.
No monetary activation is authorized.

## Stop condition

M4 acceptance is satisfied. M5 is READY; M6 and M7 remain BLOCKED. Report M4 and
stop before Bitcoin reward transaction construction/publication. M5 must consume
this journal's obligation/reserved outpoint and prove combined payout/anchor
retry/replacement/reorg behavior on Core regtest.
