# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: Aura Compute Network V1, master goal C0–C10
Current milestone: C2 — IN PROGRESS (approved worker/result implementation)
Last updated: 2026-09-12
Next node: C2 implementation and freeze gate; C3 remains BLOCKED

## Mission and frozen baseline

Extend completed Miner V1 with useful customer-requested computation. Valid useful
work earns customer-funded compensation independently of optional sponsor-funded
mining rewards. Execute one current node, validate, record evidence and stop.

Completed Miner baseline: `97ff01f`; M0–M7 DONE. The
[completed miner register](MINER_M7_SLICE.md) is preserved verbatim, with
[M7 evidence](../reports/AURA_MINER_M7_READINESS.md) and the
[active miner owner](../docs/authoritative/AURA_AURAFARMING_NODES.md).

Preserve HASH_V2, field arithmetic, Storm, TRACE_ROOT, proof format,
ProofMaterial/FractalKey/proof_hash, Authorization V2, W/M, burn, Head V2, UDOT,
Bitcoin OP_RETURN, Miner V1 eligibility and frozen job/profile bytes including the
signed-target dependency. One existing journal and Bitcoin publication path.
No public worker execution or live monetary activation is authorized.

## DAG

| ID | State | Dependency / bounded output |
| --- | --- | --- |
| C0 | DONE | D1–D4 explicitly approved as amended; controlling approval recorded in C0 evidence. |
| C1 | DONE | C1-D1–D3 and C1-P1 APPROVED; job/core schemas, authentication and signed-side binding frozen with independent Rust/TS vectors. |
| C2 | IN PROGRESS | C1 complete. C2-D1/D2 APPROVED; implementation and freeze gate pending. |
| C3 | BLOCKED | C2: real GPU-oriented ZK proving, verification, delivery, payment and optional mining binding; minimal isolation required. |
| C4 | BLOCKED | C3: deterministic/open-model inference. |
| C5 | BLOCKED | C4: molecular, media and Monte Carlo adapters, one at a time. |
| C6 | BLOCKED | C5: generic sandboxed CPU/GPU worker. |
| C7 | BLOCKED | C6: justified confidential/TEE/locality support. |
| C8 | BLOCKED | C7 plus measured proving kernels: Proof ASIC production interface. |
| C9 | BLOCKED | C8: capability discovery, routing, reliability and market. |
| C10 | BLOCKED | C9: adversarial network and activation-readiness evidence. |

## Current evidence

[C0 approval record](../reports/AURA_COMPUTE_NETWORK_V1.md) and
[C1 freeze evidence](../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md) retain decisions
and implementation evidence. The registered
[compute owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md) owns definitions.

- Exact request bytes, signatures/replay comparison, core policy schemas,
  compensation/fee vectors and result-to-signed-miner binding pass independently
  in Rust and TS. Unsupported profiles/privacy reject even if hashes match.
- [C1 gate](../scripts/verify_compute_job_v1.mjs): 10 Rust C1 + 9 M2 and 13 TS C1
  + 10 M2 tests pass; affected SDK/examples compile and Node syntax/exports pass.
  [Recorded result](../reports/compute_network_v1/c1_freeze_results.json): PASS.
  No standalone tsc, journal, adapter or Bitcoin gate claimed.
- All pre-existing Aura/Miner owners and fixtures are unchanged. Original C1
  vectors are preserved; approved core-policy vectors are additive.
- No assignment, durable compute reservation, result verdict, output delivery or
  payment state machine was added. Approved lifecycle enforcement belongs to C2.

C2 direct-owner inspection confirms the existing admission method burns Aura and
the publisher requires an Accepted miner winner. Ordinary compute needs an additive
extension inside EconomicJournalV1. No existing economic path is being repurposed.
[C2 decision proposal](../reports/AURA_COMPUTE_C2_CONTRACT_DECISIONS.md) defines the
smallest outstanding receipt/result and assignment/reservation choices. Layouts and
local links checked; no C2 source, fixtures or durable state implemented yet.

## Decisions

See the C0 record for the controlling approval and C1 for new contract decisions.

| ID | Approved C0 direction |
| --- | --- |
| D1 | Customer prefunding and durable coordinator reservation; compensation separate from mining; transport changes preserve job identity. |
| D2 | One EconomicJournalV1; authenticated compute admission/result acceptance with no automatic burn or Head V2 advance. Frozen Aura rules apply on entry to existing mining/settlement. |
| D3 | One result commitment binding the required result facts; one vector-frozen derivation into existing signed MinerJobV1 inputs before qualification. |
| D4 | Core owns common envelopes/coordination/accounting; adapters own workload semantics; backends are replaceable; requester retains content rights by default. |

C1-D1–D3 and C1-P1 are APPROVED. Freeze was conditional on full C1 validation;
that gate passed. No unresolved C1 semantic decision remains. Policy payloads and
lifecycle promises live in the compute owner, not this execution register.
No deployment values, payout transport, live funds or public execution approved.

## C2 approval

C2-D1/D2 APPROVED as documented, with the user's clarification that full net
compensation plus signed fee ceiling is reserved at assignment. One immutable
assignment/receipt; exact transition retries only. No canonical freeze yet.

## Stop condition

Complete C2 codecs, journal lifecycle, independent Rust/TS vectors, funding and
crash/recovery evidence; freeze only after the full C2 gate passes. Then mark C2
DONE and C3 READY and stop. Preserve all frozen C1/Miner/Aura bytes. No live funds
or public worker execution.
