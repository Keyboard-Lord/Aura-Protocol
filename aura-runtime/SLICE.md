# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: Aura Compute Network V1, master goal C0–C10
Current milestone: C3 — IN PROGRESS (USER_DECISION C3-D1/D2)
Last updated: 2026-09-13
Next node: C4 — BLOCKED until C3 acceptance; no later READY node

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
| C2 | DONE | C2-D1/D2 APPROVED; exact lifecycle codecs, durable assignment/reservation/receipt/result and full gate passed. |
| C3 | IN PROGRESS | C2 complete; backend/workload and shared compute-payment decisions prepared, awaiting C3-D1/D2. No production adapter registered. |
| C4 | BLOCKED | C3: deterministic/open-model inference. |
| C5 | BLOCKED | C4: molecular, media and Monte Carlo adapters, one at a time. |
| C6 | BLOCKED | C5: generic sandboxed CPU/GPU worker. |
| C7 | BLOCKED | C6: justified confidential/TEE/locality support. |
| C8 | BLOCKED | C7 plus measured proving kernels: Proof ASIC production interface. |
| C9 | BLOCKED | C8: capability discovery, routing, reliability and market. |
| C10 | BLOCKED | C9: adversarial network and activation-readiness evidence. |

## Frozen C2 evidence

[C1 freeze](../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md) remains intact.
[C2 approval/freeze evidence](../reports/AURA_COMPUTE_C2_CONTRACT_DECISIONS.md) records
implementation and limitations. The registered
[compute owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md) owns definitions.

- Distinct assignment/receipt/result/cancellation bytes and signatures; one result
  commitment, canonical byte counts and no hardware/time telemetry in identity.
- Same EconomicJournalV1: explicit installation, authenticated replay, full net/fee
  reserve at assignment, one assignment/receipt, durable artifacts, internal verifier
  finalization and atomic full-net entitlement/retention. No payment/acceptance boolean.
- [C2 gate](../scripts/verify_compute_result_v1.mjs) PASS:
  5 Rust + 6 TS codec tests; 12 journal tests (including 11 process-exit cases);
  1 opaque-token compile-fail test; 32 miner + 12 economic journal regressions;
  full C1/M2 gate (19 Rust + 23 TS), SDK compile and Node syntax/export checks.
  [Recorded result](../reports/compute_network_v1/c2_freeze_results.json).
- Funding overlap rejected in both directions; races/retries, corruption, timely
  pending receipt recovery, invalid/late work and no-double-entitlement checked.
- Frozen C1/Miner/Aura fixtures and semantics remain unchanged. Existing journal
  modifications are additive compute audit and shared backing-ownership guards.
- Only a sealed test adapter exists. No production workload, GPU measurement,
  public worker execution, compute payment or live monetary activation claimed.

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

## C2 approval and closure

C2-D1/D2 APPROVED as documented, with full net plus fee reservation at assignment.
Required parity, mutation, replay, funding and crash/recovery checks passed; the
contract is now frozen. No unresolved C2 protocol decision remains.

## Current C3 evidence and decisions

[C3 proposal and direct-owner map](../reports/AURA_COMPUTE_C3_CONTRACT_DECISIONS.md)
records the exact remaining decisions. It is non-authoritative; neither choice
has been implemented or approved.

- C3-D1: recommend local RISC Zero v3.0.5 succinct STARK proving for one reviewed
  batch SHA256 Merkle-membership guest, measured Metal GPU execution and CPU
  reference. Exact adapter byte contracts remain subject to vectors and real proof
  validation before registration. Preserve genuine proof randomness and C2 identity.
- C3-D2: recommend direct worker output-key payment and an anchor-free compute
  obligation case in the existing shared Bitcoin publisher. Full net, separate
  bounded fees and replay/reorg recovery; no live activation or deployment defaults.
- Host observation: M4 Pro, 16 GPU cores, Metal reported. No installed prover found;
  no GPU proof, sandbox/resource-enforcement or performance result yet.
- Existing publication requires miner reward/anchor; it cannot currently discharge
  an ordinary compute entitlement. Extend that owner after approval, not its ledger
  or frozen miner meaning. Existing signed-side binding and winner rule suffice.
- This step edited only the proposal and this register. Checked local references
  and whitespace; unchanged C2/Miner gates were not rerun. No frozen output changed.

## Stop condition

Current stop: USER_DECISION C3-D1/D2. Resume their bounded implementation order
after approval. C3 closes only with real GPU proof/verification, authenticated
customer delivery, independent compute payment, optional unchanged mining and
end-to-end/recovery evidence. Then mark C3 DONE/C4 READY and stop this node.
Do not activate live funds or public workers.
