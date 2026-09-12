# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: Aura Compute Network V1, master goal C0–C10
Current milestone: C0 — AWAITING USER_DECISION
Last updated: 2026-09-12
Next node: C1, blocked on C0 approval

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
| C0 | AWAITING USER_DECISION | Owner map and architecture prepared; D1–D4 approval required. |
| C1 | BLOCKED | C0: canonical compute job framing, identity, signatures, limits and Rust/TS vectors. |
| C2 | BLOCKED | C1: worker/result contracts and independent compute-payment state machine. |
| C3 | BLOCKED | C2: real GPU-oriented ZK proving, verification, delivery, payment and optional mining binding; minimal isolation required. |
| C4 | BLOCKED | C3: deterministic/open-model inference. |
| C5 | BLOCKED | C4: molecular, media and Monte Carlo adapters, one at a time. |
| C6 | BLOCKED | C5: generic sandboxed CPU/GPU worker. |
| C7 | BLOCKED | C6: justified confidential/TEE/locality support. |
| C8 | BLOCKED | C7 plus measured proving kernels: Proof ASIC production interface. |
| C9 | BLOCKED | C8: capability discovery, routing, reliability and market. |
| C10 | BLOCKED | C9: adversarial network and activation-readiness evidence. |

## Current evidence

[C0 architecture and owner map](../reports/AURA_COMPUTE_NETWORK_V1.md) is a
non-authoritative proposal. No compute codec, adapter or payment implementation
exists as a result of C0. No authoritative document was added or changed.

- Existing miner intent commits exact J and M; M can carry a result reference,
  but its current attestation checks do not verify an external workload.
- Existing reward publication requires an Accepted miner winner. Independent
  compute compensation needs an approved extension of that same payment owner.
- Existing economic consent and Authorization V2 bind completed Aura references;
  a pre-execution customer job signature cannot stand in for either envelope.
- C0 validation is documentation-only: local links, archive preservation, diff
  whitespace and changed-file scope. Completed Miner/Bitcoin gates were not rerun.

## Decisions

See the proposal's decision table for alternatives, tradeoffs and exact boundaries.

| ID | Recommended architecture awaiting approval |
| --- | --- |
| D1 | Fixed customer-prefunded custodial BTC compensation through the existing journal/publisher, independent of mining. |
| D2 | Coordinator account signs ordinary Aura compute finalization and pays the unchanged Aura burn; customer/worker signatures remain distinct. |
| D3 | Final verified-result reference binds through a strict existing-M evidence profile; normal unlinked Miner V1 remains unchanged. |
| D4 | One neutral compute authority owner, registered only after approval and implementation evidence; existing owners retain their concepts. |

These are new compute architecture choices, not covered by prior Miner V1 approval.
Exact bytes, backend selection and lifecycle details belong to subsequent nodes.
Approval does not authorize unspecified tariffs, confidential execution or live funds.

## Stop condition

Stop for D1–D4 review. After approval, record C0 DONE and C1 READY; do not silently
start C1 in this execution. No runtime implementation or authority promotion at C0.
