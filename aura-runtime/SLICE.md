# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
Program: Aura Compute Network V1, master goal C0–C10
Current milestone: C1 — READY (design begun; USER_DECISION before freeze)
Last updated: 2026-09-12
Next node: C1 design; C2 remains BLOCKED

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
| C1 | READY — DESIGN ONLY | C0 satisfied. Contract candidate prepared; C1-D1/D2/D3 review required before freeze or implementation. |
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

[C0 architecture and approval record](../reports/AURA_COMPUTE_NETWORK_V1.md)
records the user's D1–D4 amendments, not blanket approval of the earlier proposal.
[C1 design candidate](../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md) begins the next
node without adding SDK code, an adapter, a journal migration or active authority.

- Useful completion does not automatically burn or advance Head V2. The sole
  EconomicJournalV1 owns authenticated additive compute admission/acceptance.
- Result binding must enter signed J before qualification. The prior M-only
  recommendation is superseded; existing round opening accepts both side inputs.
- C1 proposes a 546-byte job, explicit commitments/signature/replay and fixed net
  BTC compensation. Funding/payment transport remains outside job identity.
- C1 proposes one result-to-signed-side expansion. [Draft binding vectors](../reports/compute_network_v1/c1_binding_candidate_vectors.json)
  are review evidence only, not frozen fixtures or verified Aura results.
- C1 is not DONE: proposed bytes, policy details and production Rust/TS parity
  still require resolution. No Miner/Bitcoin runtime gate is needed for this design.

## Decisions

See the C0 record for the controlling approval and C1 for new contract decisions.

| ID | Approved C0 direction |
| --- | --- |
| D1 | Customer prefunding and durable coordinator reservation; compensation separate from mining; transport changes preserve job identity. |
| D2 | One EconomicJournalV1; authenticated compute admission/result acceptance with no automatic burn or Head V2 advance. Frozen Aura rules apply on entry to existing mining/settlement. |
| D3 | One result commitment binding the required result facts; one vector-frozen derivation into existing signed MinerJobV1 inputs before qualification. |
| D4 | Core owns common envelopes/coordination/accounting; adapters own workload semantics; backends are replaceable; requester retains content rights by default. |

C1-D1 (canonical envelope/authentication), C1-D2 (fixed net price/transport
separation) and C1-D3 (exact side expansion) are UNAPPROVED design candidates.
Core policy schemas remain to be specified before C1 freeze. C0 approval does not
authorize unspecified C1 bytes, new winner rules, confidential execution or live funds.

## Stop condition

C0 is closed and C1 design has begun as requested. Stop for the genuinely new C1
contract choices; no canonical freeze, SDK implementation, C2 advancement or
authority promotion in this design-only execution.
