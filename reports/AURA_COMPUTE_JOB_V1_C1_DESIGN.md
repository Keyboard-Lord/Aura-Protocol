# AuraComputeJobV1 — C1 approval and freeze evidence

Classification: IMPLEMENTATION / APPROVAL EVIDENCE; NOT PROTOCOL AUTHORITY.
Date: 2026-09-12. Status: C1 DONE; C2 READY, not started.
DOC = CODE for the frozen C1 codec, authentication, core schemas and binding.
Approved lifecycle promises require C2 enforcement; this is not a live compute service.

The single [compute contract owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md)
now contains the approved definitions. This report retains approvals, rationale
and validation evidence; it does not define a second job or policy wire.
[C0 D1–D4](AURA_COMPUTE_NETWORK_V1.md#9-controlling-approval-record--d1d4-approved)
remain the controlling architecture decisions.

## Approval record

The user approved C1-D1–D3 for contract and Rust/TS parity work, with canonical
freeze conditional on exact layout, signing/replay, compensation, side-expansion,
mutation/negative and independent byte-parity evidence:

- C1-D1: fixed request envelope, SHA256 content/job commitments, detached BIP340
  requester authentication and coordinator-scoped retry classification.
- C1-D2: fixed positive net Bitcoin compensation, independent of mining, with
  funding/payment transport excluded from job identity.
- C1-D3: one domain-separated result expansion into both existing signed MinerJobV1
  sides. No new proof identity or change to frozen miner bytes.

### C1-P1 — APPROVED

Source: the user's explicit approval on 2026-09-12 of Section 9 of the pre-freeze
proposal, exactly as documented there. Its complete definitions now live only in
[Supported core policies](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md#supported-core-policies--c1-p1).
The four initial profile-01 schemas and their cancellation/reservation,
net-compensation, fee-ceiling and output-availability promises are APPROVED.
Unsupported privacy classes remain unsupported; zero fee budget is exactly zero.

This approval chooses no deployment fee ceiling, retention duration, payout
transport, funding outpoint or production default. Ordinary useful-compute
acceptance causes no automatic Miner burn, Head V2 advance or Aura issuance.
No C2 state transitions, adapter or live monetary execution were authorized for
this slice. The freeze became effective only after the full C1 gate passed.

## What changed

The existing request codec, signing/replay logic and result expansion already
matched approved C1-D1–D3. Those bytes were preserved. Rust and TS now add strict
core policy encoders/decoders, content-to-signed-job checks and a fee-ceiling
predicate. A matching hash cannot make an unsupported profile valid.

The old structural/synthetic fixture is unchanged. A separate core-policy fixture
covers actual supported payloads with test-only adapter references and numeric
parameters. Neither fixture represents funded admission or verified useful work.
The approved definitions moved from this report into the registered neutral
compute owner; the authority registry and vector matrix point to that single owner.

## Validation evidence

Reproduce: `node scripts/verify_compute_job_v1.mjs`.
[Machine-readable gate result](compute_network_v1/c1_freeze_results.json): PASS,
five stages, with exact commands, environment, elapsed times and fixture SHA256s.

| Check | Result |
| --- | --- |
| Rust C1 contract/policy tests | 10 passed |
| Rust frozen M2 regression | 9 passed |
| Independent TS C1 contract/policy tests | 13 passed |
| TS frozen M2 regression | 10 passed |
| Affected Rust SDK library/examples compile | Passed, offline |
| Node TS syntax and public SDK exports | Passed |

Environment: macOS arm64, Node v22.22.2, rustc 1.88.0. Node native TS validation
is not a standalone tsc typecheck; no standalone TypeScript compiler was available.
No full Bitcoin/miner/journal gate was rerun because their owners were unchanged.

Exact-byte fixtures:

- [Original C1 vectors](../fixtures/compute_job_v1/job_vectors_v1.json): complete
  job/signature/content bytes, all supported network tags, compensation extremes,
  replay scopes, mutation classifications and signed-miner profile expansions.
- [Core policy vectors](../fixtures/compute_job_v1/core_policy_vectors_v1.json):
  three domain-distinct fixed profiles, four exact payment encodings and eight
  signed PUBLIC/SANDBOXED jobs; fee zero, above 2^53 and u64::MAX remain exact.
- [Frozen M2 vectors](../fixtures/miner_v1/job_profile_vector_v1.json): existing
  canonical J/signature/intent/route/work and inclusive big-endian target checks.

Rust sha2/libsecp256k1 and TS Node SHA256/Noble BIP340 independently reconstruct
the exact bytes and signatures. Tests compare full hex byte strings, not only
semantic decoded fields. Fixtures never regenerate inside the gate.

Coverage includes all 546 job-byte and 64 signature-byte mutations, every job
truncation, exact offset/width checks against the owner, trailing bytes, invalid
keys/tags, wrong domains, limits/deadlines, compensation extremes, scoped retries,
same-job/different-signature identity and same-nonce/different-job conflicts.
Four result inputs exercise both sides and every SHA256 expansion block through
existing J/signature/intent/context/work owners. Wrong, swapped, padded and
alternate-counter sides; hex-input mistakes; old signatures; disabled mode; and
post-proof or M-only attachment reject.

Core-policy coverage includes every profile byte value, every payment-byte
mutation, all truncations, trailing bytes, zero availability, exact fee-boundary
checks, TS coercion/missing/extra/accessor rejection, privacy support rejection
and malformed payloads even when their content hash has been recomputed to match.
Lifecycle promises are recorded as C2 requirements, not represented as passing
durable assignment, entitlement, retention or payment tests.

## Frozen-baseline and scope evidence

Compared with completed Miner baseline `97ff01f`, existing production owners and
fixtures remain unchanged; SDK entry points only add the compute exports.
Original C1 vectors also remain byte-identical. HASH_V2, field/Storm/TRACE_ROOT,
proof/material/FractalKey/proof_hash, Authorization V2, burn, Head V2, UDOT,
Bitcoin wire and Miner V1 semantics were not modified. The archived M7 slice
register remains byte-identical to the completed baseline.

Local document links/anchors, authority membership and whitespace were checked.
No new performance, security-hardness or production-economic claim is made.

## Milestone boundary

C0 DONE; C1 DONE; C2 READY; C3–C10 BLOCKED. Stop here.
C2 must implement the worker/result contract and durable payment state machine
through EconomicJournalV1. Supported adapters, actual isolation, result delivery,
payment transport, deployment parameters and live activation remain future work.

Historical design evidence is retained in
[draft binding calculations](compute_network_v1/c1_binding_candidate_vectors.json)
and repository history; it is superseded by the frozen owner and executable
Rust/TS fixtures, not an alternate derivation.
