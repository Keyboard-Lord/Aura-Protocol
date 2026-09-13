# C1 compute-job contract — frozen 2026-09-12

Authority: [compute contract](../../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md).
Approval and full gate: [C1 evidence](../../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md).

- `job_vectors_v1.json`: original exact job/signature/content and signed-miner
  profile bytes, preserved unchanged. Its synthetic core-policy payloads exercise
  structural content binding only and fail supported-core-policy validation.
- `core_policy_vectors_v1.json`: approved core payloads, commitments, signed jobs,
  fee limits and mutation classifications. Adapter contents and numeric parameters
  are test-only, not activated workloads or deployment defaults.

Rust and TS independently reconstruct every exact byte vector. Neither fixture
represents funded admission, assignment, a verified useful result or payment.
Existing M2 fixtures are unchanged. Never regenerate expected bytes to hide a
failure; investigate against the owning contract first.

Reproduction gate: `node scripts/verify_compute_job_v1.mjs`.
Explicit producer, stdout only (tests never rewrite expected values):

```sh
cargo run -p aura_sdk_v1 --offline --example compute_job_vectors_v1
cargo run -p aura_sdk_v1 --offline --example compute_job_vectors_v1 -- --core-policies
```
