# C1 compute-job codec evidence — NOT YET CANONICALLY FROZEN

`job_vectors_v1.json` records exact request/signature/content and result-to-MinerJobV1
profile bytes. Rust and TypeScript independently construct and compare them.
All secrets, nonces, amounts and policy payloads are test-only. Synthetic policy
payloads do not constitute supported privacy/hardware/payment/rights contracts.
No fixture represents funded admission, a verified useful result or a payment.

Contract and freeze gate: [C1 evidence](../../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md).
Existing M2 fixtures are unchanged. Do not regenerate expected bytes to hide a
failure; investigate against the approved layout and derivation first.

Explicit producer (stdout only; tests never rewrite expected values):
`cargo run -p aura_sdk_v1 --offline --example compute_job_vectors_v1`.

No compute contract is frozen until the remaining core profiles are resolved and
the final required validation passes. No production parameter is selected here.
