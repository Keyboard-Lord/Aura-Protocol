# Compute lifecycle V1 — frozen 2026-09-12

Authority: [compute owner](../../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md#c2-assignment-receipt-and-verified-result).
[Approval and evidence](../../reports/AURA_COMPUTE_C2_CONTRACT_DECISIONS.md).

`result_vectors_v1.json` contains exact assignment/receipt/result/cancellation bytes,
separate signatures, canonical byte accounting and result commitments with existing
C1 miner-side expansion. Rust and TS independently reproduce every byte string.

These are codec vectors, not coordinator-accepted useful results or payments.
Keys, nonces, contents and numeric parameters are test-only. No fixture regeneration
occurs in tests. Never replace expected bytes to conceal a failure.

Full gate: `node scripts/verify_compute_result_v1.mjs`.
Explicit producer (stdout only):
`cargo run -p aura_sdk_v1 --offline --example compute_result_vectors_v1`.
