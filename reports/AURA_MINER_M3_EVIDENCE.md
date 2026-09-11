# Aura miner M3 — local execution evidence

Classification: IMPLEMENTATION / RESEARCH EVIDENCE, not active protocol authority.
Closure: 2026-09-11. M3 DONE; M4 READY and not started.
Contract: [approved miner design](AURA_MINER_PROTOCOL_V1.md). No monetary activation.

## Implementation boundary

[Rust miner_search](../crates/aura_sdk_v1/src/miner_search.rs) adds an immutable
`MinerSessionV1`, constructed from the signed M2 job, explicit trusted policy,
canonical meter, miner keypair and host work/iteration/proof-byte limits. The key's
x-only public identity must equal the metered payer/controller. The session does
not assert live round publication, head ownership or sponsor funding.

`trial(nonce, index)` composes only existing owners:

`M2 build_work → build_storm_claim_v1 (execution + TRACE_ROOT) → compact inputs →
prove_storm_air_real_v1 → canonical decoder/profile checks → verify_storm_air_real_v1
→ prepare_bound_proof_material_v1 → existing proof_hash <= signed target`.

The preparation owner verifies ProofMaterial and FractalKey binding internally.
`verify_miner_trial_v1` independently rechecks the profile, embedded claim, canonical
artifact, actual witness proof and reconstructed material/reference. It never
accepts a caller's low hash or a stored qualification flag as proof validity.

`MinerTrialV1` exposes read-only references to existing W, claim, proof and prepared
material objects, with a trial index, local qualification result and timing
diagnostics. Nonce and proof_hash accessors read their existing owners. No new
canonical serialization, proof identity or TypeScript prover was introduced.
M4 can consume these canonical objects and must independently revalidate them at
admission; local qualification is not authorization, a journal winner or a reward.

`mine(config, cancellation)` bounds trials and elapsed time, checks the signed job
window, and stops on qualification, exhaustion, cancellation, expiry or deadline.
It checks time/cancellation before and after each indivisible trial, so an in-flight
trial may overrun the wall-time budget; it cannot then be returned as a qualifying
result. The existing host N bound limits that work. Crypto owners are not preempted.
Secure mode calls the existing CSPRNG nonce producer and rejects duplicate nonces
within the session. Explicit research mode increments a BE256 nonce without wrap;
it is for deterministic tests/probes, not the approved production RNG producer.
`trial` alone is an offline single-computation primitive, not a time/replay gate.

## Section 8 decision — explicitly APPROVED

The user approved preserving `target → J → job_commitment → intent → Storm context
→ forcing → TRACE_ROOT → proof_hash`. Changing the signed target defines a different
job/computation. Diagnostic thresholds only compare already-completed hashes; they
never replace the signed target for qualification or cause another execution.

The original bounded contradiction probe changed only the final target byte of
the frozen M2 N=64 job from `ff` to `fe`, holding M/nonce/sides fixed. TRACE_ROOT
changed from `ee6c8a09cfae529d4e85e6d3b0553fdad69c4ad8fcd3690ef93ba6ff31db049d`
to `4d5d90e331490b48cf6616bb7c15237d3cbc1bbb652edd0ddfab22bae42dfc54`.
The clarification resolved the decision without modifying M2.

## Reproducible measurements

[Probe](../crates/aura_sdk_v1/examples/miner_m3_probe.rs),
[runner](miner_protocol_v1/run_m3_probe.py),
[captured measurements and all 320 hashes](miner_protocol_v1/m3_measurements.json).

```sh
cargo build -p aura_sdk_v1 --offline --release --example miner_m3_probe
python3 reports/miner_protocol_v1/run_m3_probe.py --trials 64
```

Environment: macOS 26.6.2 arm64, Rust 1.88.0, LLVM 20.1.5, release optimization,
one serial worker per N. CPU model lookup was denied by the sandbox and is recorded
as unavailable. Each N uses 64 deterministic trials plus one excluded warmup;
nonce = 24 bytes `0x42` followed by `u64_be(index)`. Each N has its own signed research
job with target `2^255 - 1` and q=1/2. These are offline fixture jobs, not open funded
rounds. No production parameters were selected.

| N | Total ms / 64 trials | Mean ms | Median ms | Trials/s | Proof bytes | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 256.896 | 4.011 | 4.003 | 249.13 | 5,817 | 2.84 |
| 16 | 456.268 | 7.126 | 7.116 | 140.27 | 10,105 | 2.91 |
| 32 | 852.080 | 13.310 | 13.309 | 75.11 | 18,681 | 3.00 |
| 64 | 1,638.572 | 25.599 | 25.581 | 39.06 | 35,833 | 3.22 |
| 128 | 3,224.283 | 50.375 | 50.339 | 19.85 | 70,137 | 3.59 |

Actual trial-stage means in milliseconds (each row contains 64 trials):

| N | Storm + claim/root | Proof construction | Full proof verification | Material/FractalKey/hash | Trace row bytes | Witness bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 0.317 | 2.073 | 1.549 | 0.039 | 1,188 | 5,002 |
| 16 | 0.554 | 3.727 | 2.751 | 0.061 | 2,244 | 9,290 |
| 32 | 1.022 | 7.002 | 5.143 | 0.109 | 4,356 | 17,866 |
| 64 | 1.936 | 13.533 | 9.897 | 0.201 | 8,580 | 35,018 |
| 128 | 3.812 | 26.656 | 19.482 | 0.390 | 17,028 | 69,322 |

Two additional pure `execute_storm_v1` diagnostics per N measured means of
0.306, 0.539, 1.061, 1.962 and 3.780 ms, respectively. Those runs and propagation
inspection are outside the timed trial batch. Claim timing includes trace-root
construction; proving/verification include their owners' internal replay work.
Total includes small sample-collection overhead. Times are Instant wall measurements
rounded to 0.001 ms, not precision or physical-energy claims.

RSS is the OS-reported child high-water mark from a fresh Python monitor per N,
including warmup and diagnostics; it is not a measurement of peak live Rust
allocations. `/usr/bin/time -l` could not read sandboxed clock metadata, so the
runner uses `getrusage(RUSAGE_CHILDREN)` for its sole Rust child. Research sequential
mode does not include the secure mode's per-session nonce-set growth.

Same-hash diagnostic results, without modifying any job or recomputing a proof:

| Diagnostic T | q | Hits / 320 | Expected hits | Observed rate |
| --- | ---: | ---: | ---: | ---: |
| `2^255 - 1` (also signed target) | 1/2 | 162 | 160 | 50.625% |
| `2^254 - 1` | 1/4 | 79 | 80 | 24.688% |
| `2^252 - 1` | 1/16 | 28 | 20 | 8.750% |

The signed-target hits by N were 32, 38, 34, 30 and 28 out of 64. All sample hashes
within each job differed. The 1/16 count is about 1.85 reference binomial standard
deviations above its expectation. This small deterministic sample is compatible
with the probability model; it neither proves independent random outputs nor
calibrates production difficulty. Exact inclusive BE32 endpoints remain frozen M2.

## Security and reuse evidence

- Nonce 0 versus nonce 1 changed context, both parameters, every forcing pair,
  every noninitial state row, TRACE_ROOT, proof bytes and proof_hash at all five N.
  The initial state intentionally remained invariant because its owner uses sides only.
- Copying a proof from nonce A into nonce B work failed full M3 revalidation.
  Sixteen fixed cheap outer-nonce/FractalKey rebindings all failed, including low
  hashes. Rewriting the claim context without recomputing its witness also failed.
- A mutated witness with reconstructed artifact digests and material failed actual
  proof verification. Replacing proof_hash with zero or changing material binding failed.
- Reusing four noninitial trace rows, with step rows made consistent and canonical
  witness bytes/artifact/material regenerated, failed full verification.
- Reusing only the identical side-derived initial state, then calling existing
  `storm_step` with each correct nonce-B forcing value, exactly reproduced B's trace.
- Two concurrent independent trials matched isolated canonical outputs byte-for-byte.
  This is an independence check, not a pool or parallel-throughput benchmark.

Harmless precomputation includes immutable J/M/intent, fixed input prefixes and the
side-derived initial state. Per-step forcing values can be derived independently
once the nonce-conditioned context is known; they are not a sequential work proof.
Cross-nonce parameters/forcing/noninitial states did not match in the tested cases.
The current prover/verifier repeat execution and validation within a single trial;
that is implementation overhead and a possible future optimization, not evidence
of an irreducible work cost. No dangerous cross-nonce reuse succeeded in these
bounded experiments, and no general non-amortization or sequential-hardness theorem
is claimed. M3 introduces no nonce-dependent state cache or alternative recurrence.

## Validation and frozen outputs

- 13 focused Rust M3 tests passed: 12 initial tests plus the added partial-trace reuse test.
  Reproduction: `cargo test -p aura_sdk_v1 --offline --lib miner_search::tests`.
- 9 existing Rust M2 tests: `cargo test -p aura_sdk_v1 --offline --test miner_v1`.
- 10 TS M2 tests and 1 M3 interoperability test:
  `node --test packages/aura_sdk_v1_ts/src/minerV1.test.ts packages/aura_sdk_v1_ts/src/minerSearchV1.test.ts`.
- SDK/example check and release build passed. Python runner completed all five N.
- Existing core Storm verifier tests: 3 passed via
  `cargo test -p aura_intent_lineage_v1 --offline --lib stark_verifier_v1::tests::storm_real`.
- Existing frozen Storm parity: 1 passed via
  `cargo test -p aura_intent_lineage_v1 --offline --test storm_parity_v1`.
- Existing proof/material/authorization vector: 1 passed via
  `cargo test -p aura_sdk_v1 --offline --test authorization_v2 shared_vector_matches_existing_proof_and_material_bytes`.

[New N=8 trial evidence](../fixtures/miner_v1/trial_vector_v1.json) contains exact
existing W/claim/proof/public-input/material/FractalKey bytes. It is fixture metadata,
not another wire. Rust compares it against independent owner execution; TS reproduces
the existing W/material/proof-reference boundary without claiming proof verification.
Its first trial is above target; deterministic bounded search tests also prove
first-hit success and exhaustion. To reproduce the vector without modifying it:
`cargo run -p aura_sdk_v1 --offline --example miner_m3_probe -- --vector`.

All pre-existing frozen fixtures, M2 codecs, cryptographic implementations,
authorization/economic/head/Bitcoin implementations and authoritative docs are
unchanged. The only existing Rust runtime-file edit exports the additive search
module. No Bitcoin migration/regtest gate was rerun because those owners did not change.

M3 establishes local verified computation and a probabilistic target filter only.
It does not establish sequential hardness, non-amortization, ASIC resistance,
minimum energy cost, commercial usefulness of all trials, Sybil resistance,
permissionless/Nakamoto consensus, economic security, production difficulty, or a
succinct/zero-knowledge Storm STARK. The active backend remains witness replay.
Round coordination, admission, rewards and Bitcoin publication are future nodes;
M4 is READY. Monetary deployment still requires separate explicit approval.
