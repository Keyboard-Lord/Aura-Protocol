# Miner M2 frozen codec/profile evidence

Classification: IMPLEMENTATION EVIDENCE, not protocol authority.
Contract: [approved miner design, sections 3–4](../../reports/AURA_MINER_PROTOCOL_V1.md).
Owners: [Rust](../../crates/aura_sdk_v1/src/miner.rs) and
[TypeScript](../../packages/aura_sdk_v1_ts/src/minerV1.ts).

`job_profile_vector_v1.json` is fixture metadata. Its hex values contain the exact
binary wires; this JSON is not an accepted job wire or another candidate identity.
The 471-byte job was framed independently from the design and matched the earlier
design probe's job/intent commitments before freezing. Both language tests construct
the typed job independently and compare the resulting bytes with this fixture.
They also decode/re-encode the frozen bytes without normalization.

The fixture contains the job, commitment, tagged signing digest, deterministic
BIP340 signature, canonical 813-byte M, nonce, intent, route, 209-byte context and
1287-byte W. All use the existing owners. Secret key 3 and zero signing auxiliary
randomness are public test inputs only. The binding-only authorization and economic
consent sign a synthetic zero proof reference; they do not represent verified PoC
or successful authorization. A nonce change may form a new structural profile but
cannot reuse consent over the original W, even if its lineage is updated.

Frozen cases exercised by **both** implementations:

- All 471 job bytes independently XORed with `0x01`: identical decoder results
  (429 valid shapes, 42 malformed), exact re-encoding for valid shapes, and rejection
  of the original job signature for every mutation. This covers every signed field.
- All 64 signature bytes independently mutated, plus invalid signature lengths.
- All 471 strict truncations, trailing bytes, all 251 unsupported network tags,
  and 11 explicit invalid-field patches: domain/version/network/key, N=0 or u64 MAX,
  zero/all-ff target, equal/reversed times and zero reward.
- Six valid binary variants: all five network tags and u64 boundary fields; no
  execution is attempted with the extreme iteration count.
- Eight raw BE32 target cases: `<`, `=`, `T+1`, byte-order traps, zero hash, maximum
  hash and a pair above floating-point integer precision. Four-byte nBits and other
  non-32-byte inputs reject; there is no hash reversal or numeric conversion.
- Every byte of W mutated against the existing authenticated boundary, every
  context byte checked against the profile, and focused payer, intent, nonce,
  route, sides, N, meter/head linkage and work/meter cap tests.
- Trusted policy mismatch for all eight fields, host limits, half-open admission
  times, stale/malformed/overflowing predecessors, historical claim slots and VK.
- A corrupted trace claim can pass profile/low-hash filters but fails the existing
  claim owner. These filters deliberately make no PoC or winner verdict.

TypeScript additionally rejects coercion, missing/extra/symbol fields, alternate
JSON input and malformed widths/types that Rust's typed API cannot represent.

## Reproduce M2 validation

Run from the repository root:

```sh
cargo test -p aura_sdk_v1 --offline --test miner_v1
node --test packages/aura_sdk_v1_ts/src/minerV1.test.ts
cargo check -p aura_sdk_v1 --offline --lib
node --check packages/aura_sdk_v1_ts/src/minerV1.ts
node --input-type=module -e 'const s = await import("./packages/aura_sdk_v1_ts/src/index.ts"); if (s.MINER_JOB_V1_BYTE_LEN !== 471 || typeof s.buildMinerWorkV1 !== "function") throw Error("M2 exports missing");'
cargo test -p aura_sdk_v1 --offline --test economic_contract_v1 --test authorization_v2
node --test packages/aura_sdk_v1_ts/src/economicV1.test.ts packages/aura_sdk_v1_ts/src/stormClaimV1.test.ts
cargo build -p aura_sdk_v1 --offline --bin aura-authorizer
node reports/miner_protocol_v1/design_probe.mjs
```

Closure evidence (2026-09-10): 9 Rust and 10 TS miner tests; 13 Rust and 7 TS
existing regression tests passed. SDK Rust check/binary build and native TypeScript
syntax/module-import checks passed. This package executes TypeScript directly in
Node; it has no separate `tsc` build configuration. The design probe output exactly
matched its existing captured JSON bytes. Existing production implementations,
authoritative documents and previously frozen fixtures were unchanged in M2 closure.

M2 is DONE. M3 is also complete; [its evidence](../../reports/AURA_MINER_M3_EVIDENCE.md)
describes `trial_vector_v1.json`, which freezes existing canonical objects from one
local trial without changing this M2 vector. Round ownership, funding, rewards and
durable coordination remain later slices.
