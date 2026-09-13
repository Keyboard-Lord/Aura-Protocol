# C3 — Real proving adapter and compute payment decisions

Classification: PROPOSAL / IMPLEMENTATION-READINESS EVIDENCE; NON-AUTHORITATIVE.
Date: 2026-09-13. Status: C3 IN PROGRESS; USER_DECISION C3-D1/D2 pending.
No adapter, payment transport or new canonical bytes are activated by this report.

## Scope and current evidence

C2 is complete. Its [freeze evidence](AURA_COMPUTE_C2_CONTRACT_DECISIONS.md)
and [nine-stage gate](compute_network_v1/c2_freeze_results.json) remain the baseline;
that unchanged gate was not rerun for this design-only step. C3 must deliver real
GPU proving, independent verification, customer delivery, compute compensation
and optional existing mining integration before C4 becomes READY.

Only direct owners were inspected. No Miner/Bitcoin migration audit was repeated.

| Dependency | Current owner and finding | C3 use |
| --- | --- | --- |
| Job, signatures, policies, result binding | [Compute authority](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md); C1/C2 bytes frozen | Reuse without a new job, receipt, result or Aura proof identity |
| Workload verification | [Sealed adapter registry](../crates/aura_sdk_v1/src/economic/journal/compute/adapters.rs); only a test-only reverse-bytes fixture | Add exactly one reviewed real proving relation; a requester cannot register arbitrary verification code |
| Assignment, funding, artifacts, entitlement | [Compute operations](../crates/aura_sdk_v1/src/economic/journal/compute/operations.rs) | Preserve single assignment/receipt, full net entitlement and retention in EconomicJournalV1 |
| Customer delivery | `compute_accepted_output` in those operations is a trusted-service read | Add requester-authenticated delivery around the existing stored output, without acknowledgement veto |
| Funding ownership | [Compute custody](../crates/aura_sdk_v1/src/economic/journal/compute/funding.rs) and [shared guard](../crates/aura_sdk_v1/src/economic/journal/funding_registry.rs) | Preserve full net plus fee reserve and compute/miner exclusion |
| Bitcoin payment | [Existing publication owner](../crates/aura_sdk_v1/src/economic/journal/miner/publication.rs) requires a miner reward, accepted economic attempt and proof anchor | Extend shared publication ownership for an existing compute entitlement; do not synthesize a miner attempt/head/anchor |
| Optional bonus | [Signed-side binding](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md#result-to-signed-miner-input-derivation), existing round opening and mining | Resolve accepted R before opening a linked round; preserve the existing winner rule |

Read-only host checks: `uname -ms`, `sw_vers`, `system_profiler SPDisplaysDataType`,
executable lookup and direct Cargo-cache inspection. The available host is Darwin
arm64, macOS 26.6.2 (25G83), Apple M4 Pro with 16 GPU cores and reported Metal
support. No RISC Zero/SP1 prover or relevant proof crates were cached. CUDA tools,
Docker and Podman were not on PATH. Bitcoin Core tools were not on PATH either;
the existing regtest scripts require explicit `BITCOIND`/`BITCOINCLI` paths, so
this does not establish that Core is absent from the machine. No GPU proof,
sandbox test, performance measurement, installation or monetary operation ran.

## C3-D1 — First proving relation and GPU execution

**Conflict:** the supported verifier tag and sealed extension point do not define
a proof system, guest relation, receipt encoding or GPU isolation backend.
Selecting those fixes what a customer buys and what earns compensation.

**Existing approved behavior:** real GPU-oriented Priority 0 proof generation;
hardware-neutral job/result meaning; core privacy profile 01; no relabelled Storm
witness and no arbitrary native customer program. The
[C0 boundary](AURA_COMPUTE_NETWORK_V1.md#7-adapters-hardware-and-hostile-execution)
requires a concrete backend and environment decision before implementation.

**Recommended decision:** adopt a local RISC Zero zkVM adapter, starting from
upstream v3.0.5, with one reviewed batch SHA256 Merkle-membership guest and
succinct STARK receipts. Target Apple Metal on the available M4 Pro for the first
measured GPU run and a CPU reference run. CUDA remains an equivalent backend
candidate, supported only after actual validation. This approval would select a
workload direction and execution environment, not freeze untested bytes or declare
the host's isolation/resource enforcement sufficient.

The initial useful service generates an independently verifiable proof of the
customer's ordered batch of membership assertions against its committed Merkle
root. Customer input supplies the batch and authentication paths. A successful
guest proves every requested membership, commits the exact C1 job commitment and
input commitment in its public journal, and exits successfully. The requester
receives that proof and can verify it without rerunning the prover. This is a
bounded first proof service, not a claim of measured commercial advantage over
ordinary Merkle verification. No arbitrary customer guest ELF is admitted initially.

The exact tree hashing/position rules, input framing, reviewed guest image ID,
public journal layout, output codec, verifier parameters and limits must be
specified and vector-checked before adapter registration. Use workload class 0
and verification class 0, with existing job content commitments pinning those
contracts. External zkVM fields/hashes remain inside the workload library; they
do not replace Aura field arithmetic, HASH_V2 or Storm.

Required contract boundaries for this direction:

- Use one canonical adapter output containing the actual customer proof. Evidence
  must not copy the proof into a second representation; if the proof is sufficient,
  define one explicit empty evidence payload. No optional proof/evidence mode.
- Select one bounded binary representation of the supported succinct receipt.
  Exclude operational metadata and alternate claim/pruning forms from identity;
  pin or derive verifier-controlled constants from the reviewed contract. Reject
  noncanonical encodings rather than normalizing them. Never deserialize the
  unrestricted recursive upstream receipt enum before enforcing shape/depth/size.
- Verify the pinned guest, successful halt, exact job/input/public-output relation
  and proof under pinned verifier parameters. Reject fake/dev receipts, unexpected
  proof kinds, unknown control parameters and unresolved assumptions. Disable
  development-mode acceptance in the build and verifier; do not use remote proving
  as an implicit fallback or treat upstream receipt metadata as authority.
- Preserve the proof system's required randomness. Different valid proof bytes
  are different actual output content under frozen C2; they are not normalized to
  another result identity. Only the single immutable assigned receipt can earn.
  CPU/GPU runs must agree on the statement and verification outcome; separately
  generated randomized proofs need not be byte-identical. The same canonical
  proof bytes must decode, verify, commit and bind identically across consumers.
- The worker and customer see PUBLIC/SANDBOXED data only. A ZK proof does not hide
  the input from the prover. Retain the no-host-secrets/no-outbound-network policy,
  explicit local owner opt-in and bounded resource/time/output enforcement.
  The native prover also needs process isolation; a zkVM alone is not a host sandbox.
  Refuse assignment if the actual GPU backend cannot enforce the signed limits.
- GPU evidence must identify the backend actually used, prove a real proof was
  generated, include independent verification and report measured memory/time.
  CPU fallback, mock receipts and upstream benchmark numbers cannot close C3.
- Track measured proof kernels as future Proof ASIC candidates. Do not invent an
  ASIC API, silicon performance, sequential-hardness or energy claim.

Why this recommendation: RISC Zero documents CPU, CUDA and Apple Metal proving,
including automatic Metal use on Apple Silicon; its Groth16 wrapper is currently
documented as unsupported on Apple Silicon. This favors a native STARK profile
for the available GPU, with portable verification. This is a suitability inference,
not a local performance result. [Upstream local proving](https://dev.risczero.com/api/generating-proofs/local-proving).

The v3.0.5 release includes verifier and hostile-input fixes. Its receipt source
also warns that unrestricted recursive deserialization can exhaust the stack;
successful integrity verification alone does not establish the expected guest and
successful exit. Those are mandatory design checks, not evidence of a completed
Aura adapter review. [Release](https://github.com/risc0/risc0/releases/tag/v3.0.5),
[pinned receipt implementation](https://raw.githubusercontent.com/risc0/risc0/v3.0.5/risc0/zkvm/src/receipt.rs).

| Viable alternative | Meaningful tradeoff |
| --- | --- |
| RISC Zero composite receipt | Same guest family; avoids final succinct compression but introduces segment-dependent proof structure and more variable verification work. Another accepted output mode would need its own reviewed contract; do not support both silently. |
| Groth16 circuit prover with GPU kernels | Potentially compact proofs and a direct MSM/NTT acceleration lane; requires choosing a circuit/setup trust model and complete proof service, not merely installing an acceleration library. [ICICLE integration documentation](https://dev.ingonyama.com/3.1.0/icicle/integrations). |
| Another zkVM, such as SP1 | Viable general program-proving architecture; would require its own pinned receipt/verifier, GPU environment and isolation evidence. No evidence gathered here establishes equivalent local Metal support. [Primary repository](https://github.com/succinctlabs/sp1). |

**Smallest decision needed:** approve this backend, initial batch-membership
workload, succinct-proof/randomness policy and local Metal/CPU validation direction
for detailed contract design and implementation. Exact adapter bytes remain
unfrozen until the checks below pass; a changed verification relation requires
another decision. No proof library installation or backend execution is necessary
to decide whether this is the intended initial customer service.

## C3-D2 — Discharging compute compensation through the shared owner

**Conflict:** the worker identity is not yet a selected Bitcoin payout script,
and the current publisher requires a miner winner and Aura anchor. Ordinary
compute acceptance intentionally creates neither.

**Existing approved behavior:** full customer-funded net compensation, separately
bounded customer fees, no automatic burn/Head, no mining prerequisite, one journal
and Bitcoin publication owner. C1 explicitly leaves payout routing and transport
unselected; C2 ends with an earned entitlement, not a completed payment.

**Recommended decision:** use on-chain Bitcoin payment through an additive
compute-obligation case in the existing publication owner. For the initial
profile, the assigned worker's BIP340 x-only key is the direct Taproot **output
key**: `scriptPubKey = 0x51 || 0x20 || worker_key[32]`. It is not an internal key
to be tweaked again. This matches the existing miner payment destination convention
without changing miner semantics or adding a mutable payout address to C1/C2.
The worker must knowingly accept this key role before signing assignment.

Proposed payment behavior:

- Pay exactly the immutable entitlement's net compensation to that script; no fee
  subtraction, worker substitution or success acknowledgement required.
- Ordinary compute publication has no Aura OP_RETURN, fake proof_hash or synthetic
  Head. Miner publications retain their exact existing anchor and reward behavior.
  A compute-only output set is an obligation case in one publisher, not a second
  ledger/RPC stack or independent settlement path. Start without batching; later
  batching cannot change job identity, net entitlement or destination authorization.
- Consume reserved customer backing, persist the signed transaction and revision
  before broadcast, and independently validate inputs, destination, exact net,
  allowed wallet change and fee. Replacements retain the same obligation and
  conflicting reserved input. No retry creates another payable entitlement.
- Charge fees only against the signed allowance. Zero means zero. If Core policy,
  dust or available fees prevent publication, do not reduce net, substitute a
  destination, erase debt or claim payment. Preflight known publication failures
  before assignment; later failure preserves the already-earned entitlement.
- Change and unused fee backing remain attributed to the customer in the existing
  custody record. No synthetic spendable Aura balance is introduced. Any funding
  repair/top-up uses explicit customer backing and cannot raise the signed fee cap.
- Separate owed, prepared, broadcast, included, confirmed and recovery observations.
  Use an explicit operator confirmation requirement; choose no production value.
  Reorg invalidates confirmation, not earned compensation, retention, burn or
  authorization state. Recover by rebroadcast/replacement of the same obligation.
- Use the existing isolated Core regtest pattern with test-only funds. Live
  customer funds, fee defaults, wallet deployment and public activation remain
  outside this approval. Do not pay from the mining sponsor's separate reservation.

Alternative: a separately worker-signed payout-instruction contract could support
wallet address rotation and different destination scripts. It adds a new signature,
replay/authorization scope and destination-update lifecycle. Payment channels also
require their own custody/settlement design. Neither is required for the first
single-worker, single-obligation service. Direct output-key payment has less
contract surface but requires workers to use a compatible key/spending tool.

**Smallest decision needed:** approve the direct output-key destination and
anchor-free compute-obligation case in the shared Bitcoin publisher, with the
above net/fee/recovery guarantees. This does not approve live monetary activation.

## Bounded implementation order after approval

| Order | Work and closure evidence |
| --- | --- |
| 1 | Pin selected upstream source/toolchain and guest relation; define all adapter content/public-input/output bytes. Independent Rust/TS framing/commitment vectors, exact proof sample, parser bounds and mutations. No adapter registration until its contract checks pass. |
| 2 | Build isolated local CPU/GPU worker and independent verifier. Real requested proofs, actual backend evidence, bounded resource/deadline failures, denied secrets/network and malicious input tests. Record proof/verification cost and size at safe measured batch sizes. |
| 3 | Register the reviewed adapter in the existing coordinator; drive real signed job through funding/assignment/receipt/verification. Provide requester-authenticated retrieval of the retained proof. Test wrong requester, input/guest/output rebinding and single-receipt recovery. |
| 4 | Extend the existing publication owner for compute entitlements. Core regtest: full net worker output, signed fee ceiling, no automatic Aura effects, publication crashes/retries/replacements/reorg and no duplicate payment. Preserve miner publication regression. |
| 5 | Resolve accepted R and open the existing signed-side-bound mining round. Useful payment succeeds independently of qualification; separately demonstrate existing mining winner/bonus/anchor. No contender restriction or new target. |
| 6 | Run one reproducible C3 end-to-end gate and frozen C1/C2/Miner regressions. Only then promote implemented adapter/payment definitions into their existing owners, mark C3 DONE/C4 READY and stop. |

Customer delivery authentication must use the existing requester key and an exact
request scope before bytes are exposed; private signing material stays outside
the worker/prover. Any new signed transport bytes require distinct domains and
vectors. That transport authenticates access, not another result or proof identity.

The existing C1 rule already leaves the mining bonus with the existing round
winner; the result's worker is not automatically the winner or sole contender.
This is preserved, not reopened. Useful work and its payment remain available
even when the linked round never opens, expires or produces no qualified candidate.

## State and stop

C0/C1/C2 DONE. C3 IN PROGRESS, awaiting C3-D1/D2. C4–C10 BLOCKED.
This turn changes only this proposal and the slice register. No canonical owner,
code, dependency lock or fixture changed; no unchanged runtime gate was rerun.
Local links, scope and whitespace were checked. Backend soundness, isolation,
performance, real customer proof delivery and payment remain unproven until the
implementation gates run. Stop at these user decisions; do not select an easier
CPU-only or mock workload to claim C3 completion.
