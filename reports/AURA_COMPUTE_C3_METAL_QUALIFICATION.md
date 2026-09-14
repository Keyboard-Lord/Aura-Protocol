# C3-METAL-1 — RISC Zero revision qualification

Classification: NON-AUTHORITATIVE DESIGN / IMPLEMENTATION EVIDENCE.
Date: 2026-09-14. Minimal CPU/Metal qualification **PASS**; adoption **not** authorized.

Recommended exact pin for a separate adoption decision:
`3bbcd44d6459b9ef6ac0df3846dc9215514934e8`. It produced independently verified
CPU and actual-Metal succinct receipts for the same fixed statement. This
qualifies the backend mechanics, not the full C3 workload or deployment.

This records bounded upstream qualification, not C3 completion or adapter
registration. Aura dependencies, canonical contracts and frozen fixtures remain
unchanged. The controlling scope is recorded in the
[C3 decision record](AURA_COMPUTE_C3_CONTRACT_DECISIONS.md).

## Candidate order and disposition

| Revision | Immutable commit | Finding |
| --- | --- | --- |
| Reviewed baseline v3.0.5 | `8eb06ab020a92dc5b63ba6dd0836d432aba6d890` | Both circuit Metal selectors disabled. Source baseline, not a successful GPU backend. |
| Latest official stable v3.0.6, release-3.0 | `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` | Both circuit Metal selectors still disabled. Not eligible. Release fixes guest building with Rust 1.97; that does not restore Metal. |
| Official v2.3.2, release-2.3 | `218e3bc4a8ffcd203a9cd4e46f921bf60aa7e2bd` | Recursion has Metal, segment proving does not. Not eligible. The screened v2.0.2/v2.1.0/v2.2.0 selectors have the same gap. |
| Official v1.2.6, release-1.2 | `1866e2a1cce4fbfa3596a49818fed03c8c869044` | Both Metal paths exist, but this is an unsafe rollback from the reviewed security baseline. Rejected before building. |
| Official development commit, workspace 5.0.0 | `3bbcd44d6459b9ef6ac0df3846dc9215514934e8` | Both Metal paths selected in source. Selected for isolated runtime qualification; not a stable release or approved Aura dependency. |

The selected commit is dated 2026-07-20 and updates the guest-building Docker
image to Rust 1.97.0. Its parent is
`5e8ea443418b12663d9cdf0efa22a3c22063156b`. GitHub compares it to v3.0.5 as
**diverged: 274 commits ahead, 43 behind**. It is not safe to infer security
inheritance merely from version numbers or date. Relevant fixes and direct owners
were compared below. [Commit](https://github.com/risc0/risc0/commit/3bbcd44d6459b9ef6ac0df3846dc9215514934e8),
[stable release](https://github.com/risc0/risc0/releases/tag/v3.0.6).

The v1.2.6 fallback predates the `sys_read` guest-memory corruption fix. The
upstream advisory says prior guests are affected and need rebuilding. Its
succinct verifier also lacks the v3.0.5 seal/control-ID equality check, and its
fake-receipt path uses ambient dev-mode state rather than the newer explicit
verifier context. A successful old Metal run would not justify adopting it.
[Upstream advisory](https://github.com/risc0/risc0/security/advisories/GHSA-jqq4-c7wq-36h7).

No maintained Aura fork or source patch was created. Source archives were fetched
over HTTPS. Required Git LFS objects were materialized only after checking their
committed SHA-256 and length. The
[source manifest](compute_network_v1/c3_metal_qualification/source_review.json)
records direct-owner hashes, LFS hashes and relevant candidate-side commits.

The screened v3.0.6 receipt owner differs from v3.0.5 only by a Clippy allowance
on fake-receipt verification. Its unchanged disabled segment/recursion selection
is sufficient to reject it here; no CPU-only runtime qualification was substituted.

## Source and format comparison against v3.0.5

| Surface | Baseline | Selected candidate / implication |
| --- | --- | --- |
| Segment selection | CUDA or CPU; Metal branch commented out | `rv32im/src/prove.rs`: Apple aarch64 selects `ProverContext::new_metal`, then FFI GPU constructor, then C++ Metal HAL. No CPU fallback branch inside this selector. |
| Recursion selection | CUDA or CPU; Metal branch commented out | `recursion/src/prove/mod.rs`: Apple aarch64 selects Metal circuit HAL. CPU remains an explicit alternative on other targets; the qualification does not enable `cuda` or `dual`. |
| Metal kernels | Generic ZKP Metal code alone is insufficient | RV32IM C++ embeds `metal_kernel.metallib`; recursion includes `RECURSION_METAL_PATH`; generic ZKP includes `ZKP_METAL_PATH`. RV32IM dispatches witness, NTT, hashing and constraint kernels; recursion dispatches its constraint/accumulator kernels and generic ZKP operations. |
| Succinct envelope | Serde/Borsh `Receipt { inner, journal, metadata }`; succinct variant contains seal words, control ID, claim, hash function, verifier-parameter digest and inclusion proof | Same outer field and succinct-variant shapes. `get_seal_bytes` remains little-endian u32 flattening. This is **not** seal-byte compatibility: the underlying RV32IM circuit and lift programs change. Neither Serde nor Borsh automatically defines Aura's eventual canonical adapter output. |
| Other serialization | Assumption enum can recursively contain Composite receipts | Composite assumption variant removed; its remaining enum discriminants shift and recursive Composite nesting is eliminated. Do not deserialize older general receipt encodings as this format. C3 must accept only its separately bounded, pinned succinct profile. |
| Verifier entry | `Receipt::verify(image_id)` verifies integrity, exact successful claim and journal | Same entry-level obligations retained. Integrity-only verification still does not establish the expected image or successful halt. Candidate changes segment verifier and uses M3 lift programs; also changes a checked cast panic to a returned format error. |
| Image ID | Combined guest+kernel program image | Same conceptual image binding; loader/memory representation and kernel change. Rebuilt guests and candidate kernel require their own exact ImageID. No cross-version ImageID equality is assumed. CPU/Metal equality must use the same combined image. |
| Recursion control root | `a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56` | `517f405d5dbda85b2dc15f3ab6f8a05170bde64980ef594a8e9fd923febe1a03`; `lift_rv32im_v2_*` becomes `lift_rv32im_m3_*`; minimum lift power changes 14 to 12. |
| Default succinct verifier-parameter digest | `ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013` | `556eeddcc0b9c119d11a3c8303bfba3dc380cbf6291951baf4206627497cc862`. This requires an explicit newly pinned verifier contract. |
| Default composite verifier-parameter digest | `4bce006e0858edf3a3726987c0b1b6258224c000971e451bc9c05cfec086a84b` | `b1c96c8a61f25f73362e555c162ec717c0b838453c2cdeb216ca9b0ff951c68f`. Composite is internal to proving, not a second accepted C3 output. |
| Protocol strings | `RISC0_STARK:v1__`, recursion `RECURSION:rev1v1` | These strings remain the same despite changed control IDs. They alone cannot identify a compatible verifier. |
| Journal and halt | Exact journal digest, successful `Halted(0)`, empty unresolved assumptions for `verify` | Preserved at the receipt boundary. Segment claim decoding changes with M3; no-output journal restriction remains. The guest's exact public journal still needs C3 contract freeze. |
| Dev mode | `disable-dev-mode`; explicit context dev flag, empty context false | Retained. Conflicting `RISC0_DEV_MODE` fails closed, rather than silently producing acceptable fake proofs. Build both prover and verifier with this feature and reject non-succinct variants. |
| Parsing bounds | General recursive receipt decoding can overflow stack; vectors may allocate before verification | Removing Composite assumptions reduces recursion but does not bound allocation. Seal, journal, string, inclusion-path, claim and container lengths must be checked before unrestricted decoding. Qualification reads only its own bounded local artifacts; that is not the production adapter parser. |
| Recursion/assumptions | Composite recursively verifies attached assumptions, inheriting dev context | Context inheritance preserved; Composite assumption conversion now rejects. Ordinary successful `verify` continues to require the expected unconditional claim. No unresolved assumption may be accepted merely because a seal verifies. |
| Randomness | Recursion witness adds RNG noise; transcript challenges derived cryptographically | Candidate retains recursion RNG noise; segment prover is substantially replaced. Different real receipts may differ without changing the statement. No deterministic proof-byte promise, normalization, extra proof identity or new zero-knowledge assurance follows. |
| Dependencies/toolchain | Rust 1.89, edition 2021; zkVM 3.0.5, circuits 4.0.4, ZKP 3.0.4; Metal 0.29 | Rust 1.97.0, edition 2024; zkVM/circuits/ZKP 5.0.0; Metal still 0.29. New C++ RV32IM/FFI path, build-generated bindings, Metal compiler and metal-cpp SDK. Qualification lockfile is separate from Aura and upstream's workspace lockfile. |

Source anchors:
[RV32IM selector](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/circuit/rv32im/src/prove.rs),
[recursion selector](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/circuit/recursion/src/prove/mod.rs),
[C++ Metal HAL](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/circuit/rv32im-sys/cxx/hal/metal/hal.cpp),
[recursion Metal HAL](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/circuit/recursion/src/prove/hal/metal.rs),
[receipt](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/zkvm/src/receipt.rs),
[succinct verifier](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/zkvm/src/receipt/succinct.rs).

Metal proving still includes host execution and CPU work. In particular, the
recursion Metal circuit HAL calls the CPU witness generator, then uses actual
Metal constraint/accumulator and ZKP kernels. Qualification must demonstrate GPU
dispatch in the proof path; it must not describe the entire prover as GPU-only.

For the rejected old stable candidate, Metal uses `RV32IM_METAL_PATH` and
`recursion/src/metal.rs`. Its 1.2.6 receipt family and
`21a829e931cda9f34723dc77d947efe264771fea83bc495b3903014d0fe50d57` succinct
parameter digest are not v3.0.5-compatible. It supports compile-time dev-mode
disable, but lacks newer context and control-ID hardening and retains recursive
general-receipt parsing. Rust 1.85 / edition 2021 and the old guest ABI/kernel
would require a separate guest/image/verifier freeze. Its RNG behavior is not
runtime-qualified. No CPU/GPU timings or workload compatibility are claimed for
this rejected security rollback.

## Security deltas and limits

Direct source checks retain v3.0.5's no-output journal restriction, explicit
dev-mode inheritance, seal/control-ID equality, and checked transcript reads.
The candidate's input-read kernel chunks a checked user slice and rejects a
host response larger than the requested chunk. Host journal output remains
bounded at 100 MiB; that upstream maximum is not an approved Aura job limit.
The M3 host-read implementation checks pointer overflow and a 1,024-byte bound
before allocating its read buffer; host writes enforce the same I/O bound before
loading data. These are direct counterparts to the host-allocation hardening.

Relevant changes in the candidate's history include:

- #3351: guest input-read safety; #3545: bounded host allocation;
  #3564: bigint-address operator precedence; #3632: no-output journal binding;
  #3637: remove seal-driven assertion/index panics; #3654: explicit dev-mode
  inheritance; #3687: seal/control-ID equality. These match baseline hardening.
- #3682 removes recursive Composite assumption receipts; #3740 changes invalid
  field casting from panic to format error; #3641 adds verifier fuzzing support.
- M3-specific fixes include #3567 soundness/determinism, #3711 underconstrained
  EcallP2Block, #3732 JALR/bigint, #3736 bigint cycle order, and #3723 Keccak bounds.
  They demonstrate that this is a different circuit lineage, not a Metal-only patch.
- #3688 enables Metal; #3721 fixes M3 Metal behavior. #3776 attempts to skip
  unavailable Metal build tools. Locally, missing `metallib` generated a placeholder
  and then failed the RV32IM build. A successful build with empty skipped kernels
  must never be accepted as GPU qualification.

Exact commit hashes for these changes are in the source manifest. This is a
bounded review of direct security/compatibility surfaces, not a new independent
cryptographic audit of every M3 constraint or transitive dependency. Upstream's
open zero-knowledge advisory prevents treating randomized receipt bytes as proof
of confidentiality. The approved PUBLIC/SANDBOXED workload makes no confidentiality
claim. [Upstream zero-knowledge advisory](https://github.com/risc0/risc0/security/advisories/GHSA-5xgj-pmjj-gw49).

## Local qualification evidence

[Machine-readable results](compute_network_v1/c3_metal_qualification/results.json),
[raw receipts/logs](compute_network_v1/c3_metal_qualification/raw),
[build evidence](compute_network_v1/c3_metal_qualification/build_evidence.json),
and the [reproduction harness](compute_network_v1/c3_metal_qualification/README.md)
record the completed minimal qualification. Build artifacts were isolated under
`/tmp/aura-c3-qualification`; no Aura dependency manifest or lockfile was changed.

Environment: Apple M4 Pro, 12 CPU cores (8 performance/4 efficiency), 16 GPU cores,
24 GB RAM, macOS 26.6.2 (25G83), Xcode 26.6 (17F113), Apple Metal compiler
32023.883 / component 17F109. Rust 1.97.0 is installed in an isolated Rustup/Cargo
home. Apple's missing Metal component was downloaded/registered as build tooling.

The minimal statement uses upstream's fixed JALR-low-bit guest plus the exact
candidate's v1compat kernel, a successful halt and empty journal. It tests real
proving/backend/verifier mechanics. It is not the batch Merkle workload, a
registered adapter, an arbitrary-customer-ELF service, or a C3 acceptance result.
Session limit is 2^20 cycles; segment limit is 2^16. No remote prover or dev mode.

| Run | Prove call + local serialization (s) | Entire process wall (s) | Independent native verification (ms) | Max process RSS (bytes) | Peak process footprint (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Metal, cold | 273.991 | 275.87 | 18.13 | 456,982,528 | 2,493,465,656 |
| Metal, warm | 2.401 | 2.50 | 15.61 | 540,622,848 | 2,483,504,232 |
| CPU reference, x86_64 under Rosetta | 14.751 | 19.19 | 15.56 | 1,533,489,152 | 1,526,741,784 |

Each receipt is a real **Succinct STARK**, with **222,668 seal bytes** and
**223,226 bytes** in the qualification harness's bincode artifact. The artifact
format is measurement evidence, not Aura's future canonical receipt contract.
Independent verification ran in fresh processes without the GPU observer.
The separate x86_64 verifier also accepted the Metal receipt (18.76 ms).

This is one run per condition, not a statistical throughput study. The cold Metal
run includes substantial first-use Apple kernel compilation and overlaps part of
the CPU build. Warm timing includes instrumentation; CPU timing includes Rosetta.
Do not use their ratio as a native CPU-versus-GPU performance claim. Process RSS
and footprint exclude Apple's separate compiler services and do not establish
total unified-memory use. One cold-start sample found compiler-service RSS of
3,202,000 and 2,922,640 KiB in addition to the prover. No production capacity,
fee, workload bound or timing guarantee is selected from these measurements.

Backend evidence for **each** Metal run:

- The unmodified Apple-aarch64 segment and recursion selectors were inspected.
- Nonempty RV32IM (8,452,681 bytes), recursion (1,716,943 bytes) and generic ZKP
  (116,305 bytes) Metal libraries compiled; their hashes are recorded.
- The C++ log records Apple M4 Pro selection, witness generation and constraint
  checking. The recursion path records operations from `risc0_zkp::hal::metal`.
- The external observer recorded **619 completed command buffers**, all status
  4, with positive GPU start/end intervals, and **800 pipeline selections**.
  Events occur during RV32IM witness/constraint processing and during recursion
  Metal processing. This is runtime GPU execution evidence, not architecture
  detection or library presence. Pipelines were unlabelled; the observer does
  not claim to recover a complete per-kernel performance breakdown.
- The observer neither creates proof data nor submits any setup kernels. Both
  generated receipts passed the independently invoked pinned verifier.

The CPU binary required explicit final-link `Metal` and `Foundation` frameworks:
upstream compiles a C++ Metal object on macOS even for x86_64, but does not emit
those link flags in that configuration. Only harness link arguments changed;
neither backend selector nor upstream source was patched. The x86_64 segment and
recursion constructors select their CPU implementations. Its receipt was verified
by the native verifier, and the Metal receipt was verified by the x86_64 verifier.

All three real receipts verify the same statement:

- ImageID: `04a1e43795245bd79dff61e2a90b258dc7bc3e278b59a8d39b542808f5541c28`.
- Empty journal, successful `Halted(0)`, no unresolved assumptions, enforced by
  `Receipt::verify` and its exact expected claim comparison.
- Control ID: `85cce34af124324c4d198906d16a671e7484d44c8b9beb53f6400e177f7d4562`.
- Verifier-parameter digest: the candidate digest recorded above.

Their receipt SHA-256 values are all different. These hashes identify saved
qualification artifacts only; they are not Aura proof identities. The two Metal
runs demonstrate output variability for one statement; they do not establish a
cryptographic randomness distribution or confidentiality property.

Focused negative checks passed independently against the CPU and cold-Metal
receipts: changed journal, changed seal, empty seal, changed control ID, changed
metadata parameters, changed inner parameters, fake receipt and wrong ImageID.
All sixteen checks returned rejection without a verifier panic. A conflicting
`RISC0_DEV_MODE=1` failed closed with exit 101 at the explicit configuration guard.
This expected configuration panic is distinct from hostile-receipt rejection.

The earlier automatic approval-review usage failure interrupted verification,
not proving. After usage became available, the same authorized checks completed.
No remaining tool-approval blocker is hidden in this result.

## Compatibility and adoption boundary

The approved fixed SHA256 batch Merkle relation remains implementable in this
zkVM direction, but this qualification does not freeze or prove that guest.
Adoption would require pinning/rebuilding its guest and kernel, ImageID, control
root, verifier parameters, exact succinct serialization, parser limits and
positive/negative vectors. No adapter may register before that gate.

Changed RISC Zero proof bytes change the C2 output commitment and therefore its
single compute-result commitment. If used for mining, that legitimately changes
the signed inputs and downstream Aura proof identity for that new computation.
It does not change the C1/C2 algorithms, frozen prior results, MinerJobV1,
HASH_V2, Storm, FractalKey, proof_hash, authorization, economics or Bitcoin wire.
Different randomized receipts must not be normalized into a substitute identity.

## USER_DECISION — exact-pin adoption

**Conflict:** v3.0.5 cannot provide the approved Metal path. The qualified candidate
has working Metal but belongs to a changed RV32IM circuit/verifier lineage.

**Existing approved behavior:** the fixed batch Merkle workload, succinct receipt,
real local Metal plus CPU reference, independent pinned verification, bounded
parsing, no confidentiality claim, and all frozen Aura semantics remain required.
Qualification approval expressly withheld dependency adoption.

**Required alternative:** use official upstream commit
`3bbcd44d6459b9ef6ac0df3846dc9215514934e8` for C3, with its exact new guest/kernel,
ImageID, control IDs and verifier parameters and a separately frozen adapter
receipt contract. It is a development revision, not a stable release.

**Smallest decision needed:** approve that exact pin for C3 implementation and
workload/proof-contract freeze, accepting the documented upstream format/verifier
changes. This does not itself approve adapter registration, C3 closure, public
workers, live funds or any change to frozen Aura outputs.

**Recommended option:** approve this upstream pin for the remaining bounded C3
work. It retains the reviewed safeguards examined here and has direct local
CPU/Metal evidence. An old vulnerable release or a maintained Aura prover fork
is not warranted by the evidence. The full C3 workload, parser/isolation,
delivery/payment, optional mining and regression gate must still pass.

C3 remains IN PROGRESS and C4 remains BLOCKED. Stop here for the adoption decision.
