# C3 fixed Merkle workload — real proof evidence

Classification: IMPLEMENTATION EVIDENCE; NON-AUTHORITATIVE. Date: 2026-11-06.
Host: Apple M4 Pro (Mac16,8), 12 CPU cores, 16 GPU cores, 24 GB RAM,
macOS 27.2 (26B123), Xcode 27.2 (27B52), Apple Metal compiler
32023.922 (metalfe-32023.922.4, Metal Toolchain component 27B47,
downloaded via `xcodebuild -downloadComponent metalToolchain`).

This directory holds the first real succinct proof of the fixed C3
batch SHA256 Merkle-membership workload and its independent
verification. It is checkpoint evidence, not adapter registration,
not C3 completion and not a production performance claim.

## Pinned identities

| Item | Value |
| --- | --- |
| RISC Zero revision | `3bbcd44d6459b9ef6ac0df3846dc9215514934e8` (APPROVED pin, `workloads/merkle_risc0_v1/source-lock.json`) |
| Guest source | `workloads/merkle_risc0_v1/guest` + `crates/aura_compute_merkle_v1` |
| Guest toolchain | `r0.1.97.0` aarch64-apple-darwin tarball sha256 `85070d82aebbe8e1027e75f2cd0c781f5c82c0ae7e06697218be9d8b71dec15d`; rustc sha256 `0c103b8fff89933298ea4858dc777a52be022204057daf9d21945f6c4fdc62eb` |
| Host toolchain | Rust/Cargo `1.97.0` (rustup `1.97.0-aarch64-apple-darwin`, rustfmt component) |
| Guest ELF | `aura-c3-merkle-guest`, 181,160 bytes, sha256 `b419563e9bc9be867ace98585fe4f68d9baff9edb7b98745675f092636426bb5` — reproduced byte-identical by a clean rebuild (`build.py guest`, ~7 min) |
| Kernel | v1compat kernel sha256 `9dd8af014a24db3752b9beda71c837f553ff361fc1bca83cc79584bd38ac9de5` |
| Program image | 239,928 bytes, sha256 `eb1df7ac379a9b232595dce21d2fa1b072a95217c66286439d8c62212d3b0ab2` |
| ImageID | `6c81a254cf79e4ba5fb03b4d797d8838d2a9f92837c2ac35a90d941cb1ebda1d` (frozen as `IMAGE_ID` in `host/src/lib.rs`) |
| Control root | `517f405d5dbda85b2dc15f3ab6f8a05170bde64980ef594a8e9fd923febe1a03` |
| Verifier parameters | `556eeddcc0b9c119d11a3c8303bfba3dc380cbf6291951baf4206627497cc862` |
| Lift po2 / control | seal po2 = 18 (raw u32 at seal word 32), control index 2, control ID `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |

## Statement proved

- Job commitment: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- Input: `input.bin` = frozen vector case 2 (`vectors/batch3.bin`),
  456 bytes, batch count 3, tree depth 3, indices [0, 2, 7],
  input sha256 `e7c2c287ea6475e0e2927df22c9ee5540ba0b9c12f71bfb358104d5eacb6d07b`
- Journal (committed by the guest, bound by the receipt claim):
  `415552415f43335f4d45524b4c455f4a4f55524e414c5f5631000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f96acd7a7e6275698f2bb67d20088d111f31a048faa4e7bcfbd78787512a8f03ef907f23f76aa01b755a614d31ef9832909f44638b4590073301e61e6d01f9a1d03000000`
  — equals `cases[2].journal_hex` in `workloads/merkle_risc0_v1/vectors/batch-v1.json`.
- Successful halt `Halted(0)`, no unresolved assumptions, enforced by
  upstream `Receipt::verify` plus the exact expected claim/journal.

## Artifacts

| File | Content |
| --- | --- |
| `metal-proof.bin` | 223,114-byte encoded succinct receipt (222,668 seal bytes), sha256 `74dc3cc4582846edaa4d97dd838c49aaf620b70f3ae99d1c2c0d811b7d68a773` |
| `metal-proof.json` | prover stdout: mode, image, journal, sizes, timings |
| `metal-runtime.log` | `/usr/bin/time -l` output plus `AURA_METAL_*` observer events |
| `metal-independent-verification.json` | separate verifier-binary `verify` result |
| `cpu-proof.bin` | 223,114-byte CPU/Rosetta receipt, sha256 `09345d72229cda305a94db74c69fb807fa6f0d92bd201352a1d03c2915352915` (different bytes, same statement) |
| `cpu-proof.json`, `cpu-runtime.log` | CPU prover stdout and `/usr/bin/time -l` output |
| `cpu-independent-verification.json` | native aarch64 verifier result on the CPU proof |
| `cpu-selfarch-verification.json` | x86_64 verifier result on the CPU proof |
| `cross-arch-verification.json` | x86_64/Rosetta verifier result on the Metal proof |

Proof bytes are randomized per run; CPU and Metal proofs verify the
same statement but need not be byte-identical.

## Reproduction

```sh
# source pin check (verifies all 2,147 locked upstream files)
cd workloads/merkle_risc0_v1 && python3 build.py check

# guest toolchain: unpack the pinned r0.1.97.0 aarch64-apple-darwin
# tarball (sha256 above) to e.g. /tmp/aura-c3 and verify bin/rustc hash
python3 build.py guest --guest-rust /tmp/aura-c3   # -> guest ELF above

# host prover / verifier-only binaries (release, --locked)
python3 build.py prover                             # prove feature
python3 build.py verifier                           # no prove feature

# identities
./target/release/aura-c3-merkle-host inspect \
  guest/target/riscv32im-risc0-zkvm-elf/release/aura-c3-merkle-guest \
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  vectors/batch3.bin /tmp/unused.bin

# prove (native aarch64 selects Metal; observer optional)
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  env -i HOME="$HOME" DYLD_INSERT_LIBRARIES=/tmp/aura-c3/metal-observer.dylib \
  /path/to/prover prove <guest.elf> <job-hex> input.bin metal-proof.bin

# independent verification: separate verifier-only binary, fresh process
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  env -i HOME="$HOME" /path/to/verifier verify \
  <guest.elf> <job-hex> input.bin metal-proof.bin

# CPU reference (x86_64 under Rosetta; requires x86_64-apple-darwin
# target for Rust 1.97.0 and Xcode Metal/ Foundation link frameworks)
CARGO_TARGET_DIR=/tmp/aura-c3/target-x86 python3 build.py cpu
/tmp/aura-c3/target-x86/x86_64-apple-darwin/release/aura-c3-merkle-host \
  prove <guest.elf> <job-hex> input.bin cpu-proof.bin
```

`RUSTUP_HOME`/`CARGO_HOME` may be isolated; `build.py` strips
`RISC0_DEV_MODE`, `RISC0_PROVER`, `RUSTFLAGS` and rustc wrappers and
builds `--locked`. `RISC0_DEV_MODE` set in the environment fails closed.

## Measurements (single runs; not production figures)

| Run | Prove call (s) | Wall (s) | Independent verify (ms) | Max RSS (bytes) | Peak footprint (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Metal, native aarch64 | 46.28 | 46.95 | 11.0 (aarch64 verifier), 19.6 (x86_64/Rosetta verifier) | 1,907,867,648 | 3,161,114,376 |
| CPU, x86_64 under Rosetta | 479.23 | 485.79 | 15.7 (aarch64 verifier), 45.1 (x86_64 verifier) | 1,732,313,088 | 1,726,054,032 |

Single runs; not production figures. Two earlier prove attempts ran
~380 s wall each while the x86_64 reference build saturated the CPU;
the recorded Metal run is uncontended. Rosetta CPU proving is a
correctness reference with translation overhead, not a native CPU
performance claim. Observer log:
8,387 completed `MTLCommandBuffer`s with positive GPU intervals and
pipeline selections on `Apple M4 Pro` / `AGXG16XFamily` — actual GPU
dispatch evidence, not architecture inference. Seal size 222,668
bytes matches the qualification profile for this recursion circuit.

## Contract notes / limitations

- The lift po2 in the seal is execution-size dependent; the verifier
  range-checks it against the approved profile (12..=24,
  upstream `MIN_LIFT_PO2..=MAX_CYCLES_PO2`) and relies on the pinned
  control root plus the receipt's control inclusion proof to bind the
  exact lift program. Seal word 32 stores the **raw** po2 u32
  (`BabyBearElem::new_raw`), not a Montgomery element — an earlier
  draft compared against the Montgomery form and could never accept
  a real receipt.
- `IMAGE_ID` is now frozen in `host/src/lib.rs`; `prove`/`verify`
  reject any guest/kernel combination producing a different image.
  `inspect` still reports candidate identities for rebuild checks.
- Prover and verifier are separate binaries; `prove` is compiled out
  of the verifier (`--features prove` only on the prover build).
- Dev/fake rejection: `RISC0_DEV_MODE` fails closed; `FakeReceipt`
  cannot enter `encode_output`; malformed/truncated/trailing/foreign
  proof bytes reject in `ProofView::parse` before upstream work.
- Not done here: adapter registration, coordinator wiring, customer
  delivery auth, payment, isolation hardening beyond
  `sandbox-exec` network denial, and C4+ work.
