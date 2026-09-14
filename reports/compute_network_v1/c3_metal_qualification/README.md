# Reproducing the bounded upstream qualification

These are research harness/evidence files, not Aura SDK code, adapter wires or
dependency adoption. The reviewed source pin is
`3bbcd44d6459b9ef6ac0df3846dc9215514934e8`. No other revision is implicitly approved.
See [comparison and disposition](../../AURA_COMPUTE_C3_METAL_QUALIFICATION.md).

Use an isolated directory outside Aura. Obtain that exact official source revision
and its Git LFS objects. `source_review.json` records inspected source hashes and
the SHA-256/length of the seven LFS objects materialized for the build. The source
must otherwise be unmodified. The guest and v1compat kernel are included upstream.

Create a separate Cargo package from `Cargo.toml.template`, replacing `@UPSTREAM@`
with the absolute extracted source path. Make `src/main.rs` from `probe.rs` with
the same replacement. Copy `qualification-Cargo.lock` to `Cargo.lock`. The
qualification uses path dependencies into that exact source snapshot; never add
them to Aura's workspace. Use isolated `RUSTUP_HOME`, `CARGO_HOME` and
`CARGO_TARGET_DIR`, Rust 1.97.0 with rustfmt, and Apple's real Metal compiler.
Build with `cargo +1.97.0 build --release --locked`. Defaults are disabled;
`prove` and `disable-dev-mode` are enabled. Do not enable CUDA, dual, dev mode,
skip-kernel builds or remote proving.

The two backends use the same source, lockfile, harness, guest and kernel:

- Native `aarch64-apple-darwin`: the upstream segment and recursion constructors
  select Metal. Compile `metal-observer.m` with
  `xcrun clang -dynamiclib -fobjc-arc -framework Foundation -framework Metal`.
  Load it into the prover with `DYLD_INSERT_LIBRARIES`.
- CPU reference: build the same package with
  `--target x86_64-apple-darwin`, using the corresponding Rust target. Run through
  Rosetta on Apple Silicon. The unmodified upstream constructors select CPU.
  This is a CPU correctness reference with translation overhead, not a native
  CPU performance comparison.

The probe accepts `prove|verify|verify-negative USER_ELF RECEIPT_PATH`. For this
qualification, USER_ELF is exactly the upstream
`risc0/zkvm/src/host/server/testdata/jalr_addr_lowest_bit.bin`, combined by the
upstream `ProgramBinary` owner with the exact candidate's v1compat kernel.
It supplies no guest environment, host files, customer program or network input.
It sets segment power 16 and session cap 2^20, requires a real Succinct receipt,
and calls `Receipt::verify` before reporting success. Run it in a sanitized
environment and deny network access. The observed macOS command used
`sandbox-exec -p '(version 1)(allow default)(deny network*)'` and `env -i`.
This network denial is **not** a complete production volunteer-host sandbox.

Use `/usr/bin/time -l` to record wall time and process maximum RSS. Save stdout
JSON and stderr logs separately. `RISC0_LOG=1` identifies the C++ Metal path;
`RUST_LOG=info,risc0_zkp::hal::metal=debug` records recursion ZKP Metal operations.
Run `verify` in a fresh process without the GPU observer or any proving action.
Run `verify-negative` against the locally produced artifact. A conflicting
`RISC0_DEV_MODE=1` invocation must fail closed. Only the saved local artifact is
decoded by this harness; it is not a hostile-receipt parser implementation.

The observer does not generate or alter proof data. It wraps command-buffer
commit and pipeline selection, records completed-buffer GPU timestamps/status,
and calls the original implementations. It creates but does not commit its own
setup buffer and executes no kernels itself. Therefore successful GPU events
must come from the observed prover. Its logging adds overhead; separate cold
kernel compilation from warm measurements. Prover RSS excludes Apple's separate
Metal compiler services and may not capture all driver/unified-memory costs.

Do not interpret this minimal fixed guest as proof of the C3 batch-Merkle relation,
performance at production sizes, GPU/ASIC parity for arbitrary workloads,
cryptographic audit, canonical receipt freeze, or permission to register an adapter.
