# Retired Solana implementation

**Classification: LEGACY / NON-AUTHORITATIVE**

This separate Cargo workspace preserves the old program and consumers as historical
evidence. It is excluded from the active Aura workspace and its lockfile. Its
`solana-client` patch is scoped here.

Members:

- `program/`: former root `aura_protocol`, including its historical tests.
- `../../crates/aura_submission_client_v1`: old Rust publication client.
- `../../crates/aura_cli_v1`: old `aura` CLI, including intent/proof/settlement commands.
- `../../crates/aura_reference_demo_v1`: old submission demo.

The TypeScript counterpart remains at `packages/aura_submission_client_v1_ts`.
Retired SDK wires are explicit `legacy` imports in Rust and TypeScript. They are
not v2 authorization objects and are never automatically converted into them.

Historical build entry:

```
cargo check --manifest-path legacy/solana/Cargo.toml -p aura_protocol
cargo test --manifest-path legacy/solana/Cargo.toml -p aura_protocol --test runtime_validation --test fractal_key_submit_e2e
```

The active repository gate does not run these commands or require their dependency
cache. Historical repository-hardening tests include assertions about former
repository structure; they are evidence of those historical expectations, not the
current authority hierarchy or a current release gate.

Use `aura_sdk_v1`'s `aura-authorizer` binary and the Bitcoin adapter for the active
boundary. The approved contracts remain in `docs/authoritative/`.
