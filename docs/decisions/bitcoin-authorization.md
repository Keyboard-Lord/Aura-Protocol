# Bitcoin authorization and freshness decision

**Status: APPROVED — AUTHORITATIVE FOR IMPLEMENTATION**

Explicitly approved by the user on 2026-09-07. The authorization owner defines
the implemented contract; this decision record preserves approval and tradeoffs.

The approved [anchoring decision](bitcoin-anchoring.md) explicitly leaves this
choice open. The user subsequently approved the BIP340 signed-nonce contract below.

## Decision resolved

Choose who authenticates Aura actions and where one-use freshness is enforced
after retiring Solana challenge accounts. This is required to connect verified
Aura results to the implemented Bitcoin anchor adapter.

Evidence at decision time:

- `crates/aura_fractal_key_integration_v1/src/lib.rs` supplies subject public-key
  bytes and challenge-account public-key bytes to FractalKey.
- `crates/aura_fractal_key_v1/src/lib.rs` binds those two 32-byte components plus
  the material hash into the existing proof reference. The construction itself
  need not change.
- `docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md` still names base58
  submitter/challenge bindings. The old Solana program enforces challenge use;
  the new OP_RETURN output provides no equivalent authorization enforcement.

## Options

| Choice | Benefit | Cost / trust boundary |
| --- | --- | --- |
| Retain application Ed25519 identities with signed nonces | Closest to the existing subject-key scheme; independent of settlement | Requires off-chain authorization and durable replay state; these identities are not Bitcoin wallet keys |
| Bitcoin BIP340 identities with signed nonces | Native Bitcoin Schnorr authentication with a 32-byte subject key; retains existing FractalKey component widths | Requires durable off-chain replay state; signature alone does not make a nonce globally single-use |
| Require consumption of a designated Bitcoin UTXO | Bitcoin consensus prevents spending the same outpoint twice in the active chain | Adds a funding/spending prerequisite, explicit subject-to-UTXO ownership rules, outpoint binding, reorg rollback, and possibly a transaction chain per subject |

**Recommendation: BIP340 identities with signed nonces**, if local/operator-scoped
authorization is acceptable. This fits the approved local-verification plus
reference-anchoring architecture and avoids adding a separate UTXO state protocol.
If global one-use enforcement by Bitcoin consensus is required, choose the UTXO
option instead; local replay state does not provide that property.

## Approved contract owner

The user approved the recommended BIP340 signed-nonce boundary on 2026-09-07.
[AURA_AUTHORIZATION_LINEAGE_V1](../authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md)
owns its single canonical v2 envelope, signing message, material/lineage checks,
and durable replay rules. Refer there for implementation requirements.

This approval preserves HASH, Storm, trace/proof semantics, proof-material hashing,
FractalKey serialization, UDOT derivation, and the approved OP_RETURN anchor.
No implicit conversion of legacy Solana authorization is authorized.

Signature semantics use [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

## Required completion evidence

Shared Rust/TypeScript vectors, negative mutations, actual proof/material/lineage
verification, durable replay and restart tests, idempotent retries, and authorization
through regtest anchoring are required. Those focused checks now exist; legacy SDK
entry-point retirement and the larger migration remain unfinished. Approval alone
is not migration completion.
