# AURA_REPORT_CONTRACT_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L3`  
**Purpose:** Own the Bitcoin anchor request and publication contract

**Status:** `ACTIVE — PIPELINE INTEGRATION INCOMPLETE`

Bitcoin OP_RETURN reference anchoring was explicitly approved in this task.
This document owns the wire; the [decision record](../decisions/bitcoin-anchoring.md)
preserves the rationale. Bitcoin records the reference, not an Aura proof verdict.

## Canonical request

`BitcoinAnchorRequestV1` contains exactly:

- `anchor_version`: the string `v1`
- `network`: `mainnet`, `testnet3`, `signet`, `regtest`, or `testnet4`
- `proof_hash_hex`: canonical lowercase 64-hex, carrying the existing proof reference

All fields are required and non-null. Unknown fields and non-canonical strings
are rejected without normalization. There are no embedded proof, authorization,
UDOT, RPC, wallet, or fee objects. Proof-reference derivation remains owned by
[AURA_ARTIFACT_STRUCTURE_V1](AURA_ARTIFACT_STRUCTURE_V1.md); this adapter does not
recompute or replace it.

## Bitcoin output

The payload is exactly 38 bytes:

| Bytes | Meaning |
| --- | --- |
| 0..4 | ASCII `AURA` |
| 4 | Anchor format `0x01` |
| 5 | Network: mainnet `0x00`, testnet3 `0x01`, signet `0x02`, regtest `0x03`, testnet4 `0x04` |
| 6..38 | The 32 bytes decoded from `proof_hash_hex`, in their existing order |

The output has zero satoshis and exactly the script `0x6a 0x26 <payload>`.
The anchor format version does not infer a proof version.

A transaction must have exactly one matching Aura output. Change and unrelated
outputs are permitted. An OP_RETURN output whose first push location begins with
ASCII `AURA` is treated as an Aura candidate, including non-minimal PUSHDATA1/2/4
forms. All candidates must pass canonical decoding; malformed or duplicate Aura
outputs are rejected. The accepted output must match the expected network and
proof reference. Nonzero values, alternate push encodings, trailing bytes,
unknown network tags, and unsupported versions are invalid.

## Verification and publication boundary

A canonical Aura pipeline must verify its proof, bind its material to the expected
reference, and authorize the operation before publication. A valid request or
transaction output is not sufficient evidence of those checks. The current Core
transport is a low-level implementation; its functions do not perform Aura proof
verification or authorization. The [authorization owner](AURA_AUTHORIZATION_LINEAGE_V1.md)
performs those checks and durably reserves the nonce before producing this request.
The older Solana SDK pipeline is isolated under explicit legacy entry points.

Operational configuration supplies the Core endpoint/wallet, explicit fee rate,
maximum fee in satoshis, and confirmation threshold. Funding and signing use
Core PSBT facilities. Inspect the final transaction's decoded outputs; immediately
before broadcast, check mempool acceptance and its actual fee against the ceiling.
Transaction IDs are transport evidence, never alternative Aura identities.

No Bitcoin fee payment implements Aura's local burn accounting. Codec/transport
errors return failures without debiting an Aura ledger. Local accounting is owned
by [AURA_LEDGER_AND_BURN_V1](AURA_LEDGER_AND_BURN_V1.md).

## Observation

The operator-controlled validating Core node is the chain-observation trust
boundary. The implemented observer retrieves a wallet transaction, checks the
actual decoded outputs and transaction ID, and checks block inclusion using an
explicit block hash. It needs wallet history and the relevant block data; it does
not require a third-party indexer or `txindex`.

Broadcast/unconfirmed transactions are pending. Positive inclusion below the
configured depth is included; meeting the depth is confirmed. Conflicted wallet
transactions are reported as conflicted. These are operational observations,
not canonical request fields. Every observation is recomputed from Core, with
active-chain block identity and stable-tip checks. Reorgs revoke prior confirmation;
a moving tip fails the observation for retry. Confirmation is not irreversible
finality. Callers must persist and refresh observations rather than treating a
stored confirmation as permanent.

An anchor alone establishes neither off-chain proof availability nor author
identity. Duplicate publication must not count as a new authorized Aura action;
that enforcement belongs at the authorization boundary, not in output decoding.

## Implementation and evidence

- Rust codec/output validation: `crates/aura_bitcoin_v1/src/lib.rs`
- Matching TypeScript codec: `packages/aura_bitcoin_v1_ts/src/index.ts`
- Core PSBT/publication/observation: `packages/aura_bitcoin_v1_ts/src/coreRpc.ts`
- Shared vectors: `fixtures/bitcoin_v1/anchor_vectors_v1.json`
- Focused gate: `bash scripts/verify_bitcoin_foundation_v1.sh`
- Regtest: `BITCOIND=/path/to/bitcoind node scripts/verify_bitcoin_regtest_v1.mjs`

Regtest verifies an actual Aura proof, material and BIP340 authorization through
the Rust journal before anchoring its reference, then checks persistent retry after
a reorg. Solana SDK wires and `fixtures/v1/canonical_pipeline_v1/` remain legacy
evidence; they no longer define the canonical settlement wire. The active Cargo
workspace excludes the Solana program and submission clients. Economic integration
remains a separate migration requirement owned by the ledger and pipeline documents.
