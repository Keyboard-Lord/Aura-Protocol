# Bitcoin anchoring architecture decision

**Status: APPROVED FOR IMPLEMENTATION — DECISION RECORD**

Explicitly approved by the user in this task on 2026-09-07. The report contract
owns the implemented wire; this record preserves the decision and tradeoffs.

Prepared against baseline `c86f674306a4dc69bec3e7d0c69c4b54f9296a11`.
Approval authorizes implementation and isolated regtest validation, not spending real Bitcoin.

## Approved decision

Use reference anchoring using one zero-value OP_RETURN output per Aura
publication, local Aura verification, and observation through an operator-controlled
Bitcoin Core node. Bitcoin anchors the reference; it does not verify Aura
computation or enforce Aura authorization itself.

## Repository constraints

- The [report owner](../authoritative/AURA_REPORT_CONTRACT_V1.md) requires a
  canonical lowercase 64-hex proof reference without embedded upstream objects.
- [FractalKey](../../crates/aura_fractal_key_v1/src/lib.rs) produces a 32-byte
  reference binding subject, challenge, and proof material. Preserve its algorithm,
  domain, component order, and bytes.
- The [integration adapter](../../crates/aura_fractal_key_integration_v1/src/lib.rs)
  and [authorization owner](../authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md)
  currently bind Solana account identities and freshness. Renaming those fields
  cannot replace their authorization semantics.
- The [proof owner](../authoritative/AURA_STARK_SPEC_V1.md) and
  [Rust wire](../../crates/aura_sdk_v1/src/proof.rs) disagree. Shape validation is
  not proof verification. Publication must consume a result verified by the
  applicable Aura verifier, with checked proof-material binding.
- The active [Storm prover](../../crates/aura_intent_lineage_v1/src/stark_prover_v1.rs)
  uses witness replay. Anchoring does not upgrade it to a succinct or zero-knowledge
  STARK. Its retained cat-map STARK is separate legacy coverage.

## Options

| Mechanism | Fit | Tradeoff |
| --- | --- | --- |
| OP_RETURN reference | Public reference in one transaction output; closest fit to the reference-only requirement | Public data and transaction fees; off-chain proof availability; node-specific relay policy |
| Taproot commitment | Commit through an output-key/script-tree construction | Requires precise opening format, keys, UTXO lifecycle, and commitment discovery/disclosure |
| Witness reveal | Disclose data through a spending transaction | Funding/spending lifecycle and witness-aware retrieval; transaction inclusion alone does not authenticate witness contents |
| BitVM-related verification | Relevant if Bitcoin-enforced computation is required | Separate verification/dispute design, security assumptions, and operating roles beyond reference anchoring |

Recommendation: OP_RETURN. Aura needs a small proof reference anchored; this
avoids adding a spending condition or dispute protocol. Core supports data
outputs through its [wallet RPC](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/send/).
Taproot's construction is specified in [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).

## Approved contract and operational boundary

The user approved these choices for implementation:

- Payload: ASCII `AURA`, anchor-format byte `0x01`, network byte (`0x00` mainnet,
  `0x01` testnet3, `0x02` signet, `0x03` regtest, `0x04` testnet4), followed by the
  existing 32 proof-reference bytes. Exactly 38 payload bytes; script
  `OP_RETURN PUSH38 <payload>`; zero satoshis. The anchor version does not infer
  a proof version. Reject alternate push encodings, lengths, networks, and
  duplicate Aura outputs.
- Requests carry only anchor version, explicit network, and proof reference.
  RPC URL, wallet, fee rate/ceiling, and confirmation threshold are operational
  configuration outside canonical proof objects. Rust and TypeScript share strict
  encoding vectors. No new canonical hash.
- Funding/signing use Bitcoin Core wallet/PSBT facilities. Private keys stay out
  of protocol objects. Check the final signed transaction's output before
  publication. Fee replacement may change the transaction ID but not the Aura
  reference. Development funding and broadcast use isolated regtest only.
- Operators explicitly configure confirmation depth. Broadcast is pending;
  inclusion plus required depth on the configured node's active chain is a
  confirmed observation. Recheck against the active chain and revoke confirmation
  after reorgs. Do not claim irreversible finality.
- Store transaction ID, output index, block identity, and observation evidence
  separately from the canonical proof reference. Transaction IDs are transport
  evidence, not alternative Aura identities.
- The operator's validating Core node is the observation trust boundary; no
  mandatory third-party indexer or new SPV/header implementation. Retrieve using
  explicit block identity or wallet records and document historical-data
  requirements. Core's [gettxoutproof](https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/gettxoutproof/)
  describes indexing/UTXO limitations when a block is not supplied.
- Proof material stays off-chain. An anchor establishes reference publication,
  not proof availability, author identity, or computation validity. Duplicate
  publication cannot count as a second authorized Aura action.
- Local burn/accounting units remain separate from miner fees. No bridge, token,
  Bitcoin burn, or Bitcoin-enforced ledger is introduced.

## Separate prerequisite: authorization and proof boundary

Approving anchoring alone does not resolve account-bound proof preparation.
Before replacing that API, a bounded follow-on decision must specify subject
authentication and freshness/replay semantics, including exact binding bytes.
Preserve the FractalKey construction; do not silently reinterpret Solana account
bytes as Bitcoin public keys or outpoints.

Reconcile SDK proof wires with their owner without regenerating fixtures to hide
Rust/TypeScript drift. Cryptographic formula conflicts remain explicit defects;
this proposal does not authorize new hash or Storm semantics.

## Required acceptance evidence

Shared Rust/TypeScript vectors and negative parsing; verified-result binding;
signed-output checks; regtest funding, broadcast, mining, wrong-network rejection,
replay handling, and reorg revocation; removal of Solana from active dependencies
and commands; updated owning documents and fixtures; milestone verification.
Until those pass, migration is incomplete.
