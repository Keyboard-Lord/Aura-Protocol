# AURA_CONTINUOUS_SETTLEMENT_V1

**Classification:** `ACTIVE AUTHORITY`
**Layer:** `L4`
**Purpose:** Own local economic settlement head progression
**Status:** `APPROVED V2; DURABLE COORDINATOR IMPLEMENTED`

The filename remains the stable registry identity. The current approved head
version is explicitly 2. This local head is distinct from the Bitcoin anchor wire
and from all Storm/proof/material/FractalKey identifiers.

## Construction

Consume the durable prior head, configured Bitcoin network, exact work W, admitted
terminal outcome and pre/post debit ledger snapshots. W and its metering are owned
by [the pipeline](AURA_CANONICAL_PIPELINE_V1.md) and [ledger](AURA_LEDGER_AND_BURN_V1.md).
The metered head linkage must agree with the derived predecessor hash and sequence;
it is signed evidence, never a caller-selected construction parameter.

```text
outcome_byte = Accepted:0 | ExecutionRejected:1 | VerificationRejected:2 | SettlementRejected:3
n = checked_u64(prior_head.head_sequence_number + 1)
C = SHA256(
  "AURA_ECONOMIC_HEAD_COMMITMENT_V1" || u32_le(2) || network_byte
  || prior_head.current_head_hash32 || u64_le(n)
  || u64_le(len(W)) || W || outcome_byte
  || pre_ledger_commitment32 || post_ledger_commitment32 || u64_le(B)
)
H = SHA256("AURA_ECONOMIC_HEAD_V1" || u32_le(2) || u64_le(n) || C)
```

The ledger owner supplies the unchanged payer-bound commitments and checked debit.
The post-debit snapshot must equal that exact debit; every admitted terminal outcome
advances the same head chain and retains the full charge.

## Head representation

Exactly five required fields:

| Field | Encoding |
| --- | --- |
| `settlement_head_version` | JSON integer 2 |
| `head_sequence_number` | Unsigned decimal u64 string; no sign or leading zero except `0` |
| `previous_head_hash_hex` | 32-byte predecessor hash, lowercase hex |
| `canonical_head_commitment_hex` | C, 32 bytes, lowercase hex |
| `current_head_hash_hex` | H, 32 bytes, lowercase hex |

Reject missing, extra, malformed and overflowing values. Validate the head hash;
validating a head in isolation does not prove the transition that produced it.
Transition construction checks its work, predecessor and debit inputs as well.

## Initialization and recovery

Explicitly initializing a new journal pins its starting ledger and a V2 genesis
head with sequence `0` and all three hash fields zero. Missing or corrupt state
never triggers implicit genesis, refund or nonce release.

Explicit V1 migration imports the exact old sequence/current hash as a trusted
predecessor checkpoint, its matching ledger and complete authorization history.
The first V2 transition uses that unchanged hash and checked sequence plus one.
Never relabel a V1 head as V2 or recompute historical bytes. Initialization is
persisted once; reopening cannot reapply a checkpoint. `EconomicJournalV1::migrate_v1`
extends an existing BIP340 authorizer journal in place, preserving its authorization
table. The operator supplies the trusted matching V1 head/ledger checkpoint; this
does not convert historical Solana authorizations into V2 objects.

## Owners and evidence

- Rust: `crates/aura_sdk_v1/src/economic/head.rs`.
- TypeScript: `packages/aura_sdk_v1_ts/src/economicV1.ts`.
- Shared codec vector: `fixtures/economic_admission_v1/contract_vector.json`.

The prior local-runner V1 head format hashes fixture-oriented request/report
material. Its stateless and persistent modes remain historical compatibility in
`aura_l2_local_chain_v0`; `fixtures/l2_canonical_pipeline_v1/continuous_chain_v1/`
protects those old outputs. They do not define successor construction or prove
V2 journal integration. Bitcoin publication failures and reorgs affect publication
or confirmation, never the already terminal economic head or authorization history.
