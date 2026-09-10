# AURA_CANONICAL_PIPELINE_V1

**Classification:** `ACTIVE AUTHORITY`
**Layer:** `L3`
**Purpose:** Own canonical pipeline dependencies and boundaries
**Status:** `BITCOIN ECONOMIC ADMISSION IMPLEMENTED`

There is one canonical production path:

`signed work -> durable admission/debit -> local work -> Storm claim / TRACE_ROOT -> canonical proof bytes -> proof_material_hash -> proof_hash -> full authorization v2 -> atomic terminal head/authorization/outbox -> Bitcoin anchor`

UDOT is a deterministic presentation derived from the same `proof_hash`, owned by
[AURA_ARTIFACT_STRUCTURE_V1](AURA_ARTIFACT_STRUCTURE_V1.md). It supplies no alternate
proof identity and is not required to establish proof soundness.

The earlier ordering put material hashing before creation of the proof bytes it
hashes. That ordering is not executable. The order above follows the existing byte
and verification dependencies without changing cryptographic semantics.

## Owners and representations

| Stage | Single owner and output |
| --- | --- |
| Execution inputs, Storm and trace commitment | `aura_intent_lineage_v1`: existing `StormExecutionInputsV1`, `StormClaim521V1`, canonical trace layout and `TRACE_ROOT` |
| Economic work, consent and durable lifecycle | `aura_sdk_v1::economic`; W below, consent/metering/lifecycle in [AURA_LEDGER_AND_BURN_V1](AURA_LEDGER_AND_BURN_V1.md) |
| Proof | Existing canonical Storm witness-backend proof bytes in `stark_prover_v1.rs`; compact public inputs are derived from that claim |
| Material and bound reference | `aura_proof_material_v1` and `aura_fractal_key_v1`; exact bytes in the artifact owner |
| Authorization | `aura_sdk_v1::authorization`; envelope and replay rules in [AURA_AUTHORIZATION_LINEAGE_V1](AURA_AUTHORIZATION_LINEAGE_V1.md) |
| Settlement | `aura_bitcoin_v1::BitcoinAnchorRequestV1`; wire and Core transport in [AURA_REPORT_CONTRACT_V1](AURA_REPORT_CONTRACT_V1.md) |

The existing proof wire contains its claim and witness. Derived proof-artifact
metadata is reconstructed by its owning decoder; decoding is not verification.
Authorization acceptance invokes the actual verifier, reconstructs the bound proof
reference, checks lineage and signature, and commits replay state before returning
an anchor request. A shape-only proof envelope never grants acceptance.

The current Storm backend is witness replay, not a succinct zero-knowledge STARK.
The retained cat-map Winterfell backend is a separate historical implementation;
a migration must not silently substitute it for Storm or claim it proves Storm.

## Canonical boundary rules

Required fields, versions, lowercase hex and network selection are explicit.
Reject missing, extra, malformed or mismatched canonical fields without normalization.
No canonical authorization or anchor wire embeds an upstream proof, UDOT bundle,
compatibility claim, or alternate representation of the same concept. Actual proof
bytes are supplied separately to the verification owner.

Legacy conversion is never canonical entry. The retired Rust SDK wires are under
`aura_sdk_v1::legacy`; TypeScript equivalents are under `src/legacy/solana.ts` and
`legacy`. Their old `StarkProofEnvelopeV1`, nested authorization/settlement objects,
and `fixtures/v1/canonical_pipeline_v1/` are historical evidence only.

Core derivations are deterministic for fixed canonical inputs. Nonce generation,
BIP340 signing randomness, journal admission, funding and chain observation are
explicit operational steps; they do not redefine canonical proof identity. Re-signing
an action or observing a reorg cannot create a new nonce reservation.

## Approved economic work boundary

The caller supplies configured Bitcoin network, binary work `W`, separate
`EconomicConsentV1`, and the existing `AuthorizationEnvelopeV2`. Consent is owned
by [the economic owner](AURA_LEDGER_AND_BURN_V1.md). Work has exactly one encoding:

```text
ASCII("AURA_ECONOMIC_WORK_REQUEST_V1")
|| u64_le(len(M)) || M
|| side_a_110 || side_b_110 || context_bytes_v1_209
|| u64_le(iteration_count)
```

`M` is decoded by the existing ledger/metering owner. The remaining tuple uses
existing `StormExecutionInputsV1` bytes; no new side-input derivation, inferred
intent preimage, duplicated proof or JSON work representation is introduced.
The payer in `M` equals the valid x-only key in context `controller_id`. Context
intent, nonce and controller equal Authorization V2 lineage. Explicit operator
work-byte, meter-byte and iteration bounds apply before expensive execution.

Rust `aura_sdk_v1::economic::EconomicWorkV1` and TS `economicV1.ts` own this framing.
They require exact length and round-trip equality. The client prepares the existing
deterministic proof reference and both signatures before submission; the service
debits before performing its own work and proof verification. Its Storm builder
uses the existing zero-filled historical commitment slots, as pinned by the active
authorization vector. The fixed V1 claim layout and all V1 proof bytes remain
unchanged. Other historical slot values are not inferred from W.

`EconomicJournalV1` owns the durable production coordinator. Standalone proof,
signature and replay-journal helpers remain primitives and do not constitute
economic admission. Success requires local execution/attestation validation,
actual Storm proof/material/lineage validation and local settlement context checks.
Only the Accepted finalization transaction writes a Bitcoin outbox request.

## Verification and scope

`scripts/verify_bitcoin_foundation_v1.sh` covers shared anchor/authorization vectors,
strict rejection, proof/material/lineage binding and durable replay. Regtest uses
the Rust acceptance command before actual Core publication and verifies reorg retry.
`aura-economic` supplies bounded init/admit/submit/resume/outbox operations; Core
publication consumes the outbox's unchanged Bitcoin request. Diagnostic command
responses are journal views, not new proof, consent or Bitcoin wire formats.

Local execution, ledger and burn requirements remain owned by
[AURA_LEDGER_AND_BURN_V1](AURA_LEDGER_AND_BURN_V1.md). The SDK's proof/authorization
and Bitcoin transport primitives do not themselves debit a ledger. The economic
regtest exercises consent, durable debit, restart, actual verification, atomic
head/authorization/outbox, Bitcoin publication and reorg retry without another burn.
