# AURA_CANONICAL_PIPELINE_V1

**Classification:** `ACTIVE AUTHORITY`
**Layer:** `L3`
**Purpose:** Own canonical pipeline dependencies and boundaries
**Status:** `BITCOIN AUTHORIZATION PATH IMPLEMENTED; INTEGRATION CLEANUP IN PROGRESS`

There is one canonical data path:

`execution inputs -> Storm claim / TRACE_ROOT -> canonical proof bytes -> proof_material_hash -> proof_hash -> authorization v2 -> Bitcoin anchor request`

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

## Verification and scope

`scripts/verify_bitcoin_foundation_v1.sh` covers shared anchor/authorization vectors,
strict rejection, proof/material/lineage binding and durable replay. Regtest uses
the Rust acceptance command before actual Core publication and verifies reorg retry.
The canonical command emits an anchor request only after successful admission.

Local execution, ledger and burn requirements remain owned by
[AURA_LEDGER_AND_BURN_V1](AURA_LEDGER_AND_BURN_V1.md). The SDK's proof/authorization
and Bitcoin transport checks do not themselves debit a ledger. End-to-end economic
integration is not established by the current authorization regtest and remains an
explicit integration discrepancy, not a claimed successful burn implementation.
