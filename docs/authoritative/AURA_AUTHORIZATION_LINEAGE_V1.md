# AURA_AUTHORIZATION_LINEAGE_V1

**Classification:** `ACTIVE AUTHORITY`
**Layer:** `L4`
**Purpose:** Own canonical authorization identity, signature and replay acceptance
**Status:** `APPROVED V2 CONTRACT; LEGACY WIRES ISOLATED`

The filename is stable registry identity; the canonical envelope version is explicitly
`v2`. The [approved decision](../decisions/bitcoin-authorization.md) records the
choice and tradeoffs. It does not define a second encoding.

## Canonical envelope and lineage

`AuthorizationEnvelopeV2` has exactly these required fields:

| Field | Representation |
| --- | --- |
| `authorization_version` | `v2` |
| `proof_hash_hex` | 32 bytes, lowercase hexadecimal |
| `authorization_lineage` | The six-field object below |
| `signature_hex` | 64-byte BIP340 signature, lowercase hexadecimal |

`authorization_lineage` has exactly these required fields:

| Field | Representation |
| --- | --- |
| `subject_binding_type` | `bip340-xonly-pubkey-hex` |
| `subject_binding` | Valid BIP340 x-only public key, 32 bytes, lowercase hexadecimal |
| `intent_type` | `opaque-intent-hash-32` |
| `intent_commitment_hex` | Intent commitment, 32 bytes, lowercase hexadecimal |
| `freshness_binding_type` | `nonce-32-hex` |
| `freshness_binding` | Cryptographically random nonce, 32 bytes, lowercase hexadecimal |

Missing, extra, malformed and legacy fields are invalid. There is no envelope-level
`intent_id_hex`, implicit version inference, normalization, nested proof, or settlement
object. The intent identity exists only in lineage. Randomness is the nonce producer's
obligation; a verifier cannot establish how supplied bytes were generated.

## Signature and proof binding

The BIP340 message is the tagged SHA-256 digest with tag `AURA_AUTHORIZATION_V2`
of `network_byte || proof_hash_bytes || intent_commitment_bytes`. The network byte
is owned by [the report contract](AURA_REPORT_CONTRACT_V1.md) and supplied explicitly
by authorizer policy. This digest is internal, not another public Aura identifier.

Acceptance verifies the signature, the actual Aura proof, proof/material identity,
and lineage before checking or reserving replay state. Shape or signature validation
alone is insufficient. The active Storm witness backend uses its existing canonical
proof bytes, compact public-input bytes, and empty external verification-key bytes
(it has no external key) as the three existing ProofMaterial inputs. Material hashing
and FractalKey serialization are unchanged. Subject bytes feed FractalKey's subject
component; nonce bytes feed its existing challenge component. Reconstructing the
FractalKey must produce the signed `proof_hash_hex`.

The existing Storm context's `intent_hash`, `freshness_nonce`, and `controller_id`
must equal the lineage's intent, nonce and subject, respectively. No context layout,
Storm derivation, trace root or proof semantic changes are authorized here. The
Bitcoin network scopes the signature and replay reservation; the existing Storm
`network_id` remains an application context field, with no inferred Bitcoin mapping.

## Durable acceptance

Reserve `(network, subject, nonce)` atomically before publication. The same proof
reference and intent is an idempotent retry, even with a different valid signature.
A different action using the same key fails. Publication failure and Bitcoin reorgs
retain the reservation; reorgs change anchor confirmation only.

The Rust owner uses an explicitly created SQLite journal, immediate transactions,
full synchronous durability and a uniqueness key. Reopening a missing, corrupt or
unrecognized journal fails; operators must recover its history. There is no automatic
empty replacement or reservation release API. All cooperating authorizers must use
the same journal or coordinated equivalent. No global nonce-uniqueness claim extends
across independent journals. Backup restoration must preserve all accepted history.
Iteration and input-size limits are explicit admission resource policy, not new
cryptographic protocol limits.

## Implementation and evidence

- Rust owner: `crates/aura_sdk_v1/src/authorization.rs`.
- TypeScript signing, signature and material checks: `packages/aura_sdk_v1_ts/src/authorizationV2.ts`.
  Actual proof verification and durable acceptance are owned by Rust.
- Shared vector: `fixtures/authorization_v2/authorization_vector_v2.json` (public test-only secret and nonce).
- Admission command (`cargo run -p aura_sdk_v1 --bin aura-authorizer --`): `crates/aura_sdk_v1/src/bin/aura-authorizer.rs`.
  `init JOURNAL` creates a journal; `accept JOURNAL NETWORK AUTHORIZATION_JSON PROOF_BYTES MAX_ITERATIONS MAX_PROOF_BYTES`
  emits only the canonical anchor request after successful acceptance. Decoding proof
  metadata is not verification; the command invokes the full acceptance owner.
- Focused gate: `scripts/verify_bitcoin_foundation_v1.sh`.
- Authorization through actual Bitcoin Core regtest, including reorg/restart retry:
  `scripts/verify_bitcoin_regtest_v1.mjs` with explicit `BITCOIND`.

Solana authorization objects and `fixtures/v1/canonical_pipeline_v1/authorization_intent_v1.json`
are legacy evidence only. They are accessible only through the explicit Rust/TypeScript `legacy` entry points
and do not implement this contract. They must never
implicitly convert into canonical v2 authorization.
