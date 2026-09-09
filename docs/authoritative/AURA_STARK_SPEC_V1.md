# AURA_STARK_SPEC_V1

**Classification:** `ACTIVE AUTHORITY`
**Layer:** `L2`
**Purpose:** Own the existing Storm proof representation and verification boundary
**Status:** `WITNESS BACKEND IMPLEMENTED; SUCCINCT STARK NOT IMPLEMENTED FOR STORM`

The stable document name does not imply a capability the active backend lacks.
Nonlinear Storm currently uses canonical witness transport and replay verification.
The separate historical cat-map Winterfell backend is not a proof of nonlinear Storm.

## Single proof owner and encoding

Rust owns proof production, decoding and soundness checks:

- `crates/aura_intent_lineage_v1/src/stark_prover_v1.rs`
- `crates/aura_intent_lineage_v1/src/stark_verifier_v1.rs`
- claim encoding: `storm_claim_v1.rs`
- witness encoding: `storm_air_v1.rs`

The existing canonical proof bytes are:

`u64_le(claim_byte_length) || canonical_claim_bytes || u64_le(witness_byte_length) || canonical_witness_bytes`

These are the bytes produced by `prove_storm_air_real_v1`. Claim, witness, field and
trace encodings are preserved. Fixed V1 claim bytes include their historical trailing
commitment fields; this migration does not remove or reinterpret them. They are not
alternate active trace roots and do not replace `TRACE_ROOT` verification.

`decode_storm_air_real_artifact_v1` is an explicitly V1 decoder. It reconstructs
backend/version metadata and digests using the existing owner; decoding alone is
not verification. Truncation, trailing bytes, malformed fields, overflowing counts
and counts exceeding available bytes fail. No alternate normalization or serialized
metadata path is accepted by the Bitcoin authorizer.

`StormAirRealProofArtifactV1` is derived verifier metadata around these bytes, not a
second external proof identity. The old SDK `StarkProofEnvelopeV1` objects are
retired to explicit legacy namespaces. The formerly specified four-field JSON
proof envelope was not implemented consistently and is not a canonical admission
object. Its historical fixtures do not establish proof verification.

## Verification and material binding

`verify_storm_air_real_v1` verifies the supported backend/version, public-input
binding, artifact digests, decoded claim and actual witness against the existing
nonlinear Storm relation. The [prover-binding owner](AURA_PROVER_BINDING_V1.md)
defines compact inputs. Admission must verify the actual proof and reconstruct
its material/proof reference as required by the [authorization owner](AURA_AUTHORIZATION_LINEAGE_V1.md).
Signature validity or shape validation alone never grants acceptance.

The witness backend has no external verification key. The authorization owner
pins empty key bytes as the input to the unchanged ProofMaterial construction.
Public-input bytes are derived from the same claim. The [artifact owner](AURA_ARTIFACT_STRUCTURE_V1.md)
defines the only material and FractalKey serialization and hash path.

The authorizer checks its explicit iteration policy and embedded-claim binding
before expensive replay. The command also bounds input file sizes. These are
resource policies, not changes to Storm's field, recurrence or canonical trace.
Proof verification failure emits no authorized Bitcoin anchor request and reserves
no nonce. Local burn accounting remains under its economic owner; it is not inferred
from this verifier's return value.

## Validation

The existing Storm verifier mutation tests recompute outer digests around altered
witness data and still require rejection. Frozen Storm parity fixtures pin existing
claim and compact-input values. Authorization tests additionally cover decoded proof
round-trip, malformed lengths, proof/material/lineage mismatch and durable replay.
The Bitcoin regtest passes actual proof bytes through this verifier before anchoring
their authorized reference.

No zero-knowledge, succinctness or universal proof uniqueness claim is made for
this witness backend. A future backend must be reviewed and verified separately;
retained mock and cat-map paths cannot silently stand in for it.
