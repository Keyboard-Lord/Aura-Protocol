# AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2

**Classification:** `ROOT AUTHORITY`
**Layer:** `L0-L5`
**Purpose:** Define protocol boundaries and direct each concept to its single owner
**Status:** `ACTIVE; IMPLEMENTATION LIMITS EXPLICIT BELOW`

The [registry](AURA_BUILD_SOURCE_OF_TRUTH.md) owns document membership, precedence
and concept ownership. This root establishes protocol invariants; the linked
owners define the exact encodings and algorithms. Repository names and historical
claims do not override implemented, tested cryptographic bytes.

## Canonical execution and proof identity

Aura preserves one deterministic execution path for fixed canonical Storm inputs.
[Hash construction](AURA_HASH_V2.md), [field arithmetic](AURA_FIELD_ARITHMETIC_V1.md),
[derivations](AURA_DERIVATION_FUNCTIONS_V1.md),
[Storm recurrence](AURA_STORM_RECURSION_V1_1.md),
[trace layout](AURA_TRACE_LAYOUT_V1.md) and
[trace commitment](AURA_TRACE_COMMITMENT_V1.md) each have one owner.

Storm's initial x coordinate is derived from side A and its initial y coordinate
from side B using their existing domain-separated derivations. It is not initialized
by assigning `x_0 = MESSAGE_ROOT` and hashing x to obtain y. No generic message-to-side
adapter is implied by this root. Message identity and proof reference are different
concepts; neither may silently substitute for the other.

[Prover binding](AURA_PROVER_BINDING_V1.md) owns compact public inputs and their
relationship to the claim. [The proof boundary](AURA_STARK_SPEC_V1.md) owns the
existing serialized proof and verification requirements. [Artifact derivation](AURA_ARTIFACT_STRUCTURE_V1.md)
owns ProofMaterial, FractalKey and `proof_hash`. Its existing SHA256 bindings remain
unchanged; SHA3-based Storm derivations do not authorize replacing those hashes.
[UDOT](AURA_UDOT_SPEC_V1.md) presents the same proof reference without introducing
another identifier.

Forward determinism does not imply an injective recurrence. A terminal state alone
does not uniquely identify an arbitrary predecessor or trace. The complete input
binding and ordered trace commitment remain necessary. Field size or deterministic
forcing alone does not establish resistance to structural or quantum attacks.

## Single pipeline and accepted action

[The canonical pipeline](AURA_CANONICAL_PIPELINE_V1.md) owns stage dependencies.
Actual proof bytes precede material hashing; authorization signs the resulting
bound proof reference. A shape-valid envelope cannot replace actual proof verification.

[Authorization](AURA_AUTHORIZATION_LINEAGE_V1.md) owns the approved BIP340 v2 envelope,
subject/intent/nonce binding and durable replay acceptance. Same-action retry and
reservation recovery follow that owner. Nonce uniqueness is scoped to a coordinated
journal, not claimed globally across independent authorizers.

[The report contract](AURA_REPORT_CONTRACT_V1.md) owns the approved Bitcoin OP_RETURN
request, output validation and observation boundary. The anchor carries the proof
reference. Bitcoin inclusion does not itself verify the off-chain Aura proof or
guarantee its availability. A reorg changes confirmation, not nonce reservation.

Canonical entry rejects unsupported versions, malformed encodings and unexpected
fields. Downstream authorization and settlement wires reference upstream identity;
they do not embed duplicate proof/claim/UDOT objects. Historical Solana wires and
cat-map compatibility surfaces are explicit legacy material, never implicit
successor authorization input.

## Verification capabilities and limits

The active nonlinear Storm backend transports a witness and verifies execution by
replay. It is not currently a succinct zero-knowledge STARK. The retained Winterfell
cat-map backend proves its own historical relation; it must not be represented as
a proof of nonlinear Storm. This root does not authorize substituting that relation
or modifying Storm to fit it. A future proof backend requires its own reviewed
implementation and validation while preserving the approved semantic boundary.

Core determinism applies to fixed canonical inputs and exact derivation bytes.
Cryptographic nonce generation, signature auxiliary randomness, durable journal
state, transaction funding and live chain observation are explicit operational
steps. Their variability does not create new canonical proof identities.

## Economics and completion boundary

[Ledger and burn](AURA_LEDGER_AND_BURN_V1.md),
[failure classes](AURA_FAILURE_CLASSES_V1.md) and
[continuous settlement](AURA_CONTINUOUS_SETTLEMENT_V1.md) retain ownership of local
economic/state rules. Bitcoin transaction fees are not Aura burn accounting.
The implemented proof authorizer and Core transport do not themselves debit an
Aura ledger. Local economic tests and authorization-to-Bitcoin tests establish
separate evidence; their end-to-end integration remains an explicit discrepancy.
No successful burn enforcement is inferred from signature verification or anchoring.

The repository is complete only when its active implementation, fixtures, validation
and owning documents agree. Unsupported security claims, historical fixture names
and passing unrelated tests do not establish that agreement.
