<!-- DOC_STATUS_HEADER_START -->
> Status: RESEARCH / SUPPORTING
> Concept: Aura Ecosystem Overview V1
> Scope Boundary: Supporting or non-authoritative material for the named surface only. It may record research, audits, planning, or supporting-layer doctrine, but it does not create active or frozen protocol authority.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as supporting context only. Candidate, future, audit, or comparison language in the body is non-authoritative unless promoted elsewhere.
> Implementation State: Supporting, research, audit, planning, or non-authoritative.
<!-- DOC_STATUS_HEADER_END -->

# Aura Ecosystem Overview V1

## 1. Purpose and Status

This document frames Aura as a deployable ecosystem surface without changing any frozen protocol
semantic.

It is intentionally narrower than a tokenomics paper.

It does not define:

- supply
- issuance
- burn
- staking
- treasury policy
- voting mechanics
- on-chain governance contracts

It does define how the existing repository surfaces can be understood operationally by users,
provers, relayers, verifiers, and counterparties.

## 2. Minimal `$AURA` Role

In ecosystem framing, `$AURA` is the narrowest possible label for Aura's native fee unit.

That role is grounded in repository concepts that already exist:

- `native_balance` in the Layer 4 data model
- `max_fee_native` in the Layer 4 intent body
- deterministic fee accounting and `fee_summary_commitment` in the frozen Layer 4 transition rules
- off-chain proving, submission, and settlement service boundaries already present in code and docs

Accordingly, the minimal role of `$AURA` is:

1. the unit of account for Aura-native balances and deterministic Layer 4 fee fields
2. the operational gas asset for proving and submission services
3. an optional minimal governance surface for versioning and configuration, if governance is later
   introduced explicitly

Nothing in the current repository requires `$AURA` to be a staking asset, a burn asset, or a
consensus-security asset.

## 3. Where Fees Occur

Aura has three fee locations worth separating clearly.

### 3.1 Proving Fee

Proof generation is an off-chain service cost.

In the current repository this includes:

- lower-layer STARK proving in `aura_intent_lineage_v1`
- future Layer 4 batch-proving services when the frozen Layer 4 proving contracts graduate into code

Operationally, the prover fee is the amount paid to generate the proof artifact and its associated
claim package.

The protocol effect is:

- proof generation happens before settlement
- the proof artifact is not automatically free just because the chain-facing payload is compact

### 3.2 Submission Fee

Submission is the cost of delivering the chain-facing artifact to Solana through the submission
client boundary.

In the implemented v1 path this means:

- validating the nested off-chain request stack
- extracting the exact canonical `proof_hash`
- paying the Solana transaction cost required to submit `tag || proof_hash`

This fee belongs to the user or the relayer that sends the transaction.

### 3.3 Settlement Fee

Settlement is the cost of accepting a proof-backed claim into the settlement layer.

There are two different maturity levels here:

- today, the repository concretely implements the v1 `proof_hash` submission adapter and local
  proof-backed settlement surfaces
- the broader Layer 4 settlement model is still a frozen contract surface rather than a complete
  deployed settlement program

Operationally, a settlement fee is the amount paid to the party that evaluates the proof/public-input
pair and advances accepted settlement state.

### 3.4 Internal Protocol Fees Versus Service Fees

The repository already distinguishes internal protocol accounting from external service pricing.

Internal protocol accounting:

- deterministic Layer 4 fee charging
- fee-collection `SystemAccount` mutation
- `fee_summary_commitment`

External service pricing:

- prover fees
- relayer fees
- settlement operator fees

`$AURA` can denominate both categories without collapsing them into one mechanism.

## 4. Actor Model

Aura's deployable ecosystem can be described with four primary actors.

### 4.1 User

The user is the party that owns the authorization context and wants a claim recognized by Aura.

The user's responsibilities are:

- create or authorize the intended action
- supply the inputs required for proof preparation
- decide whether to self-submit or delegate to a relayer
- pay the relevant proving and submission fees directly or indirectly

In the v1 path, the user ultimately cares about one result on-chain: successful recording of the
correct `proof_hash`.

### 4.2 Prover

The prover is the party that produces the proof artifact for the claimed computation.

Its responsibilities are:

- construct the proving witness
- run the STARK or later supported proof pipeline
- return the proof artifact together with the claim data needed by the verifier boundary

The prover is not the settlement layer and is not automatically the relayer.

### 4.3 Relayer

The relayer is the transport actor between off-chain Aura artifacts and the settlement chain.

Its responsibilities are:

- accept canonical nested envelopes
- preserve exact bytes and versioning
- submit the chain-facing transaction
- pay the immediate network fee and recover it from the user or application

In the current repository, the relayer is the most natural operator of the submission-client
surface.

### 4.4 Verifier

The verifier is the party that decides whether the exact claim/proof pair is valid at the active
verification boundary.

Its responsibilities are:

- evaluate the exact public-input and proof surface required by the relevant contract
- reject malformed, ambiguous, or mismatched artifacts fail-closed
- return one exact validity decision for the claimed version set

The verifier may be:

- a local verifier in the current verified foundation
- a lower-layer STARK acceptance path in `aura_intent_lineage_v1`
- a future settlement-facing verifier when the Layer 4 settlement contracts move from frozen docs
  into code

## 5. Why Solana Only Sees `proof_hash`

Solana only sees `proof_hash` because that is the frozen settlement rule of the implemented Aura v1
path.

This is not an omission. It is a design boundary.

The repository now carries richer off-chain structure:

- UDOT bundle
- submit request
- authorization intent
- STARK proof envelope
- settlement request

But all of that remains off-chain and nested.

The final chain-facing adapter still extracts and submits only:

- `tag || proof_hash`

This gives Aura three operational properties:

1. the on-chain payload stays compact
2. representation artifacts such as UDOT do not become settlement truth
3. proof and intent transport can evolve off-chain under explicit versioning without silently
   changing the settled chain payload

## 6. Why Aura Is Layer 2 and Not Layer 1

Aura is Layer 2 in the operational sense that matters here:

- execution semantics are defined above the settlement chain
- proving is performed off-chain
- typed commitments and authorization surfaces are constructed off-chain
- settlement uses Solana as the anchoring layer rather than as the place where Aura executes its
  full semantic model directly

Solana therefore acts as the settlement substrate, not as the full native executor of Aura's
off-chain proof and binding stack.

Aura is not Layer 1 because the richer Aura objects are not natively executed on-chain as first-
class state-transition logic in the current implementation.

The base chain records the compact commitment boundary, while Aura owns the higher-layer execution,
proof, and binding semantics around it.

## 7. Minimal Governance Surface

If governance is added, the smallest compatible governance surface is administrative rather than
constitutional.

The safe governance scope is:

- activation of new explicitly versioned client or proof surfaces
- configuration ratification for service-level parameters
- registry or policy decisions around relayer or verifier endpoints

The unsafe governance scope, and therefore excluded here, is:

- redefining proof truth by vote
- changing frozen wire semantics informally
- retroactively changing settlement meaning
- inventing supply or emission rules without a separate economics contract

Accordingly, governance for `$AURA` should be optional and minimal.

## 8. Minimal Go-To-Market Framing

Aura's realistic entry path is to commercialize what is already coherent, not what is merely
desirable.

### 8.1 First Market Surface

The first market surface is proof-backed commitment transport:

- SDK and CLI preparation
- UDOT generation
- canonical nested envelope production
- relayed `proof_hash` submission to Solana

This is already concrete enough to support developer onboarding, integrations, and service-based
operations.

### 8.2 Second Market Surface

The second market surface is prover and relayer infrastructure:

- proving as a service
- submission as a service
- verification and archival as a service

This is where `$AURA` most naturally functions as gas.

### 8.3 Expansion Surface

The expansion surface is broader Layer 4 settlement only after the frozen contracts become code.

That means:

- no present-tense claim that a full Aura Layer 4 settlement system is already deployed
- no need to invent token features before the settlement path exists
- no need to change the frozen `proof_hash` rule in order to build an initial ecosystem

## 9. Explicit Non-Claims

This ecosystem framing does not claim:

- a finished tokenomics model
- a live sequencer economy
- a staking market
- a burn model
- a governance token mandate
- a complete deployed Layer 4 settlement stack beyond the currently implemented surfaces

It only states that Aura can already be understood operationally as a system with users, provers,
relayers, verifiers, and a minimal native fee unit.

That is enough for a serious protocol framing, and it avoids inventing features the repository does
not yet own.
