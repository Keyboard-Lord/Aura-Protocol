<!-- DOC_STATUS_HEADER_START -->
> Status: HISTORICAL (SUPERSEDED)
> Concept: Aura 521-Bit Commitment Replacement Migration Note V1
> Scope Boundary: Historical snapshot retained for traceability only. It is superseded and must not be used as current protocol, package, fixture, or repository authority.
> Replaced By: [Aura 521-Bit Commitment Replacement Migration Note V1](../docs/AURA_521_BIT_COMMITMENT_REPLACEMENT_MIGRATION_NOTE_V1.md)
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as historical context only. Follow the replacement document for current authority.
> Implementation State: Superseded.
<!-- DOC_STATUS_HEADER_END -->

# Aura 521-Bit Commitment Bias Audit V1

Scope: research-only, non-authoritative analysis of `DeterministicCommitment521V1` on the Layer 2 `lineage_commitment` surface. This is not a claim of a full break of 521-bit commitments.

## Target

- Layer 2 `lineage_commitment`:
  `01e98f99acaa1d49e50ee1dca6d8045a7785c36bb64f5dfb20e779750641ea734a026b6c5c73882c86a694e039d2f176d2ed7ce59de94caea45fb81c29ad5a2f5617`
- Canonical lineage preimage length: `300` bytes
- Canonical packed commitment input length: `413` bytes
- Exact recomputation from canonical inputs: `true`

## Construction Trace

- Canonical Layer 2 preimage bytes are singular and byte-exact.
- The commitment primitive packs:
  `AURA_DETERMINISTIC_COMMITMENT_521_V1 || len(domain)_le || domain || len(body)_le || body`
- The varying Layer 2 field `freshness_reference` starts at byte `228` of the canonical preimage and byte `341` of the packed commitment input.
- Under the current chunking rule (`64` bytes per chunk), `freshness_reference` lands in packed-input chunk `5` covering bytes `[320, 384)`.

## Structural Finding

The first actual mixing stage already fails to diffuse the target prefix:

- `affected_chunk_element`: target first `32` bits preserved across `65536 / 65536` structured neighbors
- `affected_mixed_chunk`: `65536 / 65536`
- `x_after_affected_round`: `65536 / 65536`
- `y_after_affected_round`: `65536 / 65536`
- `final_commitment`: `65536 / 65536`

That localizes the failure to the commitment transform, not to canonical preimage packing and not to final field-byte serialization.

## Avalanche

For single-bit flips inside the `freshness_reference` field:

- `DeterministicCommitment521V1`: average changed bits `124.31 / 528`, first `8/16/24/32` prefix bits changed in `0 / 64` cases
- `SHA-256(preimage)`: average changed bits `129.91 / 256`, first `8/16/24/32` prefix bits changed in `64 / 64` cases
- `SHA-512(preimage)`: average changed bits `255.20 / 512`, first `8/16/24/32` prefix bits changed in `64 / 64` cases
- `reduce_mod_p(SHA-512(tag || preimage))`: average changed bits `255.42 / 528`, but the top `16` output bits remain structurally fixed because the digest is only `64` bytes wide
- `reduce_mod_p(SHA-512(tag_x || preimage) || SHA-512(tag_y || preimage))`: average changed bits `261.50 / 528`, first `16/24/32` prefix bits changed in `64 / 64` cases

## Control Comparison

Structured-neighbor family: `freshness_reference = 2^48 + candidate`, exact over `candidate in [0, 2^16)`.

- `DeterministicCommitment521V1`: `65536 / 65536` target-prefix matches at `8/16/24/32` bits, `1` distinct 32-bit prefix, `32` constant bits in the first 32
- `SHA-256(preimage)`: `247 / 0 / 0 / 0`, `65535` distinct 32-bit prefixes, `0` constant bits in the first 32
- `SHA-512(preimage)`: `261 / 3 / 0 / 0`, `65536` distinct 32-bit prefixes, `0` constant bits in the first 32
- `reduce_mod_p(SHA-512(tag || preimage))`: `65536 / 65536 / 260 / 0`, `41525` distinct 32-bit prefixes, `16` constant bits in the first 32
- `reduce_mod_p(SHA-512(tag_x || preimage) || SHA-512(tag_y || preimage))`: `32858 / 139 / 0 / 0`, `65475` distinct 32-bit prefixes, `7` constant bits in the first 32

The widened hash-to-field control behaves like ordinary truncation. The reduced-only 64-byte hash-to-field control shows the expected width-shortfall artifact in the top `16` bits, which is a separate issue from the current primitive’s full `32`-bit fixed-prefix concentration.

## Root Cause Hypothesis

`DeterministicCommitment521V1` is construction-level biased:

- each `64`-byte chunk is embedded directly as a field element with no avalanche/compression step
- the accumulator uses only addition, one square term, and small fixed multipliers
- high-order output bits remain dominated by fixed seeds and fixed earlier chunk structure
- local input perturbations, including `freshness_reference`, can fail to reach the top `32` output bits at all

This is not an encoding-level bug. Canonical serialization is singular, and the same `FieldElement521V1` output encoding behaves normally for widened hash-to-field controls.

## Recommendation

`DeterministicCommitment521V1` should be demoted from primary-commitment status for Layer 2 and not treated as an acceptable primary truth surface in its current form.

Minimum safe replacement:

- preserve the exact canonical Layer 2 preimage
- preserve deterministic replay and domain separation
- replace the current low-degree field accumulator with a cryptographic expand-then-reduce construction such as:
  `reduce_mod_p(SHA-512(tag_x || preimage) || SHA-512(tag_y || preimage))`

That keeps the output 521-bit-native while introducing a real compression stage before field reduction and serialization.
