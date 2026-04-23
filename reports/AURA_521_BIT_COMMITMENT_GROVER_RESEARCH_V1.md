<!-- DOC_STATUS_HEADER_START -->
> Status: HISTORICAL (SUPERSEDED)
> Concept: Aura 521-Bit Commitment Replacement Migration Note V1
> Scope Boundary: Historical snapshot retained for traceability only. It is superseded and must not be used as current protocol, package, fixture, or repository authority.
> Replaced By: [Aura 521-Bit Commitment Replacement Migration Note V1](../docs/AURA_521_BIT_COMMITMENT_REPLACEMENT_MIGRATION_NOTE_V1.md)
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as historical context only. Follow the replacement document for current authority.
> Implementation State: Superseded.
<!-- DOC_STATUS_HEADER_END -->

# Aura 521-Bit Commitment Grover-Style Research v1

Scope: research-only, non-authoritative, no claim of a real break of full 521-bit commitments.

Raw exact outputs are in [AURA_521_BIT_COMMITMENT_GROVER_RESEARCH_V1.json](/Users/mcrae/Desktop/AURA/reports/AURA_521_BIT_COMMITMENT_GROVER_RESEARCH_V1.json).

## Search policy

- Exact classical search: 16 bits and 20 bits
- Bounded classical search: 24, 28, and 32 bits with `1,048,576` queries
- Oracle family: disjoint canonical structured-neighbor second-preimage search over `freshness_reference = 2^48 + candidate`
- Canonicality rule: only the one canonical serialization path for each surface was admitted

## Exact primary targets

### Layer 2 `lineage_commitment`

- Commitment hex:

```text
01e98f99acaa1d49e50ee1dca6d8045a7785c36bb64f5dfb20e779750641ea734a026b6c5c73882c86a694e039d2f176d2ed7ce59de94caea45fb81c29ad5a2f5617
```

- Canonical input length: `300`
- Canonical recomputation: `true`

### Layer 3 `result_commitment`

- Commitment hex:

```text
01129c2b3c8160ae97a83f03dbbfaf04d5c6687e5502b33bcc6a56744d75ce33274271ae88e2e3710b612227c785d93653f5e5577fc21b3c71364d69d9ff076b04ac
```

- Canonical input length: `323`
- Canonical recomputation: `true`

### Layer 3->4 `ingress_commitment`

- Commitment hex:

```text
0031c1dc4a6c229b262f986893cea99fa84d445550e2c426e191e0ccfa3edde07fb32711b683f884e4586c68a43368014cfa319dba97fb517394425879fbd3471bed
```

- Canonical input length: `1520`
- Canonical recomputation: `true`

### Layer 4 public-statement commitment

- Commitment hex:

```text
006d29c69a69d29f02bbf59fb526bf1685bf8de424dd01092bc40b71f869f02a38c63c83780ed118c066e4843a2f0787515dde82cf9ab6146e53d6ade11b0e5a0f37
```

- Canonical input length: `371`
- Canonical recomputation: `true`

## Reduced-bit results

### Primary surfaces

| Target | 16-bit exact | 20-bit exact | 24-bit bounded (`2^20`) | 28-bit bounded (`2^20`) | 32-bit bounded (`2^20`) |
| --- | --- | --- | --- | --- | --- |
| `lineage_commitment` | `65536` / `65536` matches | `1048576` / `1048576` matches | `1048576` / `1048576` matches | `1048576` / `1048576` matches | `1048576` / `1048576` matches |
| `result_commitment` | `130` matches | `138` matches | `5` matches | `0` matches | `0` matches |
| `ingress_commitment` | `110` matches | `132` matches | `6` matches | `1` match | `0` matches |
| `public_statement_commitment` | `124` matches | `137` matches | `4` matches | `0` matches | `0` matches |

### Helper controls

| Control | 16-bit exact | 20-bit exact | 24-bit bounded (`2^20`) | 28-bit bounded (`2^20`) | 32-bit bounded (`2^20`) |
| --- | --- | --- | --- | --- | --- |
| `lineage_hash` | `0` matches | `1` match | `0` matches | `0` matches | `0` matches |
| `result_digest` | `0` matches | `3` matches | `0` matches | `0` matches | `0` matches |

## Structural reading

- Canonicalization remained singular across all tested surfaces. No alternate serializer or non-canonical encoding path was used in the oracle model.
- `result_commitment`, `ingress_commitment`, and public-statement commitment behaved like ordinary truncated deterministic targets in the reduced-bit search.
- `lineage_commitment` did not. Its high-order truncated prefixes stayed fixed across the entire tested disjoint family.
- Sample lineage commitments for candidates `0`, `1`, `255`, and `4095` all retained the same leading 32-bit prefix as the canonical target, while the helper `lineage_hash` control did not.
- Helper digests did not re-emerge as stand-alone primary truth surfaces, but Layer 3 and Layer 3->4 primary bodies still carry validated helper digest context redundantly.

## Conclusion

Aura's new primary surfaces are not all equivalent under reduced-bit testing.

- Layer 3 `result_commitment`, Layer 3->4 `ingress_commitment`, and the public-statement commitment showed no Aura-specific shortcut beyond expected truncation behavior in this research pass.
- Layer 2 `lineage_commitment` showed strong top-prefix concentration under the canonical structured-neighbor search, which is a real reduced-bit weakness signal for the current deterministic commitment primitive on that direct surface.
- This is not a claim of a full 521-bit break, but it does mean Aura does **not** yet satisfy the stronger research goal of a uniformly shortcut-free 521-bit primary commitment stack.
