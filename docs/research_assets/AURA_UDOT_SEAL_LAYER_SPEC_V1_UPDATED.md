<!-- DOC_STATUS_HEADER_START -->
> Status: HISTORICAL (SUPERSEDED)
> Concept: Aura UDOT Seal Layer Specification V2
> Scope Boundary: Historical snapshot retained for traceability only. It is superseded and must not be used as current protocol, package, fixture, or repository authority.
> Replaced By: [Aura UDOT Seal Layer Specification V2](AURA_UDOT_SEAL_LAYER_SPEC_V2.md)
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as historical context only. Follow the replacement document for current authority.
> Implementation State: Superseded.
<!-- DOC_STATUS_HEADER_END -->

# Aura UDOT Seal Layer Specification V1 (Legacy Freeze)

## 1. Status and Authority

This document freezes legacy UDOT version `1` for explicit backward compatibility only.

UDOT V1 is deprecated for new emissions. New implementations in this repository MUST use `AURA_UDOT_SEAL_LAYER_SPEC_V2.md` unless a caller explicitly requires legacy V1 handling.

This document is authoritative only for:

- validating historical V1 `seal_line` values;
- validating historical V1 `crest` values; and
- preserving the exact legacy bit-ordering and glyph mapping needed for compatibility.

This document does not define `matrix_sequence` or `matrix_form`.

## 2. Compatibility Boundary

V1 and V2 are distinct and incompatible formats.

The exact boundary is:

- V1 uses a 3-bit glyph alphabet; V2 uses a 4-bit nibble alphabet.
- V1 derives a 16-glyph line from the first 48 bits of `line_digest`; V2 derives a 16-glyph line from the first 16 hex nibbles of the same digest.
- V1 derives an 8-glyph crest from the first 24 bits of `crest_digest`; V2 derives an 8-glyph crest from the first 8 hex nibbles of the same digest.
- V1 does not define a matrix artifact.
- A stored V1 line or crest cannot be losslessly translated into V2 without the original 32-byte Aura hash.

Like V2, V1 MUST NOT be auto-detected from glyph content alone. Every semantic validator MUST know the intended version before comparison.

## 3. Inputs and Legacy Normalization Rules

The canonical V1 input is exactly:

- `aura_hash_bytes`: 32 raw bytes.

If a tool accepts a textual hash for legacy V1 derivation, it MUST follow the same strict helper profile as V2:

- exactly 64 ASCII hex characters;
- uppercase and lowercase hex decode to the same bytes;
- canonical emitted hash text is lowercase hex;
- no leading or trailing whitespace;
- no embedded whitespace, separators, or `0x` prefix; and
- no non-ASCII characters.

All V1 derivation starts from the decoded 32 bytes. No byte reversal, trimming, or reinterpretation is permitted.

## 4. Legacy V1 Glyph Alphabet

V1 uses the following fixed 3-bit alphabet:

| Bits | Glyph | Code point |
| --- | --- | --- |
| `000` | `∘` | `U+2218` |
| `001` | `•` | `U+2022` |
| `010` | `∙` | `U+2219` |
| `011` | `⟡` | `U+27E1` |
| `100` | `◦` | `U+25E6` |
| `101` | `◎` | `U+25CE` |
| `110` | `○` | `U+25CB` |
| `111` | `◌` | `U+25CC` |

The V1 alphabet is exact. Conforming legacy handlers MUST NOT accept alternate glyph sets or visually similar substitutions.

## 5. Domain Separators and Bit Ordering

V1 defines two domain-separated digests:

- `line_digest = SHA-256(ASCII("AURA_UDOT_SEAL_LINE_V1") || aura_hash_bytes)`
- `crest_digest = SHA-256(ASCII("AURA_UDOT_SEAL_V1") || aura_hash_bytes)`

V1 bit ordering is frozen exactly as follows:

- digest bytes are processed in natural byte order from byte `0` to byte `31`;
- within each byte, bits are read most-significant-bit first;
- the resulting bitstream is grouped from the beginning into consecutive 3-bit groups; and
- unused trailing bits are discarded.

Earlier V1 wording referred to an "opening glyph" and "closing glyph." Those labels are positional only. They do not carry special semantics beyond "first glyph" and "last glyph."

## 6. Legacy Seal Line

### 6.1 Derivation

`seal_line` is derived as follows:

1. Compute `line_digest`.
2. Convert the full 32-byte digest into a 256-bit stream using the bit-ordering rules in Section 5.
3. Take the first 16 consecutive 3-bit groups.
4. Map each 3-bit group through the V1 alphabet.
5. Concatenate the 16 glyphs with no separators.

### 6.2 Canonical representation

The canonical V1 `seal_line` representation is:

- exactly 16 V1 glyphs;
- no spaces;
- no tabs;
- no line breaks; and
- no leading or trailing characters.

A documentation-only pretty form MAY insert single ASCII spaces between glyphs. Canonical parsers MUST reject that spacing.

## 7. Legacy Crest

### 7.1 Derivation

`crest` is derived as follows:

1. Compute `crest_digest`.
2. Convert the full 32-byte digest into a 256-bit stream using the bit-ordering rules in Section 5.
3. Take the first 8 consecutive 3-bit groups.
4. Map each 3-bit group through the V1 alphabet.
5. Concatenate the 8 glyphs with no separators.

### 7.2 Canonical representation

The canonical V1 `crest` representation is:

- exactly 8 V1 glyphs;
- no spaces;
- no tabs;
- no line breaks; and
- no leading or trailing characters.

A documentation-only pretty form MAY insert single ASCII spaces between glyphs. Canonical parsers MUST reject that spacing.

## 8. Legacy Parser and Serializer Rules

A conforming V1 legacy parser or serializer MUST:

- require explicit V1 version selection;
- reject any glyph outside the V1 alphabet;
- reject any canonical `seal_line` not exactly 16 glyphs long;
- reject any canonical `crest` not exactly 8 glyphs long;
- reject whitespace, CR, CRLF, tabs, BOMs, and zero-width characters in canonical forms;
- compare exact Unicode code point sequences for validation; and
- re-derive the expected V1 output from the Aura hash before semantic acceptance.

A successful syntax parse is not semantic verification.

## 9. Reference Pseudocode

```text
alphabet_v1 = {
  '000': '∘', '001': '•', '010': '∙', '011': '⟡',
  '100': '◦', '101': '◎', '110': '○', '111': '◌'
}

bytes_to_msb_first_bitstream(digest_bytes):
  return concatenate(binary8(byte) for byte in digest_bytes)

map_3bit_groups(bitstream, group_count):
  groups = consecutive_chunks(bitstream, 3)
  return concatenate(alphabet_v1[group] for group in groups[0:group_count])

derive_udot_v1(aura_hash_bytes[32]):
  line_digest  = SHA256(ASCII("AURA_UDOT_SEAL_LINE_V1") || aura_hash_bytes)
  crest_digest = SHA256(ASCII("AURA_UDOT_SEAL_V1") || aura_hash_bytes)

  line_bits  = bytes_to_msb_first_bitstream(line_digest)
  crest_bits = bytes_to_msb_first_bitstream(crest_digest)

  seal_line = map_3bit_groups(line_bits, 16)
  crest     = map_3bit_groups(crest_bits, 8)

  return {
    format_version: 1,
    seal_line,
    crest
  }
```

## 10. Worked Legacy Vector

For input Aura hash:

`14eda752a31094ed7cffb71864a880373b6cc24ec252f5bb70f4661ee61e91fd`

The derived legacy values are:

- `line_digest = 9c60eed302d00ffdf86f2d92c24e86751270a12cc3497c0708e4ad0e92b555a3`
- `seal_line = ◦◌∘○∘⟡◎○○◦○∘•⟡∙∘`
- display-only pretty form: `◦ ◌ ∘ ○ ∘ ⟡ ◎ ○ ○ ◦ ○ ∘ • ⟡ ∙ ∘`
- `crest_digest = 1103c3a0fbf38e89b7a636255d1d213921f6c02cb21da1322995927acef84ef2`
- `crest = ∘◦∙∘•◌∘⟡`
- display-only pretty form: `∘ ◦ ∙ ∘ • ◌ ∘ ⟡`

## 11. Security Considerations and Non-Goals

V1 is a derived identity surface, not a primary proof or commitment surface.

The legacy security boundary is:

- `seal_line` carries only 48 bits of derived information;
- `crest` carries only 24 bits of derived information;
- both are insufficient as primary cryptographic commitments;
- unlabeled V1 strings are unsafe because they are syntactically compatible with V2 glyph parsing; and
- any parser that silently trims or auto-detects versions creates avoidable ambiguity.

V1 does not define:

- a matrix artifact;
- a transport or storage container;
- any privacy or blinding layer; or
- any alternate glyph alphabet.

Any future format that changes any V1 rule MUST use an explicit new version and MUST NOT be labeled V1.
