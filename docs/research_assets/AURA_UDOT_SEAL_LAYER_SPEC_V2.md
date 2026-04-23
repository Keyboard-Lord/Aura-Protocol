<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: Aura UDOT Seal Layer Specification V2
> Scope Boundary: Current authoritative contract for the implemented surface named by this document only. It does not expand authority outside that surface or bypass the repository source-of-truth order.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# Aura UDOT Seal Layer Specification V2

## 1. Status and Authority

This document is the canonical source of truth for UDOT version `2` in this repository.

It freezes:

- the exact input surface for UDOT derivation;
- the exact domain-separation byte strings;
- the exact V2 glyph alphabet, including Unicode code points;
- the exact derivation rules for `seal_line`, `crest`, `matrix_sequence`, and `matrix_form`;
- the exact canonical serialization and strict parser behavior; and
- the exact compatibility boundary relative to legacy UDOT V1.

This document is normative for:

- `docs/AURA_UDOT_IMPLEMENTATION_CONTRACT_V2.md`;
- `docs/AURA_UDOT_TEST_VECTOR_STATUS_V2.md`; and
- any future UDOT parser, validator, serializer, CLI surface, or UI helper built in this repository.

`AURA_UDOT_SEAL_LAYER_SPEC_V1_UPDATED.md` remains available only as a legacy compatibility freeze. New implementations MUST treat this V2 document as the active implementation contract.

UDOT is a derived identity surface. It is not the primary cryptographic commitment surface of Aura.

## 2. Versioning and Compatibility

The repository defines two incompatible UDOT formats:

- `UDOT V1`: legacy 3-bit glyph encoding, documented only for explicit backward compatibility.
- `UDOT V2`: active 4-bit nibble-to-glyph encoding, defined by this document.

The compatibility rules are strict:

- the same Aura hash produces different `seal_line` and `crest` outputs under V1 and V2;
- V2 defines `matrix_sequence` and `matrix_form`; V1 does not;
- new implementations MUST emit V2 unless an explicit legacy-mode requirement says otherwise;
- validators MUST NOT auto-detect V1 vs V2 from glyph content alone;
- any transport, storage layer, or application state that carries a UDOT artifact MUST carry explicit version metadata out of band; and
- unlabeled `seal_line` and `crest` strings MUST be treated as ambiguous until the version is established externally.

Important boundary:

- the legacy V1 glyph alphabet is a strict subset of the V2 glyph alphabet, so character-set inspection alone is insufficient for version inference.

## 3. Definitions

| Term | Canonical meaning in this repository |
| --- | --- |
| `Aura hash` | The 32-byte input commitment already defined elsewhere in Aura. UDOT does not define how the Aura hash itself is produced. |
| `hash` | A SHA-256 operation result only when the context explicitly says so. |
| `digest` | A 32-byte SHA-256 output from a UDOT domain-separated derivation. A digest is raw bytes, not text. |
| `bytes` | Exact raw octets in their original order. |
| `hex` | ASCII hexadecimal text for bytes. Unless a parser rule says otherwise, canonical emitted hex in this repository is lowercase. |
| `glyph` | One exact Unicode scalar value from the active UDOT alphabet for the selected version. |
| `glyph sequence` | An ordered string of glyphs with no separators. |
| `seal line` | The V2 16-glyph sequence derived from the first 16 hex nibbles of `line_digest`. |
| `crest` | The V2 8-glyph sequence derived from the first 8 hex nibbles of `crest_digest`. |
| `matrix_sequence` | The V2 64-glyph sequence derived from all 64 hex nibbles of `matrix_digest`. |
| `matrix_form` | The exact 8-row LF-delimited rendering of `matrix_sequence`, with 8 glyphs per row and no spaces. |
| `encoding` | The mapping from bytes or nibbles into glyphs. |
| `rendering` | A human-facing presentation of a glyph sequence. Rendering does not change glyph order or code points. |
| `serialization` | The exact string or byte form used for interchange and comparison. |
| `canonical representation` | The exact machine comparison form required by this specification. |
| `display-only representation` | A human-oriented form that is not the canonical machine comparison form. |

## 4. Inputs and Normalization

### 4.1 Canonical input

The canonical UDOT input is exactly one value:

- `aura_hash_bytes`: 32 raw bytes.

Every UDOT derivation in V2 MUST start from those 32 bytes exactly as supplied. UDOT V2 MUST NOT:

- reverse byte order;
- reinterpret the bytes as an integer;
- re-hash the bytes before domain separation;
- trim leading zero bytes; or
- normalize them through text transforms.

### 4.2 Text input profile

Some tools will receive an Aura hash as text. That textual helper profile is frozen as follows:

- the text MUST contain exactly 64 ASCII hex characters;
- uppercase `A-F` and lowercase `a-f` MUST decode to the same bytes;
- canonical emitted hash text MUST be lowercase hex;
- the parser MUST reject any leading or trailing whitespace;
- the parser MUST reject any embedded whitespace, separator, underscore, colon, or `0x` prefix;
- the parser MUST reject any non-ASCII character, including Unicode lookalikes; and
- the parser MUST decode the text to raw bytes before any UDOT processing begins.

If an implementation already has raw bytes, this text-input profile does not apply.

## 5. Common Encoding Conventions

The following conventions are frozen for V2:

- SHA-256 means the standard 32-byte SHA-256 digest.
- Domain separators are encoded as exact ASCII byte strings with no trailing NUL and no length prefix.
- `lower_hex(digest)` means lowercase ASCII hex of the digest bytes in natural byte order.
- Each digest byte contributes two hex characters: the high nibble first, then the low nibble.
- No byte-order reversal is permitted at the byte or nibble layer.
- Glyph strings are sequences of exact Unicode scalar values. Implementations MUST NOT normalize, case-fold, or compatibility-fold them.
- If a glyph string is serialized to bytes, UTF-8 MUST be used.
- Validators MUST compare glyph code point sequences, not visual appearance.

## 6. V2 Glyph Alphabet

UDOT V2 uses a fixed 4-bit alphabet with one glyph for each hexadecimal nibble.

| Hex | Bits | Glyph | Code point |
| --- | --- | --- | --- |
| `0` | `0000` | `◦` | `U+25E6` |
| `1` | `0001` | `◌` | `U+25CC` |
| `2` | `0010` | `∘` | `U+2218` |
| `3` | `0011` | `○` | `U+25CB` |
| `4` | `0100` | `⟡` | `U+27E1` |
| `5` | `0101` | `◎` | `U+25CE` |
| `6` | `0110` | `•` | `U+2022` |
| `7` | `0111` | `∙` | `U+2219` |
| `8` | `1000` | `◈` | `U+25C8` |
| `9` | `1001` | `◇` | `U+25C7` |
| `a` | `1010` | `◆` | `U+25C6` |
| `b` | `1011` | `ㅁ` | `U+3141` |
| `c` | `1100` | `■` | `U+25A0` |
| `d` | `1101` | `□` | `U+25A1` |
| `e` | `1110` | `▣` | `U+25A3` |
| `f` | `1111` | `▤` | `U+25A4` |

The alphabet is exact. A conforming V2 parser or serializer MUST NOT:

- substitute visually similar code points;
- accept alternate glyph sets;
- reorder the table;
- map uppercase hex differently from lowercase hex; or
- infer glyph meaning from font appearance.

## 7. Domain Separators

V2 defines three domain-separated derivations:

- `AURA_UDOT_SEAL_LINE_V1`
- `AURA_UDOT_SEAL_V1`
- `AURA_UDOT_MATRIX_V1`

These strings are literal ASCII byte sequences. Their `_V1` suffix is part of the frozen separator bytes and MUST NOT be rewritten to match the V2 document version.

The exact formulas are:

- `line_digest = SHA-256(ASCII("AURA_UDOT_SEAL_LINE_V1") || aura_hash_bytes)`
- `crest_digest = SHA-256(ASCII("AURA_UDOT_SEAL_V1") || aura_hash_bytes)`
- `matrix_digest = SHA-256(ASCII("AURA_UDOT_MATRIX_V1") || aura_hash_bytes)`

## 8. Seal Line

### 8.1 Derivation

`seal_line` is derived as follows:

1. Compute `line_digest`.
2. Compute `line_hex = lower_hex(line_digest)`.
3. Take `line_hex[0..15]`, the first 16 hex characters.
4. Map each hex character through the V2 glyph alphabet.
5. Concatenate the 16 glyphs with no separators.

### 8.2 Canonical representation

The canonical `seal_line` representation is:

- exactly 16 glyphs;
- no spaces;
- no tabs;
- no line breaks; and
- no leading or trailing characters of any kind.

The canonical representation is the only machine comparison form.

### 8.3 Display-only representation

A documentation-only pretty form MAY insert a single ASCII space between adjacent glyphs for human reading. That form is non-canonical. Canonical parsers MUST reject it.

## 9. Crest

### 9.1 Derivation

`crest` is derived as follows:

1. Compute `crest_digest`.
2. Compute `crest_hex = lower_hex(crest_digest)`.
3. Take `crest_hex[0..7]`, the first 8 hex characters.
4. Map each hex character through the V2 glyph alphabet.
5. Concatenate the 8 glyphs with no separators.

### 9.2 Canonical representation

The canonical `crest` representation is:

- exactly 8 glyphs;
- no spaces;
- no tabs;
- no line breaks; and
- no leading or trailing characters of any kind.

### 9.3 Display-only representation

A documentation-only pretty form MAY insert a single ASCII space between adjacent glyphs for human reading. That form is non-canonical. Canonical parsers MUST reject it.

## 10. Matrix Sequence and Matrix Form

### 10.1 `matrix_sequence`

`matrix_sequence` is derived as follows:

1. Compute `matrix_digest`.
2. Compute `matrix_hex = lower_hex(matrix_digest)`.
3. Map all 64 hex characters through the V2 glyph alphabet.
4. Concatenate the resulting 64 glyphs with no separators.

The canonical `matrix_sequence` representation is:

- exactly 64 glyphs;
- no spaces;
- no tabs;
- no line breaks; and
- no leading or trailing characters of any kind.

### 10.2 `matrix_form`

`matrix_form` is the exact rendered form of `matrix_sequence`.

It is derived by:

1. splitting `matrix_sequence` into eight consecutive groups of eight glyphs each; and
2. joining the eight rows with ASCII LF (`U+000A`).

The exact syntax rules are:

- exactly 8 rows;
- exactly 8 glyphs per row;
- LF is the only permitted row separator;
- no spaces inside a row;
- no empty rows;
- no trailing LF at the end of the eighth row; and
- no CR, CRLF, tab, BOM, or other control character anywhere.

Font choice, line height, and visual squareness are non-normative. Only glyph order and LF row breaks are normative.

## 11. Parser and Validator Behavior

The following rules are mandatory:

- every semantic validator MUST know the intended UDOT version before comparison;
- every semantic validator MUST re-derive the expected artifact from `aura_hash_bytes` and compare exact canonical code point sequences;
- a standalone glyph parser checks syntax only; it does not establish version provenance;
- a V2 `seal_line` parser MUST reject any string that is not exactly 16 V2 glyphs;
- a V2 `crest` parser MUST reject any string that is not exactly 8 V2 glyphs;
- a V2 `matrix_sequence` parser MUST reject any string that is not exactly 64 V2 glyphs;
- a V2 `matrix_form` parser MUST reject any string that is not exactly the 8x8 LF-delimited rendering defined above;
- all canonical parsers MUST reject ASCII spaces, tabs, CR, CRLF, non-breaking spaces, zero-width characters, and Unicode normalization side effects; and
- a successful syntax parse MUST NOT be treated as semantic verification.

Unlabeled `seal_line` and `crest` strings are especially unsafe because every V1 glyph is also a valid V2 glyph. Version metadata is therefore mandatory for reliable validation.

## 12. Serializer Requirements

A conforming V2 serializer MUST:

- emit canonical `seal_line`, `crest`, and `matrix_sequence` strings with no whitespace;
- emit `matrix_form` with LF row separators only when that rendered form is requested;
- emit lowercase hex if it emits any hash or digest hex for diagnostics or fixtures;
- serialize glyph strings as UTF-8 if a byte encoding is needed; and
- preserve glyph order exactly as derived.

A conforming V2 serializer MUST NOT:

- insert visual delimiters into canonical representations;
- emit CRLF for canonical `matrix_form`;
- substitute lookalike glyphs;
- normalize glyph strings; or
- infer output from display-only formatting.

## 13. Reference Pseudocode

```text
alphabet_v2 = {
  '0': '◦', '1': '◌', '2': '∘', '3': '○',
  '4': '⟡', '5': '◎', '6': '•', '7': '∙',
  '8': '◈', '9': '◇', 'a': '◆', 'b': 'ㅁ',
  'c': '■', 'd': '□', 'e': '▣', 'f': '▤'
}

decode_aura_hash_text(input_text):
  reject if length(input_text) != 64
  reject if any character is not ASCII hex
  return hex_decode_ascii_case_insensitive(input_text)

map_hex_to_glyphs(hex_text):
  return concatenate(alphabet_v2[ch] for ch in hex_text)

derive_udot_v2(aura_hash_bytes[32]):
  line_digest   = SHA256(ASCII("AURA_UDOT_SEAL_LINE_V1") || aura_hash_bytes)
  crest_digest  = SHA256(ASCII("AURA_UDOT_SEAL_V1") || aura_hash_bytes)
  matrix_digest = SHA256(ASCII("AURA_UDOT_MATRIX_V1") || aura_hash_bytes)

  line_hex   = lower_hex(line_digest)
  crest_hex  = lower_hex(crest_digest)
  matrix_hex = lower_hex(matrix_digest)

  seal_line       = map_hex_to_glyphs(line_hex[0:16])
  crest           = map_hex_to_glyphs(crest_hex[0:8])
  matrix_sequence = map_hex_to_glyphs(matrix_hex[0:64])
  matrix_form     = join_with_lf(chunk(matrix_sequence, 8))

  return {
    format_version: 2,
    seal_line,
    crest,
    matrix_sequence,
    matrix_form
  }
```

## 14. Determinism Guarantees

For a fixed `aura_hash_bytes`, a conforming V2 implementation MUST produce exactly one `seal_line`, one `crest`, one `matrix_sequence`, and one `matrix_form`.

V2 derivation MUST NOT depend on:

- locale;
- platform newline defaults;
- font selection;
- text normalization;
- UI layout;
- randomness; or
- external network state.

If two implementations receive the same 32 input bytes and follow this document, they MUST emit identical canonical outputs.

## 15. Worked Example

For input Aura hash:

`14eda752a31094ed7cffb71864a880373b6cc24ec252f5bb70f4661ee61e91fd`

The derived values are:

- `line_digest = 9c60eed302d00ffdf86f2d92c24e86751270a12cc3497c0708e4ad0e92b555a3`
- `seal_line = ◇■•◦▣▣□○◦∘□◦◦▤▤□`
- `crest_digest = 1103c3a0fbf38e89b7a636255d1d213921f6c02cb21da1322995927acef84ef2`
- `crest = ◌◌◦○■○◆◦`
- `matrix_digest = 79dacab6af716e0838c86795c725a764b4b6c82b3808559fd36d748d0463bf14`
- `matrix_sequence = ∙◇□◆■◆ㅁ•◆▤∙◌•▣◦◈○◈■◈•∙◇◎■∙∘◎◆∙•⟡ㅁ⟡ㅁ•■◈∘ㅁ○◈◦◈◎◎◇▤□○•□∙⟡◈□◦⟡•○ㅁ▤◌⟡`

`matrix_form` is:

```text
∙◇□◆■◆ㅁ•
◆▤∙◌•▣◦◈
○◈■◈•∙◇◎
■∙∘◎◆∙•⟡
ㅁ⟡ㅁ•■◈∘ㅁ
○◈◦◈◎◎◇▤
□○•□∙⟡◈□
◦⟡•○ㅁ▤◌⟡
```

Additional positive and negative vectors are frozen in `docs/AURA_UDOT_TEST_VECTOR_STATUS_V2.md`.

## 16. Acceptance Criteria and Test Vector Requirements

A conforming V2 implementation MUST:

- accept the canonical raw-byte input surface defined in Section 4;
- implement the strict text-input helper profile if it accepts textual hashes;
- derive `seal_line`, `crest`, `matrix_sequence`, and `matrix_form` exactly as defined here;
- emit canonical serializations exactly as defined here;
- reject malformed text input, malformed glyph strings, malformed matrix rendering, and unsupported versions;
- distinguish syntax validation from semantic verification;
- pass every positive and negative vector frozen in `docs/AURA_UDOT_TEST_VECTOR_STATUS_V2.md`; and
- preserve the V1 compatibility boundary documented in `AURA_UDOT_SEAL_LAYER_SPEC_V1_UPDATED.md` and `docs/AURA_UDOT_MIGRATION_NOTE_V2.md`.

## 17. Security Considerations

UDOT V2 is a derived identity surface, not a replacement for Aura's primary commitments.

The security boundary is:

- `seal_line` carries 64 bits of the line digest and is suitable for fast comparison, not primary commitment use;
- `crest` carries 32 bits of the crest digest and is even more collision-prone;
- `matrix_sequence` exposes all 256 bits of `matrix_digest`, but it is still a separate domain-separated digest rendered as glyphs, not the canonical Aura hash itself;
- version confusion is a real risk because V1 glyphs are all valid V2 glyphs;
- validators MUST compare exact code point sequences, not visual similarity; and
- any parser that silently trims, normalizes, or auto-detects versions creates avoidable ambiguity and MUST NOT be used for protocol verification.

## 18. Non-Goals and Future Versions

UDOT V2 does not:

- replace the full Aura hash in any verification flow;
- define privacy blinding, hidden salts, or off-chain masking;
- define a transport envelope or storage schema for carrying UDOT artifacts;
- define QR, barcode, OCR, AR, or machine-vision semantics; or
- authorize any alternate glyph alphabet or layout system.

Any future UDOT version MUST use an explicit new version identifier and MUST NOT be called V2 if it changes any of the following:

- the input byte surface;
- any domain-separation byte string;
- nibble ordering;
- the glyph alphabet;
- canonical whitespace or line-break rules; or
- parser rejection behavior.
