\<\!-- DOC\_STATUS\_HEADER\_START \--\>  
\> **Status:** SUPPORTING / PRESENTATION-ONLY — NON-AUTHORITATIVE  
\> **Concept:** Aura UDOT Unicode Layer V3  
\> **Scope Boundary:** Presentation-only Unicode rendering layer above canonical UDOT V2. Does NOT alter canonical UDOT derivation, proof identity, settlement identity, or any active wire.  
\> **Canonical Reference:** AURA\_UDOT\_SPEC\_V1.md (ACTIVE AUTHORITY)  
\> **Critical Rule:** If any statement here conflicts with AURA\_UDOT\_SPEC\_V1.md, the canonical UDOT spec wins.  
\> **Interpretation Rule:** This is a deterministic display-layer specification ONLY. Do NOT use for canonical semantics.  
\> **Implementation State:** Supporting presentation layer.  
\<\!-- DOC\_STATUS\_HEADER\_END \--\>

\# AURA\_UDOT\_UNICODE\_LAYER\_V3

**Classification:** \`SUPPORTING\`  
**Layer:** \`L5-PRESENTATION\`  
**Purpose:** Define deterministic Unicode display layer above canonical \`UdotBundleV2\`  
**Status:** \`SUPPORTING\`

\> **SUPPORTING — PRESENTATION LAYER ONLY**  
\> This document defines a human-facing Unicode rendering of canonical UDOT output.  
\> It MUST NOT create a parallel identity surface. Canonical identity flows from  
\> AURA\_HASH\_V2 → STORM → proof → UDOT only.

\#\# 1\. Authority Boundary

This document defines a presentation layer only.

It MUST NOT define or alter:

\- \`proof\_hash\_hex\`  
\- \`seal\_line\`  
\- \`crest\`  
\- \`matrix\_sequence\`  
\- \`UdotBundleV2\`  
\- canonical UDOT derivation  
\- canonical proof identity  
\- canonical settlement identity  
\- canonical pipeline stage order

This layer exists only to provide a richer, deterministic, human-facing Unicode rendering of canonical UDOT output.

If a consumer needs canonical UDOT semantics, it MUST use canonical UDOT directly.

\#\# 2\. Position In The Stack

This layer sits strictly above canonical UDOT V2.

The active artifact chain remains:

1\. build \`ProofMaterialV1\`  
2\. derive \`proof\_material\_hash\`  
3\. build \`FractalKeyV1\`  
4\. derive \`proof\_hash\`  
5\. derive canonical \`UdotBundleV2\`

This document defines only an optional deterministic rendering that starts after \`UdotBundleV2\` already exists.

\#\# 3\. Input Contract

The only valid semantic input is canonical \`UdotBundleV2\`:

\- \`proof\_hash\_hex\`  
\- \`seal\_line\`  
\- \`crest\`  
\- \`matrix\_sequence\`

A compliant implementation MAY derive the Unicode layer from either:

\- canonical \`proof\_hash\_hex\` by first recomputing canonical UDOT V2; or  
\- an already-validated canonical \`UdotBundleV2\`

A compliant implementation MUST NOT accept independent user-supplied Unicode display artifacts as a source of truth.

\#\# 4\. Non-Canonical Rule

The Unicode UDOT layer is not a cryptographic commitment surface.

It MUST NOT be used as:

\- hash input  
\- proof input  
\- settlement input  
\- canonical pipeline wire data  
\- authorization identity  
\- a substitute for canonical UDOT fields

A Unicode artifact is valid only when it deterministically reduces to the same canonical UDOT V2 artifact from which it was derived.

\#\# 5\. Design Goal

The Unicode UDOT layer provides:

\- deterministic display  
\- human-verifiable structure  
\- richer visual patterning than the canonical single-glyph UDOT alphabet  
\- stable rendering in terminals, docs, explorers, and UI surfaces  
\- reversible reduction back to canonical UDOT V2 glyph identity

The goal is stronger visual structure, not additional semantic freedom.

\#\# 6\. Display Model

The Unicode layer introduces a second-order rendering system:

\- canonical UDOT glyphs remain the semantic symbols  
\- each canonical glyph is rendered as one fixed Unicode cell recipe  
\- the rendered cell is presentation  
\- the cell reduces back to exactly one canonical UDOT V2 glyph class

This is a display expansion, not a semantic replacement.

\#\# 7\. Canonical Semantic Alphabet

The semantic alphabet remains the canonical UDOT V2 nibble alphabet:

| Nibble | Canonical Glyph |  
| \--- | \--- |  
| \`0\` | \`◦\` |  
| \`1\` | \`◌\` |  
| \`2\` | \`∘\` |  
| \`3\` | \`○\` |  
| \`4\` | \`⟡\` |  
| \`5\` | \`◎\` |  
| \`6\` | \`•\` |  
| \`7\` | \`∙\` |  
| \`8\` | \`◈\` |  
| \`9\` | \`◇\` |  
| \`a\` | \`◆\` |  
| \`b\` | \`ㅁ\` |  
| \`c\` | \`■\` |  
| \`d\` | \`□\` |  
| \`e\` | \`▣\` |  
| \`f\` | \`▤\` |

This document does not change that table.

\#\# 8\. Unicode Cell Layer

\#\#\# 8.1 Cell Rule

Each canonical UDOT glyph maps to exactly one fixed 3x3 Unicode cell.

A cell is three rows of three characters each.

Each row is encoded as one UTF-8 string of length 3\.

A cell is therefore:

\- row 0: 3 code points  
\- row 1: 3 code points  
\- row 2: 3 code points

\#\#\# 8.2 Allowed Cell Characters

The Unicode cell layer is restricted to the following display alphabet:

\- space: \` \`  
\- light horizontal: \`─\`  
\- light vertical: \`│\`  
\- corners: \`┌\` \`┐\` \`└\` \`┘\`  
\- tee/intersection: \`┬\` \`┴\` \`├\` \`┤\` \`┼\`  
\- open dot: \`◦\`  
\- ring dot: \`∘\`  
\- filled dot: \`•\`  
\- small dot: \`∙\`  
\- open diamond: \`◇\`  
\- filled diamond: \`◆\`  
\- light square: \`□\`  
\- heavy square: \`■\`

No other display characters are valid in V1.

\#\#\# 8.3 Normalization Rule

All display strings MUST be treated as exact Unicode scalar sequences.

Implementations MUST NOT:

\- normalize to alternate compatibility forms  
\- substitute box-drawing variants  
\- substitute visually similar code points  
\- insert zero-width characters  
\- insert variation selectors  
\- rewrite ASCII space into non-breaking space

\#\# 9\. Fixed Cell Recipes

The following table is exact.

Each canonical UDOT glyph is rendered as one fixed 3x3 cell.

\#\#\# 9.1 Open / Ring Family

\#\#\#\# \`0\` / \`◦\`

\`\`\`text  
┌─┐  
│◦│  
└─┘

#### **`1` / `◌`**

┌─┐  
│◌│  
└─┘

#### **`2` / `∘`**

┌─┐  
│∘│  
└─┘

#### **`3` / `○`**

┌┬┐  
│○│  
└┴┘

### **9.2 Diamond / Point Family**

#### **`4` / `⟡`**

┌─┐  
│◇│  
└─┘

#### **`5` / `◎`**

┌┬┐  
│∘│  
└┴┘

#### **`6` / `•`**

┌─┐  
│•│  
└─┘

#### **`7` / `∙`**

┌─┐  
│∙│  
└─┘

### **9.3 Heavy Diamond / Square Family**

#### **`8` / `◈`**

┌┬┐  
│◆│  
└┴┘

#### **`9` / `◇`**

┌┬┐  
│◇│  
└─┘

#### **`a` / `◆`**

┌┬┐  
│◆│  
└─┘

#### **`b` / `ㅁ`**

┌─┐  
│□│  
└┬┘

### **9.4 Block Family**

#### **`c` / `■`**

┌─┐  
│■│  
└─┘

#### **`d` / `□`**

┌─┐  
│□│  
└─┘

#### **`e` / `▣`**

┌┬┐  
│■│  
└┴┘

#### **`f` / `▤`**

┌┬┐  
│■│  
└┬┘

## **10\. Semantic Reduction Rule**

Each Unicode cell reduces to exactly one canonical UDOT glyph identity.

Reduction is exact and table-driven.

A parser MUST:

1. read a 3x3 cell  
2. compare the exact 9 code points against the fixed recipe table  
3. emit exactly one canonical UDOT glyph if matched  
4. reject otherwise

Approximate matching is invalid.

Visual similarity is invalid.

Font-dependent interpretation is invalid.

## **11\. Layout Modes**

This document defines four deterministic layout modes.

Layout mode affects only arrangement, not glyph semantics.

### **11.1 `seal_horizontal`**

Input: canonical `seal_line` of 16 glyphs.

Rendering rule:

* render each glyph as one 3x3 cell  
* concatenate the 16 cells horizontally  
* no column gap is inserted between cells  
* rows are separated by ASCII LF  
* final output is exactly 3 rows

### **11.2 `seal_vertical`**

Input: canonical `seal_line` of 16 glyphs.

Rendering rule:

* render each glyph as one 3x3 cell  
* stack the 16 cells vertically  
* no blank row is inserted between cells  
* rows are separated by ASCII LF  
* final output is exactly 48 rows

### **11.3 `crest_compact`**

Input: canonical `crest` of 8 glyphs.

Rendering rule:

* render each glyph as one 3x3 cell  
* concatenate horizontally  
* no column gap is inserted between cells  
* rows are separated by ASCII LF  
* final output is exactly 3 rows

### **11.4 `matrix_8x8`**

Input: canonical `matrix_sequence` of 64 glyphs.

Rendering rule:

* split the sequence into 8 consecutive rows of 8 glyphs each  
* render each glyph as one 3x3 cell  
* concatenate cells horizontally within a row  
* concatenate the 8 rendered cell-rows vertically  
* no blank spacer rows or columns are inserted  
* rows are separated by ASCII LF

The rendered matrix therefore occupies:

* width \= 24 code points per line  
* height \= 24 lines

## **12\. Optional Index Marks**

### **12.1 Purpose**

Index marks exist only to improve human navigation through long display artifacts.

They are optional.

They are never semantic.

### **12.2 Modes**

V1 defines two optional index modes:

* `none`  
* `group4`

### **12.3 `group4` Rule**

In `seal_horizontal` and `crest_compact`:

* after every fourth rendered cell, a single ASCII space MAY be inserted  
* this spacing is display-only  
* it is not part of canonical Unicode-layer comparison  
* semantic reduction MUST ignore this optional grouping space only when the parser was explicitly told to accept `group4`

In `matrix_8x8`:

* no grouping spaces are valid  
* no grouping blank lines are valid

Default mode is `none`.

## **13\. Canonical Unicode-Layer Objects**

This document defines one display object:

`UdotUnicodeLayerV1`

It is:

* `proof_hash_hex`  
* `layout_mode`  
* `index_mode`  
* `display_text`

### **13.1 Field Rules**

`proof_hash_hex`

* canonical lowercase 64-hex

`layout_mode`

* one of:  
  * `seal_horizontal`  
  * `seal_vertical`  
  * `crest_compact`  
  * `matrix_8x8`

`index_mode`

* one of:  
  * `none`  
  * `group4`

`display_text`

* exact UTF-8 text produced by the chosen layout and index rules

### **13.2 Excluded Fields**

A Unicode display object MUST NOT carry:

* `seal_line`  
* `crest`  
* `matrix_sequence`  
* `matrix_form`  
* `udot_version`  
* any alternate glyph map  
* any user-defined cell recipe table

This keeps the display object derived and minimal.

## **14\. Derivation Procedure**

### **14.1 High-Level Rule**

To derive `UdotUnicodeLayerV1`:

1. obtain canonical `proof_hash_hex`  
2. derive canonical `UdotBundleV2`  
3. select one valid `layout_mode`  
4. select one valid `index_mode`  
5. reduce canonical glyphs into fixed 3x3 cells  
6. apply deterministic layout rules  
7. emit `display_text`

### **14.2 No Alternate Recipe Rule**

No implementation may:

* customize cell art  
* choose a different border alphabet  
* change dimensions  
* change per-glyph recipes  
* add theme colors as semantic markers  
* re-order the sequence

Any such variant is outside V1.

## **15\. Parser Rules**

A compliant parser for this layer MUST require:

* explicit `layout_mode`  
* explicit `index_mode`  
* explicit expectation of V1 cell recipes

The parser MUST:

1. parse the layout structure  
2. split the layout back into 3x3 cells  
3. reduce each cell to canonical UDOT glyphs using the exact recipe table  
4. reconstruct the expected canonical sequence for that layout  
5. compare it to canonical UDOT V2 recomputed from `proof_hash_hex`  
6. reject on any mismatch

A syntax parse alone is not semantic acceptance.

## **16\. Strict Rejection**

Reject:

* invalid row count  
* invalid column width  
* unknown characters  
* unknown cell recipe  
* mixed layout rules  
* CR or CRLF  
* tabs  
* trailing spaces at line ends  
* unexpected blank lines  
* non-canonical `proof_hash_hex`  
* Unicode normalization drift  
* display text that reduces to a different canonical UDOT sequence

## **17\. Serialization Rules**

If serialized to JSON:

* UTF-8 only  
* no escaped alternate display substitution logic  
* `display_text` preserves exact LF bytes  
* `proof_hash_hex` is canonical lowercase hex  
* no inferred defaults

If displayed in docs:

* fenced code blocks are recommended  
* screenshots are non-authoritative  
* copied text must preserve exact code points

## **18\. Reference Pseudocode**

### **18.1 Cell Table**

CELL\_TABLE \= {  
 "◦": \["┌─┐", "│◦│", "└─┘"\],  
 "◌": \["┌─┐", "│◌│", "└─┘"\],  
 "∘": \["┌─┐", "│∘│", "└─┘"\],  
 "○": \["┌┬┐", "│○│", "└┴┘"\],

 "⟡": \["┌─┐", "│◇│", "└─┘"\],  
 "◎": \["┌┬┐", "│∘│", "└┴┘"\],  
 "•": \["┌─┐", "│•│", "└─┘"\],  
 "∙": \["┌─┐", "│∙│", "└─┘"\],

 "◈": \["┌┬┐", "│◆│", "└┴┘"\],  
 "◇": \["┌┬┐", "│◇│", "└─┘"\],  
 "◆": \["┌┬┐", "│◆│", "└─┘"\],  
 "ㅁ": \["┌─┐", "│□│", "└┬┘"\],

 "■": \["┌─┐", "│■│", "└─┘"\],  
 "□": \["┌─┐", "│□│", "└─┘"\],  
 "▣": \["┌┬┐", "│■│", "└┴┘"\],  
 "▤": \["┌┬┐", "│■│", "└┬┘"\]  
}

### **18.2 Horizontal Seal Render**

render\_seal\_horizontal(seal\_line\[16\]):  
 row0 \= ""  
 row1 \= ""  
 row2 \= ""

 for glyph in seal\_line:  
   cell \= CELL\_TABLE\[glyph\]  
   row0 \+= cell\[0\]  
   row1 \+= cell\[1\]  
   row2 \+= cell\[2\]

 return row0 || "\\n" || row1 || "\\n" || row2

### **18.3 Matrix Render**

render\_matrix\_8x8(matrix\_sequence\[64\]):  
 rows \= split\_into\_chunks(matrix\_sequence, 8\)  
 output\_lines \= \[\]

 for glyph\_row in rows:  
   line0 \= ""  
   line1 \= ""  
   line2 \= ""

   for glyph in glyph\_row:  
     cell \= CELL\_TABLE\[glyph\]  
     line0 \+= cell\[0\]  
     line1 \+= cell\[1\]  
     line2 \+= cell\[2\]

   output\_lines.push(line0)  
   output\_lines.push(line1)  
   output\_lines.push(line2)

 return join\_with\_lf(output\_lines)

### **18.4 Reduction**

reduce\_cell(cell\_lines\[3\]):  
 for (glyph, recipe) in CELL\_TABLE:  
   if recipe\[0\] \== cell\_lines\[0\] and recipe\[1\] \== cell\_lines\[1\] and recipe\[2\] \== cell\_lines\[2\]:  
     return glyph

 reject

## **19\. Example Workflow**

Given canonical:

* `proof_hash_hex`  
* `seal_line`  
* `crest`  
* `matrix_sequence`

A wallet MAY show:

* compact crest using `crest_compact`  
* explorer badge using `seal_horizontal`  
* full proof seal using `matrix_8x8`

All of these are valid only if they reduce back to the same canonical UDOT V2 sequence derived from the same `proof_hash_hex`.

## **20\. Invariants**

* this layer never changes canonical UDOT semantics  
* each canonical glyph has exactly one V1 cell recipe  
* each V1 cell recipe reduces to exactly one canonical glyph  
* layout is deterministic once `layout_mode` and `index_mode` are fixed  
* semantic validation always bottoms out at canonical UDOT V2 recomputation from `proof_hash_hex`  
* no user-authored Unicode display artifact is authoritative on its own

## **21\. Future Version Boundary**

Future versions MAY change:

* the cell dimension  
* the display alphabet  
* the art grammar  
* the supported layout modes

Future versions MUST NOT mutate V1 behavior.

A V2 or later Unicode layer must define:

* a new versioned document  
* a new fixed recipe table  
* new parser behavior  
* new test vectors

## **22\. Recommended Repo Placement**

Recommended path:

docs/supporting/AURA\_UDOT\_UNICODE\_LAYER\_V1.md

Recommended implementation paths:

crates/aura\_udot\_v2/src/unicode\_layer\_v1.rs  
packages/aura\_sdk\_v1\_ts/src/udotUnicodeLayerV1.ts  
fixtures/v1/udot\_unicode\_layer\_v1/test\_vectors.json

## **23\. Final Rule**

Canonical Aura truth remains:

* `proof_hash_hex`  
* canonical UDOT V2 derivation  
* canonical pipeline and settlement rules

This Unicode layer is a deterministic visual shell around that truth and nothing more.

If you want, I can turn this into the matching Rust and TypeScript implementation files next.  
