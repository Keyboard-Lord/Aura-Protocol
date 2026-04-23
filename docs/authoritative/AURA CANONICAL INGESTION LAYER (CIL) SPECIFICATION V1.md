# AURA CANONICAL INGESTION LAYER (CIL) SPECIFICATION V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `PRE-L1 (BOUNDARY)`  
**Purpose:** Define the only valid path from untrusted input into canonical message_bytes  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — INPUT BOUNDARY**
> This document defines the exclusive boundary between untrusted external input
> and canonical byte material consumed by AURA_HASH_V2. No alternate ingestion paths.

---

## Document Status

- **Classification:** ACTIVE AUTHORITY
- **Target Hash:** AURA_HASH_V2 (521-bit SHA3-512-based)

\---

\#\# 1\. Scope and Position

CIL (Canonical Ingestion Layer) is the exclusive boundary between:

\- untrusted external input; and  
- canonical byte material consumed by `AURA_HASH_V2`.

CIL does NOT:

\- perform hashing;  
\- alter hash framing;  
\- introduce alternate identity functions; or  
\- depend on STORM, AIR, or field-recursive math.

CIL strictly defines:

\- admissible input domains;  
\- canonicalization rules;  
\- deterministic byte construction; and  
\- fail-closed rejection behavior.

\---

\#\# 2\. Canonical Pipeline Position

The canonical identity path is:

\`\`\`  
untrusted\_input  
  \-\> CIL.parse  
  \-\> CIL.canonicalize  
  \-\> CIL.assemble  
  \-\> message\_bytes  
  \-\> AURA\_HASH\_V1  
\`\`\`

CIL terminates at \`message\_bytes\`.

\`AURA\_HASH\_V1\` remains the sole identity function.

\---

\#\# 3\. Input Domains

CIL defines exactly two valid input domains:

\#\#\# 3.1 Raw Domain

\`\`\`  
I\_raw \= { b | b is an arbitrary byte string }  
\`\`\`

\- No transformation is applied.  
\- Identity is byte-exact.

\---

\#\#\# 3.2 Text Domain

\`\`\`  
I\_text \= { x | x is a valid UTF-8 byte string without BOM }  
\`\`\`

Constraints:

\- MUST be valid UTF-8  
\- MUST NOT contain BOM  
\- MUST NOT contain non-canonical encodings

\---

\#\# 4\. Parsing Function

CIL defines a total parsing function over admissible inputs:

\`\`\`  
P : U \-\> (mode, payload) | reject  
\`\`\`

Where:

\- \`U\` \= untrusted input  
\- \`mode ∈ { raw, text }\`  
\- \`payload\` \= byte sequence

\#\#\# 4.1 Parsing Rules

A valid input MUST:

\- specify exactly one mode  
\- contain exactly one payload  
\- contain no unknown fields  
\- contain no implicit defaults  
\- contain no null or ambiguous mode

\#\#\# 4.2 Rejection Conditions

Reject if:

\- mode is missing or duplicated  
\- payload is missing  
\- unknown fields are present  
\- encoding is ambiguous

\---

\#\# 5\. Canonicalization Functions

CIL defines two canonical projection functions:

\`\`\`  
C\_raw  : I\_raw  \-\> B  
C\_text : I\_text \-\> B  
\`\`\`

Where \`B\` is the set of canonical \`message\_bytes\`.

\---

\#\#\# 5.1 Raw Canonicalization

\`\`\`  
C\_raw(x) \= x  
\`\`\`

Properties:

\- byte-preserving  
\- no normalization  
\- no transformation

\---

\#\#\# 5.2 Text Canonicalization

Text canonicalization is defined as a strict composition of transforms:

\`\`\`  
C\_text(x) \=  
  E\_utf8(  
    L\_lf(  
      N\_nfc(  
        R\_bom(  
          V\_utf8(x)  
        )  
      )  
    )  
  )  
\`\`\`

\#\#\#\# Transform Definitions

\- \`V\_utf8(x)\`  
  \- validates UTF-8  
  \- reject on failure

\- \`R\_bom(x)\`  
  \- reject if BOM present

\- \`N\_nfc(x)\`  
  \- normalize to Unicode NFC

\- \`L\_lf(x)\`  
  \- convert CRLF and CR → LF

\- \`E\_utf8(x)\`  
  \- encode as UTF-8 bytes

\---

\#\#\# 5.3 Canonicalization Properties

For all valid inputs:

\- Deterministic  
\- Idempotent  
\- Total over valid domain  
\- Rejecting over invalid domain

\---

\#\# 6\. Assembly Function

CIL defines canonical byte assembly:

\`\`\`  
A(m) \= u64\_le(len(m)) || m  
\`\`\`

Where:

\- \`m\` \= canonical message bytes  
\- \`u64\_le\` \= 8-byte little-endian length prefix

\---

## 7. Identity Handoff

CIL output is consumed by the active canonical identity function:

```
H_521(m) = Reduce_N(SHA3-512(A(m)))

where:
  A(m) = u64_le(len(m)) || m
  Reduce_N(x) = x mod (2^521 - 1)
```

This implements **AURA_HASH_V2**, the sole active identity function for the Aura protocol.

**Active Protocol (AURA_HASH_V2):**
- Uses SHA3-512 (not SHA-256)
- Produces 521-bit field element output
- Reduces into field modulus N = 2^521 - 1

**Deprecated (Historical Reference Only):**
- AURA_HASH_V1 used SHA-256 and produced 256-bit output
- V1 is deprecated and must not be used for new implementations

CIL does NOT modify:
- domain tag
- framing
- hash function

\---

\#\# 8\. Equivalence Classes

CIL defines equivalence only in TEXT mode.

\#\#\# 8.1 Definition

\`\`\`  
x \~ y  iff  C\_text(x) \= C\_text(y)  
\`\`\`

\#\#\# 8.2 Allowed Equivalences

Only the following are permitted:

\- Unicode NFC equivalence  
\- CRLF / CR / LF normalization

\#\#\# 8.3 Forbidden Equivalences

The system MUST NOT:

\- trim whitespace  
\- case-normalize  
\- infer encodings  
\- auto-detect formats

\---

\#\# 9\. Rejection Semantics

CIL is a partial function over \`U\` and total over valid inputs.

\#\#\# 9.1 Valid Case

\`\`\`  
valid input \-\> exactly one canonical byte string  
\`\`\`

\#\#\# 9.2 Invalid Case

\`\`\`  
invalid input \-\> exactly one rejection  
\`\`\`

\#\#\# 9.3 Fail-Closed Rules

CIL MUST:

\- never repair malformed input  
\- never normalize beyond defined transforms  
\- never fallback to alternate modes  
\- never guess intent

\---

\#\# 10\. Deterministic Guarantees

\#\#\# 10.1 Determinism Theorem

For any valid input \`x\`:

\`\`\`  
CIL(x) produces exactly one m  
\`\`\`

\---

\#\#\# 10.2 Idempotence Theorem

\`\`\`  
CIL(CIL(x)) \= CIL(x)  
\`\`\`

\---

\#\#\# 10.3 Raw Preservation Theorem

For all \`x ∈ I\_raw\`:

\`\`\`  
C\_raw(x) \= x  
\`\`\`

\---

\#\#\# 10.4 Text Equivalence Theorem

For all \`x, y ∈ I\_text\`:

\`\`\`  
HASH(x) \= HASH(y)  
iff  
C\_text(x) \= C\_text(y)  
\`\`\`

\---

\#\# 11\. Non-Goals

CIL explicitly does NOT:

\- define a new hash function  
\- interact with STORM recursion  
\- use field arithmetic (2^521 \- 1\)  
\- define commitments or proofs  
\- alter UDOT or representation layers

\---

\#\# 12\. Security Model

CIL guarantees:

\- no ambiguity at ingestion boundary  
\- no multi-path normalization  
\- no implicit behavior  
\- no hidden equivalence classes

Security boundary:

\- all ambiguity is rejected before hashing  
\- identity is derived only from canonical bytes

\---

\#\# 13\. Implementation Requirements

All implementations MUST:

\- enforce exact domain separation  
\- enforce strict parsing rules  
\- reject non-canonical encodings  
\- match byte-for-byte output across languages  
\- provide identical failure behavior

\---

\#\# 14\. Summary

CIL defines a single invariant:

\`\`\`  
Every accepted input produces exactly one canonical byte sequence,  
and every canonical byte sequence has exactly one hash identity.  
\`\`\`

No alternate ingestion path is valid.  
