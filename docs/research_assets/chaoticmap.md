<!--
Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
Matrix: [[1,1],[1,2]] mod (2^521-1)
Date: 2026-03-26
-->
<!-- DOC_STATUS_HEADER_START -->
> Status: HISTORICAL (SUPERSEDED)
> Concept: Aura DCM Core v1
> Scope Boundary: Historical snapshot retained for traceability only. It is superseded and must not be used as current protocol, package, fixture, or repository authority.
> Replaced By: [Aura DCM Core v1](docs/AURA_DCM_CORE_V1.md)
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as historical context only. Follow the replacement document for current authority.
> Implementation State: Superseded.
<!-- DOC_STATUS_HEADER_END -->

================================================================================
TECHNICAL NOTE: UPGRADE TO VOLUME-PRESERVING CHAOTIC MAP
(Arnold Cat Map variant with built-in Fibonacci-Log structure)
================================================================================
Date: 2026-03-26
Authors: Keyboard_Lord & Grok
Status: Repository implementation note for Aura's canonical lower-layer runtime

1. Old Primitive (deprecated)
   z_{n+1} = (z_n² + c) mod (2^{521} - 1)

   Problems:
   - Dissipative: information loss on every iteration
   - Multiple inputs can collide → identity collisions
   - Risk of state collapse into short cycles
   - No efficient logarithmic-time fast-forward

2. New Primitive (current standard)
   We now use the linear volume-preserving map on (Z/NZ)²:

       [ x_{n+1} ]   =   [ 1  1 ]   [ x_n ]   (mod N)
       [ y_{n+1} ]       [ 1  2 ]   [ y_n ]

   where N = 2^{521} - 1 (same Mersenne prime used everywhere).

   Matrix form:
   M = [[1, 1],
        [1, 2]]

   Determinant: det(M) = 1 → bijective for any N (invertible over Z/NZ).

3. Initialization
   x₀ = user_entropy mod N
   y₀ = verifier_challenge_z₀ mod N
   (Optionally: x₀ = Hash(entropy || z₀) mod N for extra mixing)

4. Core Properties (why this is strictly superior)
   • Perfect reversibility: every state has exactly one predecessor
   • No state collapse or identity collisions
   • Volume-preserving (area-preserving on the torus)
   • Both coordinate sequences satisfy the exact linear recurrence:
        u_{n+2} ≡ 3 u_{n+1} − u_n   (mod N)
     This is the Pell-companion / generalized Fibonacci recurrence
     induced by the matrix characteristic polynomial λ² − 3λ + 1.

5. Fibonacci-Log Structure (the feature we were chasing)
   Because M satisfies its own characteristic equation, we can:
   - Jump any number of iterations k in O(log k) time using fast matrix
     exponentiation: state_k = M^k · [x₀, y₀]^T mod N
   - Compute the inverse instantly with:
        M⁻¹ = [[2, -1],
               [-1,  1]] mod N
   - This gives us the exact “Fibonacci log” structure we wanted:
     logarithmic-time verification and fast-forward capability.

6. Implementation Notes for Aura Repo
   • All files have been upgraded using the Codex prompt dated 2026-03-26.
   • Core math module now exports:
       - one-step forward and inverse transitions
       - logarithmic-time fast-forward and rewind
       - canonical pair-state byte encoding
       - deterministic byte-to-field reduction for seed initialization
   • Modulus N remains 2^{521}-1 everywhere.
   • Public API surface intentionally kept identical where possible.

7. Security & Usage Recommendations
   • The map-level claim proven here is bijectivity, not cryptographic
     pseudorandomness or one-wayness.
   • Never expose long runs of raw (x_n, y_n) states if higher-layer
     protocol secrecy matters.
   • Use terminal states and traces only through explicit binding hashes,
     commitment roots, or KDF/extractor layers defined by the protocol.
   • Deterministic seed initialization must reduce byte strings modulo N
     in a canonical big-endian way to avoid cross-implementation drift.

8. Verification Boundary
   What this repository verifies in code:
   - exact forward transition
   - exact inverse transition
   - recurrence law
   - logarithmic jump equivalence
   - canonical serialization and deterministic hashing/binding
   - exhaustive bijection checks for reduced toy prime moduli

   What this note does not claim:
   - a proof that this linear map alone is a complete cryptographic protocol
   - that finite-field mixing claims imply higher-layer security by themselves
   - that exposing raw iterates is safe without an explicit extractor/binding layer

9. Quick Reference – Matrix Power (for fast-forward)
   M^k can be computed via exponentiation by squaring in log(k) multiplications.
   The entries of M^k are determined by the same order-2 recurrence above.

This document replaces all previous references to the quadratic map in the
repository. The new primitive is bijective, entropy-preserving, and
algebraically structured exactly like a Fibonacci logarithm.

================================================================================
End of document
