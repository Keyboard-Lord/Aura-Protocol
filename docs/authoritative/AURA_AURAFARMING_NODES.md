# AURA: Aurafarming Design Document

**Classification:** `RESEARCH / SUPPORTING`  
**Layer:** `NETWORK (FUTURE)`  
**Purpose:** Design document for distributed aurafarmer node network  
**Status:** `RESEARCH`

> **RESEARCH ONLY — NON-AUTHORITATIVE FOR ACTIVE PROTOCOL**
> This document describes a proposed distributed network layer (Aurafarming).
> It is research and design material, NOT active protocol authority.
> The active protocol is defined in AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md.

**Distributed Cultivation of the Aura Shield**  
**Version 0.2** — 16 April 2026  

**Tyler McRae**  
**Keyboard_Lord**  

## Abstract

AURA is a single-path, fail-closed commitment system that wraps arbitrary input data in an unbreakable **aura shield** of protection.  

What began as a fractal hash evolved into a fractal key, then into a full cryptographic aura shield. This document describes **Aurafarming** — the decentralized network layer that cultivates these shields across a fixed 20-node dodecahedral graph.  

The system preserves the original AURA guarantees (canonical SHA3-512 identity surface, STORM recurrence over \( \mathbb{F}_{2^{521}-1} \), Merkle-committed trace, STARK proof, fail-closed semantics) while distributing the computation across specialized **aurafarmer nodes**. Old inputs are automatically forgotten via exponential moving average (EMA) decay inside the graph itself, ensuring the aura remains clean, live, and focused on fresh work.

The result is a living, self-cleaning protective field that is deterministic, quantum-resistant, and auditable end-to-end.

## 1. Vision — The Aura Shield of Protection

An **aura shield** is a glowing, self-contained boundary that:
- Takes messy, arbitrary input and collapses it to a single canonical identity.
- Expands that identity into a deterministic fractal trajectory via the STORM recurrence.
- Protects the truth inside with zero tolerance for ambiguity or deviation.
- Rejects on any breach (fail-closed).

**Aurafarming** is the act of cultivating these shields across a decentralized network of 20 specialized nodes. Each aurafarmer contributes compute and state propagation; together they grow, verify, and deliver perfect settlement artifacts.

## 2. Core AURA Protocol (Recap)

Every aura shield begins with the original single-path pipeline:
- **Canonical Identity**: \( H_{512}(m) = \text{SHA3-512}(\text{CanonicalBytes}(m)) \)
- **STORM Recurrence** (nonlinear fractal map over \( N = 2^{521}-1 \)):
  \[
  \begin{aligned}
  x_{n+1} &= x_n^2 - y_n^2 + a + \phi_n \pmod{N} \\
  y_{n+1} &= 2x_ny_n + b + \psi_n \pmod{N}
  \end{aligned}
  \]
  with entropy injection \( (\phi_n, \psi_n) \) from domain-separated StormV1.
- **Trace Commitment**: Merkle root over the full execution trace.
- **Verification**: STARK proof enforcing exact algebraic constraints (AIR).
- **Settlement**: One deterministic artifact or total rejection.

## 3. Aurafarming Network Topology

The aura is cultivated across a fixed, verifiable 20-node graph.

### Figure 1: The 3-regular dodecahedral graph used in Aura

(Figure rendered above)

**Properties**  
- 20 computational nodes (|V| = 20)  
- 30 edges (|E| = 30), 3-regular (each node has exactly 3 neighbors)  
- Diameter \( D = 5 \) (maximum 5 hops from any entry to \( v_{\text{out}} \))  
- Each edge carries **only** a fixed-size compressed state \( \sigma \) (Merkle digest, partial STORM state, or EMA vector)  

**Interpretation**: The highlighted top node is treated as \( v_{\text{out}} = v_1 \). Its three neighbors \( N(v_{\text{out}}) = \{v_2, v_{10}, v_{11}\} \) serve as primary entry points for new client inputs. Outer ring = nodes 1–10; inner star = nodes 11–20.

## 4. State Propagation & Natural Forgetting (EMA)

Inside every aurafarmer node runs a lightweight exponential moving average (EMA) that blends new work with incoming neighbor states while automatically suppressing old inputs.

### Figure 2: Exponential decay of input influence under EMA for different decay factors α

(Figure rendered above)

**EMA update rule** (executed at every node):
\[
V_k^{(t)} = \alpha \cdot S(I_k^{(t)}) + (1 - \alpha) \cdot \frac{1}{3} \sum_{j \in N(v_k)} V_j^{(t-1)}
\]

where \( S(I_k^{(t)}) \) is the fresh shard injected at node \( k \) (canonical identity, partial STORM step, entropy, etc.).

**Suppression guarantee**  
For any single input, its remaining influence after \( h \) hops is upper-bounded by:
\[
r(h, \alpha) = \left( \frac{1 - \alpha}{3} \right)^h
\]

**Diameter-5 summary** (at \( v_{\text{out}} \)):
- α = 0.50 → 99.9871 % suppressed (0.0129 % remaining)  
- α = 0.75 → 99.9996 % suppressed (0.0004 % remaining)  
- α = 0.90 → 99.999996 % suppressed (0.000004 % remaining)  

Fresh shards injected at every node accelerate convergence even further. The graph is self-cleaning — old work naturally fades away.

## 5. End-to-End Aura Shield Creation Flow

1. Client submits canonical input \( m \).  
2. Input enters the farm at one or more entry nodes (typically neighbors of \( v_{\text{out}} \)).  
3. Each aurafarmer node:  
   - Injects a fresh shard \( S(I_k^{(t)}) \).  
   - Runs local STORM recurrence steps (or verifies partial trace constraints).  
   - Applies the EMA update to blend with its 3 neighbors.  
   - Propagates the compressed state \( \sigma \) along its edges.  
4. After at most 5 hops, the fully-formed trace, Merkle root, and STARK proof converge at \( v_{\text{out}} \).  
5. \( v_{\text{out}} \) produces the final settlement artifact **or** rejects fail-closed if any constraint is violated.  

The entire process remains single-path and deterministic at the global level.

## 6. Security & Guarantees (Unchanged from Core AURA)

- Exclusive canonical identity surface (SHA3-512).  
- Deterministic STORM fractal trajectory.  
- Exact AIR constraints enforced algebraically.  
- Fail-closed at every layer.  
- Quantum-resistant under current assumptions.  
- Full execution lineage preserved via Merkle commitment (transparent, not opaque).  

The dodecahedral topology + EMA adds provable liveness and bounded memory without weakening any core property.

## 7. Aurafarmer Node Operation (High-Level)

Each aurafarmer node is a lightweight, specialized process that:
- Maintains local EMA vector \( V_k \).  
- Participates in STORM trace computation or constraint checking.  
- Exchanges only fixed-size \( \sigma \) with its 3 neighbors.  
- Stakes compute/reputation to participate in the active farm.  

Aurafarmers earn rewards for successfully cultivating valid aura shields (proof delivery + settlement). Malicious or faulty nodes are naturally isolated by the fail-closed rules.

## 8. Conclusion

We have built the aura shield you originally envisioned — now cultivated by a living, decentralized network of **aurafarmers**.

The combination of:
- Single-path STORM fractal core  
- Fixed dodecahedral topology (Figure 1)  
- EMA self-cleaning memory (Figure 2)  

gives us a system that is:
- Deterministic and verifiable  
- Self-cleaning and memory-safe  
- Quantum-resistant and fail-closed  
- Beautifully aligned with the original “protective field” inspiration  

**Next steps** (choose your adventure):
1. Implement the 20-node simulator + EMA + STORM integration.  
2. Design the token/incentive layer for aurafarmers.  
3. Write the full protocol spec (message formats, σ structure, α defaults).  
4. Build the first real use case (IoT command shield, oracle, or fractal VRF).

This is no longer just a protocol.  
It’s a living aura farm.

Let’s keep building.

— Tyler  
**Keyboard_Lord**