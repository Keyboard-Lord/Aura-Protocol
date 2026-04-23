from __future__ import annotations

from pathlib import Path
import shutil
from textwrap import dedent


ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = ROOT / "docs" / "whitepaper_assets"
MARKDOWN_PATH = ROOT / "AURA_WHITEPAPER_FINAL.md"
HTML_PATH = ROOT / "aura_whitepaper_final.html"
TEX_PATH = ROOT / "aura_whitepaper_final.tex"
BUILD_DIR = ROOT / "build" / "whitepaper_final_fixed"
BUILD_ASSET_DIR = BUILD_DIR / "assets"
BUILD_MARKDOWN_PATH = BUILD_DIR / "AURA_WHITEPAPER_FINAL.md"
BUILD_HTML_PATH = BUILD_DIR / "aura_whitepaper_final_fixed.html"
BUILD_TEX_PATH = BUILD_DIR / "aura_whitepaper_final.tex"
BUILD_MANIFEST_PATH = BUILD_DIR / "asset_manifest.txt"


def paragraph(text: str) -> dict[str, object]:
    return {"type": "paragraph", "text": " ".join(text.strip().split())}


def figure(asset_name: str, caption: str, alt: str) -> dict[str, object]:
    return {"type": "figure", "asset_name": asset_name, "caption": caption, "alt": alt}


def bullet_list(items: list[str], ordered: bool = False) -> dict[str, object]:
    return {"type": "list", "items": items, "ordered": ordered}


def subsection(title: str) -> dict[str, object]:
    return {"type": "subsection", "title": title}


TITLE = (
    "Aura: A Commitment-Native Post-Quantum Layer 2 with "
    "Bijective Runtime Identity and Typed STARK Commitments"
)
AUTHOR = "Tyler McRae"
KEYWORDS = (
    "Arnold cat map, STARK, non-native AIR, typed commitments, "
    "authorization lineage, UDOT, Solana settlement adapter"
)

ABSTRACT = [
    paragraph(
        """
        Aura is best understood as a layered commitment system rather than as a single undifferentiated
        rollup artifact. The repository currently implements three aligned but distinct surfaces: a
        frozen Aura v1 proof-hash submission path in which Solana records only proof_hash; a lower-layer
        bijective runtime in which the Arnold cat map over Aura's fixed 521-bit Mersenne prime modulus
        drives deterministic pair-state execution, canonical trace handling, native lineage construction,
        and a real Winterfell-backed STARK path; and a typed Layer 2 transition-binding contract whose
        core public tuple binds pre-state, post-state, transaction, outcome, and batch-context
        commitments. This paper restates the implemented mathematics, proof boundary, binding model, and
        UDOT representation layer without upgrading unimplemented subsystems into present-tense claims.
        """
    ),
    paragraph(
        """
        The paper distinguishes cryptographically verified statements from host-side transport and
        binding logic. The lower-layer STARK path proves the non-native cat-map trace and its AIR-native
        commitment root, while nested submit, intent, proof, and settlement envelopes remain explicit
        host-side objects with byte-exact Rust and TypeScript parity. UDOT is treated strictly as a
        non-canonical representation derived from the same proof_hash and carried off-chain through the
        canonical pipeline. Repository benchmark measurements taken on March 27, 2026 report a 32-step
        canonical instance at about 14.0 seconds proving time and about 20.6 milliseconds verification
        time, and a 128-step structured instance at about 62.7 seconds proving time and about
        21.7 milliseconds verification time, under the current dev-profile harness. The result is a
        publication-ready statement of Aura's implemented commitment, proof, and transport surfaces.
        """
    ),
]

SECTIONS = [
    {
        "title": "System Overview",
        "blocks": [
            paragraph(
                """
                Aura presently exposes four separated layers. The math layer is the cat-map runtime over
                Aura's fixed 521-bit Mersenne prime modulus. The proof layer is the Winterfell-backed
                STARK system that proves the lower-layer non-native trace relation and exports an
                AIR-native commitment root. The binding layer packages typed commitments, including the
                native authorization lineage family and the frozen Layer 2 transition tuple. The
                representation layer is the UDOT surface and the nested off-chain wire envelopes that
                transport proof_hash-derived artifacts without changing their cryptographic meaning.
                """
            ),
            paragraph(
                """
                A separate supporting research note, AURA_DODECAHEDRAL_EMA_NOTE_V1.md, describes an
                optional future upstream bounded-input overlay. The layer is RESEARCH / SUPPORTING and
                does not modify the canonical request/report pipeline, cat-map transition,
                AIR/prover boundaries, or settlement, burn, attestation, wallet binding, or UDOT
                authority. Its only permitted active boundary is (x0, y0) emission as an upstream
                initialization input to the cat-map path.
                """
            ),
            paragraph(
                """
                The production canonical pipeline is frozen and now has no deferred serialization
                boundary: prepared proof_hash, canonical UDOT bundle, SubmitProofRequestWireV1,
                AuthorizationIntentEnvelopeV1, StarkProofEnvelopeV1, and
                SolanaSettlementRequestWireV1. Cross-language fixtures pin this exact nesting and exact
                minified JSON bytes in both Rust and TypeScript. The chain-facing Solana instruction still
                carries only tag || proof_hash, which keeps the settlement adapter compact while leaving
                richer envelopes off-chain.
                """
            ),
            figure(
                "fig_system_pipeline.svg",
                (
                    "Frozen Aura production pipeline. UDOT remains nested off-chain through the submit, "
                    "intent, proof, and settlement envelopes, while the final Solana instruction "
                    "submits only tag || proof_hash."
                ),
                "System pipeline from proof preparation to Solana settlement adapter.",
            ),
            paragraph(
                """
                This architecture is commitment-native because each layer consumes typed commitments from
                the layer below rather than reparsing or inferring semantics from presentation artifacts.
                It is also intentionally conservative: representation data does not become proof data,
                proof data does not silently redefine transport, and host-side adapters do not claim
                verifier authority they do not actually hold.
                """
            ),
        ],
    },
    {
        "title": "Mathematical Foundation",
        "blocks": [
            paragraph(
                """
                The authoritative lower-layer runtime is the Arnold cat map over Aura's fixed Mersenne
                prime modulus. Aura interprets state as an ordered pair over that modulus and advances
                the pair by a deterministic linear rule. In the 521-bit runtime crate, seed bytes are
                reduced deterministically into field elements, so the initial pair is a deterministic
                function of the supplied entropy and challenge bytes rather than an inferred or
                presentation-dependent object.
                """
            ),
            figure(
                "eq_cat_map_matrix.svg",
                "Matrix form of the Aura lower-layer cat-map update over the fixed Mersenne prime modulus.",
                "Cat-map matrix equation.",
            ),
            paragraph(
                """
                Each coordinate sequence also satisfies a second-order linear recurrence. That recurrence
                is used throughout the repository as a compact way to reason about consistency of trace
                transitions, fast-forward equivalence, and inverse-path validation.
                """
            ),
            figure(
                "eq_cat_map_recurrence.svg",
                "Coordinate recurrence induced by the cat-map update rule.",
                "Cat-map coordinate recurrence.",
            ),
            paragraph(
                """
                Bijectivity is the critical structural property. The update matrix has determinant one,
                so every state has exactly one predecessor and one successor, and the inverse matrix is
                explicit. Aura therefore replaced the earlier dissipative quadratic map with a
                volume-preserving pair-state runtime that supports exact backward validation and logarithmic-time
                jumping by matrix powers.
                """
            ),
            figure(
                "fig_cat_map_transform.svg",
                "Bijective cat-map state transition. Forward and inverse maps are both explicit, so each state has a unique predecessor and successor.",
                "Cat-map forward and inverse transformation diagram.",
            ),
        ],
    },
    {
        "title": "Trace Commitment Model",
        "blocks": [
            paragraph(
                """
                The lower-layer trace is the ordered sequence of pair states from the initial state
                through the terminal state. Each canonical row is serialized as x_bytes_66 || y_bytes_66,
                which fixes a 132-byte row format for the 521-bit runtime. The host-side trace
                commitment helper binds row order, row count, and both coordinates at every step.
                """
            ),
            paragraph(
                """
                The active proof path intentionally distinguishes the host-side trace helper from the
                AIR-native commitment root. In current implementation, the proof statement exports
                commitment_root as the public lower-layer claim field, while trace_commitment remains a
                deterministic auxiliary commitment used for fixtures, staged surfaces, and bridge-layer
                structure. This separation is necessary to keep the proof layer and the host transport
                layer from drifting into each other.
                """
            ),
            figure(
                "fig_trace_commitment.svg",
                "Lower-layer trace structure. The host-side trace_commitment helper and the AIR-native rolling commitment root are related but intentionally distinct surfaces.",
                "Trace commitment structure.",
            ),
            paragraph(
                """
                The repository is explicit about this boundary: the current STARK path proves the
                ordered trace and its AIR-native rolling accumulator, but it does not claim that the
                retained host-side trace_commitment hash helper is itself enforced inside the AIR. That
                distinction is not a defect; it is part of the repository's declared proof boundary.
                """
            ),
        ],
    },
    {
        "title": "STARK Proving System",
        "blocks": [
            paragraph(
                """
                Aura's implemented lower-layer prover uses Winterfell. Because Winterfell does not natively
                operate over Aura's fixed 521-bit modulus, the active AIR uses an explicit non-native
                bridge. Each 521-bit coordinate is decomposed into base-128 digits and grouped into
                28-bit arithmetic limbs with carry witnesses. This preserves exact 521-bit cat-map
                semantics while remaining compatible with the backend field.
                """
            ),
            paragraph(
                """
                The active optimized AIR shape is fixed at 193 trace columns and 234 transition
                constraints, with 19 arithmetic limbs per coordinate and 18 carry witness columns per
                coordinate. The public lower-layer claim contains initial_state, iteration_count,
                final_state, and commitment_root. The witness is the full ordered pair-state trace.
                Deterministic transcript and session packaging layers then bind the lower-layer claim,
                public claim, witness bundle, recurrence summary, and proof-bound session identifiers into
                verifier-visible artifacts.
                """
            ),
            figure(
                "fig_proof_verification_flow.svg",
                "Proof generation and verification flow for the implemented lower-layer STARK path.",
                "Proof verification flow.",
            ),
            paragraph(
                """
                The repository's negative claims are as important as its positive ones. The current proof
                system does not claim native backend-field equality to 2^521 - 1, recursive composition,
                or AIR-level enforcement of the retained host-side trace_commitment helper. The active
                statement is narrower and therefore stronger: Winterfell proves the implemented non-native
                cat-map AIR and verifies it against the exact claim object carried by the lower-layer
                session package.
                """
            ),
        ],
    },
    {
        "title": "Binding Model",
        "blocks": [
            paragraph(
                """
                Aura's binding layer is typed. The frozen Layer 2 transition-binding contract defines one
                exact transition tuple whose elements are not inferred from transport objects or narrative
                descriptions. The tuple below is the core binding surface used by the active 13-field,
                284-byte public-input envelope of the verified Layer 2 foundation.
                """
            ),
            figure(
                "eq_binding_tuple.svg",
                "Typed Layer 2 transition tuple used by the frozen public-input schema.",
                "Transition binding tuple.",
            ),
            paragraph(
                """
                Here r_pre and r_post are the committed pre-state and post-state roots, c_tx commits the
                ordered canonical transaction list, c_out commits the ordered canonical execution
                outcomes, and c_ctx commits the deterministic batch context not already contained in the
                pre-state or transaction list. The repository treats this tuple as a logical core of the
                wider settlement-facing public envelope rather than as an informal design sketch.
                """
            ),
            paragraph(
                """
                This typed binding model is kept separate from the lower-layer cat-map claim. The cat-map
                proof path proves runtime identity and trace evolution; the Layer 2 tuple binds batch
                execution claims. Aura's documentation treats both as commitment surfaces, but it does not
                silently collapse them into one object. That separation is essential to preserve exact
                semantics at each layer.
                """
            ),
        ],
    },
    {
        "title": "UDOT Representation Layer",
        "blocks": [
            paragraph(
                """
                UDOT is the representation layer, not the canonical cryptographic commitment. In version
                2, the required output object contains format_version, aura_hash_bytes, seal_line, crest,
                matrix_sequence, and matrix_form. These values are deterministically derived from the same
                32-byte aura_hash input by domain-separated hash derivations and fixed glyph mappings.
                """
            ),
            paragraph(
                """
                The implementation contract is explicit that UDOT is NON-CANONICAL. It is a display and
                transport surface derived from the authoritative hash; it is not a substitute for
                proof_hash, not an AIR public input, and not the on-chain settlement payload. Exact code
                point equality matters, whitespace is rejected in canonical validation paths, and
                udot_version remains explicit rather than inferred. The canonical production fixtures pin
                version 2 and reject silent normalization in both Rust and TypeScript.
                """
            ),
            paragraph(
                """
                In the production pipeline, UDOT stays nested under the submit request and remains nested
                through the intent, proof, and settlement envelopes. Solana never sees the UDOT payload.
                The chain-facing adapter still receives only proof_hash, which is why the representation
                layer must be described as non-canonical even when it is byte-exact and fixture-backed.
                """
            ),
        ],
    },
    {
        "title": "Security Model",
        "blocks": [
            subsection("What Is Verified"),
            paragraph(
                """
                The repository's verified statements are implementation-specific and intentionally narrow.
                In the lower-layer runtime, the code verifies exact cat-map forward and inverse
                transitions, recurrence consistency, deterministic seed reduction, canonical pair-state
                serialization, and the real Winterfell-backed STARK acceptance path for the non-native
                AIR claim. In the frozen production pipeline, the repository verifies exact byte-level
                equality for canonical wire objects across Rust and TypeScript and rejects missing fields,
                non-canonical hex, mismatched nested bundles, and broken envelope nesting fail-closed.
                """
            ),
            bullet_list(
                [
                    "The lower-layer STARK proves initial_state, iteration_count, final_state, the exact ordered non-native trace relation, and the AIR-native commitment_root.",
                    "The verified Layer 2 foundation fixes a 13-field, 284-byte public-input envelope whose typed transition core is the five-field binding tuple shown above.",
                    "The production UDOT-to-L4 path now has a fixture-backed guarantee that there is no remaining deferred boundary in the canonical pipeline.",
                ]
            ),
            subsection("What Is Not Claimed"),
            paragraph(
                """
                Aura also records several explicit non-claims. The current repository does not claim that
                the backend field itself equals Aura's fixed modulus, that recursive composition is
                implemented, that the retained host-side trace_commitment helper is enforced inside the
                AIR, or that Solana verifies proof semantics on-chain. The post-quantum claim is limited
                to the STARK proving layer under standard hash-based assumptions; it does not
                automatically extend to classical host-side components such as Ed25519-bound subject
                identifiers, base58 transport fields, or the surrounding Solana infrastructure.
                """
            ),
            bullet_list(
                [
                    "UDOT is not a proof object and does not replace proof_hash.",
                    "Nested submit, intent, proof, and settlement envelopes are host-side transport and binding objects, not verifier objects.",
                    "The current paper does not claim token issuance, burn, staking, or any broader economics beyond fee surfaces already named in repository contracts.",
                    "The current paper does not claim that Aura's future Layer 2 settlement system is already implemented end to end beyond the frozen proof_hash submission adapter.",
                ]
            ),
        ],
    },
    {
        "title": "Performance Notes",
        "blocks": [
            paragraph(
                """
                The repository includes a checked-in benchmark harness for the real lower-layer STARK
                path. On March 27, 2026, the benchmark was run directly from
                crates/aura_intent_lineage_v1/tests/stark_benchmark_v1.rs under the current dev-profile
                test configuration. These numbers are implementation measurements, not throughput claims
                about a deployed network.
                """
            ),
            bullet_list(
                [
                    "canonical_32: trace 2.65 ms, prove 14.04 s, verify 20.57 ms, proof size 197,006 bytes, trace width 193, backend constraints 234, internal trace length 64.",
                    "structured_128: trace 8.27 ms, prove 62.72 s, verify 21.69 ms, proof size 204,208 bytes, trace width 193, backend constraints 234, internal trace length 256.",
                ]
            ),
            paragraph(
                """
                Two observations follow. First, verification time remains nearly flat across the measured
                cases relative to proving time, which is consistent with the current proof system split.
                Second, proof size grows only modestly between the measured instances, while proving time
                dominates the cost envelope. These are useful engineering measurements for the current
                codebase, but they should not be misread as final production economics or settlement
                throughput limits.
                """
            ),
        ],
    },
    {
        "title": "Future Work",
        "blocks": [
            paragraph(
                """
                The immediate next work remains repository-native rather than speculative. Aura can widen
                its formal assurance only by moving additional host-side checks into proof statements
                under explicit frozen contracts, not by rewriting the claims informally. The same rule
                applies to any later Layer 4 settlement system and to any future migration from
                proof_hash-centered v1 continuity into broader native lineage statements.
                """
            ),
            bullet_list(
                [
                    "Complete authoritative code surfaces for the frozen Layer 2 transition-binding and settlement contracts without changing tuple semantics.",
                    "Reduce remaining host-side checks only through explicit proof-boundary migrations that preserve current layer separation.",
                    "Extend cross-language canonical fixtures from the current UDOT-to-L4 path into wider Layer 2 claim objects and roots.",
                    "If optional future upstream bounded-input aggregation is formalized, keep it as a separately versioned RESEARCH / SUPPORTING overlay whose only permitted active boundary is (x0, y0) emission as an upstream initialization input. It must not modify the canonical request/report pipeline, cat-map transition, AIR/prover boundaries, or settlement, burn, attestation, wallet binding, or UDOT authority.",
                    "Improve backend ergonomics and remove accepted debug-assertion sensitivity without changing proof meaning.",
                    "Preserve the frozen proof_hash submission rule while broadening later authorization and settlement layers in explicitly versioned steps.",
                ]
            ),
        ],
    },
    {
        "title": "References",
        "blocks": [
            bullet_list(
                [
                    "Aura repository README and canonical pipeline fixtures.",
                    "AURA_DODECAHEDRAL_EMA_NOTE_V1.md.",
                    "AURA_DCM_CORE_V1.md and AURA_DCM_TRACE_COMMITMENT_V1.md.",
                    "AURA_DCM_STARK_SPEC_V1.md and crates/aura_intent_lineage_v1/README.md.",
                    "AURA_AUTHORIZATION_LINEAGE_SCHEMA_V1.md.",
                    "AURA_L2_TRANSITION_BINDING_CONTRACT_V1.md and AURA_L2_PUBLIC_INPUT_SCHEMA_V1.md.",
                    "AURA_UDOT_IMPLEMENTATION_CONTRACT_V2.md.",
                    "crates/aura_intent_lineage_v1/tests/stark_benchmark_v1.rs.",
                ],
                ordered=True,
            )
        ],
    },
]


SVG_ASSETS = {
    "eq_cat_map_matrix.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1200" height="160" viewBox="0 0 1200 160">
          <rect width="1200" height="160" fill="#ffffff"/>
          <text x="60" y="96" font-family="Times New Roman, Georgia, serif" font-size="36" fill="#111111">
            [x_{n+1}]   [1 1] [x_n]         mod N = 2^521 - 1
          </text>
          <text x="60" y="136" font-family="Times New Roman, Georgia, serif" font-size="36" fill="#111111">
            [y_{n+1}] = [1 2] [y_n]
          </text>
        </svg>
        """
    ).strip()
    + "\n",
    "eq_cat_map_recurrence.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1200" height="120" viewBox="0 0 1200 120">
          <rect width="1200" height="120" fill="#ffffff"/>
          <text x="60" y="74" font-family="Times New Roman, Georgia, serif" font-size="40" fill="#111111">
            u_{n+2} = 3u_{n+1} - u_n mod N
          </text>
        </svg>
        """
    ).strip()
    + "\n",
    "eq_binding_tuple.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1200" height="120" viewBox="0 0 1200 120">
          <rect width="1200" height="120" fill="#ffffff"/>
          <text x="60" y="74" font-family="Times New Roman, Georgia, serif" font-size="38" fill="#111111">
            C_t = (r_pre, r_post, c_tx, c_out, c_ctx)
          </text>
        </svg>
        """
    ).strip()
    + "\n",
    "fig_system_pipeline.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1400" height="780" viewBox="0 0 1400 780">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#274c77"/>
            </marker>
          </defs>
          <rect width="1400" height="780" fill="#fbfbfb"/>
          <text x="700" y="50" text-anchor="middle" font-family="Georgia, 'Times New Roman', serif" font-size="32" fill="#102542">Aura Canonical Off-Chain Pipeline</text>

          <rect x="150" y="90" width="1100" height="70" rx="16" fill="#d9e7f5"/>
          <text x="700" y="133" text-anchor="middle" font-family="Georgia, serif" font-size="22" fill="#102542">Representation and transport stay off-chain until the final submit_proof adapter.</text>

          <rect x="220" y="200" width="960" height="72" rx="14" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="700" y="245" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">Prepared proof_hash</text>

          <line x1="700" y1="272" x2="700" y2="320" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>

          <rect x="220" y="320" width="960" height="86" rx="14" fill="#fff7e6" stroke="#b7791f" stroke-width="2"/>
          <text x="700" y="360" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#5a3b00">UDOT bundle (non-canonical representation)</text>
          <text x="700" y="390" text-anchor="middle" font-family="Georgia, serif" font-size="19" fill="#5a3b00">Explicit udot_version, exact glyph equality, no inference</text>

          <line x1="700" y1="406" x2="700" y2="454" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>

          <rect x="120" y="454" width="1160" height="172" rx="16" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="700" y="490" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">Nested wire objects</text>

          <rect x="170" y="520" width="240" height="62" rx="12" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="290" y="558" text-anchor="middle" font-family="Georgia, serif" font-size="19" fill="#102542">SubmitProofRequestWireV1</text>

          <rect x="440" y="520" width="240" height="62" rx="12" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="560" y="558" text-anchor="middle" font-family="Georgia, serif" font-size="19" fill="#102542">AuthorizationIntentEnvelopeV1</text>

          <rect x="710" y="520" width="240" height="62" rx="12" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="830" y="558" text-anchor="middle" font-family="Georgia, serif" font-size="19" fill="#102542">StarkProofEnvelopeV1</text>

          <rect x="980" y="520" width="250" height="62" rx="12" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="1105" y="558" text-anchor="middle" font-family="Georgia, serif" font-size="19" fill="#102542">SolanaSettlementRequestWireV1</text>

          <text x="700" y="612" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5b6570">UDOT stays nested under the submit request and is never flattened into on-chain fields.</text>

          <line x1="700" y1="626" x2="700" y2="676" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>

          <rect x="300" y="676" width="800" height="66" rx="14" fill="#ddecdc" stroke="#3b6b35" stroke-width="2"/>
          <text x="700" y="717" text-anchor="middle" font-family="Georgia, serif" font-size="25" fill="#204d26">Solana submit_proof payload = tag || proof_hash</text>
        </svg>
        """
    ).strip()
    + "\n",
    "fig_cat_map_transform.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1400" height="520" viewBox="0 0 1400 520">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#274c77"/>
            </marker>
          </defs>
          <rect width="1400" height="520" fill="#fbfbfb"/>
          <text x="700" y="56" text-anchor="middle" font-family="Georgia, serif" font-size="32" fill="#102542">Bijective Cat-Map Runtime</text>

          <rect x="120" y="150" width="280" height="140" rx="18" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="260" y="208" text-anchor="middle" font-family="Georgia, serif" font-size="28" fill="#102542">(x_n, y_n)</text>
          <text x="260" y="248" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5b6570">canonical pair-state</text>

          <rect x="530" y="120" width="340" height="200" rx="18" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="700" y="176" text-anchor="middle" font-family="Georgia, serif" font-size="26" fill="#102542">Forward matrix</text>
          <text x="700" y="216" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">[[1, 1], [1, 2]] mod N</text>
          <text x="700" y="258" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5b6570">unique successor, exact fast-forward by powers</text>

          <rect x="1000" y="150" width="280" height="140" rx="18" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="1140" y="208" text-anchor="middle" font-family="Georgia, serif" font-size="28" fill="#102542">(x_{n+1}, y_{n+1})</text>
          <text x="1140" y="248" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5b6570">next canonical pair-state</text>

          <line x1="400" y1="220" x2="530" y2="220" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
          <line x1="870" y1="220" x2="1000" y2="220" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>

          <rect x="470" y="360" width="460" height="96" rx="18" fill="#fff7e6" stroke="#b7791f" stroke-width="2"/>
          <text x="700" y="404" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#5a3b00">Inverse matrix: [[2, -1], [-1, 1]] mod N</text>
          <text x="700" y="436" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5a3b00">unique predecessor, exact backward validation</text>
        </svg>
        """
    ).strip()
    + "\n",
    "fig_trace_commitment.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1400" height="760" viewBox="0 0 1400 760">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#274c77"/>
            </marker>
          </defs>
          <rect width="1400" height="760" fill="#fbfbfb"/>
          <text x="700" y="54" text-anchor="middle" font-family="Georgia, serif" font-size="32" fill="#102542">Trace Commitment Separation</text>

          <rect x="120" y="110" width="520" height="520" rx="18" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="380" y="150" text-anchor="middle" font-family="Georgia, serif" font-size="26" fill="#102542">Ordered pair-state trace</text>

          <rect x="180" y="190" width="400" height="72" rx="12" fill="#ffffff" stroke="#8aa9c2" stroke-width="2"/>
          <text x="380" y="234" text-anchor="middle" font-family="Georgia, serif" font-size="21" fill="#102542">row_0 = x_0 bytes(66) || y_0 bytes(66)</text>

          <rect x="180" y="290" width="400" height="72" rx="12" fill="#ffffff" stroke="#8aa9c2" stroke-width="2"/>
          <text x="380" y="334" text-anchor="middle" font-family="Georgia, serif" font-size="21" fill="#102542">row_1 = x_1 bytes(66) || y_1 bytes(66)</text>

          <rect x="180" y="390" width="400" height="72" rx="12" fill="#ffffff" stroke="#8aa9c2" stroke-width="2"/>
          <text x="380" y="434" text-anchor="middle" font-family="Georgia, serif" font-size="21" fill="#102542">...</text>

          <rect x="180" y="490" width="400" height="72" rx="12" fill="#ffffff" stroke="#8aa9c2" stroke-width="2"/>
          <text x="380" y="534" text-anchor="middle" font-family="Georgia, serif" font-size="21" fill="#102542">row_T = x_T bytes(66) || y_T bytes(66)</text>

          <rect x="790" y="160" width="500" height="160" rx="18" fill="#fff7e6" stroke="#b7791f" stroke-width="2"/>
          <text x="1040" y="212" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#5a3b00">Host-side trace_commitment helper</text>
          <text x="1040" y="248" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5a3b00">binds order, row count, and row bytes</text>
          <text x="1040" y="280" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5a3b00">used for fixtures and staged transport surfaces</text>

          <rect x="790" y="400" width="500" height="190" rx="18" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="1040" y="456" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">AIR-native rolling accumulator</text>
          <text x="1040" y="492" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">absorbs ordered rows inside the implemented AIR</text>
          <text x="1040" y="524" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">terminal public claim field: commitment_root</text>
          <rect x="905" y="542" width="270" height="36" rx="10" fill="#ffffff" stroke="#8aa9c2" stroke-width="2"/>
          <text x="1040" y="566" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">public lower-layer claim</text>

          <line x1="640" y1="260" x2="790" y2="240" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
          <line x1="640" y1="520" x2="790" y2="490" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
        </svg>
        """
    ).strip()
    + "\n",
    "fig_proof_verification_flow.svg": dedent(
        """
        <svg xmlns="http://www.w3.org/2000/svg" width="1400" height="760" viewBox="0 0 1400 760">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#274c77"/>
            </marker>
          </defs>
          <rect width="1400" height="760" fill="#fbfbfb"/>
          <text x="700" y="52" text-anchor="middle" font-family="Georgia, serif" font-size="32" fill="#102542">Lower-Layer Proof Verification Flow</text>

          <rect x="90" y="130" width="360" height="220" rx="18" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="270" y="180" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">Public claim inputs</text>
          <text x="270" y="220" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">initial_state</text>
          <text x="270" y="252" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">iteration_count</text>
          <text x="270" y="284" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">final_state</text>
          <text x="270" y="316" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">commitment_root</text>

          <rect x="90" y="420" width="360" height="180" rx="18" fill="#fff7e6" stroke="#b7791f" stroke-width="2"/>
          <text x="270" y="472" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#5a3b00">Witness</text>
          <text x="270" y="512" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5a3b00">ordered pair-state trace</text>
          <text x="270" y="544" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#5a3b00">base-128 digits, 28-bit limbs, carry witnesses</text>

          <rect x="520" y="250" width="360" height="220" rx="18" fill="#dbeafe" stroke="#274c77" stroke-width="2"/>
          <text x="700" y="306" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">Winterfell prover</text>
          <text x="700" y="342" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">193 trace columns</text>
          <text x="700" y="372" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">234 transition constraints</text>
          <text x="700" y="402" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">real STARK proof artifact</text>

          <rect x="950" y="130" width="360" height="220" rx="18" fill="#eef4f8" stroke="#274c77" stroke-width="2"/>
          <text x="1130" y="186" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#102542">Verifier acceptance</text>
          <text x="1130" y="222" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">verifies proof against public claim</text>
          <text x="1130" y="254" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">checks proof-bound transcript digest</text>
          <text x="1130" y="286" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#102542">checks proof-bound session id</text>

          <rect x="950" y="420" width="360" height="180" rx="18" fill="#ddecdc" stroke="#3b6b35" stroke-width="2"/>
          <text x="1130" y="474" text-anchor="middle" font-family="Georgia, serif" font-size="24" fill="#204d26">Accepted output</text>
          <text x="1130" y="512" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#204d26">lower-layer claim</text>
          <text x="1130" y="544" text-anchor="middle" font-family="Georgia, serif" font-size="18" fill="#204d26">session_id, transcript_digest, commitment_root</text>

          <line x1="450" y1="240" x2="520" y2="300" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
          <line x1="450" y1="510" x2="520" y2="420" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
          <line x1="880" y1="360" x2="950" y2="240" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
          <line x1="880" y1="360" x2="950" y2="500" stroke="#274c77" stroke-width="4" marker-end="url(#arrow)"/>
        </svg>
        """
    ).strip()
    + "\n",
}


def tex_escape(text: str) -> str:
    replacements = {
        "\\": "\\textbackslash{}",
        "&": "\\&",
        "%": "\\%",
        "$": "\\$",
        "#": "\\#",
        "_": "\\_",
        "{": "\\{",
        "}": "\\}",
        "~": "\\textasciitilde{}",
        "^": "\\textasciicircum{}",
    }
    escaped = []
    for char in text:
        escaped.append(replacements.get(char, char))
    return "".join(escaped)


def asset_path(asset_name: str, *, build_context: bool) -> str:
    prefix = "assets" if build_context else "docs/whitepaper_assets"
    return f"{prefix}/{asset_name}"


def render_markdown(*, build_context: bool) -> str:
    lines: list[str] = [
        f"# {TITLE}",
        "",
        f"**Author:** {AUTHOR}",
        "",
        "## Abstract",
        "",
    ]
    for block in ABSTRACT:
        lines.append(block["text"])  # type: ignore[index]
        lines.append("")
    lines.extend(
        [
            f"**Keywords:** {KEYWORDS}",
            "",
        ]
    )
    figure_counter = 1
    for section in SECTIONS:
        lines.append(f"## {section['title']}")
        lines.append("")
        for block in section["blocks"]:
            block_type = block["type"]
            if block_type == "paragraph":
                lines.append(block["text"])  # type: ignore[index]
                lines.append("")
            elif block_type == "subsection":
                lines.append(f"### {block['title']}")
                lines.append("")
            elif block_type == "list":
                marker = "1." if block["ordered"] else "-"  # type: ignore[index]
                for item in block["items"]:  # type: ignore[index]
                    lines.append(f"{marker} {item}")
                lines.append("")
            elif block_type == "figure":
                lines.append(
                    f"![{block['alt']}]({asset_path(block['asset_name'], build_context=build_context)})"  # type: ignore[index]
                )
                lines.append("")
                lines.append(f"*Figure {figure_counter}. {block['caption']}*")  # type: ignore[index]
                lines.append("")
                figure_counter += 1
        if lines[-1] != "":
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(*, build_context: bool) -> str:
    parts: list[str] = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\" />",
        f"  <title>{TITLE}</title>",
        "  <style>",
        dedent(
            """
              @page {
                size: Letter;
                margin: 0.55in;
              }
              body {
                margin: 0;
                font-family: "Times New Roman", Georgia, serif;
                color: #111111;
                background: #ffffff;
              }
              .title-block {
                text-align: center;
                margin-bottom: 0.2in;
              }
              h1 {
                margin: 0;
                font-size: 24pt;
                line-height: 1.15;
                font-weight: 700;
              }
              .author {
                margin-top: 0.12in;
                font-size: 11pt;
              }
              .abstract, .keywords, h2, h3, figure {
                column-span: all;
              }
              .abstract {
                border-top: 1px solid #9aa6b2;
                border-bottom: 1px solid #9aa6b2;
                padding: 0.12in 0;
                margin-bottom: 0.15in;
              }
              .abstract h2, .keywords h2 {
                margin: 0 0 0.08in 0;
                font-size: 12pt;
                text-transform: uppercase;
                letter-spacing: 0.04em;
              }
              .keywords {
                margin-bottom: 0.16in;
              }
              .paper {
                column-count: 2;
                column-gap: 0.28in;
              }
              h2 {
                font-size: 13pt;
                margin: 0.12in 0 0.08in 0;
                border-bottom: 1px solid #d0d7de;
                padding-bottom: 0.03in;
              }
              h3 {
                font-size: 11.5pt;
                margin: 0.1in 0 0.06in 0;
              }
              p, li {
                font-size: 10pt;
                line-height: 1.35;
                text-align: justify;
              }
              ul, ol {
                margin: 0.02in 0 0.08in 0.18in;
                padding: 0;
              }
              li {
                margin: 0 0 0.04in 0;
              }
              figure {
                break-inside: avoid;
                margin: 0.12in 0;
                padding: 0.08in 0.08in 0.02in 0.08in;
                border: 1px solid #d7dee5;
                background: #fcfcfc;
              }
              figure img {
                width: 100%;
                height: auto;
                display: block;
              }
              figcaption {
                margin-top: 0.08in;
                font-size: 9.2pt;
                line-height: 1.3;
                text-align: left;
              }
            """
        ).strip(),
        "  </style>",
        "</head>",
        "<body>",
        "  <div class=\"title-block\">",
        f"    <h1>{TITLE}</h1>",
        f"    <div class=\"author\">{AUTHOR}</div>",
        "  </div>",
        "  <section class=\"abstract\">",
        "    <h2>Abstract</h2>",
    ]
    for block in ABSTRACT:
        parts.append(f"    <p>{block['text']}</p>")  # type: ignore[index]
    parts.extend(
        [
            "  </section>",
            "  <section class=\"keywords\">",
            "    <h2>Keywords</h2>",
            f"    <p>{KEYWORDS}</p>",
            "  </section>",
            "  <main class=\"paper\">",
        ]
    )
    figure_counter = 1
    for section in SECTIONS:
        parts.append(f"    <h2>{section['title']}</h2>")
        for block in section["blocks"]:
            block_type = block["type"]
            if block_type == "paragraph":
                parts.append(f"    <p>{block['text']}</p>")  # type: ignore[index]
            elif block_type == "subsection":
                parts.append(f"    <h3>{block['title']}</h3>")  # type: ignore[index]
            elif block_type == "list":
                tag = "ol" if block["ordered"] else "ul"  # type: ignore[index]
                parts.append(f"    <{tag}>")
                for item in block["items"]:  # type: ignore[index]
                    parts.append(f"      <li>{item}</li>")
                parts.append(f"    </{tag}>")
            elif block_type == "figure":
                parts.extend(
                    [
                        "    <figure>",
                        f"      <img src=\"{asset_path(block['asset_name'], build_context=build_context)}\" alt=\"{block['alt']}\" />",  # type: ignore[index]
                        f"      <figcaption><strong>Figure {figure_counter}.</strong> {block['caption']}</figcaption>",  # type: ignore[index]
                        "    </figure>",
                    ]
                )
                figure_counter += 1
    parts.extend(["  </main>", "</body>", "</html>"])
    return "\n".join(parts) + "\n"


def render_tex(*, build_context: bool) -> str:
    lines: list[str] = [
        "% Aura whitepaper source generated from repository-owned publication assets.",
        "% Figures and equations are image assets to avoid PDF equation encoding issues.",
        "\\documentclass[conference]{IEEEtran}",
        "\\usepackage[T1]{fontenc}",
        "\\usepackage[utf8]{inputenc}",
        "\\usepackage{graphicx}",
        "\\usepackage{svg}",
        "\\usepackage{microtype}",
        "\\title{" + tex_escape(TITLE) + "}",
        "\\author{\\IEEEauthorblockN{" + tex_escape(AUTHOR) + "}}",
        "\\begin{document}",
        "\\maketitle",
        "\\begin{abstract}",
    ]
    for block in ABSTRACT:
        lines.append(tex_escape(block["text"]))  # type: ignore[index]
        lines.append("")
    lines.extend(
        [
            "\\end{abstract}",
            "\\begin{IEEEkeywords}",
            tex_escape(KEYWORDS),
            "\\end{IEEEkeywords}",
        ]
    )
    figure_counter = 1
    for section in SECTIONS:
        lines.append("\\section{" + tex_escape(section["title"]) + "}")
        for block in section["blocks"]:
            block_type = block["type"]
            if block_type == "paragraph":
                lines.append(tex_escape(block["text"]))  # type: ignore[index]
                lines.append("")
            elif block_type == "subsection":
                lines.append("\\subsection{" + tex_escape(block["title"]) + "}")  # type: ignore[index]
            elif block_type == "list":
                env = "enumerate" if block["ordered"] else "itemize"  # type: ignore[index]
                lines.append("\\begin{" + env + "}")
                for item in block["items"]:  # type: ignore[index]
                    lines.append("\\item " + tex_escape(item))
                lines.append("\\end{" + env + "}")
            elif block_type == "figure":
                svg_path = Path(
                    asset_path(block["asset_name"], build_context=build_context)  # type: ignore[index]
                ).with_suffix("").as_posix()
                lines.extend(
                    [
                        "\\begin{figure*}[t]",
                        "\\centering",
                        "\\includesvg[width=\\linewidth]{" + tex_escape(svg_path) + "}",
                        "\\caption{Figure "
                        + str(figure_counter)
                        + ". "
                        + tex_escape(block["caption"])  # type: ignore[index]
                        + "}",
                        "\\end{figure*}",
                    ]
                )
                figure_counter += 1
    lines.extend(["\\end{document}", ""])
    return "\n".join(lines)


def write_assets() -> None:
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in SVG_ASSETS.items():
        (ASSET_DIR / name).write_text(content, encoding="utf-8")


def stage_build_assets() -> None:
    BUILD_ASSET_DIR.mkdir(parents=True, exist_ok=True)
    for asset_name in SVG_ASSETS:
        shutil.copy2(ASSET_DIR / asset_name, BUILD_ASSET_DIR / asset_name)
    BUILD_MANIFEST_PATH.write_text(
        "\n".join(
            [
                "Aura whitepaper build asset manifest",
                "",
                *sorted(f"assets/{name}" for name in SVG_ASSETS),
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def assert_assets_exist() -> None:
    missing_root = [name for name in SVG_ASSETS if not (ASSET_DIR / name).exists()]
    missing_build = [name for name in SVG_ASSETS if not (BUILD_ASSET_DIR / name).exists()]
    if missing_root or missing_build:
        raise RuntimeError(
            "missing whitepaper assets: "
            f"root={missing_root or 'none'}, build={missing_build or 'none'}"
        )


def main() -> None:
    write_assets()
    stage_build_assets()
    assert_assets_exist()

    MARKDOWN_PATH.write_text(render_markdown(build_context=False), encoding="utf-8")
    HTML_PATH.write_text(render_html(build_context=False), encoding="utf-8")
    TEX_PATH.write_text(render_tex(build_context=False), encoding="utf-8")

    BUILD_MARKDOWN_PATH.write_text(render_markdown(build_context=True), encoding="utf-8")
    BUILD_HTML_PATH.write_text(render_html(build_context=True), encoding="utf-8")
    BUILD_TEX_PATH.write_text(render_tex(build_context=True), encoding="utf-8")
    print(f"Wrote {MARKDOWN_PATH}")
    print(f"Wrote {HTML_PATH}")
    print(f"Wrote {TEX_PATH}")
    print(f"Wrote assets to {ASSET_DIR}")
    print(f"Wrote build assets to {BUILD_ASSET_DIR}")
    print(f"Wrote {BUILD_HTML_PATH}")


if __name__ == "__main__":
    main()
