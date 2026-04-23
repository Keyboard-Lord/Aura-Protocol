<!-- DOC_STATUS_HEADER_START -->
> Status: RESEARCH / SUPPORTING
> Concept: Aura Whitepaper Asset Audit V1
> Scope Boundary: Supporting or non-authoritative material for the named surface only. It may record research, audits, planning, or supporting-layer doctrine, but it does not create active or frozen protocol authority.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as supporting context only. Candidate, future, audit, or comparison language in the body is non-authoritative unless promoted elsewhere.
> Implementation State: Supporting, research, audit, planning, or non-authoritative.
<!-- DOC_STATUS_HEADER_END -->

# Aura Whitepaper Asset Audit V1

## Scope

This audit covers the authoritative whitepaper sources and build pipeline inputs:

- `AURA_WHITEPAPER_FINAL.md`
- `aura_whitepaper_final.tex`
- `aura_whitepaper_final.pdf`
- `docs/whitepaper_assets/*`
- `scripts/build_aura_whitepaper.py`
- `scripts/render_aura_whitepaper_pdf.py`

## Findings

The asset failure was caused by the PDF renderer, not by missing figure generation.

1. All required figure and equation assets already existed on disk under `docs/whitepaper_assets/`.
2. The generated HTML referenced those assets correctly as relative paths.
3. The previous PDF export path loaded the HTML with Playwright `page.set_content()` and injected a `file://` base URL instead of navigating to a real staged HTML file.
4. In that mode, Chromium reported the `<img>` elements as `complete`, but every required SVG resolved with `naturalWidth = 0` and `naturalHeight = 0`.
5. The resulting PDF embedded blank or broken image placeholders instead of the real figures and equation visuals.
6. The old pipeline also lacked a dedicated build context, deterministic asset staging, and a pre-export assertion that all images had non-zero rendered dimensions.
7. The old pipeline did not perform a post-export visual verification pass on the finished PDF pages, so the failure escaped into the published artifact.

## Exact Failure Mechanism

The broken PDF came from rendering the whitepaper HTML in a transient browser document rather than from a filesystem-backed build context. The SVG assets were present, but the browser export path treated them as zero-dimension resources during PDF generation. Because the pipeline trusted `load` completion without checking rendered image dimensions, it exported a PDF with failed visual assets.

## Repair Summary

The corrected pipeline now:

1. Builds a dedicated whitepaper directory at `build/whitepaper_final_fixed/`.
2. Copies all required SVG figure and equation assets into `build/whitepaper_final_fixed/assets/`.
3. Emits staged Markdown, HTML, TeX, and an asset manifest from the same build context.
4. Navigates Playwright to the staged HTML as a real file instead of injecting HTML with `set_content()`.
5. Fails closed if any `<img>` has `naturalWidth <= 0` or `naturalHeight <= 0` before PDF export.
6. Writes the corrected PDF as `aura_whitepaper_final_fixed.pdf`.
7. Renders the final PDF pages to PNGs through native macOS Quartz/PDFKit for visual verification.

## Conclusion

The failure was a renderer-context bug plus missing verification gates. The corrected pipeline is now self-contained, staged, dimension-checked before export, and visually verified after export.
