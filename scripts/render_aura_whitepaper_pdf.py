from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "whitepaper_final_fixed"
HTML_PATH = BUILD_DIR / "aura_whitepaper_final_fixed.html"
BUILD_PDF_PATH = BUILD_DIR / "aura_whitepaper_final_fixed.pdf"
ROOT_PDF_PATH = ROOT / "aura_whitepaper_final_fixed.pdf"
VERIFICATION_DIR = BUILD_DIR / "verification_pages"
NATIVE_RENDER_SCRIPT = ROOT / "scripts" / "render_pdf_pages_native.js"


def file_uri(path: Path) -> str:
    return f"file://{path.resolve().as_posix()}"


def html_image_status(page) -> list[dict[str, object]]:
    return page.evaluate(
        """
        () => Array.from(document.images).map((img) => ({
          src: img.getAttribute("src"),
          currentSrc: img.currentSrc,
          alt: img.getAttribute("alt"),
          complete: img.complete,
          naturalWidth: img.naturalWidth,
          naturalHeight: img.naturalHeight,
        }))
        """
    )


def assert_html_images_loaded(page) -> list[dict[str, object]]:
    page.wait_for_function(
        """
        () => Array.from(document.images).every(
          (img) => img.complete && img.naturalWidth > 0 && img.naturalHeight > 0
        )
        """,
        timeout=15000,
    )
    status = html_image_status(page)
    broken = [
        item
        for item in status
        if not item["complete"] or item["naturalWidth"] <= 0 or item["naturalHeight"] <= 0
    ]
    if broken:
        raise RuntimeError(f"Broken HTML image references: {broken}")
    return status


def render_pdf() -> list[dict[str, object]]:
    if not HTML_PATH.exists():
        raise FileNotFoundError(f"Missing staged HTML at {HTML_PATH}")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 2200}, device_scale_factor=1)
        page.goto(file_uri(HTML_PATH), wait_until="load")
        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except PlaywrightTimeoutError:
            pass
        status = assert_html_images_loaded(page)
        page.emulate_media(media="print")
        BUILD_PDF_PATH.parent.mkdir(parents=True, exist_ok=True)
        page.pdf(
            path=str(BUILD_PDF_PATH),
            format="Letter",
            print_background=True,
            prefer_css_page_size=True,
            margin={"top": "0.55in", "right": "0.55in", "bottom": "0.55in", "left": "0.55in"},
        )
        browser.close()

    shutil.copy2(BUILD_PDF_PATH, ROOT_PDF_PATH)
    return status


def infer_pdf_page_count(pdf_path: Path) -> int:
    data = pdf_path.read_bytes()
    matches = [int(value) for value in re.findall(rb"/Count\s+(\d+)", data)]
    if not matches:
        raise RuntimeError(f"Unable to infer PDF page count from {pdf_path}")
    return max(matches)


def render_pdf_pages() -> list[Path]:
    if not ROOT_PDF_PATH.exists():
        raise FileNotFoundError(f"Missing PDF at {ROOT_PDF_PATH}")

    if not NATIVE_RENDER_SCRIPT.exists():
        raise FileNotFoundError(f"Missing native render helper at {NATIVE_RENDER_SCRIPT}")

    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "osascript",
            "-l",
            "JavaScript",
            str(NATIVE_RENDER_SCRIPT),
            str(ROOT_PDF_PATH),
            str(VERIFICATION_DIR),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    page_count = infer_pdf_page_count(ROOT_PDF_PATH)
    rendered = [VERIFICATION_DIR / f"page_{index:02d}.png" for index in range(1, page_count + 1)]
    missing = [path for path in rendered if not path.exists()]
    if missing:
        raise RuntimeError(f"Missing rendered verification pages: {missing}")
    return rendered


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render and verify the Aura whitepaper PDF.")
    parser.add_argument(
        "--render-pages",
        action="store_true",
        help="Render PNG screenshots for each page of the fixed PDF.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.render_pages:
        for path in render_pdf_pages():
            print(f"Wrote {path}")
        return

    status = render_pdf()
    print(f"Wrote {BUILD_PDF_PATH}")
    print(f"Wrote {ROOT_PDF_PATH}")
    for item in status:
        print(
            "Embedded image "
            f"{item['src']} natural={item['naturalWidth']}x{item['naturalHeight']}"
        )


if __name__ == "__main__":
    main()
