"""Optional rendered map audit: run a local bilet UI with a scan, then this script.

Requires Playwright and its Chromium installation. The check never starts a scan.
Example: python scripts/check_map_browser.py --url http://127.0.0.1:8000/?lang=en
"""

import argparse


def main() -> None:
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000/?lang=en")
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            args=["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"]
        )
        try:
            page = browser.new_page(reduced_motion="reduce")
            for width, height in ((375, 812), (1280, 800), (1366, 768)):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(args.url)
                page.locator(".netmap-3d").wait_for(state="visible")
                page.locator(".nm-label:not([hidden]) .lvl-word").first.wait_for(state="visible")
                audit = page.evaluate(
                    """() => {
                      const words = [...document.querySelectorAll(
                        '.nm-label:not([hidden]) .lvl-word')];
                      const fits = selector => {
                        const node = document.querySelector(selector);
                        return node.scrollHeight <= node.clientHeight + 1;
                      };
                      return words.length > 0 && words.every(node =>
                        getComputedStyle(node).display !== 'none' &&
                        parseFloat(getComputedStyle(node).fontSize) >= 16) &&
                        fits('.netmap-detail') && fits('.netmap-directory') &&
                        document.documentElement.scrollWidth <= innerWidth;
                    }"""
                )
                if not audit:
                    raise RuntimeError(f"Map text visibility or layout failed at {width}x{height}")
                print(f"PASS {width}x{height}: risk words, text size and unclipped panels")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
