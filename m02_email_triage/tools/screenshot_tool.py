"""
screenshot_tool.py — Capture a web page screenshot using Playwright.

Usage:
    python tools/screenshot_tool.py <url> <output.png>

Or import:
    from tools.screenshot_tool import capture_screenshot

Requires playwright:
    pip install playwright
    playwright install chromium
"""

import sys
from pathlib import Path


def capture_screenshot(url: str, output_path: str, timeout_ms: int = 15000) -> dict:
    """
    Capture a full-page screenshot of a URL using headless Chromium.

    Returns:
        {"success": True, "path": output_path} on success
        {"success": False, "error": message} on failure
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {
            "success": False,
            "error": (
                "playwright not installed. Run:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            ),
        }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()
            page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            page.screenshot(path=str(out), full_page=False)
            browser.close()

        return {"success": True, "path": str(out)}
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python screenshot_tool.py <url> <output.png>")
        sys.exit(1)

    url, output = sys.argv[1], sys.argv[2]
    result = capture_screenshot(url, output)
    if result["success"]:
        print(f"Screenshot saved: {result['path']}")
    else:
        print(f"Failed: {result['error']}")
        sys.exit(1)
