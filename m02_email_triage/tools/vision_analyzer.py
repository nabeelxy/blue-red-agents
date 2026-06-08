"""
vision_analyzer.py — Analyze a web page screenshot for phishing signals using Gemini Vision.

Accepts a local screenshot file path (.png/.jpg).
Use screenshot_tool.py (playwright) to capture live pages.
"""

import base64
import io
import json
import re
from pathlib import Path
from typing import Optional

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from ai_config import get_genai_client, get_generative_model

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


VISION_MODEL = get_generative_model()

PHISHING_PROMPT = """You are a visual phishing detection expert.
Analyze this web page screenshot for phishing indicators.

Look for:
1. BRAND IMPERSONATION — logos present? Do they look authentic? Typos in brand name?
2. URL BAR — what domain is shown? Is it the real domain for the claimed brand?
3. CREDENTIAL HARVESTING — does the page ask for username, password, card number, OTP?
4. URGENCY LANGUAGE — "Account suspended", "Verify immediately", "Action required", countdown timers
5. VISUAL QUALITY — pixelated logos, misaligned elements, mixed fonts, obvious kit copy-paste
6. SSL/SECURITY — is there a padlock? Any browser security warnings visible?
7. CONTENT MATCH — does page content match what a legitimate page for this brand would show?

Respond ONLY with this JSON (no extra text):
{
  "verdict": "PHISHING" | "SUSPICIOUS" | "LEGITIMATE" | "INCONCLUSIVE",
  "confidence": <float 0.0-1.0>,
  "brand_detected": "<brand name or null>",
  "url_in_address_bar": "<URL shown or null>",
  "is_credential_harvesting": <true|false>,
  "red_flags": ["<specific element 1>", "<specific element 2>"],
  "reasoning": "<1-2 sentence explanation>"
}"""


def analyze_page_for_phishing(
    image_path: str,
    claimed_domain: Optional[str] = None,
) -> dict:
    """
    Analyze a web page screenshot for phishing indicators using Gemini Vision.

    Args:
        image_path: Local path to a .png or .jpg screenshot.
        claimed_domain: The domain the email claims to be from (adds context).

    Returns:
        Dict with verdict, confidence, red_flags, and reasoning.
        On error: dict with 'error' key and INCONCLUSIVE verdict.
    """
    path = Path(image_path)
    if not path.exists():
        return {
            "error": f"Screenshot not found: {image_path}",
            "verdict": "INCONCLUSIVE",
            "tip": (
                "Capture a screenshot first: "
                "python tools/screenshot_tool.py <url> <output.png>"
            ),
        }

    image_data = _load_image(path)
    if "error" in image_data:
        return {**image_data, "verdict": "INCONCLUSIVE"}

    prompt = PHISHING_PROMPT
    if claimed_domain:
        prompt += f"\n\nCONTEXT: The email claims to originate from domain: {claimed_domain}"

    client = get_genai_client()
    try:
        response = client.models.generate_content(
            model=VISION_MODEL,
            contents=[
                {"text": prompt},
                {"inline_data": image_data},
            ],
        )
        return _parse_response(response.text)
    except Exception as e:
        return {"error": f"Vision API error: {e}", "verdict": "INCONCLUSIVE"}


def _load_image(path: Path) -> dict:
    try:
        if HAS_PIL:
            img = Image.open(path).convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            img_bytes = buf.getvalue()
        else:
            img_bytes = path.read_bytes()
        return {
            "mime_type": "image/png",
            "data": base64.b64encode(img_bytes).decode("utf-8"),
        }
    except Exception as e:
        return {"error": f"Failed to load image {path}: {e}"}


def _parse_response(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    # Fallback: extract verdict keyword
    verdict = "INCONCLUSIVE"
    for v in ("PHISHING", "SUSPICIOUS", "LEGITIMATE"):
        if v in text.upper():
            verdict = v
            break
    return {
        "verdict": verdict,
        "confidence": 0.5,
        "reasoning": text[:400],
        "red_flags": [],
        "parse_warning": "Could not parse structured JSON from vision response",
    }
