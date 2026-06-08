"""
demo.py — Act 1, Demo 2: Prompt Injection via Email

Live demonstration of prompt injection attacks against a naive AI email
assistant. Runs all 5 payload variants and shows the model being hijacked.

RUN:
    python attack/demo.py

Shows:
1. What the human sees (rendered email content)
2. What the LLM sees (including hidden injections)
3. How the naive assistant responds (COMPROMISED)

Followed by: python defense/demo.py (the fix)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from m03_prompt_injection.attack.payloads import ALL_PAYLOADS
from m03_prompt_injection.attack.naive_processor import process_email_naive


def extract_visible_text(raw_email: str) -> str:
    """Simulate what a human sees — strip HTML tags, hidden elements, invisible chars."""
    import re
    # Remove HTML tags
    text = re.sub(r"<style[^>]*>.*?</style>", "", raw_email, flags=re.DOTALL)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
    text = re.sub(r"<!--.*?-->", "[HTML COMMENT HIDDEN]", text, flags=re.DOTALL)
    text = re.sub(r'style="[^"]*display\s*:\s*none[^"]*"[^>]*>.*?</[^>]+>', "[HIDDEN DIV]", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'style="[^"]*color\s*:\s*white[^"]*"[^>]*>(.*?)</[^>]+>', "[WHITE TEXT: \\1]", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    # Remove zero-width chars for display
    text = text.replace("\u200d", "").replace("\u200b", "").replace("\u200c", "")
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def main():
    print("=" * 70)
    print("ACT 1, DEMO 2: PROMPT INJECTION VIA EMAIL")
    print("M3AAWG Training — Controlled Security Demonstration")
    print("=" * 70)
    print()
    print("SCENARIO:")
    print("  Acme Corporation deploys an AI email assistant to triage inbox.")
    print("  The assistant reads emails and processes instructions in the content.")
    print("  Attackers send emails with HIDDEN instructions embedded in the content.")
    print()

    # Run all 5 payloads
    for payload in ALL_PAYLOADS:
        print(f"\n{'═' * 70}")
        print(f"PAYLOAD {payload['id']}: {payload['name'].upper()}")
        print(f"Technique : {payload['technique']}")
        print(f"Evasion   : {payload['evasion']}")
        print(f"{'═' * 70}")

        print("\n[WHAT THE HUMAN SEES IN THEIR EMAIL CLIENT]")
        print("─" * 50)
        visible = extract_visible_text(payload["email"])
        print(visible[:600] + ("..." if len(visible) > 600 else ""))

        print("\n[NAIVE AI ASSISTANT RESPONSE — COMPROMISED]")
        print("─" * 50)
        try:
            response = process_email_naive(payload["email"])
            print(response)
        except Exception as e:
            print(f"  [Error running demo: {e}]")
            print("  Ensure GOOGLE_API_KEY is set in .env")

        print()

    print("\n" + "=" * 70)
    print("KEY OBSERVATIONS:")
    print()
    print("• The human saw legitimate-looking email content")
    print("• The LLM saw and acted on HIDDEN instructions")
    print("• No authentication or reputation signals helped — the email")
    print("  could pass SPF, DKIM, and DMARC and still be an injection attack")
    print("• ANY organisation feeding email into an AI system is exposed")
    print()
    print("→ NEW ATTACK SURFACE: M3AAWG BCPs do not yet cover AI email tools.")
    print("  This is an emerging gap that this training aims to address.")
    print()
    print("→ DEFENSE: python defense/demo.py")
    print("  Shows the hardened pipeline catching all 5 payloads.")
    print("=" * 70)


if __name__ == "__main__":
    main()
