"""
demo.py — Act 2, Walkthrough 2: Prompt Injection Defense

Shows the hardened pipeline processing all 5 injection payloads.
Compare each result against the naive_processor output from attack/demo.py.

RUN:
    python defense/demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from m03_prompt_injection.attack.payloads import ALL_PAYLOADS
from m03_prompt_injection.defense.safe_processor import process_email_safe


def main():
    print("=" * 70)
    print("ACT 2, WALKTHROUGH 2: PROMPT INJECTION DEFENSE")
    print("M3AAWG Training — Hardened Email AI Pipeline")
    print("=" * 70)
    print()
    print("DEFENSE LAYERS:")
    print("  1. HTML → Plain Text  (removes white text, hidden divs, comments)")
    print("  2. Unicode Normalise  (removes zero-width chars, normalises leetspeak)")
    print("  3. Pattern Detection  (50+ injection signatures, leetspeak variants)")
    print("  4. Strict System Prompt (trust boundary: email = data, not instruction)")
    print("  5. Output Validation  (scan LLM response for action leakage)")
    print("  6. Action Gating      (sensitive actions require human approval)")
    print()
    print("Processing all 5 injection payloads through the hardened pipeline...")

    results_summary = []

    for payload in ALL_PAYLOADS:
        print(f"\n{'═' * 70}")
        print(f"PAYLOAD {payload['id']}: {payload['name'].upper()}")
        print(f"Technique: {payload['technique']}")
        print(f"{'═' * 70}")

        result = process_email_safe(payload["email"])
        san = result.sanitisation

        print(f"\n[SANITISATION RESULTS]")
        print(f"  HTML stripped:         {san.html_stripped}")
        print(f"  Invisible chars removed: {san.invisible_chars_removed}")
        print(f"  Injection detections:  {san.detections or 'none'}")
        print(f"  Risk level:            {san.risk_level}")

        print(f"\n[PIPELINE DECISION]")
        if result.blocked:
            print(f"  ✗ BLOCKED — {result.block_reason}")
        else:
            print(f"  ✓ Passed to LLM (sanitised content only)")
            print(f"  Suggested action: {result.suggested_action}")
            print(f"  Requires human approval: {result.requires_human_approval}")

        if not result.blocked and result.llm_output:
            print(f"\n[LLM RESPONSE (first 300 chars)]")
            print(f"  {result.llm_output[:300].strip()}...")

        outcome = "BLOCKED" if result.blocked else "FLAGGED" if result.requires_human_approval else "PROCESSED SAFELY"
        results_summary.append((payload["name"], san.risk_level, outcome))

    # Summary table
    print(f"\n{'═' * 70}")
    print("RESULTS SUMMARY")
    print(f"{'═' * 70}")
    print(f"{'Payload':<35} {'Risk Level':<12} {'Outcome'}")
    print("─" * 65)
    for name, risk, outcome in results_summary:
        status_icon = "✗" if "BLOCKED" in outcome else "⚠" if "FLAGGED" in outcome else "✓"
        print(f"{status_icon} {name:<33} {risk:<12} {outcome}")

    print(f"\n{'═' * 70}")
    print("KEY DEFENSE PRINCIPLES (M3AAWG AI-Enabled Abuse BCP):")
    print()
    print("1. SANITISE BEFORE LLM — strip HTML, remove invisible chars.")
    print("   Email content is untrusted user input, same as a web form.")
    print()
    print("2. TRUST BOUNDARY — explicitly separate instructions (system prompt)")
    print("   from data (email content). Make this boundary clear in the prompt.")
    print()
    print("3. PRINCIPLE OF LEAST PRIVILEGE — the AI assistant should not have")
    print("   access to capabilities it does not need for the task.")
    print()
    print("4. OUTPUT VALIDATION — scan LLM output for signs of compromise")
    print("   before taking any action.")
    print()
    print("5. HUMAN IN THE LOOP — any irreversible action (forward, send, delete)")
    print("   requires explicit human approval. This is M3AAWG BCP §3.1.")
    print("=" * 70)


if __name__ == "__main__":
    main()
