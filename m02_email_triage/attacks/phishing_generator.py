"""
phishing_generator.py — Act 1, Demo 1: LLM Phishing Factory

TRAINING DEMO — Shows how LLMs generate hyper-personalized phishing at scale.

This script generates phishing email content using Gemini. It demonstrates:
1. Personalization using OSINT-style target context
2. Volume: multiple variants in seconds
3. Why grammar-based detection fails against AI-generated content

RUN:
    python attacks/phishing_generator.py

NOTE: All generated content uses fictional targets and fake domains.
      This is a controlled demonstration for defensive training purposes.
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from ai_config import get_genai_client, get_generative_model

# ── Fictional targets (OSINT-style context an attacker might gather) ──────────
DEMO_TARGETS = [
    {
        "name": "Sarah Chen",
        "title": "Head of Finance",
        "company": "Acme Corporation",
        "company_domain": "acmecorp.com",
        "recent_activity": "posted about Q1 earnings on LinkedIn",
        "lure_type": "wire_transfer_bec",
    },
    {
        "name": "Mark Williams",
        "title": "IT Administrator",
        "company": "Demo Healthcare Systems",
        "company_domain": "demo-healthcare.com",
        "recent_activity": "recently deployed a new VPN solution",
        "lure_type": "credential_phishing",
    },
    {
        "name": "Jennifer Lopez",
        "title": "HR Manager",
        "company": "Sample Logistics Co",
        "company_domain": "sample-logistics.com",
        "recent_activity": "is running open enrollment for benefits",
        "lure_type": "w2_tax_fraud",
    },
]

ATTACKER_DOMAINS = {
    "wire_transfer_bec": "acme-corp-secure.com",
    "credential_phishing": "demo-healthcare-portal.net",
    "w2_tax_fraud": "irs-w2-verification.com",
}

LURE_PROMPTS = {
    "wire_transfer_bec": """
Write a Business Email Compromise (BEC) spear phishing email.
The attacker is impersonating the CEO of {company}.
Target: {name}, {title}.
Context: {recent_activity}.
Goal: Get the target to wire $127,500 to an attacker-controlled account.
Requirements:
- Urgent but professional tone
- Request secrecy and not to call
- Provide fake wire transfer details
- Reply-To should go to an attacker gmail: ceo.{company_short}@gmail.com
- Sending domain: {attacker_domain}
Write only the email body (no subject line).
""",
    "credential_phishing": """
Write a spear phishing email targeting an IT Administrator.
Sender appears to be: "IT Security Team <security@{attacker_domain}>"
Target: {name}, {title} at {company}.
Context: {recent_activity}.
Goal: Get the target to click a link and enter their VPN credentials.
The link appears to go to a legitimate company IT portal.
Requirements:
- Reference the recent VPN work specifically
- Include a plausible reason for credential re-verification
- Create urgency (security audit, compliance deadline)
- Link text should show the real company domain but href goes to attacker domain
Write only the email body (no subject line).
""",
    "w2_tax_fraud": """
Write a spear phishing email targeting an HR manager.
Sender appears to be: "IRS Employer Services <employer-services@{attacker_domain}>"
Target: {name}, {title} at {company}.
Context: {recent_activity}.
Goal: Get the target to send W-2 tax data for all employees.
Requirements:
- Reference IRS regulations and compliance requirements
- Create urgency (deadline in 48 hours)
- Request W-2 data be sent by reply email
- Professional government agency tone
Write only the email body (no subject line).
""",
}


def generate_phishing_email(target: dict, model: str | None = None) -> dict:
    """Generate a personalized phishing email for the given target."""
    lure_type = target["lure_type"]
    attacker_domain = ATTACKER_DOMAINS[lure_type]
    company_short = target["company"].lower().split()[0]

    prompt = LURE_PROMPTS[lure_type].format(
        name=target["name"],
        title=target["title"],
        company=target["company"],
        company_domain=target["company_domain"],
        company_short=company_short,
        recent_activity=target["recent_activity"],
        attacker_domain=attacker_domain,
    )

    client = get_genai_client()
    response = client.models.generate_content(
        model=model or get_generative_model(), contents=prompt
    )

    return {
        "target": target["name"],
        "title": target["title"],
        "company": target["company"],
        "lure_type": lure_type,
        "attacker_domain": attacker_domain,
        "generated_body": response.text,
    }


def generate_variants(target: dict, count: int = 3) -> list[dict]:
    """Generate multiple variants of the same lure to show volume capability."""
    return [generate_phishing_email(target) for _ in range(count)]


def main():
    print("=" * 70)
    print("ACT 1, DEMO 1: LLM PHISHING FACTORY")
    print("M3AAWG Training — Controlled Demonstration")
    print("=" * 70)
    print()
    print("Generating personalized spear phishing emails using Gemini...")
    print("Targets: fictional personas with OSINT-style context\n")

    for i, target in enumerate(DEMO_TARGETS, 1):
        print(f"{'─' * 60}")
        print(f"Target {i}: {target['name']}, {target['title']}")
        print(f"Company:   {target['company']} ({target['company_domain']})")
        print(f"OSINT:     {target['recent_activity']}")
        print(f"Lure:      {target['lure_type']}")
        print(f"{'─' * 60}")

        result = generate_phishing_email(target)

        print(f"\n[GENERATED EMAIL — attacker domain: {result['attacker_domain']}]\n")
        print(result["generated_body"])
        print()

    print("=" * 70)
    print("KEY OBSERVATIONS FOR M3AAWG AUDIENCE:")
    print()
    print("1. PERSONALIZATION: Each email references specific context about the")
    print("   target — their role, recent activity, and company specifics.")
    print()
    print("2. GRAMMAR: Zero typos, natural professional language.")
    print("   Traditional grammar-based spam filters will not catch this.")
    print()
    print("3. SCALE: This generated 3 unique phishing emails in seconds.")
    print("   A threat actor can generate millions per day at ~$0.001/email.")
    print()
    print("4. VARIANTS: Each regeneration produces a unique email —")
    print("   defeating signature-based detection.")
    print()
    print("→ DEFENSE: Act 2, Walkthrough 1 — Email Triage Agent")
    print("  The agent detects these emails via AUTHENTICATION signals,")
    print("  not content. Domain age, DMARC, WHOIS — not grammar.")
    print("=" * 70)


if __name__ == "__main__":
    main()
