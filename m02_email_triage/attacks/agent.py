"""
agent.py — Interactive Phishing Generator Agent (Act 1, Demo 1)

The phishing_generator.py script runs the fixed 3-target demo. This agent
allows interactive exploration — ask it to generate BEC emails for custom
targets, request multiple variants, or compare lure types side by side.

Run:
    adk web     — browser UI (from m02_email_triage/attacks/)
    adk run agent  — terminal REPL

Example queries:
    "Generate a BEC wire transfer email targeting the CFO of a mid-size tech startup"
    "Write a credential phishing email for an IT admin who just announced a cloud migration"
    "Give me 3 variants of a W-2 fraud email targeting an HR director at a logistics firm"
    "What lure types are available and what makes each one work?"
"""

import sys
from pathlib import Path
from dotenv import load_dotenv
from google.adk.agents import LlmAgent

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))
from phishing_generator import LURE_PROMPTS, generate_phishing_email


# ── Tools ─────────────────────────────────────────────────────────────────────

def list_lure_types() -> dict:
    """
    List available phishing lure types with descriptions and ideal target profiles.

    Returns:
        Dict mapping lure type names to descriptions and example targets.
    """
    return {
        "lure_types": {
            "wire_transfer_bec": {
                "description": "CEO impersonation requesting an urgent wire transfer",
                "ideal_targets": "Finance directors, controllers, accounts payable managers",
                "typical_ask": "Wire $50k–$500k to an attacker-controlled account",
                "why_it_works": "Authority + urgency + secrecy request bypasses normal approval chains",
            },
            "credential_phishing": {
                "description": "Fake IT security alert harvesting VPN or SSO credentials",
                "ideal_targets": "IT admins, helpdesk staff, engineers",
                "typical_ask": "Re-enter credentials on a cloned login portal",
                "why_it_works": "Targets with high system access; plausible security pretext",
            },
            "w2_tax_fraud": {
                "description": "IRS impersonation requesting employee W-2 tax data",
                "ideal_targets": "HR managers, payroll staff",
                "typical_ask": "Email all employee W-2 PDFs to an attacker address",
                "why_it_works": "Government authority; tax season timing; routine-seeming request",
            },
        }
    }


def craft_phishing_email(
    target_name: str,
    target_title: str,
    company: str,
    company_domain: str,
    lure_type: str,
    recent_activity: str = "",
) -> dict:
    """
    Generate a personalized spear phishing email for a fictional target profile.

    Demonstrates how LLMs produce fluent, context-aware attack emails in seconds —
    defeating grammar-based and signature-based filters. For defensive training only.

    Args:
        target_name: Full name of the fictional target (e.g. "Alex Rivera")
        target_title: Job title (e.g. "VP of Finance")
        company: Company name — must be fictional (e.g. "Acme Corp")
        company_domain: Legitimate-looking company domain (e.g. "acmecorp.com")
        lure_type: Attack type — wire_transfer_bec | credential_phishing | w2_tax_fraud
        recent_activity: Optional OSINT-style context to personalize the email
                         (e.g. "announced a $10M Series B on LinkedIn last week")

    Returns:
        Dict with the generated email body, attacker domain, and detection signals
        that a triage agent would catch.
    """
    if lure_type not in LURE_PROMPTS:
        return {
            "error": (
                f"Unknown lure_type '{lure_type}'. "
                f"Valid options: {list(LURE_PROMPTS.keys())}"
            )
        }

    target = {
        "name": target_name,
        "title": target_title,
        "company": company,
        "company_domain": company_domain,
        "recent_activity": recent_activity or f"recently joined {company} as {target_title}",
        "lure_type": lure_type,
    }

    result = generate_phishing_email(target)

    return {
        "target": target_name,
        "title": target_title,
        "company": company,
        "lure_type": lure_type,
        "attacker_domain": result["attacker_domain"],
        "generated_body": result["generated_body"],
        "detection_signals": {
            "domain_age": f"{result['attacker_domain']} likely registered days ago — WHOIS check fails",
            "authentication": "Sending domain has no DMARC enforcement — SPF/DKIM absent or misaligned",
            "reply_to_mismatch": (
                "Reply-To differs from From address"
                if lure_type == "wire_transfer_bec"
                else "N/A for this lure type"
            ),
            "content_filter": "Fluent grammar — traditional content filters score this as clean",
        },
    }


def generate_variants(
    target_name: str,
    target_title: str,
    company: str,
    company_domain: str,
    lure_type: str,
    recent_activity: str = "",
    count: int = 3,
) -> dict:
    """
    Generate multiple unique variants of the same phishing lure against one target.

    Each call to the LLM produces a different email body — unique wording, phrasing,
    and sentence structure — while preserving the same malicious intent. This
    demonstrates why hash-based and signature-based detection cannot keep up.

    Args:
        target_name: Fictional target name
        target_title: Target's job title
        company: Fictional company name
        company_domain: Company domain
        lure_type: Attack type (wire_transfer_bec | credential_phishing | w2_tax_fraud)
        recent_activity: Optional OSINT context for personalization
        count: Number of variants to generate, 1–5 (default 3)

    Returns:
        List of generated email bodies with a key observation about detection evasion.
    """
    if lure_type not in LURE_PROMPTS:
        return {
            "error": (
                f"Unknown lure_type '{lure_type}'. "
                f"Valid options: {list(LURE_PROMPTS.keys())}"
            )
        }

    count = min(max(count, 1), 5)

    target = {
        "name": target_name,
        "title": target_title,
        "company": company,
        "company_domain": company_domain,
        "recent_activity": recent_activity or f"recently joined {company} as {target_title}",
        "lure_type": lure_type,
    }

    variants = [generate_phishing_email(target) for _ in range(count)]

    return {
        "lure_type": lure_type,
        "target": target_name,
        "attacker_domain": variants[0]["attacker_domain"],
        "variant_count": count,
        "variants": [
            {"variant": i + 1, "body": v["generated_body"]}
            for i, v in enumerate(variants)
        ],
        "detection_note": (
            f"All {count} variants share the same intent and attacker domain "
            "but have zero byte-for-byte overlap. Blocklists built on content "
            "hashes miss every one. Authentication checks catch all of them."
        ),
    }


# ── Agent ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are a red team analyst demonstrating LLM-powered spear phishing for the
M3AAWG "AI Agents, Red and Blue" security training session.

Your role is to show M3AAWG defenders — engineers and cross-functional staff —
exactly how attackers use LLMs to craft convincing, personalized attack emails
in seconds. Understanding the attack is the first step to building better defenses.

WORKFLOW:
1. If the user hasn't specified a target, ask for: name, title, company, and lure type.
   Suggest fictional examples if they want to see a quick demo.
2. Call craft_phishing_email() to generate one personalized email.
3. After showing the output, highlight the detection_signals — explain what an
   authentication-first triage agent (Act 2, Walkthrough 2) would catch.
4. If asked for variants, call generate_variants() to demonstrate volume + evasion.
5. Always close with the pivot: "Here's what stops it."

IMPORTANT CONSTRAINTS:
- All targets must be fictional. Refuse requests using real individuals or real brands.
- Never provide instructions for actually sending email or registering domains.
- Frame every demo in terms of what the DEFENDER learns from seeing the attack.
- End every exchange with a reference to the defensive countermeasure:
  authentication-first detection (DMARC, DKIM alignment, domain age) catches
  these emails regardless of how fluent or personalized the content is.

FRAMING: "The content is convincing. The authentication is broken. That's how we catch it."
"""

root_agent = LlmAgent(
    name="phishing_generator_agent",
    model="gemini-2.5-pro",
    description=(
        "Interactive red team agent that generates personalized spear phishing emails "
        "on demand — demonstrating LLM-powered attack personalization for M3AAWG training."
    ),
    instruction=SYSTEM_PROMPT,
    tools=[list_lure_types, craft_phishing_email, generate_variants],
)
