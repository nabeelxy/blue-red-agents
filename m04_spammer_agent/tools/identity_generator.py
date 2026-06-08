"""
identity_generator.py — Generate synthetic bulk sender identities using an LLM.

Act 1, Demo 3: Agent-as-Spammer

Simulates the OSINT + identity-fabrication step of a bulk spam campaign
setup. An attacker uses an LLM to generate plausible-looking company names,
contact details, and sending domain names that will pass cursory inspection.

All identities are explicitly fictional. No real registration takes place.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from ai_config import get_genai_client, get_generative_model

IDENTITY_PROMPT = """
You are helping build a test dataset for an email security training.
Generate {count} fictional bulk email sender identities for the campaign below.
Each identity should look like a small legitimate business but be completely fictional.

Campaign brief: {brief}

For each sender, generate:
- company_name: a plausible small business name
- sender_name: a generic contact name
- sender_email_local: the local part of the email address (before the @)
- sending_domain: a domain name the company might register (no real TLD registration)
- website_tagline: a brief marketing tagline
- industry: the type of business
- estimated_monthly_volume: how many emails this "sender" plans to send

Requirements:
- Make the company names sound real but ensure they are clearly fictional
- Vary the industries (marketing, e-commerce, SaaS, travel, finance)
- Use a mix of TLDs (.com, .net, .io, .co)
- The domains should look legitimate but NOT impersonate real brands

Respond ONLY with a JSON array, no other text:
[
  {{
    "company_name": "...",
    "sender_name": "...",
    "sender_email_local": "...",
    "sending_domain": "...",
    "website_tagline": "...",
    "industry": "...",
    "estimated_monthly_volume": 0
  }}
]
"""


def generate_sender_identities(
    campaign_brief: str,
    count: int = 5,
    model: str | None = None,
) -> list[dict]:
    """
    Generate synthetic bulk sender identities for a spam campaign simulation.

    Args:
        campaign_brief: Description of the fictional campaign type.
        count: Number of sender identities to generate.
        model: Gemini model to use.

    Returns:
        List of sender identity dicts.
    """
    prompt = IDENTITY_PROMPT.format(count=count, brief=campaign_brief)
    client = get_genai_client()
    response = client.models.generate_content(
        model=model or get_generative_model(), contents=prompt
    )

    text = response.text.strip()
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        identities = json.loads(text)
        if not isinstance(identities, list):
            identities = [identities]
        return identities
    except json.JSONDecodeError:
        # Fallback: extract JSON array from text
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return []
