"""
agent.py — Interactive Spammer Agent (for extended exploration)

The demo.py script runs the fixed 5-minute demo. This agent allows
interactive exploration of the attack workflow — ask it to generate
identities, probe specific domains, or estimate costs for different
campaign types.

Run:
    adk web     — browser UI
    adk run agent  — terminal REPL

Example queries:
    "Generate 3 sender identities for a fake crypto trading platform campaign"
    "Probe the domain quickloans-today.net for authentication posture"
    "What would it cost to run a 1M email campaign with 10 sender domains?"
"""

import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent / "tools"))
from identity_generator import generate_sender_identities
from domain_prober import probe_domain, estimate_campaign_cost


# ── Wrap tools for direct ADK function calling ─────────────────────────────────

def generate_identities(campaign_brief: str, count: int = 5) -> dict:
    """
    Generate synthetic bulk sender identities for a spam campaign simulation.

    Args:
        campaign_brief: Description of the spam campaign type and target audience.
        count: Number of sender identities to generate (default 5).

    Returns:
        JSON with list of generated sender identities including company, domain, volume.
    """
    results = generate_sender_identities(campaign_brief, count=count)
    return {"identities": results, "count": len(results)}


def check_domain_auth_posture(domain: str) -> dict:
    """
    Check a domain's authentication posture from an attacker's perspective.

    Checks whether the domain has SPF, DMARC, MX records, and blocklist status.
    Returns an attacker verdict: GREEN (exploit), YELLOW (risky), RED (avoid).

    Args:
        domain: Domain name to probe (e.g., quickloans-today.net)

    Returns:
        Dict with spf_present, dmarc_policy, dnsbl_listed, attacker_verdict.
    """
    return probe_domain(domain)


def calculate_campaign_economics(identities_json: str) -> dict:
    """
    Calculate spam campaign cost economics comparing AI agents vs. traditional team.

    Args:
        identities_json: JSON string of sender identity list (from generate_identities).

    Returns:
        Cost comparison table with cost_reduction_factor.
    """
    try:
        identities = json.loads(identities_json)
        if isinstance(identities, dict) and "identities" in identities:
            identities = identities["identities"]
    except Exception:
        return {"error": "Invalid JSON for identities"}
    return estimate_campaign_cost(identities)


SYSTEM_PROMPT = """
You are a red team analyst simulating bulk email abuse campaigns for security training.

Your role is to demonstrate how LLM agents lower the barrier to spam infrastructure
setup — for the purpose of helping M3AAWG defenders understand and counter these threats.

When asked to simulate a campaign:
1. Call generate_identities() to create synthetic sender identities
2. Call check_domain_auth_posture() on each generated domain
3. Call calculate_campaign_economics() to show cost comparison
4. Clearly explain the DEFENDER'S PERSPECTIVE: which signals would catch this campaign

IMPORTANT CONSTRAINTS:
- All identities are fictional. Never use real company names or impersonate real brands.
- Never provide instructions for actually registering domains or sending spam.
- Always conclude with the defensive countermeasures (DMARC p=reject, authentication-first).

FRAMING: Every demo ends with "And here's what stops it..."
"""

root_agent = LlmAgent(
    name="spammer_agent_demo",
    model="gemini-2.5-pro",
    description="Red team demo agent simulating bulk sender abuse workflow.",
    instruction=SYSTEM_PROMPT,
    tools=[generate_identities, check_domain_auth_posture, calculate_campaign_economics],
)
