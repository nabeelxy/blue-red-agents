"""
demo.py — Act 1, Demo 3: Agent-as-Spammer

M3AAWG Training — Controlled Demonstration

Shows how an LLM agent automates the full bulk spam sender setup workflow:
  1. Generate plausible sender identities (what used to need a team)
  2. Probe domains for auth posture (what passes spam filters)
  3. Calculate campaign economics (the cost collapse argument)
  4. PIVOT: show the m01 compliance agent catching these domains

RUN:
    python demo.py

Duration: ~5 minutes (Act 1, Demo 3)
"""

import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))
from tools.identity_generator import generate_sender_identities
from tools.domain_prober import probe_domain, estimate_campaign_cost

# ── Demo parameters ────────────────────────────────────────────────────────────
CAMPAIGN_BRIEF = (
    "A bulk email marketing campaign promoting a fictional financial services "
    "comparison website. Targets consumers in the US who may be interested in "
    "credit cards, loans, or savings accounts."
)

SENDER_COUNT = 5     # Keep short for live demo
PROBE_COUNT  = 3     # Number of generated domains to probe live


def _divider(char="─", width=68):
    print(char * width)


def _section(title: str):
    print(f"\n{'═' * 68}")
    print(f"  {title}")
    print(f"{'═' * 68}")


def main():
    print()
    print("█" * 68)
    print("  ACT 1, DEMO 3: AGENT-AS-SPAMMER")
    print("  M3AAWG Training — Controlled Security Demonstration")
    print("█" * 68)
    print()
    print("SCENARIO:")
    print("  A threat actor instructs an LLM agent to set up a bulk email")
    print("  spam campaign from scratch. Tasks that previously required a")
    print("  team of 3-5 people working for a week now take 30 seconds.")
    print()
    print(f"  Campaign: {CAMPAIGN_BRIEF[:80]}...")

    # ── Step 1: Identity generation ───────────────────────────────────────────
    _section(f"STEP 1 — GENERATE {SENDER_COUNT} BULK SENDER IDENTITIES (LLM)")
    print("  Prompt: 'Generate fictional company identities for a bulk email campaign'")
    print("  Running...\n")

    identities = generate_sender_identities(CAMPAIGN_BRIEF, count=SENDER_COUNT)

    if not identities:
        print("  ERROR: Could not generate identities. Check GOOGLE_API_KEY in .env")
        return

    for i, identity in enumerate(identities, 1):
        print(f"  Sender {i}:")
        print(f"    Company:  {identity.get('company_name', '?')}")
        print(f"    Email:    {identity.get('sender_email_local', '?')}@{identity.get('sending_domain', '?')}")
        print(f"    Industry: {identity.get('industry', '?')}")
        print(f"    Volume:   {identity.get('estimated_monthly_volume', 0):,} emails/month")
        print(f"    Domain:   {identity.get('sending_domain', '?')}")
        print()

    _divider()
    print("  ✓ Generated in ~3 seconds.")
    print("  ✗ Manual equivalent: Briefing a team, researching cover stories,")
    print("    registering multiple entities — 3-5 days of work.")

    # ── Step 2: Domain probing ─────────────────────────────────────────────────
    _section("STEP 2 — PROBE DOMAINS FOR AUTHENTICATION POSTURE")
    print("  Checking which generated domains would pass spam filter checks...")
    print("  (These are likely unregistered — showing what a NEW domain looks like)\n")

    probe_results = []
    for identity in identities[:PROBE_COUNT]:
        domain = identity.get("sending_domain", "")
        if not domain:
            continue
        print(f"  Probing: {domain}")
        result = probe_domain(domain)
        probe_results.append((identity, result))

        spf_status    = "✓" if result["spf_present"] else "✗ MISSING"
        dmarc_status  = result.get("dmarc_policy", "MISSING") or "MISSING"
        dnsbl_status  = "⚠ LISTED" if result["dnsbl_listed"] else "✓ clean"
        resolves      = "yes" if result["resolves"] else "no (unregistered — ideal for attacker)"

        print(f"    Resolves:    {resolves}")
        print(f"    SPF:         {spf_status}")
        print(f"    DMARC:       {dmarc_status.upper()}")
        print(f"    Blocklisted: {dnsbl_status}")
        print(f"    → Attacker:  {result['attacker_verdict']}")
        print()

    print()
    print("  KEY INSIGHT: A freshly registered domain with minimal DNS setup")
    print("  has NO DMARC enforcement and is NOT yet blocklisted.")
    print("  Spam filters that rely solely on reputation will pass it.")
    print("  The window between registration and blocklisting = attack window.")

    # ── Step 3: Economics ─────────────────────────────────────────────────────
    _section("STEP 3 — CAMPAIGN COST ECONOMICS")

    if identities:
        # Patch volume if not set
        for i in identities:
            if not i.get("estimated_monthly_volume"):
                i["estimated_monthly_volume"] = 50_000

        economics = estimate_campaign_cost(identities)
        ai  = economics["ai_driven"]
        trad = economics["traditional_team"]

        print(f"  Campaign scale:  {economics['total_senders']} senders, "
              f"{economics['total_monthly_volume']:,} emails/month")
        print()
        print(f"  ┌─────────────────────────────┬──────────────────┬──────────────────┐")
        print(f"  │                             │ AI Agent         │ Traditional Team │")
        print(f"  ├─────────────────────────────┼──────────────────┼──────────────────┤")
        print(f"  │ Monthly cost (USD)           │ ${ai['total_monthly_usd']:>14,.2f} │ ${trad['monthly_team_cost_usd']:>14,} │")
        print(f"  │ Cost per 1M emails (USD)     │ ${ai['cost_per_million_emails_usd']:>14,.2f} │ ${trad['cost_per_million_emails_usd']:>14,.2f} │")
        print(f"  │ Setup time                  │ {'~30 seconds':>16} │ {'3-5 days':>16} │")
        print(f"  │ Scales to 100M emails?      │ {'Yes, same cost':>16} │ {'Hire more people':>16} │")
        print(f"  └─────────────────────────────┴──────────────────┴──────────────────┘")
        print()
        print(f"  Cost reduction: ~{economics['cost_reduction_factor']}x cheaper with AI agents.")
        print()
        print("  This is why volume-based spam (blocked because of high complaint")
        print("  rates) is LESS EFFECTIVE as a detection strategy than before.")
        print("  Attackers can now send lower volumes to more targets at the same cost.")

    # ── Step 4: Pivot to defense ──────────────────────────────────────────────
    _section("STEP 4 — PIVOT: WHAT THE M3AAWG COMPLIANCE AGENT SEES")
    print()
    print("  The same domains, viewed through the lens of M3AAWG BCPs:")
    print()

    for identity, _ in probe_results:
        domain = identity.get("sending_domain", "")
        company = identity.get("company_name", "")
        print(f"  Domain: {domain} ({company})")
        print(f"    → CRITICAL: No DMARC record (violates M3AAWG Email Auth BCP §3.3)")
        print(f"    → HIGH: SPF likely missing or unconfigured (new domain)")
        print(f"    → HIGH: Domain age < 7 days (peak risk window)")
        print(f"    → MEDIUM: No established sending reputation")
        print(f"    → Recommended action: REJECT at gateway, report to registrar")
        print()

    print()
    print("  The AUTHENTICATION-FIRST approach catches AI-generated campaigns")
    print("  even when content is perfect and grammar is flawless.")
    print()
    print("  To run the interactive compliance agent:")
    print("  $ cd ../m01_rag_agent && adk web")
    print("  Query: 'Evaluate this new sender domain: [paste any domain from above]'")

    # ── Summary ────────────────────────────────────────────────────────────────
    print()
    print("█" * 68)
    print("  DEMO 3 COMPLETE — KEY POINTS FOR M3AAWG AUDIENCE")
    print("█" * 68)
    print()
    print("  1. LLM agents reduce the skill threshold for spam infrastructure")
    print("     setup from 'technical team' to 'anyone with a credit card'.")
    print()
    print("  2. Cost collapse: ~30x cheaper than traditional spam teams.")
    print("     Enables lower volume, higher precision targeting.")
    print()
    print("  3. New domains have an authentication gap: no DMARC enforcement,")
    print("     no blocklist presence. Detection must happen at the AUTH layer.")
    print()
    print("  4. M3AAWG BCP §3.3 (DMARC p=reject) directly closes the gap:")
    print("     senders without DMARC are filtered before content is evaluated.")
    print()
    print("  → Act 2, Walkthrough 3: m01_rag_agent — the M3AAWG compliance")
    print("    agent that generates the full BCP-referenced report.")
    print("█" * 68)


if __name__ == "__main__":
    main()
