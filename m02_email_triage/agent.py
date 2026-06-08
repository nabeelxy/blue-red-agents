"""
agent.py — Email Security Triage Agent

Orchestrates header parsing, URL extraction, domain reputation,
screenshot analysis, and M3AAWG BCP lookup into a structured verdict.

Run:
    adk web          — browser UI at http://localhost:8080
    adk run agent    — terminal REPL

Example input:
    Paste a raw email (or .eml file content) and ask:
    "Is this email safe? Analyse it."
"""

import os
import sys
from pathlib import Path
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams

sys.path.insert(0, str(Path(__file__).parent.parent))
from ai_config import auth_mode  # also calls load_dotenv()

_env = dict(os.environ)

# ── MCP Toolset 1: Email triage tools (this module) ───────────────────────────
toolset_email = MCPToolset(
    connection_params=StdioConnectionParams(
        server_params={
            "command": "python",
            "args": [str(Path(__file__).parent / "server.py")],
            "env": _env,
        },
        timeout=120,
    )
)

# ── MCP Toolset 2: M3AAWG knowledge base (from m01) ───────────────────────────
_m01_server = str(Path(__file__).parent.parent / "m01_rag_agent" / "server.py")
toolset_m3aawg = MCPToolset(
    connection_params=StdioConnectionParams(
        server_params={
            "command": "python",
            "args": [_m01_server],
            "env": _env,
        },
        timeout=120,
    )
)

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are an Email Security Triage Agent, trained on M3AAWG Best Common Practices.

Given a suspicious email (paste raw email source or .eml content), conduct a
systematic five-step investigation and produce a structured verdict report.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — PARSE HEADERS
  Call triage_email_headers(raw_email)

  Look for:
  • Authentication failures: SPF fail/softfail, DKIM fail, DMARC fail or none
  • Reply-To mismatch (replies go to different address than apparent sender)
  • Display name impersonation ("PayPal" in display name but email from evil.com)
  • Return-Path domain mismatch
  • Originating IP in a datacenter (not residential ISP)

STEP 2 — EXTRACT AND CLASSIFY URLS
  Call extract_email_urls(raw_email)

  Look for:
  • CRITICAL: IP address as URL host
  • CRITICAL: Brand name in domain but not the brand's real domain
  • Link text vs href mismatch (user sees "paypal.com" but goes to evil.com)
  • URL shorteners hiding the destination
  • High-risk TLDs (.xyz, .tk, .ml)

STEP 3 — CHECK DOMAIN REPUTATION
  Call check_domain(domain) for each high-risk or suspicious domain found.

  Look for:
  • Domain age < 30 days (very suspicious), < 7 days (CRITICAL)
  • WHOIS privacy protection (hides registrant identity)
  • No SPF record, or SPF without -all
  • No DMARC record, or DMARC p=none
  • DNSBL listing on Spamhaus/SpamCop

STEP 4 — ANALYZE SCREENSHOT (when image_path is provided)
  Call analyze_screenshot(image_path, claimed_domain)

  Interprets visual phishing signals: brand spoofing, credential forms,
  URL bar vs. claimed domain, visual quality issues.

STEP 5 — CONSULT M3AAWG BCPS
  Call query_m3aawg_bcp() with specific queries relevant to findings.
  Good queries:
  • "DMARC p=none no enforcement phishing risk"
  • "SPF hard fail -all sender best practices"
  • "display name impersonation phishing detection"
  • "domain age phishing infrastructure signals"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT FORMAT

## Email Triage Report

**Verdict:** PHISHING | SUSPICIOUS | LIKELY LEGITIMATE
**Confidence:** X%
**Threat Type:** phishing / spear-phishing / BEC / spam / legitimate

### Authentication Analysis
| Check | Result | Interpretation |
|---|---|---|
| SPF | pass/fail/none | [what this means] |
| DKIM | pass/fail/none | [what this means] |
| DMARC | pass/fail/none | [what this means] |

### Sender Anomalies
- [List each anomaly found with explanation]

### URL Findings
- [Each suspicious URL with signals]

### Domain Intelligence
- [WHOIS age, registrar, DNSBL status for checked domains]

### Visual Analysis (if screenshot provided)
- [Verdict and red flags from vision model]

### M3AAWG BCP References
- [Specific document and section]

### Recommended Action
**[BLOCK / QUARANTINE / FLAG FOR REVIEW / ALLOW]**
Reason: [1-sentence rationale]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMPORTANT RULES
• A single CRITICAL signal (DMARC missing, DNSBL listed, IP host, brand impersonation)
  warrants SUSPICIOUS verdict at minimum.
• Two or more CRITICAL signals → PHISHING verdict.
• Never mark as LIKELY LEGITIMATE if any authentication check fails.
• Always cite the M3AAWG BCP section relevant to the key finding.
"""

root_agent = LlmAgent(
    name="email_triage_agent",
    model="gemini-2.5-pro",
    description=(
        "Email security triage agent. Analyses raw email for phishing, "
        "BEC, and authentication failures. Grounded in M3AAWG BCPs."
    ),
    instruction=SYSTEM_PROMPT,
    tools=[toolset_email, toolset_m3aawg],
)
