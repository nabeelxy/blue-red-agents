"""
server.py — MCP server exposing email triage tools.

Tools exposed:
  - triage_email_headers   → parse headers, auth results, anomalies
  - extract_email_urls     → extract and classify URLs from email body
  - check_domain           → WHOIS + DNS + DNSBL reputation check
  - analyze_screenshot     → Gemini Vision phishing analysis on a screenshot

Started automatically by agent.py via StdioConnectionParams.
"""

import json
import sys
from pathlib import Path

# Make tools/ importable regardless of working directory
sys.path.insert(0, str(Path(__file__).parent / "tools"))

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from header_parser import parse_email_headers
from url_extractor import extract_urls_from_email
from domain_checker import check_domain_reputation
from vision_analyzer import analyze_page_for_phishing

load_dotenv()

mcp = FastMCP("Email Triage Server")


@mcp.tool()
def triage_email_headers(raw_email: str) -> str:
    """
    Parse raw email headers and return structured security signals.

    Extracts:
    - Sender info: From, Reply-To, Return-Path, display name vs email address
    - Authentication: SPF, DKIM, DMARC results from Authentication-Results header
    - Routing: hop count, originating IP, Received chain
    - Anomalies: Reply-To mismatch, display name impersonation, domain mismatches
    - Risk signals: prioritised list of findings with CRITICAL prefix for severe issues

    Args:
        raw_email: Complete raw email in RFC 2822 format (headers + body).
                   Paste the full email source including all headers.

    Returns:
        JSON object with sender, authentication, routing, anomalies, risk_signals, risk_level.
    """
    result = parse_email_headers(raw_email)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def extract_email_urls(raw_email: str) -> str:
    """
    Extract and analyse all URLs from an email's HTML and plain text body.

    Detects:
    - Link text vs href mismatches (visible URL differs from actual destination)
    - Brand impersonation in URL (e.g., paypal in domain but not on paypal.com)
    - URL shorteners that hide the real destination
    - IP addresses used as URL host (strong phishing signal)
    - High-risk TLDs (.xyz, .tk, .ml, etc.)
    - Open redirect patterns in query strings

    Args:
        raw_email: Complete raw email in RFC 2822 format.

    Returns:
        JSON with total_urls, high_risk_count, and per-URL analysis with signals and risk level.
    """
    result = extract_urls_from_email(raw_email)
    return json.dumps(result, indent=2)


@mcp.tool()
def check_domain(domain: str) -> str:
    """
    Run WHOIS and DNS reputation checks on a domain.

    Checks:
    - Domain age (newly registered domains are high risk)
    - Registrar trustworthiness (MarkMonitor, CSC = brand protected)
    - WHOIS privacy protection
    - SPF record presence and hard-fail (-all) configuration
    - DMARC record presence and policy level (none/quarantine/reject)
    - MX records (does the domain send/receive email?)
    - DNSBL listing: Spamhaus ZEN, SpamCop, SORBS

    Args:
        domain: Domain name to check (e.g., paypal-secure-login.com).
                Do not include http:// or paths.

    Returns:
        JSON with whois, dns, dnsbl, risk_signals, and overall risk_level.
    """
    result = check_domain_reputation(domain)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def analyze_screenshot(image_path: str, claimed_domain: str = "") -> str:
    """
    Analyze a web page screenshot for phishing indicators using Gemini Vision.

    The vision model looks for:
    - Brand logo impersonation and visual design quality
    - URL in the browser address bar vs. claimed domain
    - Credential harvesting forms (login, card number, OTP)
    - Urgency language and pressure tactics
    - Visual quality issues typical of phishing kits

    Args:
        image_path: Local path to a .png or .jpg screenshot file.
                    Capture with: python tools/screenshot_tool.py <url> screenshots/out.png
        claimed_domain: Optional — the domain the suspicious email claims to be from.
                        Helps the vision model assess impersonation.

    Returns:
        JSON with verdict (PHISHING/SUSPICIOUS/LEGITIMATE/INCONCLUSIVE),
        confidence, brand_detected, red_flags, and reasoning.
    """
    result = analyze_page_for_phishing(
        image_path,
        claimed_domain=claimed_domain if claimed_domain else None,
    )
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
