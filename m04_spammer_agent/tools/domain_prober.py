"""
domain_prober.py — Probe a domain's auth posture and blocklist status via DNS.

Used by the spammer agent to simulate pre-send checklist:
"Does this domain pass the basic authentication checks that filters look for?"

No actual domain registration or email sending — DNS queries only.
"""

import re
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def probe_domain(domain: str) -> dict:
    """
    Check whether a domain has the auth configuration that spam filters look for.

    Returns a dict showing what an attacker's pre-send checklist would reveal:
      - spf_present: does a valid SPF record exist?
      - dmarc_present: does a DMARC record exist?
      - dmarc_policy: if so, what enforcement level?
      - mx_present: does the domain have MX records?
      - dnsbl_listed: is the IP on common blocklists?
      - attacker_verdict: from the attacker's perspective, is this domain "safe to use"?
    """
    domain = domain.lower().strip()

    result = {
        "domain": domain,
        "spf_present": False,
        "spf_record": None,
        "spf_hard_fail": False,
        "dmarc_present": False,
        "dmarc_record": None,
        "dmarc_policy": None,
        "mx_present": False,
        "mx_records": [],
        "dnsbl_listed": False,
        "dnsbl_hits": [],
        "resolves": False,
        "a_records": [],
    }

    if not HAS_DNS:
        result["error"] = "dnspython not installed"
        return result

    # A records (does the domain resolve at all?)
    try:
        answers = dns.resolver.resolve(domain, "A")
        result["a_records"] = [str(r) for r in answers]
        result["resolves"] = bool(result["a_records"])
    except Exception:
        pass

    # SPF
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                result["spf_present"] = True
                result["spf_record"] = txt
                result["spf_hard_fail"] = "-all" in txt
                break
    except Exception:
        pass

    # DMARC
    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc_present"] = True
                result["dmarc_record"] = txt
                m = re.search(r"\bp=(\w+)", txt)
                result["dmarc_policy"] = m.group(1).lower() if m else "none"
                break
    except Exception:
        pass

    # MX
    try:
        mx = [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
        result["mx_records"] = mx
        result["mx_present"] = bool(mx)
    except Exception:
        pass

    # DNSBL check on resolved IPs
    for ip in result["a_records"][:1]:
        rev = ".".join(reversed(ip.split(".")))
        for bl in ["zen.spamhaus.org", "bl.spamcop.net"]:
            try:
                dns.resolver.resolve(f"{rev}.{bl}", "A")
                result["dnsbl_listed"] = True
                result["dnsbl_hits"].append(f"{ip} on {bl}")
            except Exception:
                pass

    # Attacker's verdict: would they use this domain?
    # A new domain with no DMARC (or p=none) and no DNSBL listing = "green light"
    spf_ok = result["spf_present"]  # filter-friendly (even ~all passes most filters)
    dmarc_weak = not result["dmarc_present"] or result["dmarc_policy"] in (None, "none")
    not_listed = not result["dnsbl_listed"]

    if not_listed and dmarc_weak:
        verdict = "GREEN — no DMARC enforcement, not blocklisted. Safe to use."
    elif not_listed and not dmarc_weak:
        verdict = "YELLOW — DMARC enforced. Messages may be rejected. Avoid."
    else:
        verdict = "RED — blocklisted. Do not use."

    result["attacker_verdict"] = verdict
    return result


def estimate_campaign_cost(
    identities: list[dict],
    cost_per_million: float = 0.60,  # Gemini Flash ~$0.60/1M input tokens, email generation ~$0.001/email
) -> dict:
    """
    Estimate the cost of running a spam campaign with the given sender pool.

    Provides a before/after comparison (manual team vs. AI agent).
    """
    total_volume = sum(i.get("estimated_monthly_volume", 10000) for i in identities)
    total_domains = len(identities)

    # AI-driven cost model
    ai_content_cost = total_volume * 0.001 / 1000  # ~$0.001 per 1K tokens, ~1K tokens per email
    ai_infra_cost = total_domains * 10             # ~$10/domain for registration + hosting/month
    ai_total = ai_content_cost + ai_infra_cost
    ai_cost_per_million = (ai_total / total_volume) * 1_000_000 if total_volume else 0

    # Traditional team cost model (rough estimate)
    traditional_team_monthly = 15_000   # 3-5 person spam team @ ~$5K/person
    traditional_volume = 500_000        # typical team capacity/month
    traditional_cost_per_million = (traditional_team_monthly / traditional_volume) * 1_000_000

    return {
        "total_senders": total_domains,
        "total_monthly_volume": total_volume,
        "ai_driven": {
            "content_generation_cost_usd": round(ai_content_cost, 2),
            "infrastructure_cost_usd": round(ai_infra_cost, 2),
            "total_monthly_usd": round(ai_total, 2),
            "cost_per_million_emails_usd": round(ai_cost_per_million, 2),
        },
        "traditional_team": {
            "monthly_team_cost_usd": traditional_team_monthly,
            "max_volume": traditional_volume,
            "cost_per_million_emails_usd": round(traditional_cost_per_million, 2),
        },
        "cost_reduction_factor": round(
            traditional_cost_per_million / ai_cost_per_million, 1
        ) if ai_cost_per_million > 0 else "N/A",
    }
