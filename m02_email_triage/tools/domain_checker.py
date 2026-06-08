"""
domain_checker.py — WHOIS + DNS reputation check for a sender domain.

Checks: domain age, registrar trust, SPF/DMARC/MX records, DNSBL listing.
Requires: python-whois, dnspython
"""

import re
import json
from datetime import datetime, timezone

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    import dns.reversename
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


TRUSTED_REGISTRARS = [
    "markmonitor", "csc corporate domains", "network solutions",
    "godaddy", "namecheap", "verisign", "register.com",
    "tucows", "google domains", "squarespace",
]

DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
]


def check_domain_reputation(domain: str) -> dict:
    """
    Run WHOIS + DNS reputation checks on a domain.

    Returns a structured dict with:
      - whois: registrar, age, privacy protection
      - dns: SPF, DMARC, MX records
      - dnsbl: blocklist status for each resolved IP
      - risk_signals: prioritised list of findings
      - risk_level: LOW / MEDIUM / HIGH / CRITICAL
    """
    # Sanitise input
    domain = re.sub(r"^https?://", "", domain.lower().strip())
    domain = domain.split("/")[0].split(":")[0].split("?")[0]

    result: dict = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "dnsbl": {},
        "risk_signals": [],
    }

    _check_whois(domain, result)
    _check_dns(domain, result)
    _check_dnsbls(domain, result)

    # Overall risk level
    critical = [s for s in result["risk_signals"] if s.startswith("CRITICAL:")]
    non_critical = [s for s in result["risk_signals"] if not s.startswith("CRITICAL:")]
    result["risk_level"] = (
        "CRITICAL" if critical
        else "HIGH" if len(non_critical) >= 3
        else "MEDIUM" if non_critical
        else "LOW"
    )

    return result


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def _check_whois(domain: str, result: dict) -> None:
    if not HAS_WHOIS:
        result["whois"]["error"] = "python-whois not installed (pip install python-whois)"
        return
    try:
        w = whois.whois(domain)
    except Exception as e:
        result["whois"]["error"] = str(e)
        return

    created = w.creation_date
    if isinstance(created, list):
        created = created[0]
    expires = w.expiration_date
    if isinstance(expires, list):
        expires = expires[0]

    age_days = None
    if isinstance(created, datetime):
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days

    registrar = str(w.registrar or "unknown")
    is_trusted = any(t in registrar.lower() for t in TRUSTED_REGISTRARS)

    privacy_fields = [
        str(w.registrant_name or ""),
        str(getattr(w, "org", "") or ""),
    ]
    is_privacy = any(
        p in " ".join(privacy_fields).lower()
        for p in ["privacy", "proxy", "redacted", "whoisguard", "withheld"]
    )

    result["whois"] = {
        "registrar": registrar,
        "is_trusted_registrar": is_trusted,
        "created": str(created) if created else "unknown",
        "expires": str(expires) if expires else "unknown",
        "age_days": age_days,
        "privacy_protected": is_privacy,
        "name_servers": [str(ns) for ns in (w.name_servers or [])],
    }

    # Risk signals
    if age_days is not None:
        if age_days < 7:
            result["risk_signals"].append(f"CRITICAL:domain_{age_days}_days_old")
        elif age_days < 30:
            result["risk_signals"].append(f"very_new_domain:{age_days}_days_old")
        elif age_days < 90:
            result["risk_signals"].append(f"new_domain:{age_days}_days_old")

    if is_privacy:
        result["risk_signals"].append("registrant_privacy_protected")

    if not is_trusted:
        result["risk_signals"].append("non_trusted_registrar")


# ── DNS ───────────────────────────────────────────────────────────────────────

def _check_dns(domain: str, result: dict) -> None:
    if not HAS_DNS:
        result["dns"]["error"] = "dnspython not installed (pip install dnspython)"
        return

    # SPF
    spf = _resolve_txt(domain, prefix="v=spf1")
    result["dns"]["spf"] = spf
    if not spf:
        result["risk_signals"].append("no_spf_record")
    elif "-all" not in spf:
        qualifier = "~all" if "~all" in spf else "?all" if "?all" in spf else "+all"
        result["risk_signals"].append(f"spf_no_hard_fail:{qualifier}")

    # DMARC
    dmarc = _resolve_txt(f"_dmarc.{domain}", prefix="v=DMARC1")
    result["dns"]["dmarc"] = dmarc
    if not dmarc:
        result["risk_signals"].append("CRITICAL:no_dmarc_record")
    else:
        policy_match = re.search(r"\bp=(\w+)", dmarc)
        policy = policy_match.group(1).lower() if policy_match else "none"
        result["dns"]["dmarc_policy"] = policy
        if policy == "none":
            result["risk_signals"].append("CRITICAL:dmarc_p=none_no_enforcement")
        elif policy == "quarantine":
            result["risk_signals"].append("dmarc_p=quarantine_partial_enforcement")

    # MX
    try:
        mx_records = [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
        result["dns"]["mx"] = mx_records
        if not mx_records:
            result["risk_signals"].append("no_mx_records")
    except Exception:
        result["dns"]["mx"] = []
        result["risk_signals"].append("no_mx_records")

    # A records (needed for DNSBL)
    try:
        result["dns"]["a_records"] = [str(r) for r in dns.resolver.resolve(domain, "A")]
    except Exception:
        result["dns"]["a_records"] = []


def _resolve_txt(domain: str, prefix: str) -> str | None:
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            txt = rdata.to_text().strip('"')
            if txt.startswith(prefix):
                return txt
    except Exception:
        pass
    return None


# ── DNSBL ─────────────────────────────────────────────────────────────────────

def _check_dnsbls(domain: str, result: dict) -> None:
    if not HAS_DNS:
        return
    for ip in result["dns"].get("a_records", [])[:2]:
        rev = ".".join(reversed(ip.split(".")))
        for dnsbl in DNSBLS:
            try:
                dns.resolver.resolve(f"{rev}.{dnsbl}", "A")
                result["dnsbl"][dnsbl] = f"LISTED (IP: {ip})"
                result["risk_signals"].append(f"CRITICAL:ip_{ip}_listed_on_{dnsbl}")
            except Exception:
                result["dnsbl"][dnsbl] = "not_listed"
