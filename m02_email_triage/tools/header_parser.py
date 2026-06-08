"""
header_parser.py — Parse raw email headers into structured security signals.

Extracts sender info, authentication results (SPF/DKIM/DMARC), routing chain,
and detects anomalies like Reply-To mismatches and display name impersonation.
"""

import email
import re
from datetime import datetime, timezone
from email.header import decode_header


TRUSTED_REGISTRARS_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "chase",
    "bank of america", "wells fargo", "irs", "fedex", "usps", "dhl",
    "linkedin", "facebook", "instagram", "twitter", "netflix", "spotify",
]


def parse_email_headers(raw_email: str) -> dict:
    """
    Parse a raw email (RFC 2822 format) and return structured security signals.

    Returns a dict with:
      - subject, date, message_id
      - sender: from_email, from_domain, from_display_name, reply_to, return_path
      - authentication: spf, dkim, dmarc results from Authentication-Results header
      - routing: hop count, originating IP, first/last Received header
      - anomalies: list of detected suspicious patterns
      - risk_signals: prioritised list for the agent
    """
    try:
        msg = email.message_from_string(raw_email)
    except Exception as e:
        return {"error": f"Failed to parse email: {e}"}

    result = {}

    # ── Basic headers ──────────────────────────────────────────────────────────
    result["subject"] = _decode_header_value(msg.get("Subject", ""))
    result["date"] = msg.get("Date", "")
    result["message_id"] = msg.get("Message-ID", "")

    # ── Sender analysis ────────────────────────────────────────────────────────
    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")

    from_display, from_email = _parse_address(from_raw)
    _, reply_to_email = _parse_address(reply_to_raw) if reply_to_raw else ("", "")
    from_domain = from_email.split("@")[1].lower() if "@" in from_email else ""

    result["sender"] = {
        "from_raw": from_raw,
        "from_display_name": from_display,
        "from_email": from_email,
        "from_domain": from_domain,
        "reply_to_email": reply_to_email,
        "return_path": return_path_raw,
    }

    # ── Anomaly detection ──────────────────────────────────────────────────────
    anomalies = []
    risk_signals = []

    # Reply-To mismatch
    if reply_to_email and reply_to_email.lower() != from_email.lower():
        anomalies.append(
            f"Reply-To ({reply_to_email}) differs from From ({from_email}) — "
            "replies will go to a different mailbox than the apparent sender"
        )
        risk_signals.append("reply_to_mismatch")

    # Return-Path domain mismatch
    if return_path_raw and from_domain:
        rp_domain_match = re.search(r"@([^>@\s]+)", return_path_raw)
        if rp_domain_match:
            rp_domain = rp_domain_match.group(1).lower()
            if rp_domain != from_domain:
                anomalies.append(
                    f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})"
                )
                risk_signals.append("return_path_domain_mismatch")

    # Display name impersonation (e.g., "PayPal Security <attacker@evil.com>")
    for brand in TRUSTED_REGISTRARS_BRANDS:
        if brand in from_display.lower() and brand not in from_domain:
            anomalies.append(
                f"Display name impersonation: display name contains '{brand}' "
                f"but email comes from '{from_domain}'"
            )
            risk_signals.append(f"CRITICAL:display_name_impersonation:{brand}")
            break

    # No-reply from unexpected domain
    if "noreply" in from_email.lower() or "no-reply" in from_email.lower():
        if reply_to_email and "@" in reply_to_email:
            reply_domain = reply_to_email.split("@")[1].lower()
            if reply_domain != from_domain:
                anomalies.append(
                    f"No-reply sender with Reply-To on different domain ({reply_domain})"
                )
                risk_signals.append("noreply_with_foreign_reply_to")

    result["anomalies"] = anomalies

    # ── Authentication results ─────────────────────────────────────────────────
    auth_header = msg.get("Authentication-Results", "")
    auth = _parse_auth_results(auth_header)
    result["authentication"] = auth

    if auth["spf"] in ("fail", "softfail"):
        risk_signals.append(f"spf_{auth['spf']}")
    if auth["dkim"] == "fail":
        risk_signals.append("dkim_fail")
    if auth["dmarc"] in ("fail", "none"):
        risk_signals.append(f"dmarc_{auth['dmarc']}")
    if auth["spf"] == "none" and auth["dkim"] == "none":
        risk_signals.append("CRITICAL:no_authentication_at_all")

    # DKIM signature presence (independent check)
    dkim_sig = msg.get("DKIM-Signature", "")
    result["dkim_signature_present"] = bool(dkim_sig)
    if dkim_sig:
        d_match = re.search(r"\bd=([^;]+)", dkim_sig)
        result["dkim_signing_domain"] = d_match.group(1).strip() if d_match else ""
        # DKIM domain alignment check
        if result.get("dkim_signing_domain") and from_domain:
            signing_domain = result["dkim_signing_domain"].lower()
            if not from_domain.endswith(signing_domain) and not signing_domain.endswith(from_domain):
                risk_signals.append(
                    f"dkim_domain_misalignment:{signing_domain}_vs_{from_domain}"
                )

    # ── Routing analysis ───────────────────────────────────────────────────────
    received_headers = msg.get_all("Received", []) or []
    originating_ip = "unknown"
    if received_headers:
        # Oldest Received header is the originating hop
        oldest = received_headers[-1]
        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", oldest)
        if ip_match:
            originating_ip = ip_match.group(1)

    result["routing"] = {
        "hop_count": len(received_headers),
        "originating_ip": originating_ip,
        "first_received": received_headers[-1] if received_headers else "",
        "last_received": received_headers[0] if received_headers else "",
    }

    # Datacenter/hosting IP heuristic (not a residential ISP)
    if originating_ip != "unknown":
        octets = originating_ip.split(".")
        # Known cloud/datacenter ranges (simplified — a real check would use GeoLite ASN)
        known_dc_prefixes = ["104.", "162.", "167.", "185.", "45.33", "23."]
        if any(originating_ip.startswith(p) for p in known_dc_prefixes):
            risk_signals.append(f"originating_ip_likely_datacenter:{originating_ip}")

    # ── Content type ───────────────────────────────────────────────────────────
    is_html = False
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                is_html = True
                break
    elif msg.get_content_type() == "text/html":
        is_html = True
    result["is_html_email"] = is_html

    # ── Summary risk level ─────────────────────────────────────────────────────
    critical = [s for s in risk_signals if s.startswith("CRITICAL:")]
    result["risk_signals"] = risk_signals
    result["risk_level"] = (
        "CRITICAL" if critical
        else "HIGH" if len(risk_signals) >= 3
        else "MEDIUM" if risk_signals
        else "LOW"
    )

    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _decode_header_value(value: str) -> str:
    parts = []
    for chunk, charset in decode_header(value):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return " ".join(parts)


def _parse_address(header_value: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a From/To header value."""
    header_value = header_value.strip()
    match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', header_value)
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    email_match = re.search(r"[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,}", header_value)
    if email_match:
        return "", email_match.group(0).lower()
    return "", header_value.lower()


def _parse_auth_results(auth_header: str) -> dict:
    """Extract SPF/DKIM/DMARC pass/fail results from Authentication-Results header."""
    result = {
        "raw": auth_header,
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "reporting_mta": "",
    }
    if not auth_header:
        return result

    for field in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{field}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            result[field] = match.group(1).lower()

    mta_match = re.match(r"^([^\s;]+)", auth_header)
    if mta_match:
        result["reporting_mta"] = mta_match.group(1)

    return result
