"""
url_extractor.py — Extract and analyse URLs from email body (HTML + plain text).

Detects: link text vs href mismatches, brand impersonation in URLs,
URL shorteners, IP-address hosts, and redirect chains.
"""

import email
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, unquote


# Brands mapped to their legitimate root domains
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "netflix": "netflix.com",
    "spotify": "spotify.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "irs": "irs.gov",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.link", "tiny.cc", "rebrand.ly", "is.gd",
    "cutt.ly", "shorte.st", "adf.ly",
}

# High-risk TLDs frequently abused for phishing
RISKY_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".work", ".click"}


class _LinkExtractor(HTMLParser):
    """Extract <a href> links from HTML with their visible link text."""

    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self._in_anchor = False
        self._current_href = ""
        self._current_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._in_anchor = True
            self._current_href = dict(attrs).get("href", "")
            self._current_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._in_anchor:
            text = "".join(self._current_text).strip()
            self.links.append({"href": self._current_href, "text": text})
            self._in_anchor = False
            self._current_href = ""
            self._current_text = []

    def handle_data(self, data):
        if self._in_anchor:
            self._current_text.append(data)


def extract_urls_from_email(raw_email: str) -> dict:
    """
    Extract all URLs from an email's HTML and plain-text body parts.

    Returns:
      - total_urls: count of unique URLs found
      - high_risk_count: URLs with 2+ suspicious signals
      - urls: list of URL objects with domain, link_text, suspicious_signals, risk level
    """
    try:
        msg = email.message_from_string(raw_email)
    except Exception as e:
        return {"error": str(e), "urls": []}

    html_body, text_body = _extract_bodies(msg)

    links: list[dict] = []

    # Structured extraction from HTML anchor tags
    if html_body:
        parser = _LinkExtractor()
        try:
            parser.feed(html_body)
            links.extend(parser.links)
        except Exception:
            pass

    # Bare URL extraction from plain text
    for url in re.findall(r"https?://[^\s<>\"']+", text_body):
        if not any(lnk["href"] == url for lnk in links):
            links.append({"href": url, "text": url})

    # Also catch bare URLs in HTML that aren't inside <a> tags
    for url in re.findall(r"https?://[^\s<>\"']+", html_body):
        if not any(lnk["href"] == url for lnk in links):
            links.append({"href": url, "text": url})

    analyzed = [_analyse_url(lnk) for lnk in links]

    return {
        "total_urls": len(analyzed),
        "high_risk_count": sum(1 for u in analyzed if u["risk"] == "high"),
        "urls": analyzed,
    }


def _extract_bodies(msg) -> tuple[str, str]:
    html_body = ""
    text_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            decoded = payload.decode("utf-8", errors="replace")
            if ct == "text/html":
                html_body += decoded
            elif ct == "text/plain":
                text_body += decoded
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_body = decoded
            else:
                text_body = decoded
    return html_body, text_body


def _analyse_url(link: dict) -> dict:
    href = link.get("href", "")
    link_text = link.get("text", "")

    try:
        parsed = urlparse(href)
        domain = parsed.netloc.lower().split(":")[0]  # strip port
    except Exception:
        domain = ""

    signals: list[str] = []

    # Link text vs href mismatch (visible text looks like a URL but goes elsewhere)
    text_url_match = re.search(r"https?://([^/\s]+)", link_text)
    if text_url_match:
        text_domain = text_url_match.group(1).lower()
        if domain and text_domain != domain:
            signals.append(f"link_text_mismatch:text_shows_{text_domain}_href_goes_{domain}")

    # URL shortener
    if any(domain == s or domain.endswith("." + s) for s in URL_SHORTENERS):
        signals.append("url_shortener:destination_hidden")

    # IP address as host
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain):
        signals.append("CRITICAL:ip_address_host_not_domain")

    # High-risk TLD
    for tld in RISKY_TLDS:
        if domain.endswith(tld):
            signals.append(f"high_risk_tld:{tld}")
            break

    # Excessive subdomains (e.g., paypal.com.login.evil.xyz)
    if domain.count(".") >= 4:
        signals.append("excessive_subdomains:possible_domain_confusion")

    # Brand name in URL but not the real brand domain
    for brand, real_domain in BRAND_DOMAINS.items():
        if brand in domain and not (
            domain == real_domain or domain.endswith("." + real_domain)
        ):
            signals.append(f"CRITICAL:brand_impersonation:{brand}_not_on_{real_domain}")
            break

    # Redirect patterns in query string
    if any(k in href.lower() for k in ["redirect=", "url=", "link=", "goto=", "return="]):
        signals.append("open_redirect_pattern")

    # URL-encoded characters (obfuscation)
    if "%" in href and any(c in href for c in ["%40", "%2F", "%3A", "%2E"]):
        signals.append("url_encoding_obfuscation")

    # Domain registered-looking lookalike (hyphens + brand)
    hyphen_brand = re.search(r"([a-z]+-[a-z]+\.(com|net|org|io))", domain)
    if hyphen_brand:
        for brand in BRAND_DOMAINS:
            if brand in domain and "-" in domain:
                signals.append(f"hyphenated_brand_lookalike:{domain}")
                break

    critical = [s for s in signals if s.startswith("CRITICAL:")]
    return {
        "url": href,
        "domain": domain,
        "link_text": link_text,
        "suspicious_signals": signals,
        "risk": "high" if (critical or len(signals) >= 2) else "medium" if signals else "low",
    }
