"""
fetch_docs.py — Download M3AAWG public publications and key RFCs into docs/.

Run once before building the vector index:
    python fetch_docs.py

Sources:
  - M3AAWG public PDFs (m3aawg.org)
  - IETF RFCs: SPF (7208), DKIM (6376), DMARC (7489), ARC (8617), MTA-STS (8461)

If a PDF download fails (network issues, URL changes), the seed docs already
in docs/*.txt are sufficient to build a working index. This script adds
supplementary depth from the primary source documents.
"""

import os
import sys
import time
import requests
from pathlib import Path

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

DOCS_DIR = Path(__file__).parent / "docs"
DOCS_DIR.mkdir(exist_ok=True)
(DOCS_DIR / "rfcs").mkdir(exist_ok=True)

TIMEOUT = 30
RETRY_DELAY = 2

# ---------------------------------------------------------------------------
# M3AAWG public documents
# These are freely available on m3aawg.org without login.
# ---------------------------------------------------------------------------
M3AAWG_DOCS = [
    {
        "url": "https://www.m3aawg.org/sites/default/files/m3aawg-sender-best-common-practices-2015-12.pdf",
        "filename": "docs/m3aawg_sender_bcp_official.txt",
        "description": "M3AAWG Sender Best Common Practices (official PDF)",
    },
    {
        "url": "https://www.m3aawg.org/sites/default/files/m3aawg-email-authentication-recommended-best-practices-09-2020.pdf",
        "filename": "docs/m3aawg_email_auth_official.txt",
        "description": "M3AAWG Email Authentication Recommended Best Practices (official PDF)",
    },
    {
        "url": "https://www.m3aawg.org/sites/default/files/m3aawg-practical-guide-dmarc-2015-10.pdf",
        "filename": "docs/m3aawg_dmarc_guide_official.txt",
        "description": "M3AAWG Practical Guide to DMARC (official PDF)",
    },
    {
        "url": "https://www.m3aawg.org/sites/default/files/m3aawg-compromised-user-remediation-2020-04.pdf",
        "filename": "docs/m3aawg_compromised_user_official.txt",
        "description": "M3AAWG Compromised User Remediation Best Practices (official PDF)",
    },
    {
        "url": "https://www.m3aawg.org/sites/default/files/m3aawg-messaging-best-common-practices-full-version-2015-09.pdf",
        "filename": "docs/m3aawg_messaging_bcp_official.txt",
        "description": "M3AAWG Messaging Best Common Practices (official PDF)",
    },
]

# ---------------------------------------------------------------------------
# IETF RFCs (plain text versions — stable URLs, no PDF conversion needed)
# ---------------------------------------------------------------------------
RFC_DOCS = [
    {
        "url": "https://www.rfc-editor.org/rfc/rfc7208.txt",
        "filename": "docs/rfcs/rfc7208_spf.txt",
        "description": "RFC 7208 — Sender Policy Framework (SPF)",
    },
    {
        "url": "https://www.rfc-editor.org/rfc/rfc6376.txt",
        "filename": "docs/rfcs/rfc6376_dkim.txt",
        "description": "RFC 6376 — DomainKeys Identified Mail (DKIM)",
    },
    {
        "url": "https://www.rfc-editor.org/rfc/rfc7489.txt",
        "filename": "docs/rfcs/rfc7489_dmarc.txt",
        "description": "RFC 7489 — DMARC",
    },
    {
        "url": "https://www.rfc-editor.org/rfc/rfc8617.txt",
        "filename": "docs/rfcs/rfc8617_arc.txt",
        "description": "RFC 8617 — Authenticated Received Chain (ARC)",
    },
    {
        "url": "https://www.rfc-editor.org/rfc/rfc8461.txt",
        "filename": "docs/rfcs/rfc8461_mta_sts.txt",
        "description": "RFC 8461 — SMTP MTA Strict Transport Security (MTA-STS)",
    },
    {
        "url": "https://www.rfc-editor.org/rfc/rfc8058.txt",
        "filename": "docs/rfcs/rfc8058_list_unsubscribe.txt",
        "description": "RFC 8058 — Signaling One-Click Functionality for List Unsubscribe",
    },
]


def fetch_url(url: str, retries: int = 2) -> bytes | None:
    headers = {
        "User-Agent": "M3AAWG-Training-KB-Builder/1.0 (educational use)"
    }
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except requests.RequestException as e:
            if attempt < retries:
                print(f"    Retry {attempt + 1}/{retries}: {e}")
                time.sleep(RETRY_DELAY)
            else:
                print(f"    FAILED: {e}")
    return None


def pdf_to_text(pdf_bytes: bytes) -> str:
    if not HAS_PYPDF:
        raise RuntimeError(
            "pypdf not installed. Run: pip install pypdf"
        )
    import io
    reader = PdfReader(io.BytesIO(pdf_bytes))
    pages = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages.append(text)
    return "\n\n".join(pages)


def download_m3aawg_docs():
    print("\n=== Downloading M3AAWG Publications ===")
    if not HAS_PYPDF:
        print("WARNING: pypdf not installed. PDF conversion will fail.")
        print("         Install with: pip install pypdf")
        print("         Seed docs in docs/*.txt will still be used.\n")

    ok, skipped, failed = 0, 0, 0
    for doc in M3AAWG_DOCS:
        dest = DOCS_DIR.parent / doc["filename"]
        if dest.exists():
            print(f"  [skip] {dest.name} (already exists)")
            skipped += 1
            continue

        print(f"  Fetching: {doc['description']}")
        print(f"    URL: {doc['url']}")
        data = fetch_url(doc["url"])
        if data is None:
            failed += 1
            continue

        try:
            text = pdf_to_text(data)
            dest.write_text(text, encoding="utf-8")
            print(f"    OK — {len(text):,} chars → {dest.name}")
            ok += 1
        except Exception as e:
            print(f"    PDF conversion failed: {e}")
            failed += 1

    return ok, skipped, failed


def download_rfcs():
    print("\n=== Downloading IETF RFCs ===")
    ok, skipped, failed = 0, 0, 0
    for doc in RFC_DOCS:
        dest = DOCS_DIR.parent / doc["filename"]
        if dest.exists():
            print(f"  [skip] {dest.name} (already exists)")
            skipped += 1
            continue

        print(f"  Fetching: {doc['description']}")
        data = fetch_url(doc["url"])
        if data is None:
            failed += 1
            continue

        try:
            text = data.decode("utf-8", errors="replace")
            dest.write_text(text, encoding="utf-8")
            print(f"    OK — {len(text):,} chars → {dest.name}")
            ok += 1
        except Exception as e:
            print(f"    Save failed: {e}")
            failed += 1

    return ok, skipped, failed


def main():
    print("M3AAWG Knowledge Base — Document Fetcher")
    print("=========================================")
    print(f"Output directory: {DOCS_DIR}\n")

    # Check existing seed docs
    seed_docs = list(DOCS_DIR.glob("*.txt"))
    print(f"Existing seed documents: {len(seed_docs)} files")
    for f in sorted(seed_docs):
        print(f"  {f.name} ({f.stat().st_size:,} bytes)")

    m_ok, m_skip, m_fail = download_m3aawg_docs()
    r_ok, r_skip, r_fail = download_rfcs()

    total_ok = m_ok + r_ok
    total_fail = m_fail + r_fail

    print("\n=== Summary ===")
    print(f"  M3AAWG docs:  {m_ok} downloaded, {m_skip} skipped, {m_fail} failed")
    print(f"  RFCs:         {r_ok} downloaded, {r_skip} skipped, {r_fail} failed")

    all_docs = list(DOCS_DIR.rglob("*.txt"))
    total_chars = sum(f.stat().st_size for f in all_docs)
    print(f"\n  Total documents: {len(all_docs)} files ({total_chars:,} bytes)")

    if total_fail > 0:
        print(f"\nNOTE: {total_fail} downloads failed.")
        print("  The seed docs in docs/*.txt will still be indexed.")
        print("  Re-run this script when network access is available.")

    print("\nNext step: python create_vector_db.py")


if __name__ == "__main__":
    main()
