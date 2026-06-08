"""
create_vector_db.py — Build the FAISS vector index from M3AAWG documents.

Run once after fetch_docs.py (or directly — seed docs are included):
    python create_vector_db.py

Produces:
    m3aawg_rag_index.faiss  — FAISS flat L2 index
    m3aawg_chunks.json      — chunk text + metadata

Uses Google embedding models. Supports Vertex AI (isr-matrix) and API key modes.
See ../.env.example for configuration.
"""

import sys
import json
import time
import numpy as np
import faiss
from pathlib import Path
from langchain_text_splitters import RecursiveCharacterTextSplitter

sys.path.insert(0, str(Path(__file__).parent.parent))
from ai_config import get_genai_client, get_embed_model, auth_mode

DOCS_DIR    = Path(__file__).parent / "docs"
INDEX_PATH  = Path(__file__).parent / "m3aawg_rag_index.faiss"
CHUNKS_PATH = Path(__file__).parent / "m3aawg_chunks.json"

CHUNK_SIZE    = 1200
CHUNK_OVERLAP = 300
BATCH_SIZE    = 20   # Gemini embedding API batch limit


# ---------------------------------------------------------------------------
# Friendly source name from filename stem
# ---------------------------------------------------------------------------
SOURCE_LABELS = {
    "m3aawg_sender_bcp":             "M3AAWG Sender Best Common Practices",
    "m3aawg_sender_bcp_official":    "M3AAWG Sender BCP (Official)",
    "m3aawg_email_auth_bcp":         "M3AAWG Email Authentication BCP",
    "m3aawg_email_auth_official":    "M3AAWG Email Authentication BCP (Official)",
    "m3aawg_dmarc_bcp":              "M3AAWG DMARC Best Common Practices",
    "m3aawg_dmarc_guide_official":   "M3AAWG Practical Guide to DMARC (Official)",
    "m3aawg_compromised_account_bcp": "M3AAWG Compromised User Remediation BCP",
    "m3aawg_compromised_user_official": "M3AAWG Compromised User Remediation (Official)",
    "m3aawg_phishing_abuse_bcp":     "M3AAWG Anti-Phishing and Abuse Handling BCP",
    "m3aawg_messaging_bcp":          "M3AAWG Messaging Best Common Practices",
    "m3aawg_messaging_bcp_official": "M3AAWG Messaging BCP (Official)",
    "m3aawg_ai_abuse_bcp":           "M3AAWG AI-Enabled Abuse and Defensive AI Practices",
    "rfc7208_spf":                   "RFC 7208 — Sender Policy Framework (SPF)",
    "rfc6376_dkim":                  "RFC 6376 — DomainKeys Identified Mail (DKIM)",
    "rfc7489_dmarc":                 "RFC 7489 — DMARC",
    "rfc8617_arc":                   "RFC 8617 — Authenticated Received Chain (ARC)",
    "rfc8461_mta_sts":               "RFC 8461 — MTA-STS",
    "rfc8058_list_unsubscribe":      "RFC 8058 — One-Click List Unsubscribe",
}


def load_documents() -> list[dict]:
    documents = []
    for filepath in sorted(DOCS_DIR.rglob("*.txt")):
        content = filepath.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            continue
        stem = filepath.stem
        label = SOURCE_LABELS.get(stem, stem.replace("_", " ").title())
        documents.append({
            "source": stem,
            "label": label,
            "filepath": str(filepath),
            "content": content,
        })
        print(f"  {label}  ({len(content):,} chars)")
    return documents


def chunk_documents(documents: list[dict]) -> list[dict]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks = []
    for doc in documents:
        splits = splitter.split_text(doc["content"])
        for i, text in enumerate(splits):
            chunks.append({
                "text": text,
                "source": doc["source"],
                "label": doc["label"],
                "chunk_index": i,
                "total_chunks": len(splits),
            })
    return chunks


def embed_chunks(chunks: list[dict]) -> np.ndarray:
    client = get_genai_client()
    embed_model = get_embed_model()
    all_embeddings: list[list[float]] = []

    for batch_start in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[batch_start : batch_start + BATCH_SIZE]
        texts = [c["text"] for c in batch]

        # Retry once on transient error
        for attempt in range(2):
            try:
                result = client.models.embed_content(
                    model=embed_model,
                    contents=texts,
                )
                all_embeddings.extend(e.values for e in result.embeddings)
                break
            except Exception as e:
                if attempt == 0:
                    print(f"  Embedding error (retry): {e}")
                    time.sleep(3)
                else:
                    raise

        done = min(batch_start + BATCH_SIZE, len(chunks))
        print(f"  Embedded {done}/{len(chunks)} chunks...")

    return np.array(all_embeddings, dtype="float32")


def build_and_save(chunks: list[dict], embeddings: np.ndarray) -> None:
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)

    faiss.write_index(index, str(INDEX_PATH))
    CHUNKS_PATH.write_text(json.dumps(chunks, indent=2), encoding="utf-8")

    print(f"\n  Index:  {INDEX_PATH}  ({index.ntotal} vectors, dim={dim})")
    print(f"  Chunks: {CHUNKS_PATH}  ({len(chunks)} entries)")


def main():
    print("=== M3AAWG Knowledge Base Builder ===")
    print(f"  Auth:  {auth_mode()}")
    print(f"  Model: {get_embed_model()}")
    print()

    print("Step 1: Loading documents from docs/")
    docs = load_documents()
    if not docs:
        print(f"\nERROR: No .txt files found in {DOCS_DIR}")
        print("  Seed docs should already be present. Check the docs/ directory.")
        raise SystemExit(1)
    print(f"\n  Loaded {len(docs)} documents\n")

    print("Step 2: Chunking documents")
    chunks = chunk_documents(docs)
    print(f"  {len(chunks)} chunks  (size={CHUNK_SIZE}, overlap={CHUNK_OVERLAP})\n")

    print("Step 3: Embedding chunks with gemini-embedding-001")
    embeddings = embed_chunks(chunks)
    print()

    print("Step 4: Building and saving FAISS index")
    build_and_save(chunks, embeddings)

    print("\nDone. Next step:")
    print("  adk web          — launch the agent in the browser UI")
    print("  python agent.py  — run the agent interactively")


if __name__ == "__main__":
    main()
