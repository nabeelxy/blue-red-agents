"""
server.py — MCP server exposing the M3AAWG knowledge base as tools.

Started automatically by the agent via StdioConnectionParams.
Can also be tested standalone:
    echo '{"method":"tools/list"}' | python server.py
"""

import sys
import json
import numpy as np
import faiss
from pathlib import Path
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent.parent))
from ai_config import get_genai_client, get_embed_model, auth_mode

INDEX_PATH  = Path(__file__).parent / "m3aawg_rag_index.faiss"
CHUNKS_PATH = Path(__file__).parent / "m3aawg_chunks.json"

mcp = FastMCP("M3AAWG Knowledge Base")

# Lazy-loaded singletons
_index: faiss.Index | None = None
_chunks: list[dict] | None = None


def _load() -> tuple[faiss.Index, list[dict]]:
    global _index, _chunks
    if _index is None:
        if not INDEX_PATH.exists():
            raise FileNotFoundError(
                f"Index not found at {INDEX_PATH}. "
                "Run: python create_vector_db.py"
            )
        _index = faiss.read_index(str(INDEX_PATH))
        _chunks = json.loads(CHUNKS_PATH.read_text(encoding="utf-8"))
    return _index, _chunks


def _embed(text: str) -> np.ndarray:
    client = get_genai_client()
    result = client.models.embed_content(
        model=get_embed_model(),
        contents=[text],
    )
    return np.array(result.embeddings[0].values, dtype="float32")


@mcp.tool()
def query_m3aawg_bcp(query: str, top_k: int = 6) -> str:
    """
    Search the M3AAWG Best Common Practices knowledge base.

    Use this to find authoritative M3AAWG guidance on:
    - Email authentication: SPF, DKIM, DMARC, BIMI, ARC
    - Sender best practices: consent, list hygiene, unsubscribe, bounce handling
    - Abuse handling: complaint feedback loops, phishing response, blocklists
    - Compromised account detection and remediation
    - Platform infrastructure security (MTA configuration, port 25, TLS)
    - Regulatory compliance: CAN-SPAM, CASL, GDPR, TCPA
    - AI-enabled attacks and defensive AI practices
    - Industry cooperation and coordinated abuse response

    Args:
        query: Topic or question to search for in M3AAWG best practices.
               Be specific — e.g. "DMARC p=reject deployment" rather than "email security".
        top_k: Number of relevant passages to return (default 6, max 10).

    Returns:
        JSON array of the most relevant passages, each with:
          - rank: relevance rank (1 = most relevant)
          - relevance_score: float 0-1
          - source: document identifier
          - label: human-readable document name
          - text: the passage text
    """
    top_k = min(top_k, 10)
    index, chunks = _load()

    query_vec = _embed(query)
    distances, indices = index.search(np.array([query_vec]), top_k)

    results = []
    for rank, (dist, idx) in enumerate(zip(distances[0], indices[0])):
        if 0 <= idx < len(chunks):
            chunk = chunks[idx]
            results.append({
                "rank": rank + 1,
                "relevance_score": round(float(1.0 / (1.0 + dist)), 4),
                "source": chunk.get("source", ""),
                "label": chunk.get("label", ""),
                "text": chunk.get("text", ""),
            })

    return json.dumps(results, indent=2)


@mcp.tool()
def list_m3aawg_documents() -> str:
    """
    List all M3AAWG documents currently in the knowledge base.

    Use this at the start of an investigation to understand what sources
    are available before querying for specific topics.

    Returns:
        JSON array of available documents with source ID, label, and chunk count.
    """
    _, chunks = _load()

    sources: dict[str, dict] = {}
    for chunk in chunks:
        src = chunk.get("source", "unknown")
        if src not in sources:
            sources[src] = {
                "source": src,
                "label": chunk.get("label", src),
                "chunks": 0,
            }
        sources[src]["chunks"] += 1

    return json.dumps(sorted(sources.values(), key=lambda x: x["label"]), indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
