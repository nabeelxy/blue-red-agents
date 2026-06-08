"""
ai_config.py — Dual-mode Google AI credential configuration.

Two authentication modes are supported:

  Mode A — Vertex AI (isr-matrix project members)
    Requires Application Default Credentials (gcloud auth application-default login)
    Set in .env:
        GOOGLE_GENAI_USE_VERTEXAI=1
        GOOGLE_CLOUD_PROJECT=isr-matrix
        GOOGLE_CLOUD_LOCATION=us-central1

  Mode B — Gemini API key (workshop participants)
    Set in .env:
        GOOGLE_API_KEY=your_api_key_here

Usage in any module file:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))  # adjust depth as needed
    from ai_config import get_genai_client, get_embed_model, get_generative_model

This module calls load_dotenv() on import, so callers don't need to.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from google import genai

# Load .env — search in priority order (first match wins for each key):
#   1. Directory of the running script (e.g. m01_rag_agent/ when running create_vector_db.py)
#   2. Project root (next to this file)
#   3. CWD and upward (fallback)
_script_env = Path(sys.argv[0]).resolve().parent / ".env" if sys.argv else None
if _script_env and _script_env.exists():
    load_dotenv(dotenv_path=_script_env)
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=False)
load_dotenv(override=False)

# ── Defaults ──────────────────────────────────────────────────────────────────
_GENERATIVE_MODEL = "gemini-2.5-pro"
_EMBED_MODEL_API  = "gemini-embedding-001"   # Gemini Developer API
_EMBED_MODEL_VTX  = "text-embedding-004"     # Vertex AI
_VERTEX_PROJECT   = "isr-matrix"
_VERTEX_LOCATION  = "us-central1"


def _using_vertex() -> bool:
    return os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("1", "true", "yes")


def get_genai_client() -> genai.Client:
    """
    Return a configured genai.Client for the current auth mode.

    Vertex AI mode:  GOOGLE_GENAI_USE_VERTEXAI=1 (uses Application Default Credentials)
    API key mode:    GOOGLE_API_KEY=your-key
    """
    if _using_vertex():
        project  = os.environ.get("GOOGLE_CLOUD_PROJECT", _VERTEX_PROJECT)
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", _VERTEX_LOCATION)
        return genai.Client(vertexai=True, project=project, location=location)

    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError(
            "\n"
            "No Google AI credentials found. Add ONE of the following to .env:\n\n"
            "  Option A — Vertex AI (isr-matrix project members):\n"
            "    GOOGLE_GENAI_USE_VERTEXAI=1\n"
            "    GOOGLE_CLOUD_PROJECT=isr-matrix\n"
            "    GOOGLE_CLOUD_LOCATION=us-central1\n"
            "    (Also run: gcloud auth application-default login)\n\n"
            "  Option B — API Key (workshop participants):\n"
            "    GOOGLE_API_KEY=your_api_key_here\n"
        )
    return genai.Client(api_key=api_key)


def get_generative_model() -> str:
    """Generative model for content generation tasks."""
    return os.environ.get("GENERATIVE_MODEL", _GENERATIVE_MODEL)


def get_embed_model() -> str:
    """
    Embedding model for vector indexing and search.

    Defaults differ by mode:
      Vertex AI  → text-embedding-004
      API key    → gemini-embedding-001

    Override with EMBED_MODEL= in .env if needed.
    NOTE: The FAISS index must be rebuilt if you change this model.
    """
    if "EMBED_MODEL" in os.environ:
        return os.environ["EMBED_MODEL"]
    return _EMBED_MODEL_VTX if _using_vertex() else _EMBED_MODEL_API


def auth_mode() -> str:
    """Human-readable label for the current auth mode (useful for startup logging)."""
    if _using_vertex():
        project  = os.environ.get("GOOGLE_CLOUD_PROJECT", _VERTEX_PROJECT)
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", _VERTEX_LOCATION)
        return f"Vertex AI  project={project}  location={location}"
    return "Gemini API key"
