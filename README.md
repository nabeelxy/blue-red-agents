# Blue and Red Teaming Agents

A hands-on training program for the M3AAWG community demonstrating how AI tools are already being used by attackers — and the authentication-first defenses that work against them. Each module pairs an attack demo with a corresponding defense agent, all grounded in M3AAWG Best Common Practices.


---

## Repo Configuration

All modules share a single `ai_config.py` at the project root that handles credential loading. Two auth modes are supported — set one per module `.env` file:

**Option A — Vertex AI**
```
GOOGLE_GENAI_USE_VERTEXAI=1
GOOGLE_CLOUD_PROJECT=<project-name>
GOOGLE_CLOUD_LOCATION=<location>
```
Also requires: `gcloud auth application-default login`

**Option B — Gemini API key**
```
GOOGLE_API_KEY=your_api_key_here
```

Each module directory contains its own `.env` and `requirements.txt`. Install dependencies per module:
```bash
cd m0X_<module>
pip install -r requirements.txt
```

All ADK agents are run with:
```bash
adk web    # browser UI at http://localhost:8000
adk run agent  # terminal REPL
```

---

## Modules

### M01 — M3AAWG Knowledge Base & Compliance Agent

A RAG agent over M3AAWG Best Common Practices documents and IETF RFCs. Given a sender domain, email scenario, or security question, it returns a structured compliance report with specific BCP citations.

The knowledge base covers M3AAWG sender, authentication, DMARC, phishing, and AI-abuse BCPs alongside the SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489), ARC (RFC 8617), MTA-STS (RFC 8461), and one-click unsubscribe (RFC 8058) specifications.

Build the FAISS vector index once before use:
```bash
cd m01_rag_agent
python create_vector_db.py
```

**Role in session:** Act 2, Defense 1 — pivots from the Agent-as-Spammer demo by evaluating the same attacker-chosen domains against the BCP rubric.

---

### M02 — Email Triage Agent

A five-step triage agent that analyses raw email for phishing, BEC, and authentication failures. Detection is authentication-first — it catches AI-generated phishing via infrastructure signals rather than content or grammar.

The agent calls two MCP servers in sequence: one for email-specific tools (header parsing, URL extraction, domain reputation via WHOIS/DNSBL, Gemini Vision screenshot analysis) and one for M3AAWG BCP lookups from M01.

This module also contains the phishing generator attack demo (`attacks/phishing_generator.py`) that produces personalized spear-phishing emails used in Act 1 Demo 1.

**Role in session:** Act 1 Demo 1 (phishing generator attack) → Act 2 Defense 2 (triage agent defense).

---

### M03 — Prompt Injection via Email

Demonstrates a novel attack surface that exists because organisations deploy AI assistants to process email: the email body itself can hijack those assistants.

**Attack** (`attack/demo.py`): five injection techniques run against a naive processor — CSS white text, HTML comments, zero-width Unicode characters, subject header injection, and leetspeak obfuscation. Each instructs the AI to exfiltrate inbox contents.

**Defense** (`defense/demo.py`): a seven-layer hardened pipeline catches all five payloads — HTML stripping, Unicode normalisation, regex pattern detection, a hardened system prompt with explicit trust boundaries, output validation, and action gating for irreversible operations.

**Role in session:** Act 1 Demo 2 (attack) → Act 2 Defense 3 (hardened pipeline).

---

### M04 — Agent-as-Spammer

An LLM agent that automates bulk spam sender setup: generating plausible fake company identities, probing sending domains for weak authentication posture (SPF, DMARC, blocklist status), and computing campaign cost economics.

The core argument: AI collapses the cost of spam infrastructure by ~30x, enabling lower-volume, higher-precision targeting that evades traditional volume-based filters. The defense is DMARC enforcement — a three-day-old domain with no signing history is rejected at the authentication layer regardless of content quality.

**Role in session:** Act 1 Demo 3 — transitions directly into Act 2 Defense 1 (M01 compliance agent) by re-evaluating the same probed domains.
