"""
AI Copilot — hybrid LLM service voor de SOC Security Orchestrator.

Routing:
  risk_score < 70  → Ollama (lokaal, Mistral 7B)  — snelle realtime analyse
  risk_score >= 70 → Claude API (claude-sonnet-4-20250514) — diepgaande threat reports

Capabilities:
  - Alert analyse
  - Threat actor profiel samenvatting
  - FBI evidence rapport generatie
  - Vrije SOC chat (Q&A)
"""
