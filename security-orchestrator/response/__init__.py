"""
Response Engine — geautomatiseerde incident response voor de SOC Orchestrator.

Tiers op basis van risk score:
  risk >= 90  → IP blokkeren (CrowdSec) + email alert
  risk >= 70  → email + webhook alert + account flaggen voor review
  risk >= 50  → webhook alert + audit log
  < 50        → alleen audit log

Speciale regel:
  account_takeover detected → account lock + critical alert (ongeacht score)

Alle acties worden gelogd in een immutable, append-only audit trail (PostgreSQL).
"""
