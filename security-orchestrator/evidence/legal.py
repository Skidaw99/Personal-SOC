"""
Legal References — wettelijk kader voor evidence rapporten.

Bevat relevante wetsartikelen gegroepeerd per jurisdictie (US/EU)
en gemapped naar incident typen. De Evidence Builder selecteert
automatisch de van toepassing zijnde statuten.
"""
from __future__ import annotations

from .schemas import LegalReference


# ── US Federal statuten ──────────────────────────────────────────────────────

_CFAA = LegalReference(
    jurisdiction="US",
    statute="18 U.S.C. § 1030",
    name="Computer Fraud and Abuse Act (CFAA)",
    section=None,
    relevance="",
)

_CFAA_SECTIONS: dict[str, LegalReference] = {
    "unauthorized_access": LegalReference(
        jurisdiction="US",
        statute="18 U.S.C. § 1030(a)(2)",
        name="CFAA — Unauthorized Access to Protected Computer",
        section="(a)(2)",
        relevance=(
            "Intentionally accessing a protected computer without authorization "
            "and obtaining information. Applies to unauthorized login, "
            "credential stuffing, and account takeover incidents."
        ),
    ),
    "damage": LegalReference(
        jurisdiction="US",
        statute="18 U.S.C. § 1030(a)(5)",
        name="CFAA — Causing Damage to Protected Computer",
        section="(a)(5)",
        relevance=(
            "Knowingly causing the transmission of a program, code, or command "
            "that intentionally causes damage to a protected computer. "
            "Applies to malware, ransomware, and destructive attack incidents."
        ),
    ),
    "extortion": LegalReference(
        jurisdiction="US",
        statute="18 U.S.C. § 1030(a)(7)",
        name="CFAA — Extortion via Threat to Protected Computer",
        section="(a)(7)",
        relevance=(
            "Threatening to damage a protected computer or obtain/release "
            "information to extort money or other value. "
            "Applies to ransomware and data exfiltration with extortion."
        ),
    ),
    "fraud": LegalReference(
        jurisdiction="US",
        statute="18 U.S.C. § 1030(a)(4)",
        name="CFAA — Computer Fraud",
        section="(a)(4)",
        relevance=(
            "Knowingly accessing a protected computer with intent to defraud "
            "and obtaining anything of value. Applies to credential fraud, "
            "API abuse, and financially motivated attacks."
        ),
    ),
    "identity_theft": LegalReference(
        jurisdiction="US",
        statute="18 U.S.C. § 1028A",
        name="Aggravated Identity Theft",
        relevance=(
            "Using means of identification of another person during and in "
            "relation to a felony. Applies when stolen credentials are used "
            "to impersonate victims."
        ),
    ),
    "wire_fraud": LegalReference(
        jurisdiction="US",
        statute="18 U.S.C. § 1343",
        name="Wire Fraud",
        relevance=(
            "Using wire communications (internet) in furtherance of a scheme "
            "to defraud. Broad applicability to cyber-enabled fraud, phishing, "
            "and social engineering attacks."
        ),
    ),
}

# ── EU Directives ────────────────────────────────────────────────────────────

_NIS2 = LegalReference(
    jurisdiction="EU",
    statute="Directive (EU) 2022/2555",
    name="NIS2 Directive",
    relevance=(
        "EU Network and Information Security Directive 2 — establishes "
        "cybersecurity risk management and incident reporting obligations "
        "for essential and important entities. Requires notification to "
        "competent authorities within 24 hours (early warning) and 72 hours "
        "(full incident notification)."
    ),
)

_GDPR_BREACH = LegalReference(
    jurisdiction="EU",
    statute="Regulation (EU) 2016/679, Art. 33-34",
    name="GDPR — Personal Data Breach Notification",
    relevance=(
        "When a security incident involves personal data, GDPR requires "
        "notification to the supervisory authority within 72 hours (Art. 33) "
        "and, if high risk, to the affected data subjects (Art. 34)."
    ),
)

_CYBERCRIME_CONVENTION = LegalReference(
    jurisdiction="International",
    statute="Budapest Convention on Cybercrime (ETS No. 185)",
    name="Council of Europe Convention on Cybercrime",
    relevance=(
        "International treaty on computer crime providing a framework for "
        "mutual legal assistance between signatory countries. Relevant for "
        "cross-border investigations involving multiple jurisdictions."
    ),
)


# ── Mapping: incident type → relevante wetsartikelen ─────────────────────────

_INCIDENT_TYPE_MAP: dict[str, list[str]] = {
    "brute_force":          ["unauthorized_access"],
    "credential_stuffing":  ["unauthorized_access", "fraud"],
    "account_takeover":     ["unauthorized_access", "identity_theft"],
    "unauthorized_login":   ["unauthorized_access"],
    "mfa_bypass":           ["unauthorized_access"],
    "exploit_attempt":      ["damage", "unauthorized_access"],
    "c2_communication":     ["damage"],
    "data_exfiltration":    ["unauthorized_access", "wire_fraud"],
    "port_scan":            ["unauthorized_access"],
    "api_abuse":            ["fraud", "unauthorized_access"],
    "social_engineering":   ["wire_fraud", "identity_theft"],
    "suspicious_activity":  ["unauthorized_access"],
    "anomaly":              [],
}


def get_legal_references(incident_type: str) -> list[LegalReference]:
    """
    Retourneer de relevante wetsartikelen voor een incident type.

    Bevat altijd de CFAA basis, NIS2, en GDPR breach notification.
    Voegt incident-specifieke CFAA secties en andere statuten toe
    op basis van het incident type.
    """
    refs: list[LegalReference] = []

    # Altijd de CFAA basis referentie
    refs.append(_CFAA)

    # Incident-specifieke CFAA secties
    section_keys = _INCIDENT_TYPE_MAP.get(incident_type, ["unauthorized_access"])
    for key in section_keys:
        if key in _CFAA_SECTIONS:
            refs.append(_CFAA_SECTIONS[key])

    # Altijd EU NIS2 en GDPR
    refs.append(_NIS2)
    refs.append(_GDPR_BREACH)

    # Internationaal verdrag
    refs.append(_CYBERCRIME_CONVENTION)

    return refs
