"""
Device Fingerprint — extractie, normalisatie en similarity scoring.

Een fingerprint is een gestandaardiseerde representatie van de kenmerken
van een HTTP client: browser, OS, device type, taal, headers.

Twee fingerprints worden vergeleken met een weighted similarity score (0.0–1.0):
  1.0  = identieke fingerprints (exact hash match, score 85 in matcher)
  0.7+ = zelfde browser-familie + OS (partial match, score 45)
  0.4+ = zelfde device-type (weak signal)
  <0.4 = geen meaningful overlap

Afhankelijkheden
────────────────
- `user-agents` package voor UA parsing (pip install user-agents)
  Als het package ontbreekt worden UA-velden op None gezet — geen crash.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import user_agents as _ua_lib
    _UA_AVAILABLE = True
except ImportError:
    _UA_AVAILABLE = False
    logger.warning("user-agents package not installed — UA parsing disabled")


# ── DeviceFingerprint dataclass ────────────────────────────────────────────────

@dataclass
class DeviceFingerprint:
    """
    Normalized device fingerprint.

    fingerprint_hash: SHA-256 of the canonical tuple used for exact DB matching.
    All other fields are stored separately for partial matching and display.
    """

    # Raw
    user_agent_raw: Optional[str] = None
    accept_language: Optional[str] = None

    # Parsed UA components
    browser_family: Optional[str] = None       # e.g. "Chrome", "Firefox", "python-requests"
    browser_version_major: Optional[int] = None
    os_family: Optional[str] = None            # e.g. "Windows", "Linux", "Android"
    os_version_major: Optional[int] = None
    device_type: Optional[str] = None          # "desktop" | "mobile" | "tablet" | "bot"

    # Additional headers that contribute to fingerprinting
    extra_headers: dict[str, str] = field(default_factory=dict)

    # Computed hash (set by extract() or compute_hash())
    fingerprint_hash: str = ""

    # ── Derived properties ─────────────────────────────────────────────────────

    @property
    def is_bot(self) -> bool:
        return self.device_type == "bot"

    @property
    def canonical_tuple(self) -> tuple:
        """
        Stable, normalized tuple used to compute fingerprint_hash.
        Lowercase everything to avoid case-sensitivity noise.
        """
        return (
            (self.browser_family or "").lower(),
            str(self.browser_version_major or ""),
            (self.os_family or "").lower(),
            str(self.os_version_major or ""),
            (self.device_type or "").lower(),
            _normalize_lang(self.accept_language),
        )

    def compute_hash(self) -> str:
        """Compute and store the SHA-256 fingerprint hash."""
        raw = "|".join(self.canonical_tuple)
        self.fingerprint_hash = hashlib.sha256(raw.encode()).hexdigest()
        return self.fingerprint_hash


# ── Extractor ─────────────────────────────────────────────────────────────────

def extract(
    user_agent: Optional[str],
    accept_language: Optional[str] = None,
    extra_headers: Optional[dict[str, str]] = None,
) -> DeviceFingerprint:
    """
    Build a DeviceFingerprint from raw HTTP client data.

    Always returns a valid DeviceFingerprint — even if all inputs are None
    (produces an empty fingerprint with a stable hash of empty fields).
    """
    fp = DeviceFingerprint(
        user_agent_raw=user_agent,
        accept_language=accept_language,
        extra_headers=extra_headers or {},
    )

    if user_agent and _UA_AVAILABLE:
        _parse_ua(fp, user_agent)
    elif user_agent:
        # Heuristic parsing without the library
        _heuristic_ua_parse(fp, user_agent)

    fp.accept_language = _normalize_lang(accept_language)
    fp.compute_hash()
    return fp


def _parse_ua(fp: DeviceFingerprint, raw_ua: str) -> None:
    """Full UA parsing using the user-agents library."""
    try:
        ua = _ua_lib.parse(raw_ua)

        if ua.is_bot:
            fp.device_type = "bot"
            fp.browser_family = ua.browser.family or "bot"
        elif ua.is_mobile:
            fp.device_type = "mobile"
        elif ua.is_tablet:
            fp.device_type = "tablet"
        else:
            fp.device_type = "desktop"

        fp.browser_family = ua.browser.family
        try:
            fp.browser_version_major = int(ua.browser.version[0]) if ua.browser.version else None
        except (IndexError, TypeError, ValueError):
            fp.browser_version_major = None

        fp.os_family = ua.os.family
        try:
            fp.os_version_major = int(ua.os.version[0]) if ua.os.version else None
        except (IndexError, TypeError, ValueError):
            fp.os_version_major = None

    except Exception as exc:
        logger.debug("ua_parse_error", error=str(exc))
        _heuristic_ua_parse(fp, raw_ua)


def _heuristic_ua_parse(fp: DeviceFingerprint, raw_ua: str) -> None:
    """Fallback: simple keyword-based UA heuristics (no external library)."""
    ua_lower = raw_ua.lower()

    # Device type
    if any(k in ua_lower for k in ("bot", "spider", "crawler", "curl", "python", "requests", "go-http")):
        fp.device_type = "bot"
    elif any(k in ua_lower for k in ("android", "iphone", "mobile")):
        fp.device_type = "mobile"
    elif "ipad" in ua_lower or "tablet" in ua_lower:
        fp.device_type = "tablet"
    else:
        fp.device_type = "desktop"

    # Browser family
    if "firefox" in ua_lower:
        fp.browser_family = "Firefox"
    elif "chrome" in ua_lower and "chromium" not in ua_lower:
        fp.browser_family = "Chrome"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        fp.browser_family = "Safari"
    elif "python-requests" in ua_lower:
        fp.browser_family = "python-requests"
    elif "curl" in ua_lower:
        fp.browser_family = "curl"
    else:
        fp.browser_family = "Other"

    # OS family
    if "windows" in ua_lower:
        fp.os_family = "Windows"
    elif "linux" in ua_lower:
        fp.os_family = "Linux"
    elif "mac os" in ua_lower or "darwin" in ua_lower:
        fp.os_family = "Mac OS X"
    elif "android" in ua_lower:
        fp.os_family = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        fp.os_family = "iOS"
    else:
        fp.os_family = "Other"


def _normalize_lang(lang: Optional[str]) -> str:
    """Normalize Accept-Language to the primary language tag (e.g. 'nl-NL,nl;...' → 'nl')."""
    if not lang:
        return ""
    # Take only the primary subtag
    primary = lang.split(",")[0].split(";")[0].strip().lower()
    # Normalize to just the language code (e.g. "nl-nl" → "nl")
    return primary.split("-")[0] if "-" in primary else primary


# ── Similarity ────────────────────────────────────────────────────────────────

def similarity(a: DeviceFingerprint, b: DeviceFingerprint) -> float:
    """
    Compute weighted similarity between two fingerprints (0.0 – 1.0).

    Weights reflect how discriminating each component is:
      browser_family     0.30  (high: many families exist)
      os_family          0.25  (high: Windows/Linux/Android/iOS/Mac)
      device_type        0.15  (medium: only 4 buckets)
      browser_version    0.15  (medium: catches version-locked tools)
      accept_language    0.10  (low: shared by many users)
      os_version         0.05  (low: minor discriminator)

    Returns 1.0 for exact hash match — call code checks hash first.
    """
    if a.fingerprint_hash and b.fingerprint_hash:
        if a.fingerprint_hash == b.fingerprint_hash:
            return 1.0

    score = 0.0

    score += 0.30 * _field_match(a.browser_family, b.browser_family)
    score += 0.25 * _field_match(a.os_family, b.os_family)
    score += 0.15 * _field_match(a.device_type, b.device_type)
    score += 0.15 * _version_match(a.browser_version_major, b.browser_version_major)
    score += 0.10 * _field_match(
        _normalize_lang(a.accept_language),
        _normalize_lang(b.accept_language),
    )
    score += 0.05 * _version_match(a.os_version_major, b.os_version_major)

    return round(score, 4)


def _field_match(a: Optional[str], b: Optional[str]) -> float:
    """1.0 if equal (case-insensitive), 0.0 if either is None or differs."""
    if a is None or b is None:
        return 0.0
    return 1.0 if a.lower() == b.lower() else 0.0


def _version_match(a: Optional[int], b: Optional[int]) -> float:
    """1.0 exact, 0.5 within 2 major versions, 0.0 otherwise."""
    if a is None or b is None:
        return 0.0
    if a == b:
        return 1.0
    if abs(a - b) <= 2:
        return 0.5
    return 0.0
