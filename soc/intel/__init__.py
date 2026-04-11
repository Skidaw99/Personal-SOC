"""
soc.intel — IP Intelligence Engine.

Orchestrates multi-provider IP enrichment, caching, threat scoring,
and persistence to the soc_ip_intel_cache table.

Providers
─────────
  AbuseIPDB      abuse confidence + report history      (API key)
  VirusTotal     engine votes + community reputation     (API key)
  Shodan         InternetDB (free) + Host API (key)      (optional key)
  MaxMind        GeoLite2-City local MMDB                (no key)
  ip-api.com     geo fallback + proxy/hosting flags      (no key)

Architecture
────────────
  IntelEngine  ← single entry point
    ├── BaseProvider (abstract)
    │     ├── AbuseIPDBProvider
    │     ├── VirusTotalProvider
    │     ├── ShodanProvider
    │     ├── MaxMindProvider
    │     └── IpApiProvider
    ├── IntelScorer   (weighted composite 0-100)
    ├── IntelCache    (Redis L1 → Postgres L2)
    └── IntelPersist  (upsert to soc_ip_intel_cache)
"""
from soc.intel.engine import IntelEngine
from soc.intel.scorer import IntelScorer
from soc.intel.cache import IntelRedisCache
from soc.intel.schemas import IntelResult, GeoData

__all__ = [
    "IntelEngine",
    "IntelScorer",
    "IntelRedisCache",
    "IntelResult",
    "GeoData",
]
