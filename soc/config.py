from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class SocSettings(BaseSettings):
    # ── Database ──────────────────────────────────────────────────────────────
    # Reuses the same Postgres instance as SFD but in schema 'soc'
    soc_database_url: str = Field(..., env="SOC_DATABASE_URL")

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = Field(..., env="REDIS_URL")
    # Queue name where SFD engine pushes events for SOC ingestion
    soc_ingest_queue: str = Field(default="soc:events:ingest", env="SOC_INGEST_QUEUE")

    # ── IP Intelligence providers ─────────────────────────────────────────────
    abuseipdb_api_key: str = Field(default="", env="ABUSEIPDB_API_KEY")
    virustotal_api_key: str = Field(default="", env="VIRUSTOTAL_API_KEY")
    shodan_api_key: str = Field(default="", env="SHODAN_API_KEY")
    # Local MaxMind GeoLite2-City database path (mounted via Docker volume)
    maxmind_db_path: str = Field(default="/data/geoip/GeoLite2-City.mmdb", env="MAXMIND_DB_PATH")

    # ── Cache TTLs (seconds) ──────────────────────────────────────────────────
    # How long each provider's result is cached in Redis before a fresh lookup
    cache_ttl_abuseipdb: int = Field(default=3600, env="CACHE_TTL_ABUSEIPDB")    # 1 h
    cache_ttl_virustotal: int = Field(default=7200, env="CACHE_TTL_VIRUSTOTAL")  # 2 h
    cache_ttl_shodan: int = Field(default=86400, env="CACHE_TTL_SHODAN")         # 24 h
    cache_ttl_maxmind: int = Field(default=604800, env="CACHE_TTL_MAXMIND")      # 7 d (static DB)

    # ── Threat scoring weights ────────────────────────────────────────────────
    # Must sum to 1.0; used by scorer.py to compute the composite threat score
    score_weight_abuseipdb: float = Field(default=0.40, env="SCORE_WEIGHT_ABUSEIPDB")
    score_weight_virustotal: float = Field(default=0.35, env="SCORE_WEIGHT_VIRUSTOTAL")
    score_weight_shodan: float = Field(default=0.25, env="SCORE_WEIGHT_SHODAN")

    # ── AI Copilot ────────────────────────────────────────────────────────────
    ollama_base_url: str = Field(default="http://ollama:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama3.2:3b", env="OLLAMA_MODEL")
    anthropic_api_key: str = Field(default="", env="ANTHROPIC_API_KEY")
    # "local" → Ollama only, "cloud" → Claude only, "hybrid" → local first, cloud fallback
    ai_mode: str = Field(default="hybrid", env="AI_MODE")

    # ── CrowdSec ──────────────────────────────────────────────────────────────
    crowdsec_api_url: str = Field(default="http://crowdsec:8080", env="CROWDSEC_API_URL")
    crowdsec_api_key: str = Field(default="", env="CROWDSEC_API_KEY")
    # Threat score threshold above which an IP is auto-blocked via CrowdSec
    auto_block_threshold: float = Field(default=75.0, env="AUTO_BLOCK_THRESHOLD")
    auto_block_enabled: bool = Field(default=False, env="AUTO_BLOCK_ENABLED")

    # ── SOC API ───────────────────────────────────────────────────────────────
    soc_api_port: int = Field(default=8001, env="SOC_API_PORT")
    soc_secret_key: str = Field(..., env="SOC_SECRET_KEY")

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_soc_settings() -> SocSettings:
    return SocSettings()
