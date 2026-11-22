"""
Configuration module for PhishIntel Backend (Phase 1).
"""

import os
from pathlib import Path
from typing import List


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    PROJECT_NAME: str = "PhishIntel"
    API_V1_STR: str = "/api/v1"
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    ALLOWED_EXTENSIONS: List[str] = [".eml"]
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    # --- Online authentication (live SPF / DKIM / DMARC via DNS) ---------------------------
    # Set PHISHINTEL_ONLINE_AUTH=0 to fall back to fully offline behaviour.
    ONLINE_AUTH_ENABLED: bool = _env_bool("PHISHINTEL_ONLINE_AUTH", True)
    DNS_TIMEOUT_SECONDS: float = float(os.getenv("PHISHINTEL_DNS_TIMEOUT", "3"))
    # Optional comma-separated resolver IPs, e.g. PHISHINTEL_DNS_SERVERS=1.1.1.1,8.8.8.8
    # Empty = use the operating system's resolver configuration.
    DNS_NAMESERVERS: List[str] = [
        s.strip() for s in os.getenv("PHISHINTEL_DNS_SERVERS", "").split(",") if s.strip()
    ]
    DNS_CACHE_TTL_SECONDS: int = int(os.getenv("PHISHINTEL_DNS_CACHE_TTL", "300"))

    # Pinned DKIM public keys: the key source in offline mode, and in online mode used ONLY as a
    # fallback when DNS is temporarily unreachable (never when DNS says the key is gone/rotated).
    DKIM_KEYSTORE_PATH: Path = Path(__file__).resolve().parents[1] / "data" / "dkim_keys.json"
    TRUSTED_AUTHSERV_DOMAINS: List[str] = [
        "google.com",
        "mx.google.com",
        "protection.outlook.com",
        "outlook.com",
        "microsoft.com",
        "office365.com",
        "proofpoint.com",
        "pphosted.com",
        "mimecast.com",
        "cisco.com",
        "ironport.com",
        "barracuda.com",
        "sendgrid.net",
        "mailgun.org",
        "amazonses.com",
    ]


settings = Settings()
