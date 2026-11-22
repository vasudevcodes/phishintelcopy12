"""
PhishIntel Backend Application Entry Point (Phase 1).
Forensic Email Parser & Threat Investigation Foundation.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.core.config import settings

app = FastAPI(
    title="PhishIntel API",
    description="Forensic Email Parser & Investigation Platform - Phase 1 Foundation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for local frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 endpoints
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "phase": "Phase 1 - Forensic Foundation",
        "online_authentication": settings.ONLINE_AUTH_ENABLED,
    }


@app.get(f"{settings.API_V1_STR}/system/status", tags=["System"])
async def system_status():
    """Lightweight status used by the UI header badge (lives under /api so the dev proxy forwards it)."""
    return {"online_authentication": settings.ONLINE_AUTH_ENABLED}


@app.get("/health/model", tags=["System"])
async def model_health():
    """Diagnostic: is PyTorch/transformers importable and is the DistilBERT checkpoint present?"""
    from app.services.model_inference import get_model_inference_engine

    return get_model_inference_engine().diagnostics()


@app.get("/health/dns", tags=["System"])
async def dns_health():
    """Diagnostic: can this server perform the live DNS lookups needed for SPF/DKIM/DMARC?"""
    from starlette.concurrency import run_in_threadpool

    from app.services.live_auth_verifier import get_shared_resolver

    def _probe():
        try:
            resolver = get_shared_resolver(settings)
        except Exception as exc:
            return {"dns_reachable": False, "detail": f"Resolver unavailable (is 'dnspython' installed?): {exc}"}
        try:
            txt = resolver.txt("google.com")
            ok = any(t.lower().startswith("v=spf1") for t in txt)
            return {"dns_reachable": ok, "detail": "Resolved google.com SPF record." if ok else "DNS answered but no SPF record was returned."}
        except Exception as exc:
            return {"dns_reachable": False, "detail": str(exc)}

    result = await run_in_threadpool(_probe)
    return {"online_auth_enabled": settings.ONLINE_AUTH_ENABLED, **result}


@app.get("/", tags=["System"])
async def root():
    """Root redirect / information endpoint."""
    return {
        "message": "Welcome to PhishIntel Forensic Analysis Engine",
        "docs": "/docs",
        "health": "/health",
        "analyze_endpoint": f"{settings.API_V1_STR}/email/analyze",
    }
