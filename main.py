"""
ClockHash HRM — Salary Slip Management API

Entry point for the FastAPI application.

Startup sequence:
  1. Configure logging
  2. Validate critical environment variables
  3. Initialize Firebase Admin SDK
  4. Mount routers

All secrets are loaded from .env — see .env.example for required variables.
"""

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import get_settings
from utils.logging_config import configure_logging
from services.firebase_service import initialize_firebase
from routes.salary import router as salary_router

# ---------------------------------------------------------------------------
# Bootstrap logging before anything else
# ---------------------------------------------------------------------------
settings = get_settings()
configure_logging(debug=settings.debug)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Startup validation — fail fast if critical env vars are missing
# ---------------------------------------------------------------------------
def _validate_env() -> None:
    missing = []
    if not settings.firebase_credentials_json:
        missing.append("FIREBASE_CREDENTIALS_JSON")
    if not settings.firebase_storage_bucket:
        missing.append("FIREBASE_STORAGE_BUCKET")
    if not settings.admin_api_key:
        missing.append("ADMIN_API_KEY")
    if not settings.employee_api_key:
        missing.append("EMPLOYEE_API_KEY")
    if not settings.master_key_seed:
        missing.append("MASTER_KEY_SEED")

    if missing:
        logger.critical(
            "Missing required environment variables: %s. "
            "Copy .env.example to .env and fill in all values.",
            ", ".join(missing),
        )
        sys.exit(1)


_validate_env()

# ---------------------------------------------------------------------------
# Initialize Firebase
# ---------------------------------------------------------------------------
try:
    initialize_firebase()
except Exception as exc:
    logger.critical("Firebase initialization failed: %s", str(exc))
    sys.exit(1)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.app_name,
    description=(
        "Backend for HR Salary Slip Management. "
        "Encrypts PDFs server-side (AES-256-GCM) before storing to Firebase Storage. "
        "Employees download encrypted slips and decrypt locally with their unique password."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — restrict to your frontend origin in production
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # ← replace with your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(salary_router)


# ---------------------------------------------------------------------------
# Health check — public, no API key required
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok", "service": settings.app_name}


# ---------------------------------------------------------------------------
# Global exception handler — never leak internal errors to client
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )


logger.info("Application startup complete. Docs at /docs")
