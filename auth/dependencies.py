"""
FastAPI dependencies for API key authentication.

Two roles are defined:
  - Admin key (ADMIN_API_KEY): finance / admin operations
  - Employee key (EMPLOYEE_API_KEY): employee self-service operations

Both keys also accept the admin key (admin can do everything).
"""

import logging
from fastapi import Header, HTTPException, status, Depends
from config.settings import get_settings, Settings

logger = logging.getLogger(__name__)


def _resolve_key(x_api_key: str, settings: Settings) -> str:
    """
    Validates X-API-Key header and returns role string.
    Returns 'admin' or 'employee'. Raises 403 on invalid key.
    """
    if x_api_key == settings.admin_api_key:
        return "admin"
    if x_api_key == settings.employee_api_key:
        return "employee"

    # Log attempt without logging the key value
    logger.warning("Rejected request with invalid API key.")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing API key.",
    )


def require_admin_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    Dependency: allows only requests with ADMIN_API_KEY.
    For upload, password retrieval, and admin list operations.
    """
    role = _resolve_key(x_api_key, settings)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin API key required for this operation.",
        )
    return role


def require_any_valid_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    Dependency: allows both admin and employee API keys.
    Returns resolved role ('admin' | 'employee') for downstream logic.
    """
    return _resolve_key(x_api_key, settings)
