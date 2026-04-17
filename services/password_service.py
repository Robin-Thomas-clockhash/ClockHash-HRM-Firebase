"""
Employee password service.

Each employee_id maps to a unique, deterministic password derived via:
    HMAC-SHA256(key=MASTER_KEY_SEED, msg=employee_id)

This is:
  - Deterministic: can always re-derive without DB lookup
  - Unique per employee: different employee_id → different password
  - Secret: requires knowledge of MASTER_KEY_SEED to reproduce
  - Never stored in plaintext anywhere

NEVER log the returned password value.
"""

import hashlib
import hmac
import logging

from config.settings import get_settings

logger = logging.getLogger(__name__)


def derive_employee_password(employee_id: str) -> str:
    """
    Derives a unique, strong password for the given employee_id
    using HMAC-SHA256 keyed on MASTER_KEY_SEED.

    The output is a 64-character hex string (256 bits of entropy).

    Args:
        employee_id: The employee's unique identifier string

    Returns:
        64-character hex password string — DO NOT log this value
    """
    settings = get_settings()

    if not settings.master_key_seed:
        raise RuntimeError(
            "MASTER_KEY_SEED is not configured. "
            "Set it in .env before running the application."
        )

    digest = hmac.new(
        key=settings.master_key_seed.encode("utf-8"),
        msg=employee_id.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    # Log only employee_id — never the derived password
    logger.debug("Derived password for employee_id=%s", employee_id)

    return digest
