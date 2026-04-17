"""
Structured logging configuration.

Rules enforced:
  - NEVER log: PDF content, encryption keys, passwords, salary data
  - DO log: file_id, employee_id (anonymizable), timestamps, HTTP status, operation names
"""

import logging
import sys


def configure_logging(debug: bool = False) -> None:
    """
    Configure application-wide structured logging.
    Call once at application startup from main.py.
    """
    log_level = logging.DEBUG if debug else logging.INFO

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = []
    root_logger.addHandler(handler)

    # Suppress verbose third-party loggers
    for noisy_lib in ("urllib3", "google.auth", "firebase_admin", "httpx", "httpcore"):
        logging.getLogger(noisy_lib).setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        "Logging configured. Level=%s", logging.getLevelName(log_level)
    )
