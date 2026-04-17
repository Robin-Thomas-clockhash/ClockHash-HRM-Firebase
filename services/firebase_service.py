"""
Firebase service — wraps Firebase Admin SDK for Storage and Firestore operations.

Responsibilities:
  - Initialize Firebase app once (singleton via firebase_admin)
  - Upload encrypted PDF bytes to Firebase Storage
  - Download encrypted PDF bytes from Firebase Storage
  - Delete a file from Firebase Storage
  - CRUD helpers for salary slip metadata in Firestore

Security notes:
  - Only encrypted bytes are ever uploaded — this module never sees raw PDFs
  - Firestore metadata contains no salary data, only file references
  - NEVER log file content or encryption keys
"""

import logging
import io
import json
from datetime import datetime, timezone
from typing import Optional

import firebase_admin
from firebase_admin import credentials, storage, firestore
from google.cloud import firestore as gcp_firestore

from config.settings import get_settings

logger = logging.getLogger(__name__)

_firebase_initialized = False


def _get_firebase_credentials_dict() -> dict:
    """Reconstructs the Firebase Service Account JSON from individual env vars."""
    settings = get_settings()
    if not settings.firebase_credentials_json_project_id:
        raise ValueError("FIREBASE_CREDENTIALS_JSON_PROJECT_ID is missing or empty")
        
    return {
        "type": settings.firebase_credentials_json_type,
        "project_id": settings.firebase_credentials_json_project_id,
        "private_key_id": settings.firebase_credentials_json_private_key_id,
        "private_key": settings.firebase_credentials_json_private_key.replace("\\n", "\n"),
        "client_email": settings.firebase_credentials_json_client_email,
        "client_id": settings.firebase_credentials_json_client_id,
        "auth_uri": settings.firebase_credentials_json_auth_uri,
        "token_uri": settings.firebase_credentials_json_token_uri,
        "auth_provider_x509_cert_url": settings.firebase_credentials_json_auth_provider_x509_cert_url,
        "client_x509_cert_url": settings.firebase_credentials_json_client_x509_cert_url,
    }


def initialize_firebase() -> None:
    """
    Initializes Firebase Admin SDK using service account credentials.
    Safe to call multiple times — only initializes once.
    """
    global _firebase_initialized
    if _firebase_initialized:
        return

    settings = get_settings()

    try:
        cred_dict = _get_firebase_credentials_dict()
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred, {
            "storageBucket": settings.firebase_storage_bucket,
        })
        _firebase_initialized = True
        logger.info(
            "Firebase initialized. bucket=%s", settings.firebase_storage_bucket
        )
    except Exception as exc:
        logger.error("Failed to initialize Firebase: %s", str(exc))
        raise


# ---------------------------------------------------------------------------
# Storage operations
# ---------------------------------------------------------------------------

def upload_encrypted_pdf(
    encrypted_bytes: bytes,
    firebase_path: str,
) -> str:
    """
    Uploads encrypted PDF bytes to Firebase Storage.

    Args:
        encrypted_bytes: AES-256-GCM encrypted blob (never raw PDF)
        firebase_path: Destination path in bucket, e.g. "salary_slips/EMP001/2024_01.enc"

    Returns:
        The firebase_path (used as reference in Firestore)
    """
    bucket = storage.bucket()
    blob = bucket.blob(firebase_path)

    blob.upload_from_file(
        io.BytesIO(encrypted_bytes),
        content_type="application/octet-stream",
    )

    logger.info(
        "Encrypted PDF uploaded. path=%s size_bytes=%d",
        firebase_path,
        len(encrypted_bytes),
    )
    return firebase_path


def download_encrypted_pdf(firebase_path: str) -> bytes:
    """
    Downloads encrypted PDF bytes from Firebase Storage.

    Args:
        firebase_path: Path in bucket

    Returns:
        Encrypted bytes blob — caller is responsible for decryption
    """
    bucket = storage.bucket()
    blob = bucket.blob(firebase_path)

    encrypted_bytes = blob.download_as_bytes()

    logger.info(
        "Encrypted PDF downloaded. path=%s size_bytes=%d",
        firebase_path,
        len(encrypted_bytes),
    )
    return encrypted_bytes


def delete_encrypted_pdf(firebase_path: str) -> None:
    """Deletes a file blob from Firebase Storage."""
    bucket = storage.bucket()
    blob = bucket.blob(firebase_path)
    blob.delete()
    logger.info("Deleted file from storage. path=%s", firebase_path)


# ---------------------------------------------------------------------------
# Firestore — salary slip metadata
# ---------------------------------------------------------------------------

COLLECTION_SALARY_SLIPS = "salary_slips"


def _get_db():
    """
    Returns a Firestore client.
    Handles named Google Cloud databases natively if the database name is not '(default)'.
    """
    settings = get_settings()
    if settings.firestore_database_name != "(default)":
        cred_dict = _get_firebase_credentials_dict()
        return gcp_firestore.Client(
            project=cred_dict.get("project_id"),
            database=settings.firestore_database_name,
            credentials=credentials.Certificate(cred_dict).get_credential()
        )
    return firestore.client()


def save_slip_metadata(
    file_id: str,
    employee_id: str,
    month: int,
    year: int,
    firebase_path: str,
    uploaded_by: str,
    original_filename: str,
) -> None:
    """Persists salary slip metadata to Firestore. No salary data stored."""
    db = _get_db()
    doc_ref = db.collection(COLLECTION_SALARY_SLIPS).document(file_id)
    doc_ref.set({
        "file_id": file_id,
        "employee_id": employee_id,
        "month": month,
        "year": year,
        "firebase_path": firebase_path,
        "uploaded_by": uploaded_by,
        "uploaded_at": datetime.now(timezone.utc),
        "original_filename": original_filename,
    })
    logger.info(
        "Slip metadata saved. file_id=%s employee_id=%s month=%d year=%d",
        file_id, employee_id, month, year,
    )


def get_slip_metadata(file_id: str) -> Optional[dict]:
    """Fetches a single salary slip metadata document by file_id."""
    db = _get_db()
    doc = db.collection(COLLECTION_SALARY_SLIPS).document(file_id).get()
    if not doc.exists:
        return None
    return doc.to_dict()


def list_slips_for_employee(employee_id: str) -> list[dict]:
    """Returns all slip metadata records for a given employee_id."""
    db = _get_db()
    docs = (
        db.collection(COLLECTION_SALARY_SLIPS)
        .where("employee_id", "==", employee_id)
        .order_by("uploaded_at", direction=firestore.Query.DESCENDING)
        .stream()
    )
    results = [doc.to_dict() for doc in docs]
    logger.info(
        "Listed slips for employee_id=%s count=%d", employee_id, len(results)
    )
    return results


def list_all_slips() -> list[dict]:
    """Returns all salary slip metadata records (admin only)."""
    db = _get_db()
    docs = (
        db.collection(COLLECTION_SALARY_SLIPS)
        .order_by("uploaded_at", direction=firestore.Query.DESCENDING)
        .stream()
    )
    results = [doc.to_dict() for doc in docs]
    logger.info("Listed all slips. count=%d", len(results))
    return results


def delete_slip_metadata(file_id: str) -> None:
    """Deletes a salary slip metadata document from Firestore."""
    db = _get_db()
    db.collection(COLLECTION_SALARY_SLIPS).document(file_id).delete()
    logger.info("Slip metadata deleted. file_id=%s", file_id)
