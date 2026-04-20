"""
Salary slip routes.

Endpoints:
  POST   /salary/upload                  — Upload + encrypt salary slip (admin key)
  GET    /salary/download/{file_id}      — Download encrypted PDF (any valid key, scoped)
  GET    /salary/list                    — List salary slips (scoped by role)
  GET    /salary/password/{employee_id}  — Get employee decryption password (admin key)
  DELETE /salary/{file_id}               — Delete a salary slip (admin key)

Role scoping:
  - admin key: sees/manages all employees
  - employee key: must supply their own employee_id; can only see their own slips
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import Response

from auth.dependencies import require_admin_key, require_any_valid_key
from config.settings import get_settings
from models.salary import (
    PasswordResponse,
    SalarySlipListItem,
    SalarySlipUploadResponse,
)
from services import encryption_service, firebase_service, password_service
from utils.email_service import send_password_email

router = APIRouter(prefix="/salary", tags=["Salary Slips"])
logger = logging.getLogger(__name__)

# Maximum allowed upload size: 20 MB
MAX_PDF_SIZE_BYTES = 20 * 1024 * 1024


# ---------------------------------------------------------------------------
# POST /salary/upload
# ---------------------------------------------------------------------------

@router.post(
    "/upload",
    response_model=SalarySlipUploadResponse,
    summary="Upload and encrypt a salary slip (admin only)",
    status_code=status.HTTP_201_CREATED,
)
async def upload_salary_slip(
    employee_id: str = Form(..., description="Target employee's unique ID"),
    month: int = Form(..., ge=1, le=12, description="Payroll month (1-12)"),
    year: int = Form(..., ge=2000, le=2100, description="Payroll year"),
    uploaded_by: str = Form(..., description="Uploader identifier (e.g. finance username)"),
    pdf_file: UploadFile = File(..., description="Salary slip PDF file"),
    role: str = Depends(require_admin_key),
):
    """
    Finance/admin uploads a salary slip PDF.

    Flow:
      1. Read PDF bytes into memory (never written to disk)
      2. Derive employee password from employee_id + MASTER_KEY_SEED
      3. Encrypt PDF bytes with AES-256-GCM
      4. Upload encrypted blob to Firebase Storage
      5. Save metadata to Firestore
      6. Explicitly clear PDF bytes from memory
    """
    # Validate file type
    if pdf_file.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are accepted.",
        )

    # Read PDF into memory
    pdf_bytes = await pdf_file.read()

    if len(pdf_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )
    if len(pdf_bytes) > MAX_PDF_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {MAX_PDF_SIZE_BYTES // (1024*1024)} MB.",
        )

    logger.info(
        "Upload initiated. employee_id=%s month=%d year=%d uploaded_by=%s size_bytes=%d",
        employee_id, month, year, uploaded_by, len(pdf_bytes),
    )

    # Derive per-employee password
    emp_password = password_service.derive_employee_password(employee_id)
    settings = get_settings()

    # Layer 1: Native PDF Password
    try:
        protected_pdf_bytes = encryption_service.apply_native_pdf_password(pdf_bytes, emp_password)
    except Exception as e:
        logger.error("Failed to apply native PDF password: %s", str(e))
        raise HTTPException(status_code=500, detail="Failed to protect PDF.")
    finally:
        pdf_bytes = b""
        del pdf_bytes

    # Layer 2: Encrypt in-memory blob via AES-GCM and MASTER_KEY_SEED
    try:
        encrypted_blob = encryption_service.encrypt_pdf(protected_pdf_bytes, settings.master_key_seed)
    finally:
        # Zero out plaintext bytes (best-effort)
        protected_pdf_bytes = b""
        del protected_pdf_bytes

    # Generate unique file ID
    file_id = str(uuid.uuid4())
    firebase_path = f"salary_slips/{employee_id}/{year}_{month:02d}_{file_id}.enc"

    # Upload encrypted blob
    firebase_service.upload_encrypted_pdf(encrypted_blob, firebase_path)

    # Save metadata to Firestore
    firebase_service.save_slip_metadata(
        file_id=file_id,
        employee_id=employee_id,
        month=month,
        year=year,
        firebase_path=firebase_path,
        uploaded_by=uploaded_by,
        original_filename=pdf_file.filename or "salary_slip.pdf",
    )

    logger.info(
        "Upload complete. file_id=%s employee_id=%s", file_id, employee_id
    )

    return SalarySlipUploadResponse(
        file_id=file_id,
        employee_id=employee_id,
        month=month,
        year=year,
    )


# ---------------------------------------------------------------------------
# GET /salary/download/{file_id}
# ---------------------------------------------------------------------------

@router.get(
    "/download/{file_id}",
    summary="Download encrypted salary slip",
    response_class=Response,
)
async def download_salary_slip(
    file_id: str,
    employee_id: Optional[str] = Query(
        None,
        description="Required when using employee API key — must match slip owner",
    ),
    role: str = Depends(require_any_valid_key),
):
    """
    Returns the encrypted PDF blob for the given file_id.

    - Admin key: can download any slip
    - Employee key: must supply employee_id; 403 if not the owner
    
    The returned file is the AES-256-GCM encrypted blob.
    Decryption happens on the client side using the employee's password.
    """
    metadata = firebase_service.get_slip_metadata(file_id)
    if metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No salary slip found for file_id={file_id}",
        )

    # Role-based ownership check
    if role == "employee":
        if not employee_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="employee_id query parameter is required for employee access.",
            )
        if metadata["employee_id"] != employee_id:
            logger.warning(
                "Unauthorized download attempt. file_id=%s requested_by=%s actual_owner=%s",
                file_id, employee_id, metadata["employee_id"],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to download this salary slip.",
            )

    settings = get_settings()
    encrypted_bytes = firebase_service.download_encrypted_pdf(metadata["firebase_path"])

    # Unlock Layer 2
    try:
        unlocked_pdf_bytes = encryption_service.decrypt_pdf(encrypted_bytes, settings.master_key_seed)
    except Exception as e:
        logger.error("Failed to decrypt Layer 2 binary blob: %s", str(e))
        raise HTTPException(status_code=500, detail="Corrupted file in storage.")

    logger.info(
        "Slip downloaded and unlocked. file_id=%s employee_id=%s role=%s",
        file_id, metadata["employee_id"], role,
    )

    filename = f"salary_slip_{metadata['employee_id']}_{metadata['year']}_{metadata['month']:02d}.pdf"
    return Response(
        content=unlocked_pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# GET /salary/list
# ---------------------------------------------------------------------------

@router.get(
    "/list",
    response_model=list[SalarySlipListItem],
    summary="List salary slips",
)
async def list_salary_slips(
    employee_id: Optional[str] = Query(
        None,
        description="Filter by employee_id. Required for employee key, optional for admin.",
    ),
    role: str = Depends(require_any_valid_key),
):
    """
    - Admin key: can list all slips, or filter by employee_id
    - Employee key: must supply employee_id and can only see their own slips
    """
    if role == "employee":
        if not employee_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="employee_id query parameter is required for employee access.",
            )
        raw_slips = firebase_service.list_slips_for_employee(employee_id)
    else:
        # Admin can optionally filter
        if employee_id:
            raw_slips = firebase_service.list_slips_for_employee(employee_id)
        else:
            raw_slips = firebase_service.list_all_slips()

    slips = []
    for s in raw_slips:
        uploaded_at = s.get("uploaded_at")
        # Firestore returns DatetimeWithNanoseconds — convert to datetime if needed
        if not isinstance(uploaded_at, datetime):
            uploaded_at = datetime.now(timezone.utc)
        slips.append(SalarySlipListItem(
            file_id=s["file_id"],
            employee_id=s["employee_id"],
            month=s["month"],
            year=s["year"],
            uploaded_at=uploaded_at,
            original_filename=s.get("original_filename", ""),
        ))

    return slips


# ---------------------------------------------------------------------------
# GET /salary/password/{employee_id}
# ---------------------------------------------------------------------------

@router.get(
    "/password/{employee_id}",
    response_model=PasswordResponse,
    summary="Send employee decryption password to email (admin only)",
)
async def get_employee_password(
    employee_id: str,
    email: str = Query(..., description="Email address to send the password to"),
    role: str = Depends(require_admin_key),
):
    """
    Sends the deterministically derived decryption password for the given employee to the provided email.
    
    ⚠️  Only accessible with ADMIN_API_KEY.
    ⚠️  Never log the returned password value.
    """
    # Derive password — does not log the value
    emp_password = password_service.derive_employee_password(employee_id)
    
    settings = get_settings()
    if not settings.smtp_password:
        raise HTTPException(status_code=500, detail="SMTP credentials not configured.")

    try:
        send_password_email(
            recipient_email=email,
            employee_id=employee_id,
            password=emp_password,
            smtp_user=settings.smtp_user,
            smtp_password=settings.smtp_password,
        )
    except RuntimeError as e:
        logger.error("Email error for employee_id=%s: %s", employee_id, e)
        raise HTTPException(status_code=500, detail="Failed to send the password email.")

    logger.info(
        "Password sent to email for employee_id=%s by role=%s", employee_id, role
    )

    return PasswordResponse(employee_id=employee_id)


# ---------------------------------------------------------------------------
# DELETE /salary/{file_id}
# ---------------------------------------------------------------------------

@router.delete(
    "/{file_id}",
    summary="Delete a salary slip (admin only)",
    status_code=status.HTTP_200_OK,
)
async def delete_salary_slip(
    file_id: str,
    role: str = Depends(require_admin_key),
):
    """
    Permanently deletes the encrypted PDF from Firebase Storage
    and removes the metadata document from Firestore.
    """
    metadata = firebase_service.get_slip_metadata(file_id)
    if metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No salary slip found for file_id={file_id}",
        )

    firebase_service.delete_encrypted_pdf(metadata["firebase_path"])
    firebase_service.delete_slip_metadata(file_id)

    logger.info("Slip deleted. file_id=%s", file_id)

    return {"message": f"Salary slip {file_id} deleted successfully."}
