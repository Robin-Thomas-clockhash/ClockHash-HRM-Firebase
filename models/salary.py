"""
Pydantic models for salary slips.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SalarySlipMetadata(BaseModel):
    """Stored in Firestore — no PDF content, no passwords."""
    file_id: str
    employee_id: str
    month: int = Field(..., ge=1, le=12, description="Month number 1-12")
    year: int = Field(..., ge=2000, le=2100)
    firebase_path: str
    uploaded_by: str = Field(..., description="Identifier of uploader (e.g. finance username)")
    uploaded_at: datetime
    original_filename: str


class SalarySlipUploadResponse(BaseModel):
    """Response returned after a successful upload."""
    file_id: str
    employee_id: str
    month: int
    year: int
    message: str = "Salary slip encrypted and uploaded successfully."


class SalarySlipListItem(BaseModel):
    """Lightweight list item — no paths exposed to frontend."""
    file_id: str
    employee_id: str
    month: int
    year: int
    uploaded_at: datetime
    original_filename: str


class PasswordResponse(BaseModel):
    """
    Response for GET /salary/password/{employee_id}.
    Only accessible by admin API key.
    """
    employee_id: str
    password: str
    note: str = (
        "This password decrypts the employee's salary slip PDFs. "
        "Transmit only over secure channels."
    )
