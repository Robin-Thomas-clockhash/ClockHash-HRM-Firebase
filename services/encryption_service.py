"""
AES-256-GCM encryption service.

Encryption format per file:
  [salt: 16 bytes][nonce: 12 bytes][GCM tag: 16 bytes][ciphertext: N bytes]

Process:
  1. Derive a 32-byte AES key from employee password using PBKDF2-HMAC-SHA256
     with a random per-file salt.
  2. Encrypt using AES-256-GCM with a random nonce.
  3. Prepend salt + nonce + tag to ciphertext.

Security notes:
  - Salt and nonce are random per encryption call (never reused).
  - GCM authentication tag ensures ciphertext integrity.
  - NEVER log plaintext, keys, or passwords.
"""

import logging
import io
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pypdf import PdfReader, PdfWriter

logger = logging.getLogger(__name__)

# Constants
SALT_LENGTH = 16       # bytes — random per file
NONCE_LENGTH = 12      # bytes — AES-GCM standard nonce
KEY_LENGTH = 32        # bytes — AES-256
PBKDF2_ITERATIONS = 260_000  # OWASP 2023 recommendation for PBKDF2-SHA256


def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte AES key from a password string and salt
    using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_pdf(plaintext_bytes: bytes, password: str) -> bytes:
    """
    Encrypts PDF bytes using AES-256-GCM.

    Args:
        plaintext_bytes: Raw PDF bytes (in-memory, never written to disk)
        password: Employee-specific derived password (not logged)

    Returns:
        Encrypted blob = salt(16) + nonce(12) + tag(16) + ciphertext
    """
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    # encrypt() returns ciphertext + tag appended (tag is last 16 bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

    encrypted_blob = salt + nonce + ciphertext_with_tag

    # Log only byte length — never content
    logger.info(
        "PDF encrypted successfully. plaintext_size=%d encrypted_size=%d",
        len(plaintext_bytes),
        len(encrypted_blob),
    )

    # Explicitly zero-out the key from memory (best-effort in Python)
    del key

    return encrypted_blob


def decrypt_pdf(encrypted_blob: bytes, password: str) -> bytes:
    """
    Decrypts an encrypted blob produced by encrypt_pdf().

    Args:
        encrypted_blob: Bytes from Firebase Storage
        password: Employee-specific derived password

    Returns:
        Original plaintext PDF bytes
    """
    if len(encrypted_blob) < SALT_LENGTH + NONCE_LENGTH + 16:
        raise ValueError("Encrypted blob too short — data may be corrupted.")

    salt = encrypted_blob[:SALT_LENGTH]
    nonce = encrypted_blob[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    ciphertext_with_tag = encrypted_blob[SALT_LENGTH + NONCE_LENGTH:]

    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    logger.info(
        "PDF decrypted successfully. decrypted_size=%d", len(plaintext)
    )

    del key
    return plaintext


def apply_native_pdf_password(pdf_bytes: bytes, password: str) -> bytes:
    """
    Applies native AES-256 PDF password protection to the given PDF bytes.
    This is Layer 1 of the encryption process.

    Args:
        pdf_bytes: Raw plaintext PDF bytes.
        password: The user password to lock the PDF with.

    Returns:
        Bytes of the new password-protected PDF.
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()

    writer.append_pages_from_reader(reader)

    # Encrypt natively using AES-256 standard
    writer.encrypt(password, algorithm="AES-256")

    output_stream = io.BytesIO()
    writer.write(output_stream)

    protected_bytes = output_stream.getvalue()

    logger.info(
        "Native PDF password applied successfully. original_size=%d new_size=%d",
        len(pdf_bytes),
        len(protected_bytes),
    )

    return protected_bytes
