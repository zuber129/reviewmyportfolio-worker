"""
Encryption utilities for PII data storage.
Issue #41: Store PII in encrypted form for ownership verification.

Uses AES-256-GCM for encryption with a key derived from settings.
"""

import base64
import hashlib
import hmac
import os
import re
from typing import Optional, Tuple

from app.core.config import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_encryption_key() -> bytes:
    """
    Derive a 256-bit encryption key from the secret key.
    Uses SHA-256 to ensure consistent key length.
    """
    secret = (
        getattr(settings, "pii_encryption_key", None) or settings.supabase_service_key
    )
    return hashlib.sha256(secret.encode()).digest()


def encrypt_pii(plaintext: str) -> str:
    """
    Encrypt PII data using AES-256-GCM.

    Args:
        plaintext: The PII string to encrypt

    Returns:
        Base64-encoded string containing nonce + ciphertext + tag
    """
    if not plaintext:
        return ""

    key = _get_encryption_key()
    aesgcm = AESGCM(key)

    # Generate random 96-bit nonce (recommended for GCM)
    nonce = os.urandom(12)

    # Encrypt (GCM provides authentication)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Combine nonce + ciphertext for storage
    encrypted_data = nonce + ciphertext

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt_pii(encrypted_text: str) -> Optional[str]:
    """
    Decrypt PII data encrypted with encrypt_pii.

    Args:
        encrypted_text: Base64-encoded encrypted data

    Returns:
        Decrypted plaintext or None if decryption fails
    """
    if not encrypted_text:
        return None

    try:
        key = _get_encryption_key()
        aesgcm = AESGCM(key)

        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_text)

        # Extract nonce (first 12 bytes) and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Decrypt
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext.decode("utf-8")
    except Exception:
        return None


def _get_pii_hash_salt() -> str:
    """
    Get PII hash salt from settings.
    Uses constant for dev/staging, requires env var for production.
    """
    return settings.pii_hash_salt


def hash_pii(holder_name: str, pan_number: str) -> str:
    """
    Create HMAC-SHA256 hash of PII for duplicate detection.
    Uses global salt to prevent rainbow table attacks.

    This allows detecting if the same person uploads multiple portfolios
    without needing to decrypt the PII.

    Args:
        holder_name: Full name from CAS PDF
        pan_number: PAN number from CAS PDF

    Returns:
        HMAC-SHA256 hash as hex string
    """
    # Aggressive normalization
    normalized_name = re.sub(r'\s+', ' ', holder_name.strip().upper())
    normalized_pan = pan_number.strip().upper()
    
    # Combine with delimiter
    pii_string = f"{normalized_name}:{normalized_pan}"
    
    # HMAC-SHA256 with global salt
    salt = _get_pii_hash_salt()
    return hmac.new(
        salt.encode('utf-8'),
        pii_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


encrypt_token = encrypt_pii
decrypt_token = decrypt_pii


def mask_pan(pan_number: str) -> str:
    """
    Return last 4 characters of PAN for display purposes.

    Args:
        pan_number: Full PAN number

    Returns:
        Last 4 characters (e.g., "XXXX1234" -> "1234")
    """
    if not pan_number or len(pan_number) < 4:
        return ""
    return pan_number[-4:]
