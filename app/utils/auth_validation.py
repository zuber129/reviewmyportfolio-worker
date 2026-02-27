"""
Backend validation for authentication inputs.
Ensures email and password meet security requirements regardless of frontend validation.
"""

import re
from typing import Tuple


def validate_email(email: str) -> Tuple[bool, str | None]:
    """
    Validate email format.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"

    if len(email) > 254:
        return False, "Email is too long"

    # RFC 5322 compliant email regex (simplified)
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        return False, "Invalid email format"

    return True, None


def validate_password(password: str) -> Tuple[bool, str | None]:
    """
    Validate password strength requirements.

    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character (@$!%*?&)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"

    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if len(password) > 128:
        return False, "Password is too long"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"

    # Reduced secure special character set for passwords
    # Common, safe characters that are easy to type and remember
    if not re.search(r"[!@#$%&*]", password):
        return False, "Password must contain at least one special character (!@#$%&*)"

    return True, None


def validate_auth_inputs(email: str, password: str) -> Tuple[bool, str | None]:
    """
    Validate both email and password for signup/signin.

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Validate email
    is_valid, error = validate_email(email)
    if not is_valid:
        return False, error

    # Validate password
    is_valid, error = validate_password(password)
    if not is_valid:
        return False, error

    return True, None
