"""
Username validation module with comprehensive rules.

Validates usernames for:
- Length (6-20 characters)
- Format (letters, numbers, underscores, hyphens)
- Reserved names (admin, api, system, etc.)
- Profanity filtering (using better-profanity library)
- Character patterns (must start with letter, no consecutive special chars)
"""

import re
from typing import Tuple

from better_profanity import profanity

# Initialize profanity filter with default word list
profanity.load_censor_words()

# Reserved usernames that cannot be used
RESERVED_USERNAMES = {
    "admin",
    "administrator",
    "root",
    "superuser",
    "system",
    "api",
    "app",
    "application",
    "server",
    "service",
    "moderator",
    "mod",
    "staff",
    "support",
    "help",
    "info",
    "contact",
    "about",
    "terms",
    "privacy",
    "user",
    "users",
    "profile",
    "profiles",
    "account",
    "settings",
    "setting",
    "config",
    "configuration",
    "dashboard",
    "panel",
    "control",
    "console",
    "login",
    "logout",
    "signin",
    "signout",
    "signup",
    "register",
    "auth",
    "authentication",
    "password",
    "email",
    "mail",
    "message",
    "messages",
    "inbox",
    "notification",
    "notifications",
    "alert",
    "alerts",
    "portfolio",
    "portfolios",
    "feed",
    "feeds",
    "review",
    "reviews",
    "rating",
    "ratings",
    "comment",
    "comments",
    "reply",
    "replies",
    "upload",
    "download",
    "file",
    "files",
    "image",
    "images",
    "photo",
    "photos",
    "video",
    "videos",
    "document",
    "documents",
    "test",
    "testing",
    "demo",
    "example",
    "null",
    "undefined",
    "none",
    "true",
    "false",
    "public",
    "private",
    "protected",
    "internal",
}

# Validation rules
MIN_LENGTH = 6  # Minimum for pattern like "a-b-1234" would be 8, but allow shorter custom usernames
MAX_LENGTH = 30  # Increased to accommodate hex-suffix pattern (e.g., "magnificent-rhinoceros-a1b2")
ALLOWED_CHARS_PATTERN = (
    r"^[a-z0-9_-]+$"  # Lowercase only for privacy (reduces cross-platform correlation)
)


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username format and content.

    Args:
        username: The username to validate

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if valid, False otherwise
        - error_message: Empty string if valid, error description if invalid

    Examples:
        >>> validate_username("brave-shark-8f3c")
        (True, "")

        >>> validate_username("ad")
        (False, "Username must be at least 6 characters")

        >>> validate_username("admin")
        (False, "This username is reserved")

        >>> validate_username("User-Name-1234")
        (False, "Username can only contain lowercase letters, numbers, underscores, and hyphens")
    """
    # Basic checks
    if not username:
        return False, "Username is required"

    # Length check
    if len(username) < MIN_LENGTH:
        return False, f"Username must be at least {MIN_LENGTH} characters"

    if len(username) > MAX_LENGTH:
        return False, f"Username must be at most {MAX_LENGTH} characters"

    # Character check - lowercase letters, numbers, underscores, hyphens only
    if not re.match(ALLOWED_CHARS_PATTERN, username):
        return (
            False,
            "Username can only contain lowercase letters, numbers, underscores, and hyphens",
        )

    # Must start with a lowercase letter
    if not username[0].islower() or not username[0].isalpha():
        return False, "Username must start with a lowercase letter"

    # Cannot end with special character
    if username[-1] in ["_", "-"]:
        return False, "Username cannot end with underscore or hyphen"

    # No consecutive special characters
    if "__" in username or "--" in username or "_-" in username or "-_" in username:
        return False, "Username cannot have consecutive special characters"

    # Reserved username check (case-insensitive)
    if username.lower() in RESERVED_USERNAMES:
        return False, "This username is reserved"

    # Profanity check using better-profanity library (checks 1000+ words)
    # Check both standalone words and embedded profanity
    username_lower = username.lower()

    # Method 1: Check standalone profane words
    if profanity.contains_profanity(username_lower):
        return False, "This username contains inappropriate content"

    # Method 2: Check for embedded profanity using sliding window
    # This catches cases like "fuck123", "shituser", etc.
    # Check all substrings of length 4-10 (most profane words are in this range)
    for length in range(4, min(11, len(username_lower) + 1)):
        for i in range(len(username_lower) - length + 1):
            substring = username_lower[i : i + length]
            # Only check alphabetic substrings
            if substring.isalpha() and profanity.contains_profanity(substring):
                return False, "This username contains inappropriate content"

    # All checks passed
    return True, ""


def sanitize_username(username: str) -> str:
    """
    Sanitize username by removing invalid characters and converting to appropriate case.

    Args:
        username: The username to sanitize

    Returns:
        Sanitized username (may still be invalid, call validate_username to check)

    Examples:
        >>> sanitize_username("  BraveShark472!  ")
        "BraveShark472"

        >>> sanitize_username("my@username#123")
        "myusername123"
    """
    # Remove leading/trailing whitespace
    username = username.strip()

    # Remove all characters except letters, numbers, underscores, hyphens
    username = re.sub(r"[^a-zA-Z0-9_-]", "", username)

    # Remove consecutive special characters
    username = re.sub(r"[_-]{2,}", "_", username)

    # Remove leading/trailing special characters
    username = username.strip("_-")

    return username


def is_username_available(username: str, taken_usernames: set) -> bool:
    """
    Check if username is available (not taken).

    Args:
        username: The username to check
        taken_usernames: Set of already taken usernames

    Returns:
        True if available, False if taken
    """
    return username.lower() not in {u.lower() for u in taken_usernames}
