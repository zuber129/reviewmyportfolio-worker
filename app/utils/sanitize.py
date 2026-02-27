"""
HTML sanitization utilities to prevent XSS attacks.
"""

from typing import Dict, List, Optional

import bleach

# Allowed HTML tags for rich text (opinions, bios)
ALLOWED_TAGS = [
    "p",
    "br",
    "strong",
    "em",
    "u",
    "a",
    "ul",
    "ol",
    "li",
    "blockquote",
    "code",
    "pre",
]

# Allowed attributes per tag
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "rel"],
    "code": ["class"],
}

# Allowed protocols in links
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def sanitize_html(content: str) -> str:
    """
    Sanitize HTML content while preserving safe formatting.

    Used for: opinion content, user bios

    Args:
        content: Raw HTML/text content from user

    Returns:
        Cleaned HTML with only safe tags
    """
    if not content:
        return ""

    cleaned = bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )

    # Also linkify URLs (convert plain text URLs to links)
    cleaned = bleach.linkify(cleaned)

    return cleaned.strip()


def sanitize_plain_text(content: str) -> str:
    """
    Strip ALL HTML tags for plain text fields.

    Used for: usernames, titles, short descriptions

    Args:
        content: Raw content from user

    Returns:
        Plain text with all HTML removed
    """
    if not content:
        return ""

    # Remove all HTML
    cleaned = bleach.clean(content, tags=[], strip=True)

    return cleaned.strip()


def sanitize_dict(
    data: dict,
    text_fields: Optional[List[str]] = None,
    html_fields: Optional[List[str]] = None,
) -> dict:
    """
    Sanitize multiple fields in a dictionary.

    Args:
        data: Dictionary with user input
        text_fields: List of keys to sanitize as plain text
        html_fields: List of keys to sanitize as HTML

    Returns:
        Dictionary with sanitized values
    """
    sanitized = data.copy()

    if text_fields:
        for field in text_fields:
            if field in sanitized and sanitized[field]:
                sanitized[field] = sanitize_plain_text(str(sanitized[field]))

    if html_fields:
        for field in html_fields:
            if field in sanitized and sanitized[field]:
                sanitized[field] = sanitize_html(str(sanitized[field]))

    return sanitized
