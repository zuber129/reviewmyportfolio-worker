"""Access control utilities for 60-day upload requirement."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

# Access control constants
ACTIVE_WINDOW_DAYS = 60
GRACE_WINDOW_DAYS = 14
BLOCK_THRESHOLD_DAYS = ACTIVE_WINDOW_DAYS + GRACE_WINDOW_DAYS  # 74


@dataclass
class AccessStatusResult:
    """Result of access status computation."""

    status: str  # "active" | "restricted" | "blocked"
    days_since_last_upload: Optional[int]  # None if never uploaded
    days_until_restricted: Optional[
        int
    ]  # Days remaining in active window (None if restricted/blocked)
    days_until_blocked: Optional[
        int
    ]  # Days remaining in grace period (None if active/blocked)
    can_browse_feed: bool  # Whether user can access feed
    requires_upload: bool  # Whether upload is required to restore access
    has_ever_uploaded: bool  # Whether user has uploaded at least once


def compute_access_status(
    last_portfolio_upload_at: Optional[datetime], now: Optional[datetime] = None
) -> AccessStatusResult:
    """
    Pure function to compute access status based on last upload date.

    Policy:
    - Days 0-60: ACTIVE - Full access, countdown to restricted
    - Days 61-74: RESTRICTED - Grace period active, warning shown, feed limited
    - Days 75+: BLOCKED - No feed access, must upload to restore

    Args:
        last_portfolio_upload_at: Timestamp of last portfolio upload (None for new users)
        now: Current timestamp (for testing, defaults to now())

    Returns:
        AccessStatusResult with all computed fields

    Examples:
        >>> # New user (never uploaded)
        >>> compute_access_status(None)
        AccessStatusResult(status='active', days_since_last_upload=None, days_until_restricted=60, ...)

        >>> # Uploaded 30 days ago
        >>> compute_access_status(datetime.now(timezone.utc) - timedelta(days=30))
        AccessStatusResult(status='active', days_since_last_upload=30, days_until_restricted=30, ...)

        >>> # Uploaded 65 days ago (restricted)
        >>> compute_access_status(datetime.now(timezone.utc) - timedelta(days=65))
        AccessStatusResult(status='restricted', days_since_last_upload=65, days_until_blocked=9, ...)

        >>> # Uploaded 80 days ago (blocked)
        >>> compute_access_status(datetime.now(timezone.utc) - timedelta(days=80))
        AccessStatusResult(status='blocked', days_since_last_upload=80, can_browse_feed=False, ...)
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # New user case: never uploaded - MUST upload to browse ("share to browse")
    if last_portfolio_upload_at is None:
        return AccessStatusResult(
            status="active",  # Still "active" for onboarding flow, but can_browse_feed=False
            days_since_last_upload=None,
            days_until_restricted=ACTIVE_WINDOW_DAYS,
            days_until_blocked=None,
            can_browse_feed=False,  # Changed: must upload first to browse
            requires_upload=True,  # Changed: upload required for "share to browse"
            has_ever_uploaded=False,
        )

    # Ensure timezone-aware
    if last_portfolio_upload_at.tzinfo is None:
        last_portfolio_upload_at = last_portfolio_upload_at.replace(tzinfo=timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    days_since_upload = (now - last_portfolio_upload_at).days

    # BLOCKED: 75+ days (strictly greater than 74)
    if days_since_upload > BLOCK_THRESHOLD_DAYS:
        return AccessStatusResult(
            status="blocked",
            days_since_last_upload=days_since_upload,
            days_until_restricted=None,
            days_until_blocked=None,
            can_browse_feed=False,
            requires_upload=True,
            has_ever_uploaded=True,
        )

    # RESTRICTED: 61-74 days (grace period)
    if days_since_upload > ACTIVE_WINDOW_DAYS:
        days_until_blocked = BLOCK_THRESHOLD_DAYS - days_since_upload
        return AccessStatusResult(
            status="restricted",
            days_since_last_upload=days_since_upload,
            days_until_restricted=None,
            days_until_blocked=days_until_blocked,
            can_browse_feed=True,  # Can still browse during grace period
            requires_upload=False,  # Not yet required, but strongly encouraged
            has_ever_uploaded=True,
        )

    # ACTIVE: 0-60 days
    days_until_restricted = ACTIVE_WINDOW_DAYS - days_since_upload
    return AccessStatusResult(
        status="active",
        days_since_last_upload=days_since_upload,
        days_until_restricted=days_until_restricted,
        days_until_blocked=None,
        can_browse_feed=True,
        requires_upload=False,
        has_ever_uploaded=True,
    )


def get_access_info(profile: Dict) -> Dict:
    """
    Add access control info to profile dict.

    Args:
        profile: User profile dict from database (expects last_portfolio_upload_at field)

    Returns:
        Profile dict enriched with:
        - access_status: "active" | "restricted" | "blocked"
        - days_until_restricted: Days remaining in active window (None if not active)
        - days_until_blocked: Days remaining in grace period (None if not restricted)
        - can_browse_feed: Whether user can access feed
        - has_ever_uploaded: Whether user has uploaded at least once
    """
    # Support both field names for backward compatibility
    last_upload = profile.get("last_portfolio_upload_at") or profile.get(
        "last_upload_date"
    )

    # Parse if string
    if isinstance(last_upload, str):
        last_upload = datetime.fromisoformat(last_upload.replace("Z", "+00:00"))

    result = compute_access_status(last_upload)

    return {
        **profile,
        "access_status": result.status,
        "days_until_restricted": result.days_until_restricted,
        "days_until_blocked": result.days_until_blocked,
        "can_browse_feed": result.can_browse_feed,
        "has_ever_uploaded": result.has_ever_uploaded,
    }
