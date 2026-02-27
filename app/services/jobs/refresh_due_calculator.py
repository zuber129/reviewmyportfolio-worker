"""
Portfolio refresh due date calculator.

Calculates when a user's portfolio becomes stale and needs refreshing.
Runs as an async Celery task after successful portfolio upload.

The DB trigger on portfolios.holdings_last_updated_at sets a fast default
(MAX + 186 days). This service overwrites it with a potentially more
sophisticated calculation.

Future enhancements could factor in:
- User tier / subscription level
- Upload frequency patterns
- Market conditions
- Admin overrides (already supported via admin advance endpoint)
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog

from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger(__name__)

# Default refresh window in days
DEFAULT_REFRESH_DAYS = 186


async def calculate_refresh_due_at(user_id: str) -> Optional[datetime]:
    """
    Calculate when the user's portfolio refresh is next due.

    Currently uses a simple algorithm:
    - MAX(holdings_last_updated_at) + DEFAULT_REFRESH_DAYS

    This function is the single place to evolve into a complex algo
    (e.g. tier-based, frequency-based, market-aware).

    Args:
        user_id: The user whose refresh date to calculate.

    Returns:
        The computed due date, or None if no portfolios exist.
    """
    try:
        result = supabase_client.client.table("portfolios").select(
            "holdings_last_updated_at"
        ).eq("user_id", user_id).is_("deleted_at", "null").execute()

        if not result.data:
            return None

        timestamps = [
            row["holdings_last_updated_at"]
            for row in result.data
            if row.get("holdings_last_updated_at")
        ]

        if not timestamps:
            return None

        # Parse and get max
        parsed = []
        for ts in timestamps:
            if isinstance(ts, str):
                parsed.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            else:
                parsed.append(ts)

        latest = max(parsed)

        # ---------------------------------------------------------------
        # Algorithm: currently simple.  Replace / extend this block when
        # more sophisticated logic is needed (tier, frequency, market).
        # ---------------------------------------------------------------
        refresh_days = DEFAULT_REFRESH_DAYS
        due_at = latest + timedelta(days=refresh_days)

        logger.info(
            "refresh_due_calculated",
            user_id=user_id,
            latest_update=latest.isoformat(),
            refresh_days=refresh_days,
            due_at=due_at.isoformat(),
        )

        return due_at

    except Exception as e:
        logger.error("refresh_due_calculation_failed", user_id=user_id, error=str(e))
        return None


async def update_profile_refresh_due(user_id: str) -> bool:
    """
    Calculate and persist the refresh due date to profiles.

    Returns True on success, False on failure.
    """
    due_at = await calculate_refresh_due_at(user_id)

    if due_at is None:
        logger.info("refresh_due_no_portfolios", user_id=user_id)
        return True  # Not an error — user has no portfolios

    try:
        supabase_client.client.table("profiles").update({
            "portfolio_refresh_due_at": due_at.isoformat(),
        }).eq("id", user_id).execute()

        logger.info(
            "refresh_due_updated",
            user_id=user_id,
            due_at=due_at.isoformat(),
        )
        return True

    except Exception as e:
        logger.error("refresh_due_update_failed", user_id=user_id, error=str(e))
        return False
