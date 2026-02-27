"""
Moderation Service
Handles auto-flagging logic for content moderation
"""

import re
from typing import Optional

import structlog

logger = structlog.get_logger()


class ModerationService:
    """Service for content moderation and auto-flagging"""

    # Extreme XIRR thresholds (conservative approach)
    EXTREME_POSITIVE_XIRR = 100.0  # 100%+ returns
    EXTREME_NEGATIVE_XIRR = -50.0  # -50% or worse

    # URL detection pattern (simple but effective)
    URL_PATTERN = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )

    @classmethod
    def check_auto_flag_opinion(cls, content: str) -> tuple[bool, Optional[str]]:
        """
        Check if an opinion should be auto-flagged.

        Returns:
            (is_flagged, reason)
        """
        # Check for external URLs in content
        if cls.URL_PATTERN.search(content):
            logger.info("auto_flag_detected", type="opinion", reason="external_url")
            return True, "Contains external URL"

        return False, None

    @classmethod
    def check_auto_flag_portfolio(
        cls, xirr: Optional[float], holding_count: int
    ) -> tuple[bool, Optional[str]]:
        """
        Check if a portfolio should be auto-flagged.

        Returns:
            (is_flagged, reason)
        """
        # Check for extreme positive returns
        if xirr is not None and xirr >= cls.EXTREME_POSITIVE_XIRR:
            logger.info(
                "auto_flag_detected",
                type="portfolio",
                reason="extreme_positive_xirr",
                xirr=xirr,
            )
            return True, f"Extreme positive returns ({xirr:.1f}%)"

        # Check for extreme negative returns
        if xirr is not None and xirr <= cls.EXTREME_NEGATIVE_XIRR:
            logger.info(
                "auto_flag_detected",
                type="portfolio",
                reason="extreme_negative_xirr",
                xirr=xirr,
            )
            return True, f"Extreme negative returns ({xirr:.1f}%)"

        return False, None


moderation_service = ModerationService()
