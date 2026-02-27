"""
Trending Algorithm Service
Calculates trending scores for portfolios based on recent activity
"""

from datetime import datetime, timedelta
from typing import Any, Dict

import structlog

logger = structlog.get_logger()

# Weights for trending score components
VIEWS_WEIGHT = 0.2
REACTIONS_WEIGHT = 0.3
OPINIONS_WEIGHT = 0.3
RECENCY_WEIGHT = 0.2

# Time decay factor (portfolios lose trending score over time)
DECAY_HOURS = 72  # 3 days


class TrendingService:
    """Service for calculating trending scores"""

    @staticmethod
    def calculate_trending_score(
        views_count: int,
        reactions_count: int,
        opinions_count: int,
        created_at: str,
        current_time: datetime = None,
    ) -> float:
        """
        Calculate trending score for a portfolio.

        Formula:
        trending = (views * 0.2 + reactions * 0.3 + opinions * 0.3) * recency_multiplier

        Recency multiplier decays exponentially over DECAY_HOURS
        """
        if current_time is None:
            current_time = datetime.utcnow()

        # Parse created_at
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if created.tzinfo:
            current_time = current_time.replace(tzinfo=created.tzinfo)

        # Calculate age in hours
        age_hours = (current_time - created).total_seconds() / 3600

        # Calculate recency multiplier (exponential decay)
        # New portfolios get full multiplier, older ones decay
        recency_multiplier = max(0.1, 2 ** (-age_hours / DECAY_HOURS))

        # Calculate engagement score
        engagement_score = (
            (views_count * VIEWS_WEIGHT)
            + (reactions_count * REACTIONS_WEIGHT)
            + (opinions_count * OPINIONS_WEIGHT)
        )

        # Apply recency multiplier
        trending_score = engagement_score * recency_multiplier

        logger.debug(
            "trending_score_calculated",
            views=views_count,
            reactions=reactions_count,
            opinions=opinions_count,
            age_hours=age_hours,
            recency_multiplier=recency_multiplier,
            trending_score=trending_score,
        )

        return trending_score

    @staticmethod
    def get_time_decay_multiplier(age_hours: float) -> float:
        """
        Get time decay multiplier based on age.

        Exponential decay: 2^(-age_hours / DECAY_HOURS)
        - 0 hours: 1.0x
        - 24 hours: 0.63x
        - 48 hours: 0.40x
        - 72 hours: 0.25x
        - 144 hours: 0.06x
        """
        return max(0.1, 2 ** (-age_hours / DECAY_HOURS))
