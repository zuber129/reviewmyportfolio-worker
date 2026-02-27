"""
Reputation Calculation Service
Implements the 4-axis reputation system:
  - Performance (0-100): XIRR-based, scaled to 0-100
  - Portfolio Quality (0-100): Diversification + position sizing + thesis
  - Community Impact (0-100): Weighted helpful votes + opinion quality
  - Trust & Activity (0-100): Verification + no-spam + recency

Composite: R = 0.4 * Performance + 0.2 * Portfolio Quality + 0.2 * Community + 0.2 * Trust
"""

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()

# Composite weights (must sum to 1.0)
PERFORMANCE_WEIGHT = 0.4
PORTFOLIO_QUALITY_WEIGHT = 0.2
COMMUNITY_WEIGHT = 0.2
TRUST_WEIGHT = 0.2

# Tier thresholds (composite score 0-100)
TIER_THRESHOLDS = {
    "newcomer": 0,
    "contributor": 21,
    "trusted": 41,
    "expert": 61,
    "legend": 81,
}

# Minimum axis scores required to unlock each tier
TIER_AXIS_REQUIREMENTS: Dict[str, Dict[str, int]] = {
    "contributor": {"community_score": 30, "trust_score": 20},
    "trusted": {"performance_score": 40, "trust_score": 40},
    "expert": {"performance_score": 60, "community_score": 50},
    "legend": {
        "performance_score": 70,
        "portfolio_quality_score": 70,
        "community_score": 70,
        "trust_score": 70,
    },
}


class ReputationService:
    """Service for calculating and managing user reputation using the 4-axis model."""

    # ------------------------------------------------------------------
    # Axis 1: Performance Score (0-100)
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_performance_score(
        xirr_1y: Optional[float],
        portfolio_xirr: Optional[float],
        total_value: Optional[float],
        history_months: Optional[int],
    ) -> int:
        """
        Calculate performance score (0-100) from XIRR data.

        Formula: min(100, max(0, xirr * 2.5))
        where xirr is in percentage points (e.g. 20.0 for 20%).

        Down-weight by 50% if:
        - portfolio_value < 100,000 (INR)
        - history < 9 months

        Falls back to portfolio.xirr if xirr_1y is None.
        """
        xirr = xirr_1y if xirr_1y is not None else portfolio_xirr
        if xirr is None:
            return 0

        raw_score = min(100.0, max(0.0, xirr * 2.5))

        # Apply down-weight for small portfolios or short history
        down_weight = False
        if total_value is not None and total_value < 100_000:
            down_weight = True
        if history_months is not None and history_months < 9:
            down_weight = True

        if down_weight:
            raw_score *= 0.5

        return int(raw_score)

    # ------------------------------------------------------------------
    # Axis 2: Portfolio Quality Score (0-100) — delegated to service
    # ------------------------------------------------------------------
    # Handled by PortfolioQualityService; imported in trigger_reputation_update.

    # ------------------------------------------------------------------
    # Axis 3: Community Impact Score (0-100)
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_community_score(
        opinions: List[Dict[str, Any]],
        voter_reputations: Optional[Dict[str, int]] = None,
    ) -> int:
        """
        Calculate community impact score (0-100).

        Component 1 – Weighted Helpful Votes (0-60):
          weighted_sum = sum(vote_count * voter_rep/100 * time_decay)
          time_decay   = exp(-0.01 * days_old)
          score        = min(60, sqrt(weighted_sum) * 6)

        Component 2 – Opinion Quality (0-40):
          base = min(40, opinion_count * 4)  (diminishing returns)
          bonus for opinions with > 10 helpful votes (+5 each, capped)
          penalty for hidden opinions (-10 each)
        """
        if not opinions:
            return 0

        now = datetime.now(timezone.utc)
        voter_reputations = voter_reputations or {}

        # Component 1: weighted helpful votes
        weighted_sum = 0.0
        for opinion in opinions:
            vote_count = opinion.get("helpful_count", 0)
            if vote_count <= 0:
                continue

            created_at_raw = opinion.get("created_at")
            days_old = 0
            if created_at_raw:
                try:
                    created_at = datetime.fromisoformat(
                        str(created_at_raw).replace("Z", "+00:00")
                    )
                    days_old = max(0, (now - created_at).days)
                except (ValueError, TypeError):
                    days_old = 0

            time_decay = math.exp(-0.01 * days_old)
            # Minimum 10% weight so old content never fully disappears
            time_decay = max(0.1, time_decay)

            voter_weight = voter_reputations.get(opinion.get("id", ""), 50) / 100.0
            weighted_sum += vote_count * voter_weight * time_decay

        helpful_component = min(60, int(math.sqrt(weighted_sum) * 6))

        # Component 2: opinion quality
        opinion_count = len(opinions)
        base_quality = min(40, opinion_count * 4)

        bonus = 0
        penalty = 0
        for opinion in opinions:
            if opinion.get("helpful_count", 0) > 10:
                bonus = min(bonus + 5, 20)  # cap bonus at 20
            if opinion.get("moderation_status") == "hidden":
                penalty += 10

        quality_component = max(0, min(40, base_quality + bonus - penalty))

        total = helpful_component + quality_component
        return max(0, min(100, total))

    # ------------------------------------------------------------------
    # Axis 4: Trust & Activity Score (0-100)
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_trust_score(
        has_pii: bool,
        is_suspicious: bool,
        last_portfolio_upload_at: Optional[str],
        last_comment_or_vote_at: Optional[str] = None,
    ) -> int:
        """
        Calculate trust & activity score (0-100).

        Component 1 – Verification (0-40):
          Has encrypted PII (holder_name + pan_last4) = 40 pts

        Component 2 – Data Consistency (0-20):
          No suspicious flags = 20 pts

        Component 3 – Activity Recency (0-40):
          Last upload within 30 days = 40 pts
          30-60 days = linear decay to 0
          >60 days   = 0 pts
          Bonus: +10 if commented/voted in last 7 days (capped at 40)
        """
        # Component 1: verification
        verification = 40 if has_pii else 0

        # Component 2: data consistency
        consistency = 0 if is_suspicious else 20

        # Component 3: activity recency
        recency = 0
        now = datetime.now(timezone.utc)

        if last_portfolio_upload_at:
            try:
                last_upload = datetime.fromisoformat(
                    last_portfolio_upload_at.replace("Z", "+00:00")
                )
                days_since = max(0, (now - last_upload).days)

                if days_since <= 30:
                    recency = 40
                elif days_since <= 60:
                    recency = int(40 * (60 - days_since) / 30)
                else:
                    recency = 0
            except (ValueError, TypeError):
                recency = 0

        # Bonus for recent engagement (comments/votes in last 7 days)
        if last_comment_or_vote_at:
            try:
                last_active = datetime.fromisoformat(
                    last_comment_or_vote_at.replace("Z", "+00:00")
                )
                days_since_active = max(0, (now - last_active).days)
                if days_since_active <= 7:
                    recency = min(40, recency + 10)
            except (ValueError, TypeError):
                pass

        total = verification + consistency + recency
        return max(0, min(100, total))

    # ------------------------------------------------------------------
    # Composite Score & Tier
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_composite_score(
        performance_score: int,
        portfolio_quality_score: int,
        community_score: int,
        trust_score: int,
    ) -> int:
        """
        Calculate composite reputation score (0-100).

        R = 0.4 * Performance + 0.2 * Portfolio Quality + 0.2 * Community + 0.2 * Trust
        """
        composite = (
            performance_score * PERFORMANCE_WEIGHT
            + portfolio_quality_score * PORTFOLIO_QUALITY_WEIGHT
            + community_score * COMMUNITY_WEIGHT
            + trust_score * TRUST_WEIGHT
        )
        return max(0, min(100, int(composite)))

    @staticmethod
    def determine_tier(
        reputation_score: int,
        performance_score: int = 0,
        portfolio_quality_score: int = 0,
        community_score: int = 0,
        trust_score: int = 0,
    ) -> str:
        """
        Determine reputation tier based on composite score and axis requirements.

        Tiers (composite score):
        - newcomer    (0-20)
        - contributor (21-40): requires Community >= 30, Trust >= 20
        - trusted     (41-60): requires Performance >= 40, Trust >= 40
        - expert      (61-80): requires Performance >= 60, Community >= 50
        - legend      (81-100): requires all axes >= 70
        """
        axis_scores = {
            "performance_score": performance_score,
            "portfolio_quality_score": portfolio_quality_score,
            "community_score": community_score,
            "trust_score": trust_score,
        }

        # Walk tiers from highest to lowest
        for tier in ("legend", "expert", "trusted", "contributor"):
            threshold = TIER_THRESHOLDS[tier]
            if reputation_score < threshold:
                continue

            # Check axis requirements
            requirements = TIER_AXIS_REQUIREMENTS.get(tier, {})
            meets_requirements = all(
                axis_scores.get(axis, 0) >= min_val
                for axis, min_val in requirements.items()
            )
            if meets_requirements:
                return tier

        return "newcomer"

    # ------------------------------------------------------------------
    # Legacy compatibility (kept for backward-compat callers)
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_total_reputation(
        portfolios: List[Dict[str, Any]],
        opinion_count: int,
        helpful_votes_given: int,
        reactions_received: int,
        helpful_votes_received: int,
    ) -> int:
        """
        Legacy method: returns composite reputation score (0-100).
        Kept for backward compatibility with existing callers.
        """
        # Performance: use best XIRR from portfolios
        xirrs: List[float] = [p["xirr"] for p in portfolios if p.get("xirr") is not None]
        best_xirr: Optional[float] = max(xirrs) if xirrs else None
        performance = ReputationService.calculate_performance_score(
            xirr_1y=None,
            portfolio_xirr=best_xirr,
            total_value=None,
            history_months=None,
        )

        # Community: build minimal opinion dicts from counts
        opinions = [{"helpful_count": helpful_votes_received, "created_at": None}]
        community = ReputationService.calculate_community_score(opinions)

        # Trust: no PII info available in legacy call, assume 0
        trust = 0

        # Portfolio quality: no holdings in legacy call, assume 0
        portfolio_quality = 0

        return ReputationService.calculate_composite_score(
            performance_score=performance,
            portfolio_quality_score=portfolio_quality,
            community_score=community,
            trust_score=trust,
        )

    # ------------------------------------------------------------------
    # Async trigger (full 4-axis update)
    # ------------------------------------------------------------------

    @staticmethod
    async def trigger_reputation_update(user_id: str, supabase_client):
        """
        Trigger full 4-axis reputation update for a user asynchronously.
        Called after portfolio upload, opinion post, helpful vote, or reaction.

        This runs in the background and doesn't block the main request.
        """
        try:
            from app.services.social.portfolio_quality_service import PortfolioQualityService

            # Get user's portfolios with holdings
            portfolios_response = (
                supabase_client.client.table("portfolios")
                .select("id, xirr, total_value, investment_thesis, encrypted_holder_name, encrypted_pan_last4, holdings(percentage)")
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .execute()
            )
            portfolios = portfolios_response.data or []

            # Get user profile for xirr_1y, last_portfolio_upload_at, activity
            profile_response = (
                supabase_client.client.table("profiles")
                .select("xirr_1y, last_portfolio_upload_at, updated_at")
                .eq("id", user_id)
                .single()
                .execute()
            )
            profile = profile_response.data or {}

            # Get opinions with helpful counts (opinions table replaced comments)
            opinions_response = (
                supabase_client.client.table("opinions")
                .select("id, helpful_count, created_at")
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .execute()
            )
            opinions = opinions_response.data or []

            # Check for suspicious portfolios
            is_suspicious = any(p.get("is_suspicious", False) for p in portfolios)

            # --- Axis 1: Performance ---
            xirr_1y = profile.get("xirr_1y")
            best_portfolio_xirr = (
                max((p.get("xirr") for p in portfolios if p.get("xirr") is not None), default=None)
            )
            total_value = sum(p.get("total_value", 0) for p in portfolios)
            performance_score = ReputationService.calculate_performance_score(
                xirr_1y=xirr_1y,
                portfolio_xirr=best_portfolio_xirr,
                total_value=total_value if total_value > 0 else None,
                history_months=None,
            )

            # --- Axis 2: Portfolio Quality ---
            portfolio_quality_score = PortfolioQualityService.calculate_best_portfolio_quality(
                portfolios
            )

            # --- Axis 3: Community Impact ---
            community_score = ReputationService.calculate_community_score(opinions)

            # --- Axis 4: Trust & Activity ---
            # PII fields (encrypted_holder_name, encrypted_pan_last4) live on portfolios
            has_pii = any(
                p.get("encrypted_holder_name") and p.get("encrypted_pan_last4")
                for p in portfolios
            )
            last_upload_at = profile.get("last_portfolio_upload_at")
            last_active_at = profile.get("updated_at")
            trust_score = ReputationService.calculate_trust_score(
                has_pii=has_pii,
                is_suspicious=is_suspicious,
                last_portfolio_upload_at=last_upload_at,
                last_comment_or_vote_at=last_active_at,
            )

            # --- Composite ---
            reputation_score = ReputationService.calculate_composite_score(
                performance_score=performance_score,
                portfolio_quality_score=portfolio_quality_score,
                community_score=community_score,
                trust_score=trust_score,
            )

            # --- Tier ---
            reputation_tier = ReputationService.determine_tier(
                reputation_score=reputation_score,
                performance_score=performance_score,
                portfolio_quality_score=portfolio_quality_score,
                community_score=community_score,
                trust_score=trust_score,
            )

            # Update profile
            supabase_client.client.table("profiles").update(
                {
                    "reputation_score": reputation_score,
                    "reputation_tier": reputation_tier,
                    "performance_score": performance_score,
                    "portfolio_quality_score": portfolio_quality_score,
                    "community_score": community_score,
                    "trust_score": trust_score,
                }
            ).eq("id", user_id).execute()

            logger.info(
                "reputation_auto_updated",
                user_id=user_id,
                score=reputation_score,
                tier=reputation_tier,
                performance=performance_score,
                portfolio_quality=portfolio_quality_score,
                community=community_score,
                trust=trust_score,
            )

        except Exception as e:
            # Log but don't fail the main request
            logger.error("reputation_auto_update_failed", user_id=user_id, error=str(e))
