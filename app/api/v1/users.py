"""
User-related API endpoints
Includes access control and user profile management
"""

from datetime import datetime, timedelta
from typing import Optional

import structlog
from app.api.dependencies import get_current_user
from app.core.decorators import require_proxy_caller
from app.domain.schemas import (
    AccessStatusResponse,
    DashboardStats,
    RecentPortfolio,
    ReputationRadar,
    ReputationResponse,
    UserSearchResult,
)
from app.infrastructure.supabase_client import supabase_client
from app.services.social.reputation_service import ReputationService
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from typing import List

logger = structlog.get_logger()
router = APIRouter(prefix="/users", tags=["Users"])

# Access control constants
ACCESS_PERIOD_DAYS = 60
WARNING_THRESHOLD_DAYS = 14


@router.get("/me/dashboard", response_model=DashboardStats)
@require_proxy_caller
async def get_dashboard_stats(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Get dashboard quick stats for current user.
    
    Must be called via UI proxy.

    Returns:
    - portfolio_count: Total portfolios uploaded
    - recent_portfolios: Last 3 uploads
    - total_reactions_received: Total reactions on all portfolios
    - total_opinions_given: Total opinions written
    - total_helpful_votes_received: Total helpful votes on opinions
    - access_status: Current access status
    """
    try:
        user_id = current_user["id"]

        # Get portfolio count and recent uploads
        portfolios_response = (
            supabase_client.client.table("portfolios")
            .select("id, title, created_at, total_value, xirr")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .order("created_at", desc=True)
            .limit(100)
            .execute()
        )

        portfolios = portfolios_response.data or []
        portfolio_count = len(portfolios)
        recent_portfolios = [
            RecentPortfolio(
                id=p["id"],
                title=p["title"],
                created_at=p["created_at"],
                total_value=p["total_value"],
                xirr=p.get("xirr"),
            )
            for p in portfolios[:3]
        ]

        # Get access status, reputation, and all pre-computed snapshots from profile (single read)
        from app.services.social.leaderboard_service import LeaderboardService
        from app.utils.access_control import compute_access_status, get_access_info

        profile = await supabase_client.get_user_profile(user_id)
        profile_with_access = get_access_info(profile)

        # Read pre-computed snapshot counters — updated by DB triggers on comment/reaction changes
        total_reactions_received = profile.get("total_reactions_received", 0)
        total_opinions_given = profile.get("total_reviews_given", 0)
        total_helpful_votes_received = 0
        portfolios_rated = profile.get("portfolios_reviewed_count", 0)

        # Reputation and 4-axis scores (also pre-computed snapshots)
        reputation_score = profile.get("reputation_score", 0)
        reputation_tier = profile.get("reputation_tier", "newcomer")
        performance_score = profile.get("performance_score", 0)
        portfolio_quality_score = profile.get("portfolio_quality_score", 0)
        community_score = profile.get("community_score", 0)
        trust_score = profile.get("trust_score", 0)

        # Calculate ranks (async, may be slow - consider caching)
        performance_rank = await LeaderboardService.get_user_performance_rank(
            supabase_client=supabase_client, user_id=user_id
        )
        contribution_rank = await LeaderboardService.get_user_contribution_rank(
            supabase_client=supabase_client, user_id=user_id
        )

        # Get streak data from profiles table (calculated async by triggers)
        current_streak = profile.get("current_streak", 0)
        longest_streak = profile.get("longest_streak", 0)

        logger.info(
            "dashboard_stats_fetched",
            user_id=user_id,
            portfolio_count=portfolio_count,
            opinions=total_opinions_given,
            portfolios_rated=portfolios_rated,
            access_status=profile_with_access["access_status"],
            reputation_tier=reputation_tier,
            reputation_score=reputation_score,
            performance_rank=performance_rank,
            contribution_rank=contribution_rank,
        )

        return DashboardStats(
            portfolio_count=portfolio_count,
            recent_portfolios=recent_portfolios,
            total_reactions_received=total_reactions_received,
            total_opinions_given=total_opinions_given,
            total_helpful_votes_received=total_helpful_votes_received,
            access_status=profile_with_access["access_status"],
            days_until_restricted=profile_with_access["days_until_restricted"],
            days_until_blocked=profile_with_access["days_until_blocked"],
            can_browse_feed=profile_with_access["can_browse_feed"],
            reputation_score=reputation_score,
            reputation_tier=reputation_tier,
            performance_rank=performance_rank,
            contribution_rank=contribution_rank,
            reputation_radar=ReputationRadar(
                performance_score=performance_score,
                portfolio_quality_score=portfolio_quality_score,
                community_score=community_score,
                trust_score=trust_score,
            ),
            current_streak=current_streak,
            longest_streak=longest_streak,
            portfolios_rated=portfolios_rated,
        )

    except Exception as e:
        logger.error(
            "get_dashboard_stats_error", error=str(e), user_id=current_user["id"]
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get dashboard stats",
        )


@router.get("/me/access-status", response_model=AccessStatusResponse)
async def get_access_status(
    current_user: dict = Depends(get_current_user),
):
    """
    Get user's access status based on 60-day upload rule with 14-day grace period.

    Policy:
    - Days 0-60: ACTIVE - Full access
    - Days 61-74: RESTRICTED - Grace period, show warning
    - Days 75+: BLOCKED - No feed access, upload required

    Returns:
    - status: "active" | "restricted" | "blocked"
    - days_until_restricted: Days remaining in active window (None if not active)
    - days_until_blocked: Days remaining in grace period (None if not restricted)
    - can_browse_feed: bool - Whether user can access feed
    - requires_upload: bool - Whether upload is required to restore access
    - last_upload_date: str | null - ISO date of last upload
    - message: Human-readable status message
    """
    try:
        from app.utils.access_control import compute_access_status

        # Get user profile
        profile = await supabase_client.get_user_profile(current_user["id"])
        last_upload_str = profile.get("last_portfolio_upload_at")

        # Parse last upload date if present
        last_upload = None
        if last_upload_str:
            last_upload = datetime.fromisoformat(last_upload_str.replace("Z", "+00:00"))

        # Compute access status using centralized logic
        result = compute_access_status(last_upload)

        # Generate message
        if result.status == "active":
            if result.days_since_last_upload is None:
                message = f"Welcome! You have {result.days_until_restricted} days to upload your first portfolio."
            else:
                message = f"Access active. {result.days_until_restricted} days remaining until grace period."
        elif result.status == "restricted":
            message = f"Grace period active. Upload within {result.days_until_blocked} days to avoid account block."
        else:  # blocked
            days_over = (
                result.days_since_last_upload - 74
                if result.days_since_last_upload
                else 0
            )
            message = f"Account blocked. Upload a portfolio to restore access (blocked {days_over} days ago)."

        logger.info(
            "access_status_checked",
            user_id=current_user["id"],
            status=result.status,
            days_until_restricted=result.days_until_restricted,
            days_until_blocked=result.days_until_blocked,
        )

        return AccessStatusResponse(
            access_status=result.status,
            can_upload=not result.requires_upload,
            can_browse_feed=result.can_browse_feed,
            days_until_restricted=result.days_until_restricted,
            days_until_blocked=result.days_until_blocked,
            last_upload_date=last_upload,
            message=message,
        )

    except Exception as e:
        logger.error(
            "get_access_status_error", error=str(e), user_id=current_user["id"]
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get access status",
        )


@router.post("/me/reputation/calculate", response_model=ReputationResponse)
async def calculate_reputation(
    current_user: dict = Depends(get_current_user),
):
    """
    Calculate and update 4-axis reputation score for current user.

    Composite: R = 0.4*Performance + 0.2*Portfolio Quality + 0.2*Community + 0.2*Trust

    Triggers the full async reputation update and returns the result.
    """
    try:
        user_id = current_user["id"]

        # Trigger full 4-axis reputation update
        await ReputationService.trigger_reputation_update(user_id, supabase_client)

        # Read back updated profile
        profile = await supabase_client.get_user_profile(user_id)
        reputation_score = profile.get("reputation_score", 0)

        # Get opinion count for response (opinions table replaced comments)
        opinions_response = (
            supabase_client.client.table("opinions")
            .select("id, helpful_count")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .execute()
        )
        opinions = opinions_response.data or []
        opinion_count = len(opinions)
        helpful_votes_received = sum(op.get("helpful_count", 0) for op in opinions)

        # Get portfolios for avg rating
        portfolios_response = (
            supabase_client.client.table("portfolios")
            .select("id, xirr")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .execute()
        )
        portfolios = portfolios_response.data or []
        avg_rating = (
            sum(p.get("xirr", 0) for p in portfolios) / len(portfolios)
            if portfolios
            else 0.0
        )

        logger.info(
            "reputation_calculated",
            user_id=user_id,
            score=reputation_score,
            tier=profile.get("reputation_tier", "newcomer"),
        )

        return ReputationResponse(
            reputation_score=reputation_score,
            total_reviews=opinion_count,
            avg_rating=avg_rating,
            helpful_votes=helpful_votes_received,
            rank=None,
        )

    except Exception as e:
        logger.error(
            "calculate_reputation_error", error=str(e), user_id=current_user["id"]
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to calculate reputation",
        )


@router.get("/search", response_model=List[UserSearchResult])
async def search_users(
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(6, ge=1, le=20, description="Maximum results"),
):
    """
    Search users by username for @mentions.
    Returns username, avatar, and reputation tier.
    """
    try:
        # Search profiles by username (case-insensitive)
        response = (
            supabase_client.client.table("profiles")
            .select("username, avatar_url, reputation_tier")
            .ilike("username", f"%{q}%")
            .limit(limit)
            .execute()
        )
        
        users = [
            UserSearchResult(
                username=user["username"],
                avatar_url=user.get("avatar_url"),
                reputation_tier=user.get("reputation_tier"),
            )
            for user in response.data
        ]
        
        return users
    except Exception as e:
        logger.error("search_users_error", error=str(e), query=q)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search users",
        )


@router.get("/{user_id}/badges")
async def get_user_badges(
    user_id: str,
):
    """
    Get badges earned by a user.
    
    TODO: Implement full badge system with database tables.
    This is a stub endpoint to prevent 404 errors in frontend.
    """
    try:
        # Stub response - return empty badges for now
        # In future, query badges table and join with user_badges
        logger.info("get_user_badges_stub", user_id=user_id)
        
        return {
            "badges": []
        }
    except Exception as e:
        logger.error("get_user_badges_error", error=str(e), user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch badges",
        )


@router.get("/{user_id}/challenges")
async def get_user_challenges(
    user_id: str,
):
    """
    Get active challenges for a user.
    
    TODO: Implement full challenge system with database tables.
    This is a stub endpoint to prevent 404 errors in frontend.
    """
    try:
        # Stub response - return empty challenges for now
        # In future, query challenges table and join with user_challenges
        logger.info("get_user_challenges_stub", user_id=user_id)
        
        return {
            "challenges": []
        }
    except Exception as e:
        logger.error("get_user_challenges_error", error=str(e), user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch challenges",
        )
