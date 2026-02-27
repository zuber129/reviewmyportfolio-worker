from datetime import datetime
from typing import Any, Dict, List

import structlog
from app.api.dependencies import get_optional_user
from app.domain.schemas import (
    ErrorResponse,
    LeaderboardEntry,
    LeaderboardRequest,
    LeaderboardResponse,
    TimeRange,
)
from app.infrastructure.redis_client import redis_client
from app.infrastructure.supabase_client import supabase_client
from fastapi import APIRouter, Depends, HTTPException, status

logger = structlog.get_logger()
router = APIRouter(prefix="/leaderboard", tags=["Leaderboard"])


@router.get("", response_model=LeaderboardResponse)
async def get_leaderboard(
    time_range: TimeRange = TimeRange.ALL_TIME,
    limit: int = 100,
    current_user: dict = Depends(get_optional_user),
):
    """
    Get the performance leaderboard with top portfolios by XIRR.
    Results are cached for improved performance.
    """
    try:
        from app.services.social.leaderboard_service import LeaderboardService

        # Create cache key
        cache_key = f"leaderboard:performance:{time_range}:{limit}"

        # Check cache first
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("leaderboard_cache_hit", key=cache_key)
            response = LeaderboardResponse(**cached_data)
            return response

        # Get leaderboard data using new service
        leaderboard_data = await LeaderboardService.get_performance_leaderboard(
            supabase_client=supabase_client,
            limit=limit,
            time_range=time_range.value,
        )

        # Transform to LeaderboardEntry schema
        entries = []
        for user_data in leaderboard_data:
            entry = LeaderboardEntry(
                rank=user_data.get("rank"),
                user_id=user_data.get("user_id"),
                username=user_data.get("username", "Unknown"),
                avatar_url=user_data.get("avatar_url"),
                xirr=user_data.get("best_xirr", 0.0),
                total_value=user_data.get("total_value", 0.0),
                portfolio_count=user_data.get("portfolio_count", 0),
                avg_rating=0.0,  # Not calculated for performance leaderboard
                tier=user_data.get("tier", "beginner"),
                badges=[],  # TODO: Implement badge fetching if needed
            )
            entries.append(entry)

        # Create response
        response = LeaderboardResponse(
            entries=entries, time_range=time_range, updated_at=datetime.utcnow()
        )

        # Cache the response for 5 minutes
        await redis_client.set(cache_key, response.dict(), expire=300)

        logger.info("leaderboard_fetched", time_range=time_range, count=len(entries))

        return response

    except Exception as e:
        logger.error("leaderboard_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch leaderboard",
        )


@router.get("/rankings", response_model=LeaderboardResponse)
async def get_rankings(
    request: LeaderboardRequest = Depends(),
    current_user: dict = Depends(get_optional_user),
):
    """
    Get the performance leaderboard rankings with custom parameters.
    This is an alternative endpoint with request body parameters.
    """
    try:
        from app.services.social.leaderboard_service import LeaderboardService

        # Create cache key
        cache_key = f"rankings:{request.time_range}:{request.limit}"

        # Check cache first
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("rankings_cache_hit", key=cache_key)
            return LeaderboardResponse(**cached_data)

        # Get leaderboard data using new service
        leaderboard_data = await LeaderboardService.get_performance_leaderboard(
            supabase_client=supabase_client,
            limit=request.limit,
            time_range=request.time_range.value,
        )

        # Transform to leaderboard entries
        entries = []
        for user_data in leaderboard_data:
            entry = LeaderboardEntry(
                rank=user_data.get("rank"),
                user_id=user_data.get("user_id"),
                username=user_data.get("username", "Unknown"),
                avatar_url=user_data.get("avatar_url"),
                xirr=user_data.get("best_xirr", 0.0),
                total_value=user_data.get("total_value", 0.0),
                portfolio_count=user_data.get("portfolio_count", 0),
                avg_rating=0.0,
                tier=user_data.get("tier", "beginner"),
                badges=[],
            )
            entries.append(entry)

        # Create response
        response = LeaderboardResponse(
            entries=entries, time_range=request.time_range, updated_at=datetime.utcnow()
        )

        # Cache for 5 minutes
        await redis_client.set(cache_key, response.dict(), expire=300)

        logger.info(
            "rankings_fetched", time_range=request.time_range, count=len(entries)
        )

        return response

    except Exception as e:
        logger.error("rankings_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch rankings",
        )


@router.get("/contribution")
async def get_contribution_leaderboard(
    time_range: str = "all_time",
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_optional_user),
):
    """
    Get contribution leaderboard ranked by opinions and helpful votes.

    Weighted Formula: (opinions * 5) + (helpful_votes_received * 3)
    Results are cached for 5 minutes.
    """
    try:
        from app.services.social.leaderboard_service import LeaderboardService

        # Check cache first
        cache_key = f"leaderboard:contribution:{time_range}:{limit}:{offset}"
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("contribution_leaderboard_cache_hit")
            return cached_data

        # Get from new service
        all_entries = await LeaderboardService.get_contribution_leaderboard(
            supabase_client=supabase_client,
            limit=limit + offset,  # Get extra for offset
            time_range=time_range,
        )

        # Apply offset pagination
        entries = all_entries[offset : offset + limit]

        # Adjust ranks after offset
        for entry in entries:
            entry["total_opinions"] = entry.pop("opinion_count")
            entry["total_helpful_votes"] = entry.pop("helpful_votes_received")

        response = {
            "entries": entries,
            "time_range": time_range,
            "updated_at": datetime.utcnow().isoformat(),
        }

        # Cache for 5 minutes
        await redis_client.set(cache_key, response, expire=300)

        logger.info(
            "contribution_leaderboard_fetched",
            count=len(entries),
            time_range=time_range,
        )

        return response

    except Exception as e:
        logger.error("contribution_leaderboard_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch contribution leaderboard",
        )


@router.get("/performance-1y", response_model=LeaderboardResponse)
async def get_1y_performance_leaderboard(
    limit: int = 100,
    min_history_days: int = 270,
    current_user: dict = Depends(get_optional_user),
):
    """
    Get 1-year performance leaderboard with time-bounded XIRR.

    Reduces survivorship bias by focusing on recent 12-month performance
    rather than all-time maximum returns.

    Eligibility:
    - Minimum 9 months of history (270 days by default)
    - At least 2 portfolio snapshots available
    - XIRR within bounds (-50% to 200%)
    - Not flagged as suspicious
    """
    try:
        from app.services.social.leaderboard_service import LeaderboardService

        # Create cache key
        cache_key = f"leaderboard:performance_1y:{limit}:{min_history_days}"

        # Check cache first
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("leaderboard_1y_cache_hit", key=cache_key)
            return LeaderboardResponse(**cached_data)

        # Get leaderboard data
        leaderboard_data = await LeaderboardService.get_1y_performance_leaderboard(
            supabase_client=supabase_client,
            limit=limit,
            min_history_days=min_history_days,
        )

        # Transform to LeaderboardEntry schema
        entries = []
        for user_data in leaderboard_data:
            entry = LeaderboardEntry(
                rank=user_data.get("rank"),
                user_id=user_data.get("user_id"),
                username=user_data.get("username", "Unknown"),
                avatar_url=user_data.get("avatar_url"),
                xirr=user_data.get("xirr_1y", 0.0),
                xirr_1y=user_data.get("xirr_1y"),
                consistency_score=user_data.get("consistency_score"),
                total_value=user_data.get("total_value", 0.0),
                portfolio_count=user_data.get("portfolio_count", 0),
                avg_rating=0.0,
                tier=user_data.get("tier", "beginner"),
                badges=[],
                data_points=user_data.get("data_points"),
                history_months=user_data.get("history_months"),
            )
            entries.append(entry)

        # Create response
        response = LeaderboardResponse(
            entries=entries, time_range=TimeRange.ALL_TIME, updated_at=datetime.utcnow()
        )

        # Cache for 10 minutes
        await redis_client.set(cache_key, response.dict(), expire=600)

        logger.info("leaderboard_1y_fetched", count=len(entries))

        return response

    except Exception as e:
        logger.error("leaderboard_1y_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch 1-year performance leaderboard",
        )


@router.get("/consistency", response_model=LeaderboardResponse)
async def get_consistency_leaderboard(
    limit: int = 100,
    min_snapshots: int = 6,
    current_user: dict = Depends(get_optional_user),
):
    """
    Get consistency leaderboard ranked by stability of returns.

    Rewards portfolios with steady, reliable performance over time
    rather than volatile spikes.

    Eligibility:
    - Minimum 6 portfolio snapshots
    - At least 6 months of history
    - Not flagged as suspicious
    """
    try:
        from app.services.social.leaderboard_service import LeaderboardService

        # Create cache key
        cache_key = f"leaderboard:consistency:{limit}:{min_snapshots}"

        # Check cache first
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("leaderboard_consistency_cache_hit", key=cache_key)
            return LeaderboardResponse(**cached_data)

        # Get leaderboard data
        leaderboard_data = await LeaderboardService.get_consistency_leaderboard(
            supabase_client=supabase_client,
            limit=limit,
            min_snapshots=min_snapshots,
        )

        # Transform to LeaderboardEntry schema
        entries = []
        for user_data in leaderboard_data:
            entry = LeaderboardEntry(
                rank=user_data.get("rank"),
                user_id=user_data.get("user_id"),
                username=user_data.get("username", "Unknown"),
                avatar_url=user_data.get("avatar_url"),
                xirr=user_data.get(
                    "consistency_score", 0.0
                ),  # Use consistency as main metric
                xirr_1y=user_data.get("xirr_1y"),
                consistency_score=user_data.get("consistency_score"),
                total_value=user_data.get("total_value", 0.0),
                portfolio_count=user_data.get("portfolio_count", 0),
                avg_rating=0.0,
                tier=user_data.get("tier", "beginner"),
                badges=[],
                data_points=user_data.get("data_points"),
                history_months=user_data.get("history_months"),
            )
            entries.append(entry)

        # Create response
        response = LeaderboardResponse(
            entries=entries, time_range=TimeRange.ALL_TIME, updated_at=datetime.utcnow()
        )

        # Cache for 10 minutes
        await redis_client.set(cache_key, response.dict(), expire=600)

        logger.info("leaderboard_consistency_fetched", count=len(entries))

        return response

    except Exception as e:
        logger.error("leaderboard_consistency_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch consistency leaderboard",
        )


@router.post("/refresh", status_code=status.HTTP_204_NO_CONTENT)
async def refresh_leaderboard_cache():
    """
    Admin endpoint to refresh the leaderboard cache.
    Should be protected with admin authentication in production.
    """
    try:
        # Clear all leaderboard cache keys
        await redis_client.delete("leaderboard:*")
        await redis_client.delete("rankings:*")

        logger.info("leaderboard_cache_cleared")

    except Exception as e:
        logger.error("cache_clear_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear cache",
        )
