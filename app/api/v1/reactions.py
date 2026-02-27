"""
Reactions API endpoints (Hearts/Likes)
Handles portfolio reactions with toggle functionality
"""

import asyncio
from typing import Optional

import structlog
from app.api.dependencies import get_current_user, get_optional_user
from app.core.exceptions import PortfolioNotFoundError
from app.infrastructure.redis_client import redis_client
from app.infrastructure.supabase_client import supabase_client
from app.services.social.reputation_service import ReputationService
from fastapi import APIRouter, Depends, HTTPException, status

logger = structlog.get_logger()
router = APIRouter(prefix="/portfolios", tags=["Reactions"])


@router.post("/{portfolio_id}/reactions")
async def toggle_reaction(
    portfolio_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Toggle reaction (heart/like) on a portfolio.

    If user already reacted, removes the reaction.
    If user hasn't reacted, adds a reaction.

    Returns the new state and updated count.
    """
    try:
        # Verify portfolio exists
        try:
            portfolio = await supabase_client.get_portfolio(portfolio_id)
        except PortfolioNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Portfolio not found",
            )

        # Check current reaction state
        has_reacted = await supabase_client.check_user_reacted(
            portfolio_id=portfolio_id,
            user_id=current_user["id"],
        )

        if has_reacted:
            # Remove reaction
            await supabase_client.remove_reaction(
                portfolio_id=portfolio_id,
                user_id=current_user["id"],
            )
            is_reacted = False
            logger.info(
                "reaction_removed",
                portfolio_id=portfolio_id,
                user_id=current_user["id"],
            )
        else:
            # Add reaction
            await supabase_client.add_reaction(
                portfolio_id=portfolio_id,
                user_id=current_user["id"],
            )
            is_reacted = True
            logger.info(
                "reaction_added",
                portfolio_id=portfolio_id,
                user_id=current_user["id"],
            )

        # Get updated count
        reactions_count = await supabase_client.get_reaction_count(portfolio_id)

        # Trigger reputation update for portfolio owner in background
        if portfolio and portfolio.get("user_id"):
            asyncio.create_task(
                ReputationService.trigger_reputation_update(
                    portfolio["user_id"], supabase_client
                )
            )

        # Invalidate caches
        await redis_client.delete(f"portfolio:{portfolio_id}")
        await redis_client.delete(f"reactions:{portfolio_id}:user:{current_user['id']}")

        return {
            "is_reacted": is_reacted,
            "reactions_count": reactions_count,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("toggle_reaction_error", error=str(e), portfolio_id=portfolio_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle reaction",
        )


@router.get("/{portfolio_id}/reactions")
async def get_reaction_status(
    portfolio_id: str,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Get reaction status for a portfolio.

    Returns reaction count and current user's reaction state (if authenticated).
    """
    try:
        # Check cache first (for authenticated users)
        if current_user:
            cache_key = f"reactions:{portfolio_id}:user:{current_user['id']}"
            cached_data = await redis_client.get(cache_key)
            if cached_data:
                logger.info("reactions_cache_hit", portfolio_id=portfolio_id)
                return cached_data

        # Verify portfolio exists
        try:
            portfolio = await supabase_client.get_portfolio(portfolio_id)
        except PortfolioNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Portfolio not found",
            )

        # Get reaction count
        reactions_count = await supabase_client.get_reaction_count(portfolio_id)

        # Check if current user reacted (if authenticated)
        is_reacted = False
        if current_user:
            is_reacted = await supabase_client.check_user_reacted(
                portfolio_id=portfolio_id,
                user_id=current_user["id"],
            )

        response = {
            "is_reacted": is_reacted,
            "reactions_count": reactions_count,
        }

        # Cache for 5 minutes
        if current_user:
            cache_key = f"reactions:{portfolio_id}:user:{current_user['id']}"
            await redis_client.set(cache_key, response, expire=300)

        logger.info(
            "reaction_status_fetched",
            portfolio_id=portfolio_id,
            is_reacted=is_reacted,
            count=reactions_count,
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "get_reaction_status_error", error=str(e), portfolio_id=portfolio_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get reaction status",
        )
