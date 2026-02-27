"""
Portfolio Review endpoints (reviews table)
Handles typed reviews written on a specific portfolio.
Instrument/general opinions live in instrument_opinions.py (opinions table).
"""

import asyncio
from typing import Optional

import structlog
from app.api.dependencies import get_current_user, get_optional_user  # noqa: F401 (get_optional_user used in list_opinions)
from app.core.exceptions import PortfolioNotFoundError
from app.domain.schemas import (
    PortfolioOpinion,
    PortfolioOpinionCreate,
    PortfolioOpinionListResponse,
)
from app.infrastructure.redis_client import redis_client
from app.infrastructure.supabase_client import supabase_client
from app.services.social.reputation_service import ReputationService
from app.utils.sanitize import sanitize_html
from fastapi import APIRouter, Depends, HTTPException, status

logger = structlog.get_logger()

# Portfolio reviews are nested under /portfolios/{id}/opinions
portfolios_router = APIRouter()


@portfolios_router.post(
    "/{portfolio_id}/opinions",
    response_model=PortfolioOpinion,
    status_code=status.HTTP_201_CREATED,
)
async def create_opinion(
    portfolio_id: str,
    opinion_data: PortfolioOpinionCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new opinion/comment on a portfolio.

    Opinion types:
    - fundamental: Fundamental analysis
    - technical: Technical analysis
    - risk: Risk assessment
    - general: General feedback

    Content must be 20-1000 characters.
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

        # Sanitize content to prevent XSS attacks
        sanitized_content = sanitize_html(opinion_data.content)

        # Validate length after sanitization
        if len(sanitized_content) < 20:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Opinion content too short after sanitization (min 20 characters)",
            )

        if len(sanitized_content) > 1000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Opinion content too long (max 1000 characters)",
            )

        opinion_type_str = opinion_data.opinion_type if isinstance(opinion_data.opinion_type, str) else opinion_data.opinion_type.value
        opinion = await supabase_client.create_review(
            portfolio_id=portfolio_id,
            user_id=current_user["id"],
            opinion_type=opinion_type_str,
            content=sanitized_content,
        )

        # Get user profile for response (opinion already has user data from create method)
        user_profile = await supabase_client.get_user_profile(current_user["id"])

        # Invalidate opinions cache for this portfolio
        cache_key_pattern = f"opinions:portfolio:{portfolio_id}:*"
        await redis_client.delete(cache_key_pattern)

        # Trigger reputation update in background (async, non-blocking)
        asyncio.create_task(
            ReputationService.trigger_reputation_update(
                current_user["id"], supabase_client
            )
        )

        logger.info(
            "opinion_created",
            opinion_id=opinion["id"],
            portfolio_id=portfolio_id,
            user_id=current_user["id"],
            opinion_type=opinion_type_str,
        )

        return PortfolioOpinion(
            id=opinion["id"],
            portfolio_id=portfolio_id,
            user_id=current_user["id"],
            username=user_profile.get("username"),
            avatar_url=user_profile.get("avatar_url"),
            reputation_tier=user_profile.get("reputation_tier"),
            opinion_type=opinion_data.opinion_type,
            content=opinion["content"],
            helpful_count=opinion.get("helpful_count", 0),
            is_helpful_by_user=False,
            created_at=opinion["created_at"],
            updated_at=opinion["updated_at"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_opinion_error", error=str(e), portfolio_id=portfolio_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create opinion",
        )


@portfolios_router.get(
    "/{portfolio_id}/opinions",
    response_model=PortfolioOpinionListResponse,
)
async def list_opinions(
    portfolio_id: str,
    page: int = 1,
    page_size: int = 20,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    List all opinions for a portfolio.

    Returns opinions sorted by helpful_count (most helpful first),
    then by created_at (newest first).

    Cached for 5 minutes for performance.
    """
    try:
        # Check cache first
        cache_key = f"opinions:portfolio:{portfolio_id}:page:{page}:size:{page_size}"
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("opinions_cache_hit", portfolio_id=portfolio_id)
            return PortfolioOpinionListResponse(**cached_data)

        # Get portfolio reviews from database
        opinions_data, total = await supabase_client.list_portfolio_reviews(
            portfolio_id=portfolio_id,
            offset=(page - 1) * page_size,
            limit=page_size,
        )

        # Enrich with user profiles and vote status
        opinions = []
        for opinion_data in opinions_data:
            user_profile = await supabase_client.get_user_profile(
                opinion_data["user_id"]
            )

            # Check if current user voted helpful
            is_helpful = False
            if current_user:
                is_helpful = await supabase_client.check_user_voted_helpful(
                    opinion_id=opinion_data["id"],
                    user_id=current_user["id"],
                )

            opinions.append(
                PortfolioOpinion(
                    id=opinion_data["id"],
                    portfolio_id=portfolio_id,
                    user_id=opinion_data["user_id"],
                    username=user_profile.get("username"),
                    avatar_url=user_profile.get("avatar_url"),
                    reputation_tier=user_profile.get("reputation_tier"),
                    opinion_type=opinion_data["opinion_type"],
                    content=opinion_data["content"],
                    helpful_count=opinion_data.get("helpful_count", 0),
                    is_helpful_by_user=is_helpful,
                    created_at=opinion_data["created_at"],
                    updated_at=opinion_data["updated_at"],
                )
            )

        response = PortfolioOpinionListResponse(
            opinions=opinions,
            total=total,
            page=page,
            page_size=page_size,
        )

        # Cache for 5 minutes
        await redis_client.set(cache_key, response.dict(), expire=300)

        logger.info(
            "opinions_listed",
            portfolio_id=portfolio_id,
            count=len(opinions),
            total=total,
        )

        return response

    except Exception as e:
        logger.error("list_opinions_error", error=str(e), portfolio_id=portfolio_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list opinions",
        )


