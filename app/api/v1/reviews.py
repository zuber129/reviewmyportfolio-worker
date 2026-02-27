"""Portfolio Reviews API endpoints for portfolio-scoped reviews."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
import structlog

from app.api.dependencies import get_current_user
from app.domain.schemas import (
    ReviewCreate,
    ReviewUpdate,
    Review,
    ReviewListResponse,
)
from app.infrastructure.supabase_client import SupabaseClient

logger = structlog.get_logger()
router = APIRouter()


@router.post("/portfolios/{portfolio_id}/reviews", response_model=Review, status_code=status.HTTP_201_CREATED)
async def create_review(
    portfolio_id: str,
    review_data: ReviewCreate,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Create a new review on a portfolio.
    Simple, lightweight feedback (1-500 chars).
    """
    user_id = current_user["id"]
    
    try:
        # Verify portfolio exists
        portfolio = await supabase.get_portfolio(portfolio_id)
        if not portfolio:
            raise HTTPException(status_code=404, detail="Portfolio not found")
        
        # Create review
        review = await supabase.create_review(
            user_id=user_id,
            portfolio_id=portfolio_id,
            content=review_data.content,
        )
        
        logger.info(
            "review_created",
            review_id=review["id"],
            user_id=user_id,
            portfolio_id=portfolio_id,
        )
        
        return review
    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_review_failed", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail=f"Failed to create review: {str(e)}")


@router.get("/portfolios/{portfolio_id}/reviews", response_model=ReviewListResponse)
async def get_portfolio_reviews(
    portfolio_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    supabase: SupabaseClient = Depends(),
):
    """
    Get reviews for a portfolio.
    """
    try:
        reviews = await supabase.get_portfolio_reviews(
            portfolio_id=portfolio_id,
            page=page,
            page_size=page_size,
        )
        
        return reviews
    except Exception as e:
        logger.error("get_portfolio_reviews_failed", error=str(e), portfolio_id=portfolio_id)
        raise HTTPException(status_code=500, detail=f"Failed to fetch reviews: {str(e)}")


@router.delete("/reviews/{review_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_review(
    review_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Delete own review (soft delete).
    """
    user_id = current_user["id"]
    
    try:
        # Check if review exists and belongs to user
        review = await supabase.get_review_by_id(review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        
        if review["user_id"] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own reviews"
            )
        
        await supabase.delete_review(review_id)
        
        logger.info("review_deleted", review_id=review_id, user_id=user_id)
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_review_failed", error=str(e), review_id=review_id)
        raise HTTPException(status_code=500, detail=f"Failed to delete review: {str(e)}")
