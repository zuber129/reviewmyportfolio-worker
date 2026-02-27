"""Instrument Opinions API endpoints for instrument-scoped opinions with threading."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
import structlog

from app.api.dependencies import get_current_user, get_optional_user
from app.domain.schemas import (
    OpinionCreate,
    OpinionUpdate,
    Opinion,
    OpinionListResponse,
    ReportCreate,
)
from app.infrastructure.supabase_client import SupabaseClient
from app.services.social.reputation_service import ReputationService

logger = structlog.get_logger()
router = APIRouter()

# Minimum reputation score required to post opinions (Skilled tier)
MIN_REPUTATION_FOR_OPINIONS = 500


@router.post("", response_model=Opinion, status_code=status.HTTP_201_CREATED)
async def create_opinion(
    opinion_data: OpinionCreate,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Create a new opinion on an instrument.
    Requires Skilled tier (reputation >= 500).
    Supports threading up to 3 levels deep.
    """
    user_id = current_user["id"]
    
    try:
        # Check reputation requirement
        reputation_service = ReputationService(supabase)
        user_reputation = await reputation_service.get_user_reputation(user_id)
        
        if user_reputation.get("reputation_score", 0) < MIN_REPUTATION_FOR_OPINIONS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You need Skilled tier (reputation >= {MIN_REPUTATION_FOR_OPINIONS}) to post opinions. "
                       "Build reputation by commenting on portfolios."
            )
        
        # Verify instrument exists (if provided)
        if opinion_data.instrument_id:
            instrument = await supabase.get_instrument_by_id(opinion_data.instrument_id)
            if not instrument:
                raise HTTPException(status_code=404, detail="Instrument not found")
        
        # If replying, verify parent exists and check depth
        if opinion_data.parent_id:
            parent = await supabase.get_opinion_by_id(opinion_data.parent_id)
            if not parent:
                raise HTTPException(status_code=404, detail="Parent opinion not found")
            
            if parent.get("thread_depth", 0) >= 3:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Maximum thread depth (3) reached. Use @username to continue discussion."
                )
        
        # Create opinion
        opinion = await supabase.create_opinion(
            user_id=user_id,
            instrument_id=opinion_data.instrument_id,  # May be None
            content=opinion_data.content,
            opinion_type=opinion_data.opinion_type.value,
            parent_id=opinion_data.parent_id,
        )
        
        logger.info(
            "opinion_created",
            opinion_id=opinion["id"],
            user_id=user_id,
            instrument_id=opinion_data.instrument_id,
            opinion_type=opinion_data.opinion_type.value,
        )
        
        return opinion
    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_opinion_failed", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail=f"Failed to create opinion: {str(e)}")


@router.get("/feed", response_model=OpinionListResponse)
async def get_opinions_feed(
    opinion_type: Optional[str] = Query(None, description="Filter by opinion type"),
    sort_by: str = Query("newest", description="Sort by: newest, most_helpful"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: Optional[dict] = Depends(get_optional_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Get a paginated feed of all opinions (not filtered by instrument).
    """
    try:
        user_id = current_user["id"] if current_user else None
        result = await supabase.get_all_opinions(
            opinion_type=opinion_type,
            sort_by=sort_by,
            page=page,
            page_size=page_size,
            user_id=user_id,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_opinions_feed_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to fetch opinions feed: {str(e)}")


@router.get("/instruments/{symbol}", response_model=OpinionListResponse)
async def get_instrument_opinions(
    symbol: str,
    opinion_type: Optional[str] = Query(None, description="Filter by opinion type"),
    sort_by: str = Query("newest", description="Sort by: newest, most_helpful"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: Optional[dict] = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Get opinions for an instrument by symbol.
    Returns threaded opinions with replies nested.
    """
    try:
        # Resolve symbol to instrument
        instrument = await supabase.get_instrument_by_symbol(symbol)
        if not instrument:
            raise HTTPException(status_code=404, detail="Instrument not found")
        
        user_id = current_user["id"] if current_user else None
        
        opinions = await supabase.get_instrument_opinions(
            instrument_id=instrument["id"],
            opinion_type=opinion_type,
            sort_by=sort_by,
            page=page,
            page_size=page_size,
            user_id=user_id,
        )
        
        return opinions
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_instrument_opinions_failed", error=str(e), symbol=symbol)
        raise HTTPException(status_code=500, detail=f"Failed to fetch opinions: {str(e)}")


@router.post("/{opinion_id}/helpful", status_code=status.HTTP_200_OK)
async def toggle_helpful_vote(
    opinion_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Toggle helpful vote on an opinion.
    """
    user_id = current_user["id"]
    
    try:
        # Check if opinion exists
        opinion = await supabase.get_opinion_by_id(opinion_id)
        if not opinion:
            raise HTTPException(status_code=404, detail="Opinion not found")
        
        # Toggle vote
        result = await supabase.toggle_opinion_helpful_vote(
            opinion_id=opinion_id,
            user_id=user_id,
        )
        
        logger.info(
            "opinion_helpful_vote_toggled",
            opinion_id=opinion_id,
            user_id=user_id,
            action=result["action"],
        )
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error("toggle_helpful_vote_failed", error=str(e), opinion_id=opinion_id)
        raise HTTPException(status_code=500, detail=f"Failed to toggle vote: {str(e)}")


@router.delete("/{opinion_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_opinion(
    opinion_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Delete own opinion (soft delete).
    """
    user_id = current_user["id"]
    
    try:
        # Check if opinion exists and belongs to user
        opinion = await supabase.get_opinion_by_id(opinion_id)
        if not opinion:
            raise HTTPException(status_code=404, detail="Opinion not found")
        
        if opinion["user_id"] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own opinions"
            )
        
        await supabase.delete_opinion(opinion_id)
        
        logger.info("opinion_deleted", opinion_id=opinion_id, user_id=user_id)
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_opinion_failed", error=str(e), opinion_id=opinion_id)
        raise HTTPException(status_code=500, detail=f"Failed to delete opinion: {str(e)}")


@router.post("/{opinion_id}/report", status_code=status.HTTP_201_CREATED)
async def report_opinion(
    opinion_id: str,
    report_data: ReportCreate,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Report an opinion for moderation.
    """
    user_id = current_user["id"]
    
    try:
        # Check if opinion exists
        opinion = await supabase.get_opinion_by_id(opinion_id)
        if not opinion:
            raise HTTPException(status_code=404, detail="Opinion not found")
        
        # Create report
        report = await supabase.create_report(
            reporter_id=user_id,
            target_type="opinion",
            target_id=opinion_id,
            reason=report_data.reason.value,
            note=report_data.note,
        )
        
        logger.info(
            "opinion_reported",
            opinion_id=opinion_id,
            reporter_id=user_id,
            reason=report_data.reason.value,
        )
        
        return report
    except HTTPException:
        raise
    except Exception as e:
        logger.error("report_opinion_failed", error=str(e), opinion_id=opinion_id)
        raise HTTPException(status_code=500, detail=f"Failed to report opinion: {str(e)}")
