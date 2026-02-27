"""
Generic flow state API endpoints.

Provides unified interface for querying and triggering state machine events
across all flow types (upload, parsing, onboarding, portfolio).
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Any, Dict
import structlog

from app.api.dependencies import get_current_user
from app.state_machines.registry import get_flow_machine
from app.infrastructure.supabase_client import supabase_client

router = APIRouter(prefix="/flows", tags=["flows"])
logger = structlog.get_logger(__name__)


@router.get("/{flow_type}/{entity_id}")
async def get_flow_state(
    flow_type: str,
    entity_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get current state and allowed events for a flow.
    
    Args:
        flow_type: Type of flow (upload, parsing, onboarding, portfolio)
        entity_id: ID of the entity (file_id, profile_id, portfolio_id)
        current_user: Authenticated user
        
    Returns:
        Flow info with state, allowed_events, metadata, error
        
    Raises:
        HTTPException: If flow not found or user not authorized
    """
    try:
        model = await _load_model(flow_type, entity_id)
        
        sm = get_flow_machine(
            flow_type=flow_type,
            model=model,
            user_id=current_user["id"]
        )
        
        if not sm.is_owner(current_user["id"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this flow"
            )
        
        return sm.get_flow_info()
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error("get_flow_state_error", error=str(e), flow_type=flow_type)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get flow state"
        )


@router.post("/{flow_type}/{entity_id}/events/{event_name}")
async def send_flow_event(
    flow_type: str,
    entity_id: str,
    event_name: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Trigger a state machine event.
    
    Args:
        flow_type: Type of flow (upload, parsing, onboarding, portfolio)
        entity_id: ID of the entity
        event_name: Name of event to trigger
        current_user: Authenticated user
        
    Returns:
        Updated flow info after transition
        
    Raises:
        HTTPException: If event not allowed or transition fails
    """
    try:
        model = await _load_model(flow_type, entity_id)
        
        sm = get_flow_machine(
            flow_type=flow_type,
            model=model,
            user_id=current_user["id"]
        )
        
        if not sm.is_owner(current_user["id"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to trigger events on this flow"
            )
        
        if not hasattr(sm, event_name):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Event '{event_name}' not found on {flow_type} flow"
            )
        
        event_method = getattr(sm, event_name)
        event_method()
        
        sm.sync_to_db()
        
        return sm.get_flow_info()
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error("send_flow_event_error", error=str(e), event=event_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger event"
        )


async def _load_model(flow_type: str, entity_id: str) -> Dict[str, Any]:
    """
    Load model from database based on flow type.
    
    Args:
        flow_type: Type of flow
        entity_id: Entity ID
        
    Returns:
        Model as dict
        
    Raises:
        HTTPException: If model not found
    """
    if flow_type == "upload":
        model = await supabase_client.get_file_by_id(entity_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        return model
        
    elif flow_type == "onboarding":
        model = await supabase_client.get_user_profile(entity_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Profile not found"
            )
        return model
        
    elif flow_type == "portfolio":
        model = await supabase_client.get_portfolio(entity_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Portfolio not found"
            )
        return model
        
    elif flow_type == "parsing":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parsing flow is in-memory only, not queryable via API"
        )
    
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown flow type: {flow_type}"
        )
