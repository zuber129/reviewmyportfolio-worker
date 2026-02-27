"""
Auth session service for managing session-scoped state machine.

Provides helpers for:
- Loading/saving session state
- Checking portfolio staleness
- Restoring user sessions after portfolio refresh
- Extracting session ID from JWT
"""

import jwt
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.state_machines.auth_session_flow import AuthSessionFlowMachine
from app.infrastructure.supabase_client import SupabaseClient
from app.core.exceptions import AuthenticationError
import structlog

logger = structlog.get_logger(__name__)


async def get_last_holdings_update(user_id: str, supabase_client: SupabaseClient) -> Optional[datetime]:
    """
    Get MAX(holdings_last_updated_at) across all user's portfolios.
    
    Args:
        user_id: User ID
        supabase_client: Supabase client instance
        
    Returns:
        Most recent holdings update timestamp or None if no portfolios
    """
    try:
        # Supabase client operations are synchronous
        result = supabase_client.client.table("portfolios").select(
            "holdings_last_updated_at"
        ).eq("user_id", user_id).is_("deleted_at", "null").execute()
        
        if not result.data:
            return None
        
        # Get max timestamp
        timestamps = [
            row["holdings_last_updated_at"] 
            for row in result.data 
            if row.get("holdings_last_updated_at")
        ]
        
        if not timestamps:
            return None
        
        # Convert to datetime objects and get max
        datetime_objects = []
        for ts in timestamps:
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = ts
            datetime_objects.append(dt)
        
        return max(datetime_objects) if datetime_objects else None
        
    except Exception as e:
        logger.error("get_last_holdings_update_failed", user_id=user_id, error=str(e))
        return None


async def get_portfolio_refresh_due_at(user_id: str, supabase_client: SupabaseClient) -> Optional[datetime]:
    """
    Get portfolio_refresh_due_at from the user's profile.
    
    Returns:
        Due date or None if no deadline set (new user)
    """
    try:
        result = supabase_client.client.table("profiles").select(
            "portfolio_refresh_due_at"
        ).eq("id", user_id).single().execute()
        
        raw = result.data.get("portfolio_refresh_due_at") if result.data else None
        if not raw:
            return None
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return raw
    except Exception as e:
        logger.error("get_portfolio_refresh_due_at_failed", user_id=user_id, error=str(e))
        return None


def is_portfolio_stale(last_holdings_update: Optional[datetime], refresh_due_at: Optional[datetime] = None) -> bool:
    """
    Check if portfolio needs refresh.
    
    Uses portfolio_refresh_due_at if available (single source of truth).
    Falls back to 186-day calculation from last_holdings_update for backward compat.
    
    Args:
        last_holdings_update: Most recent holdings update timestamp
        refresh_due_at: Explicit due date from profiles.portfolio_refresh_due_at
        
    Returns:
        True if portfolio is stale / overdue
    """
    # Use explicit due date if available (admin may have extended it)
    if refresh_due_at is not None:
        if isinstance(refresh_due_at, str):
            refresh_due_at = datetime.fromisoformat(refresh_due_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= refresh_due_at
    
    # Fallback: compute from last_holdings_update
    if not last_holdings_update:
        # New users (no portfolios) — not stale
        return False
    
    if isinstance(last_holdings_update, str):
        last_holdings_update = datetime.fromisoformat(last_holdings_update.replace("Z", "+00:00"))
    
    days_since = (datetime.now(timezone.utc) - last_holdings_update).days
    return days_since >= 186


def get_session_id_from_token(access_token: str) -> str:
    """
    Extract session_id from Supabase JWT.
    
    Args:
        access_token: JWT access token
        
    Returns:
        Session ID
    """
    try:
        decoded = jwt.decode(access_token, options={"verify_signature": False})
        # Supabase uses 'sub' as session identifier
        return decoded.get("session_id") or decoded.get("sub")
    except Exception as e:
        logger.error("session_id_extraction_failed", error=str(e))
        raise AuthenticationError("Invalid token")


async def get_session_machine(
    session_id: str,
    user_id: str,
    supabase_client: SupabaseClient
) -> AuthSessionFlowMachine:
    """
    Load session state and initialize state machine.
    
    Args:
        session_id: Session ID
        user_id: User ID
        supabase_client: Supabase client instance
        
    Returns:
        Initialized state machine
    """
    # Load session from database (synchronous)
    session_result = supabase_client.client.table("auth_sessions").select("*").eq(
        "session_id", session_id
    ).execute()
    
    if not session_result.data:
        # Session doesn't exist yet - will be created on signin/signup
        raise AuthenticationError("Session not found")
    
    session = session_result.data[0]
    
    # Load user profile for guards (synchronous)
    profile_result = supabase_client.client.table("profiles").select(
        "username, username_confirmed, privacy_consent_given"
    ).eq("id", user_id).execute()
    
    profile = profile_result.data[0] if profile_result.data else {}
    
    # Get staleness data
    last_holdings_update = await get_last_holdings_update(user_id, supabase_client)
    refresh_due_at = await get_portfolio_refresh_due_at(user_id, supabase_client)
    
    # Merge session + profile data for state machine
    model = {
        **session,
        **profile,
        "last_holdings_update": last_holdings_update,
        "refresh_due_at": refresh_due_at,
    }
    
    # Initialize state machine with current state from database
    machine = AuthSessionFlowMachine(model=model, user_id=user_id, start_value=session["state"])
    return machine


async def save_session_state(
    machine: AuthSessionFlowMachine,
    supabase_client: SupabaseClient
):
    """
    Persist state machine state to database.
    
    Args:
        machine: State machine instance
        supabase_client: Supabase client instance
    """
    # Handle both dict and StateMachine Model object
    if hasattr(machine.model, 'get'):
        session_id = machine.model.get("session_id")
        metadata = machine.model.get("metadata", {})
    else:
        session_id = getattr(machine.model, 'session_id', None)
        metadata = getattr(machine.model, 'metadata', {})
    
    if not session_id:
        logger.error("save_session_state_no_session_id", user_id=machine.user_id)
        return
    
    try:
        # Supabase client operations are synchronous
        supabase_client.client.table("auth_sessions").update({
            "state": machine.current_state.id,
            "metadata": metadata,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("session_id", session_id).execute()
        
        logger.info(
            "session_state_saved",
            session_id=session_id,
            user_id=machine.user_id,
            state=machine.current_state.id
        )
    except Exception as e:
        logger.error(
            "save_session_state_failed",
            session_id=session_id,
            user_id=machine.user_id,
            error=str(e)
        )


async def create_auth_session(
    session_id: str,
    user_id: str,
    state: str,
    expires_at: Optional[datetime],
    supabase_client: SupabaseClient,
    metadata: Optional[Dict[str, Any]] = None
):
    """
    Create new auth session record.
    
    Args:
        session_id: Session ID
        user_id: User ID
        state: Initial state
        expires_at: Session expiry timestamp
        supabase_client: Supabase client instance
        metadata: Optional metadata dict
    """
    try:
        # Supabase client operations are synchronous, not async
        supabase_client.client.table("auth_sessions").insert({
            "session_id": session_id,
            "user_id": user_id,
            "state": state,
            "metadata": metadata or {},
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).execute()
        
        logger.info(
            "auth_session_created",
            session_id=session_id,
            user_id=user_id,
            state=state
        )
    except Exception as e:
        logger.error(
            "create_auth_session_failed",
            session_id=session_id,
            user_id=user_id,
            error=str(e)
        )


async def restore_all_user_sessions(user_id: str, supabase_client: SupabaseClient):
    """
    Restore all sessions for user after portfolio upload.
    Transitions all sessions from portfolio_refresh_required → active.
    
    Args:
        user_id: User ID
        supabase_client: Supabase client instance
    """
    try:
        # Supabase client operations are synchronous
        supabase_client.client.table("auth_sessions").update({
            "state": "active",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("user_id", user_id).eq("state", "portfolio_refresh_required").execute()
        
        logger.info("user_sessions_restored", user_id=user_id)
    except Exception as e:
        logger.error("restore_user_sessions_failed", user_id=user_id, error=str(e))


async def signout_all_user_sessions(user_id: str, supabase_client: SupabaseClient):
    """
    Sign out all sessions for user across all devices.
    
    Args:
        user_id: User ID
        supabase_client: Supabase client instance
    """
    try:
        # Supabase client operations are synchronous
        supabase_client.client.table("auth_sessions").update({
            "state": "signed_out",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("user_id", user_id).ne("state", "signed_out").execute()
        
        logger.info("all_user_sessions_signed_out", user_id=user_id)
    except Exception as e:
        logger.error("signout_all_sessions_failed", user_id=user_id, error=str(e))


async def derive_initial_session_state(
    user_id: str,
    supabase_client: SupabaseClient
) -> str:
    """
    Derive initial session state from user flags + portfolio freshness.
    Used during signin/signup to determine where to route user.
    
    Args:
        user_id: User ID
        supabase_client: Supabase client instance
        
    Returns:
        Initial state string
    """
    # Load user profile (synchronous)
    profile_result = supabase_client.client.table("profiles").select(
        "username, username_confirmed, privacy_consent_given"
    ).eq("id", user_id).execute()
    
    profile = profile_result.data[0] if profile_result.data else {}
    
    # Check onboarding status via state machine guards
    if not profile.get("username_confirmed"):
        return "username_selection"
    
    if not profile.get("privacy_consent_given"):
        return "needs_consent"
    
    # Check portfolio freshness using profile due date
    refresh_due_at = await get_portfolio_refresh_due_at(user_id, supabase_client)
    last_holdings_update = await get_last_holdings_update(user_id, supabase_client)
    if is_portfolio_stale(last_holdings_update, refresh_due_at=refresh_due_at):
        return "portfolio_refresh_required"
    
    return "active"
