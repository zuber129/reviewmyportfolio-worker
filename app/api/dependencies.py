from typing import Optional

import structlog
from app.core.exceptions import ProfileNotFoundError
from app.core.security import security
from app.infrastructure.supabase_client import supabase_client
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = structlog.get_logger()

# HTTP Bearer scheme for JWT tokens
bearer_scheme = HTTPBearer()
optional_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    Dependency to get the current authenticated user from Supabase token
    """
    token = credentials.credentials

    # Verify the Supabase token and get user
    user = await supabase_client.verify_token_and_get_user(token)

    if not user:
        logger.warning("invalid_token_attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = user.get("id")
    if not user_id:
        logger.warning("token_missing_user_id")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing user information",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user profile with metadata from Supabase
    # Let domain exceptions bubble up - controller will handle HTTP status codes
    profile = await supabase_client.get_user_profile(user_id)

    # Always add email from auth user (not stored in profiles table)
    profile["email"] = user.get("email")
    
    # Extract session_id from JWT for state machine operations
    import jwt
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        profile["session_id"] = decoded.get("session_id") or decoded.get("sub")
    except Exception:
        # Fallback to user_id if session_id not available
        profile["session_id"] = user_id
    
    # Load session state for routing and per-endpoint guards
    # Only enforce hard auth failures (signed_out, locked) here.
    # Onboarding guards (username_selection, needs_consent) are enforced
    # per-endpoint via the permissions module — NOT here.
    from app.services.auth.auth_session_service import get_session_machine
    try:
        machine = await get_session_machine(profile["session_id"], user_id, supabase_client)
        current_state = machine.current_state.id
        
        # Hard auth failures — session is truly invalid
        if current_state in ["signed_out", "locked"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or locked. Please sign in again."
            )
        
        # Attach state for per-endpoint guards and frontend routing
        profile["session_state"] = current_state
        
    except HTTPException:
        raise
    except Exception as e:
        # Log but don't block if state machine check fails
        logger.warning("session_state_validation_failed", user_id=user_id, error=str(e))

    # Update last_seen_at on every authenticated request (async, non-blocking)
    try:
        from datetime import datetime, timezone
        supabase_client.client.table("profiles").update({
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", user_id).execute()
    except Exception as e:
        # Non-critical — don't block request if update fails
        logger.debug("last_seen_update_failed", user_id=user_id, error=str(e))

    return profile


async def require_admin(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Dependency that rejects non-admin users with 403.
    Must be used on all admin endpoints.
    """
    if not current_user.get("is_admin", False):
        logger.warning(
            "admin_access_denied",
            user_id=current_user.get("id"),
            endpoint="admin",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_bearer_scheme),
) -> Optional[dict]:
    """
    Dependency to optionally get the current user (for public endpoints that can be enhanced with auth)
    """
    if not credentials:
        return None

    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None
