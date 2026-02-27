"""
Gmail Integration API Endpoints

Provides OAuth flow for connecting Gmail accounts and syncing CAS statements.

FEATURE DISABLED: Gmail API access requires months of Google verification.
This module is kept for reference but is not active in the application.
"""

# FEATURE FLAG: Gmail integration disabled
GMAIL_FEATURE_ENABLED = False

import secrets
from datetime import datetime
from typing import Optional

import structlog
from app.api.dependencies import get_current_user
from app.infrastructure.supabase_client import supabase_client
from app.services.integrations.gmail_client import gmail_client
from app.services.jobs.tasks import sync_gmail_task
from app.utils.encryption import encrypt_token
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter(prefix="/gmail", tags=["Gmail Integration"])


class GmailAuthResponse(BaseModel):
    authorization_url: str
    state: str


class GmailCallbackRequest(BaseModel):
    code: str
    state: str


class GmailAccountResponse(BaseModel):
    id: str
    email_address: str
    status: str
    sync_enabled: bool
    last_sync_at: Optional[datetime]
    connected_at: datetime


class GmailSyncResponse(BaseModel):
    task_id: str
    status: str
    message: str


@router.get("/auth/url", response_model=GmailAuthResponse)
async def get_gmail_auth_url(current_user: dict = Depends(get_current_user)):
    """
    Generate Gmail OAuth authorization URL.
    User will be redirected to this URL to grant access.
    """
    try:
        # Check if user already has Gmail connected
        existing = await supabase_client.get_gmail_account(current_user["id"])
        if existing:
            logger.info(
                "gmail_already_connected",
                user_id=current_user["id"],
                email=existing.get("email_address"),
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Gmail account already connected. Revoke existing connection first.",
            )

        # Generate CSRF state token
        state = secrets.token_urlsafe(32)

        # Store state in session (using Redis)
        from app.infrastructure.redis_client import redis_client

        await redis_client.set(
            f"gmail_oauth_state:{current_user['id']}", state, ex=600  # 10 min expiry
        )

        # Generate authorization URL
        auth_url = gmail_client.get_authorization_url(state)

        logger.info(
            "gmail_auth_url_generated",
            user_id=current_user["id"],
            state=state,
        )

        return GmailAuthResponse(authorization_url=auth_url, state=state)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "gmail_auth_url_error", user_id=current_user["id"], error=str(e), exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Gmail authorization URL: {str(e)}",
        )


@router.post("/auth/callback", response_model=GmailAccountResponse)
async def gmail_auth_callback(
    request: GmailCallbackRequest, current_user: dict = Depends(get_current_user)
):
    """
    Handle Gmail OAuth callback.
    Exchanges authorization code for tokens and stores them securely.
    """
    try:
        # Verify state token (CSRF protection)
        from app.infrastructure.redis_client import redis_client

        stored_state = await redis_client.get(f"gmail_oauth_state:{current_user['id']}")
        if not stored_state or stored_state != request.state:
            logger.warning(
                "gmail_oauth_state_mismatch",
                user_id=current_user["id"],
                expected=stored_state,
                received=request.state,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid state token. Please try again.",
            )

        # Delete state token (one-time use)
        await redis_client.delete(f"gmail_oauth_state:{current_user['id']}")

        # Exchange code for tokens
        access_token, refresh_token, expires_at, email = (
            await gmail_client.exchange_code_for_tokens(request.code)
        )

        # Encrypt tokens
        encrypted_access_token = encrypt_token(access_token)
        encrypted_refresh_token = encrypt_token(refresh_token)

        # Store in database
        gmail_account = await supabase_client.create_gmail_account(
            {
                "user_id": current_user["id"],
                "email_address": email,
                "encrypted_access_token": encrypted_access_token,
                "encrypted_refresh_token": encrypted_refresh_token,
                "token_expires_at": expires_at.isoformat(),
                "status": "active",
                "sync_enabled": True,
            }
        )

        logger.info(
            "gmail_account_connected",
            user_id=current_user["id"],
            email=email,
            gmail_account_id=gmail_account["id"],
        )

        # Trigger initial sync
        task = sync_gmail_task.delay(current_user["id"], sync_type="initial")
        logger.info(
            "gmail_initial_sync_triggered",
            user_id=current_user["id"],
            task_id=task.id,
        )

        return GmailAccountResponse(
            id=gmail_account["id"],
            email_address=gmail_account["email_address"],
            status=gmail_account["status"],
            sync_enabled=gmail_account["sync_enabled"],
            last_sync_at=gmail_account.get("last_sync_at"),
            connected_at=gmail_account["connected_at"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "gmail_auth_callback_error",
            user_id=current_user["id"],
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to connect Gmail account: {str(e)}",
        )


@router.get("/account", response_model=Optional[GmailAccountResponse])
async def get_gmail_account(current_user: dict = Depends(get_current_user)):
    """
    Get user's connected Gmail account details.
    Returns null if no account connected.
    """
    try:
        gmail_account = await supabase_client.get_gmail_account(current_user["id"])

        if not gmail_account:
            return None

        return GmailAccountResponse(
            id=gmail_account["id"],
            email_address=gmail_account["email_address"],
            status=gmail_account["status"],
            sync_enabled=gmail_account["sync_enabled"],
            last_sync_at=gmail_account.get("last_sync_at"),
            connected_at=gmail_account["connected_at"],
        )

    except Exception as e:
        logger.error(
            "get_gmail_account_error",
            user_id=current_user["id"],
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch Gmail account: {str(e)}",
        )


@router.post("/sync", response_model=GmailSyncResponse)
async def trigger_gmail_sync(current_user: dict = Depends(get_current_user)):
    """
    Manually trigger Gmail sync to fetch new CAS statements.
    """
    try:
        # Check if Gmail account exists
        gmail_account = await supabase_client.get_gmail_account(current_user["id"])
        if not gmail_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No Gmail account connected. Please connect your Gmail first.",
            )

        if not gmail_account.get("sync_enabled"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gmail sync is disabled. Please enable it in settings.",
            )

        # Trigger sync task
        task = sync_gmail_task.delay(current_user["id"], sync_type="manual")

        logger.info(
            "gmail_manual_sync_triggered",
            user_id=current_user["id"],
            task_id=task.id,
        )

        return GmailSyncResponse(
            task_id=task.id,
            status="started",
            message="Gmail sync started. This may take a few minutes.",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "trigger_gmail_sync_error",
            user_id=current_user["id"],
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger Gmail sync: {str(e)}",
        )


@router.delete("/account")
async def revoke_gmail_access(current_user: dict = Depends(get_current_user)):
    """
    Revoke Gmail access and delete stored tokens.
    """
    try:
        gmail_account = await supabase_client.get_gmail_account(current_user["id"])
        if not gmail_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No Gmail account connected.",
            )

        # Delete Gmail account (cascades to sync logs and emails)
        await supabase_client.delete_gmail_account(current_user["id"])

        logger.info(
            "gmail_account_revoked",
            user_id=current_user["id"],
            email=gmail_account.get("email_address"),
        )

        return {"message": "Gmail access revoked successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "revoke_gmail_access_error",
            user_id=current_user["id"],
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke Gmail access: {str(e)}",
        )


@router.get("/sync-history")
async def get_sync_history(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(default=10, ge=1, le=50),
):
    """
    Get Gmail sync history for debugging.
    """
    try:
        gmail_account = await supabase_client.get_gmail_account(current_user["id"])
        if not gmail_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No Gmail account connected.",
            )

        sync_logs = await supabase_client.get_gmail_sync_logs(
            gmail_account["id"], limit=limit
        )

        return {"sync_logs": sync_logs}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "get_sync_history_error",
            user_id=current_user["id"],
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch sync history: {str(e)}",
        )


@router.patch("/account/toggle-sync")
async def toggle_gmail_sync(current_user: dict = Depends(get_current_user)):
    """
    Enable or disable automatic Gmail sync.
    """
    try:
        gmail_account = await supabase_client.get_gmail_account(current_user["id"])
        if not gmail_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No Gmail account connected.",
            )

        new_status = not gmail_account.get("sync_enabled", True)

        await supabase_client.update_gmail_account(
            current_user["id"], {"sync_enabled": new_status}
        )

        logger.info(
            "gmail_sync_toggled",
            user_id=current_user["id"],
            sync_enabled=new_status,
        )

        return {
            "sync_enabled": new_status,
            "message": f"Gmail sync {'enabled' if new_status else 'disabled'}",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "toggle_gmail_sync_error",
            user_id=current_user["id"],
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to toggle Gmail sync: {str(e)}",
        )
