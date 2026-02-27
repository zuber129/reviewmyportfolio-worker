"""
Background job to check portfolio staleness and update session states.

Runs daily to transition active → portfolio_refresh_required for users
whose portfolios are 186+ days old.
"""

import structlog
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger(__name__)


async def check_portfolio_staleness_job():
    """
    Check for stale portfolios (186+ days) and block all user sessions.
    
    This job:
    1. Finds users whose most recent portfolio is 186+ days old
    2. Updates ALL their sessions from active → portfolio_refresh_required
    3. Logs the action
    
    Should be run daily via cron or scheduler.
    """
    try:
        # Call the database function
        await supabase_client.client.rpc("check_portfolio_staleness").execute()
        
        logger.info("portfolio_staleness_check_completed")
        
    except Exception as e:
        logger.error("portfolio_staleness_check_failed", error=str(e))
        raise


async def cleanup_expired_sessions_job():
    """
    Cleanup expired sessions from auth_sessions table.
    
    Should be run periodically (e.g., hourly) to keep table clean.
    """
    try:
        # Call the database function
        await supabase_client.client.rpc("cleanup_expired_sessions").execute()
        
        logger.info("expired_sessions_cleanup_completed")
        
    except Exception as e:
        logger.error("expired_sessions_cleanup_failed", error=str(e))
        raise
