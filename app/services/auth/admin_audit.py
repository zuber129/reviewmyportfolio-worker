"""
Admin audit logging service.

Persists every admin mutation to admin_action_log with before/after state
for full auditability.
"""

from typing import Any, Dict, Optional
import structlog
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger(__name__)


async def log_admin_action(
    admin_id: str,
    action: str,
    reason: str,
    target_user_id: Optional[str] = None,
    target_file_id: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Log an admin action to the admin_action_log table.

    Args:
        admin_id: UUID of the admin performing the action
        action: Action name (e.g., 'ban', 'unlock_session', 'force_retry')
        reason: Mandatory reason string from admin
        target_user_id: UUID of the user being acted upon
        target_file_id: UUID of the file being acted upon
        before_state: JSON snapshot of state before the action
        after_state: JSON snapshot of state after the action
        ip_address: IP address of the admin (from X-Forwarded-For)
    """
    try:
        record = {
            "admin_id": admin_id,
            "action": action,
            "reason": reason,
            "before_state": before_state or {},
            "after_state": after_state or {},
        }
        if target_user_id:
            record["target_user_id"] = target_user_id
        if target_file_id:
            record["target_file_id"] = target_file_id
        if ip_address:
            record["ip_address"] = ip_address

        supabase_client.client.table("admin_action_log").insert(record).execute()

        logger.info(
            "admin_action_logged",
            admin_id=admin_id,
            action=action,
            target_user_id=target_user_id,
            target_file_id=target_file_id,
        )
    except Exception as e:
        logger.error(
            "admin_action_log_failed",
            admin_id=admin_id,
            action=action,
            error=str(e),
        )
