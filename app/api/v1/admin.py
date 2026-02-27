"""
Admin Panel API endpoints
Protected endpoints for system administration
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import structlog
from pydantic import BaseModel, Field

from app.api.dependencies import get_current_user, require_admin
from app.core.decorators import require_proxy_caller
from app.domain.schemas import ModerationAction, Report, ReportListResponse
from app.infrastructure.redis_client import redis_client
from app.infrastructure.supabase_client import supabase_client
from app.services.auth.admin_audit import log_admin_action
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

logger = structlog.get_logger()
router = APIRouter(prefix="/admin", tags=["Admin"])


# ---------------------------------------------------------------------------
# Request/Response schemas for new admin endpoints
# ---------------------------------------------------------------------------

class AdminReasonRequest(BaseModel):
    reason: str = Field(..., min_length=10, description="Mandatory reason for admin action")

class FlagUpdateRequest(BaseModel):
    field: str = Field(..., pattern="^(is_admin|is_banned|is_shadow_banned)$")
    value: bool
    reason: str = Field(..., min_length=10)

class SessionAdvanceRequest(BaseModel):
    reason: str = Field(..., min_length=10)
    extension_days: int = Field(default=186, ge=1, le=365, description="Days to extend portfolio refresh deadline")

class BatchRetryRequest(BaseModel):
    file_ids: List[str]
    reason: str = Field(..., min_length=10)


def is_admin(current_user: dict) -> bool:
    """
    Check if user is admin.

    In production, this should check against a proper admin role/permission system.
    For now, checking if user has admin flag in profile.
    """
    # TODO: Implement proper admin role checking
    return current_user.get("is_admin", False)


@router.get("/stats")
@require_proxy_caller
async def get_system_stats(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Get system-wide statistics.

    Admin only endpoint - must be called via UI proxy.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # Get user count
        users_response = (
            supabase_client.client.table("profiles")
            .select("id", count="exact")
            .execute()
        )
        total_users = users_response.count or 0

        # Get portfolio count
        portfolios_response = (
            supabase_client.client.table("portfolios")
            .select("id", count="exact")
            .is_("deleted_at", "null")
            .execute()
        )
        total_portfolios = portfolios_response.count or 0

        # Get review count
        opinions_response = (
            supabase_client.client.table("reviews")
            .select("id", count="exact")
            .is_("deleted_at", "null")
            .execute()
        )
        total_opinions = opinions_response.count or 0

        # Get reaction count
        reactions_response = (
            supabase_client.client.table("reactions")
            .select("id", count="exact")
            .is_("deleted_at", "null")
            .execute()
        )
        total_reactions = reactions_response.count or 0

        logger.info(
            "admin_stats_fetched",
            admin_id=current_user["id"],
            users=total_users,
            portfolios=total_portfolios,
        )

        return {
            "total_users": total_users,
            "total_portfolios": total_portfolios,
            "total_opinions": total_opinions,
            "total_reactions": total_reactions,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_system_stats_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system stats",
        )


@router.post("/cache/clear")
@require_proxy_caller
async def clear_all_caches(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Clear all Redis caches.

    Admin only endpoint.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # Clear specific cache patterns
        cache_patterns = [
            "portfolio:*",
            "feed:*",
            "leaderboard:*",
            "opinions:*",
            "reactions:*",
        ]

        cleared_count = 0
        for pattern in cache_patterns:
            try:
                await redis_client.delete(pattern)
                cleared_count += 1
            except Exception as e:
                logger.warning(
                    "cache_clear_pattern_failed", pattern=pattern, error=str(e)
                )

        logger.info(
            "admin_cache_cleared",
            admin_id=current_user["id"],
            patterns_cleared=cleared_count,
        )

        return {
            "status": "success",
            "patterns_cleared": cleared_count,
            "message": "All caches cleared successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("clear_all_caches_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear caches",
        )


@router.get("/users/recent")
@require_proxy_caller
async def get_recent_users(
    request: Request,
    limit: int = 20,
    current_user: dict = Depends(get_current_user),
):
    """
    Get recently registered users.

    Admin only endpoint.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        response = (
            supabase_client.client.table("profiles")
            .select(
                "id, username, email, created_at, reputation_score, reputation_tier"
            )
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        users = response.data or []

        logger.info(
            "admin_recent_users_fetched",
            admin_id=current_user["id"],
            count=len(users),
        )

        return {
            "users": users,
            "count": len(users),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_recent_users_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get recent users",
        )


@router.delete("/portfolios/{portfolio_id}")
@require_proxy_caller
async def delete_portfolio_admin(
    request: Request,
    portfolio_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Delete any portfolio (admin override).

    Admin only endpoint.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # Soft delete
        from datetime import datetime

        supabase_client.client.table("portfolios").update(
            {
                "deleted_at": datetime.utcnow().isoformat(),
            }
        ).eq("id", portfolio_id).execute()

        # Invalidate caches
        await redis_client.delete(f"portfolio:{portfolio_id}")
        await redis_client.delete("feed:*")

        logger.info(
            "admin_portfolio_deleted",
            admin_id=current_user["id"],
            portfolio_id=portfolio_id,
        )

        return {
            "status": "success",
            "message": "Portfolio deleted successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_portfolio_admin_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete portfolio",
        )


@router.delete("/opinions/{opinion_id}")
@require_proxy_caller
async def delete_opinion_admin(
    request: Request,
    opinion_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Delete any opinion (admin override).

    Admin only endpoint.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # Soft delete
        from datetime import datetime

        supabase_client.client.table("reviews").update(
            {
                "deleted_at": datetime.utcnow().isoformat(),
            }
        ).eq("id", opinion_id).execute()

        logger.info(
            "admin_opinion_deleted",
            admin_id=current_user["id"],
            opinion_id=opinion_id,
        )

        return {
            "status": "success",
            "message": "Opinion deleted successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_opinion_admin_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete opinion",
        )


@router.get("/moderation/reports", response_model=ReportListResponse)
@require_proxy_caller
async def list_moderation_reports(
    request: Request,
    status_filter: str = Query("pending", regex="^(pending|resolved)$"),
    target_type: str = Query(None, regex="^(portfolio|opinion)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    """
    List moderation reports with filters.

    Admin only endpoint.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # Build query
        query = (
            supabase_client.client.table("reports")
            .select("*")
            .eq("status", status_filter)
        )

        if target_type:
            query = query.eq("target_type", target_type)

        query = query.order("created_at", desc=True)

        response = query.execute()
        reports_data = response.data or []

        reports = [Report(**report) for report in reports_data]

        logger.info(
            "admin_reports_listed",
            admin_id=current_user["id"],
            count=len(reports),
            status=status_filter,
        )

        return ReportListResponse(reports=reports, total=len(reports))

    except HTTPException:
        raise
    except Exception as e:
        logger.error("list_reports_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list reports",
        )


@router.post("/moderation/reports/{report_id}/action")
@require_proxy_caller
async def take_moderation_action(
    request: Request,
    report_id: str,
    action_data: ModerationAction,
    current_user: dict = Depends(get_current_user),
):
    """
    Take action on a moderation report.

    Actions:
    - hide_content: Hide the reported content
    - restore_content: Restore previously hidden content
    - ignore_report: Mark report as resolved without action

    Admin only endpoint.
    """
    try:
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # Get report
        report_response = (
            supabase_client.client.table("reports")
            .select("*")
            .eq("id", report_id)
            .single()
            .execute()
        )

        if not report_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found",
            )

        report = report_response.data
        target_type = report["target_type"]
        target_id = report["target_id"]

        # Take action based on type
        if action_data.action.value in ["hide_content", "restore_content"]:
            new_status = (
                "hidden" if action_data.action.value == "hide_content" else "visible"
            )

            # Update moderation_status on target content
            if target_type == "portfolio":
                supabase_client.client.table("portfolios").update(
                    {"moderation_status": new_status}
                ).eq("id", target_id).execute()

                # Invalidate portfolio cache
                await redis_client.delete(f"portfolio:{target_id}")
                await redis_client.delete("feed:*")

            elif target_type == "opinion":
                supabase_client.client.table("reviews").update(
                    {"moderation_status": new_status}
                ).eq("id", target_id).execute()

                # Invalidate opinions cache
                await redis_client.delete("opinions:*")

        # Update report status
        from datetime import datetime

        supabase_client.client.table("reports").update(
            {
                "status": "resolved",
                "resolved_by": current_user["id"],
                "resolved_at": datetime.utcnow().isoformat(),
                "resolution_action": action_data.action.value,
            }
        ).eq("id", report_id).execute()

        logger.info(
            "moderation_action_taken",
            admin_id=current_user["id"],
            report_id=report_id,
            action=action_data.action.value,
            target_type=target_type,
            target_id=target_id,
        )

        return {
            "status": "success",
            "action": action_data.action.value,
            "message": f"Action completed: {action_data.action.value}",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("moderation_action_error", error=str(e), report_id=report_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to take moderation action",
        )


# ---------------------------------------------------------------------------
# NEW Admin Portal Endpoints (using require_admin dependency)
# These match the frontend contracts from v0.dev PR #15
# ---------------------------------------------------------------------------

def _get_ip(request: Request) -> Optional[str]:
    """Extract client IP from request headers."""
    return request.headers.get("x-forwarded-for", request.headers.get("x-real-ip"))


@router.get("/metrics")
async def get_admin_metrics(
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Dashboard metrics: users, portfolios, stuck files, pending reports, active sessions."""
    try:
        users_resp = supabase_client.client.table("profiles").select("id", count="exact").execute()
        total_users = users_resp.count or 0

        portfolios_resp = (
            supabase_client.client.table("portfolios")
            .select("id", count="exact")
            .is_("deleted_at", "null")
            .execute()
        )
        total_portfolios = portfolios_resp.count or 0

        stuck_resp = (
            supabase_client.client.table("portfolio_files")
            .select("id", count="exact")
            .not_.is_("status", "null")
            .in_("status", ["validating", "scanning", "parsing"])
            .execute()
        )
        stuck_files = stuck_resp.count or 0

        reports_resp = (
            supabase_client.client.table("reports")
            .select("id", count="exact")
            .eq("status", "pending")
            .execute()
        )
        pending_reports = reports_resp.count or 0

        sessions_resp = (
            supabase_client.client.table("auth_sessions")
            .select("id", count="exact")
            .eq("state", "active")
            .execute()
        )
        active_sessions = sessions_resp.count or 0

        return {
            "total_users": total_users,
            "total_portfolios": total_portfolios,
            "stuck_files": stuck_files,
            "pending_reports": pending_reports,
            "active_sessions": active_sessions,
        }
    except Exception as e:
        logger.error("get_admin_metrics_error", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to load metrics")


@router.get("/users")
async def list_admin_users(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: str = Query("all", alias="status"),
    search: Optional[str] = Query(None),
    admin: dict = Depends(require_admin),
):
    """User list with pagination, search, and status filter."""
    try:
        offset = (page - 1) * per_page

        query = supabase_client.client.table("profiles").select(
            "id, username, email, is_admin, is_shadow_banned, last_seen_at, created_at",
            count="exact",
        )

        if search:
            query = query.or_(f"username.ilike.%{search}%,id.eq.{search}" if len(search) == 36 else f"username.ilike.%{search}%")

        if status_filter == "banned":
            # Banned = has any locked session
            locked_sessions = supabase_client.client.table("auth_sessions").select("user_id").eq("state", "locked").execute()
            locked_user_ids = list({s["user_id"] for s in (locked_sessions.data or [])})
            if locked_user_ids:
                query = query.in_("id", locked_user_ids)
            else:
                return {"users": [], "total": 0, "page": page, "per_page": per_page}
        elif status_filter == "shadow_banned":
            query = query.eq("is_shadow_banned", True)
        elif status_filter == "admin":
            query = query.eq("is_admin", True)

        query = query.order("created_at", desc=True).range(offset, offset + per_page - 1)
        resp = query.execute()
        profiles = resp.data or []
        total = resp.count or 0

        # Check banned status for each user (locked session)
        user_ids = [p["id"] for p in profiles]
        locked_resp = (
            supabase_client.client.table("auth_sessions")
            .select("user_id")
            .in_("user_id", user_ids)
            .eq("state", "locked")
            .execute()
        ) if user_ids else type("R", (), {"data": []})()
        locked_ids = {s["user_id"] for s in (locked_resp.data or [])}

        users = []
        for p in profiles:
            users.append({
                "id": p["id"],
                "username": p.get("username") or "—",
                "email": p.get("email") or "—",
                "is_admin": p.get("is_admin", False),
                "is_banned": p["id"] in locked_ids,
                "is_shadow_banned": p.get("is_shadow_banned", False),
                "created_at": p["created_at"],
                "last_seen": p.get("last_seen_at"),
            })

        return {"users": users, "total": total, "page": page, "per_page": per_page}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("list_admin_users_error", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list users")


@router.get("/users/{user_id}")
async def get_admin_user_detail(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Single user detail for the user detail page header."""
    try:
        profile_resp = (
            supabase_client.client.table("profiles")
            .select("*")
            .eq("id", user_id)
            .single()
            .execute()
        )
        if not profile_resp.data:
            raise HTTPException(status_code=404, detail="User not found")

        p = profile_resp.data

        # Check banned
        locked_resp = (
            supabase_client.client.table("auth_sessions")
            .select("session_id")
            .eq("user_id", user_id)
            .eq("state", "locked")
            .limit(1)
            .execute()
        )
        is_banned = bool(locked_resp.data)

        # Get email
        email = "—"
        try:
            user_resp = supabase_client.client.auth.admin.get_user_by_id(user_id)
            if user_resp and user_resp.user:
                email = user_resp.user.email
        except Exception:
            pass

        # Last seen
        last_seen_resp = (
            supabase_client.client.table("auth_sessions")
            .select("updated_at")
            .eq("user_id", user_id)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
        last_seen = last_seen_resp.data[0]["updated_at"] if last_seen_resp.data else None

        return {
            "id": p["id"],
            "username": p.get("username") or "—",
            "email": email,
            "is_admin": p.get("is_admin", False),
            "is_banned": is_banned,
            "is_shadow_banned": p.get("is_shadow_banned", False),
            "created_at": p["created_at"],
            "last_seen": last_seen,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_admin_user_detail_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to load user")


@router.get("/users/{user_id}/sessions")
async def get_user_sessions(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """List all auth sessions for a user."""
    try:
        resp = (
            supabase_client.client.table("auth_sessions")
            .select("session_id, state, metadata, created_at, updated_at, expires_at")
            .eq("user_id", user_id)
            .order("updated_at", desc=True)
            .execute()
        )
        sessions = []
        for s in (resp.data or []):
            sessions.append({
                "id": s["session_id"],
                "state": s["state"],
                "created_at": s["created_at"],
                "updated_at": s["updated_at"],
            })

        return {"sessions": sessions}
    except Exception as e:
        logger.error("get_user_sessions_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to load sessions")


@router.get("/users/{user_id}/files")
async def get_user_files(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """List all portfolio files for a user."""
    try:
        resp = (
            supabase_client.client.table("portfolio_files")
            .select("id, original_filename, status, error_code, error_message, retry_count, created_at, updated_at")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .order("created_at", desc=True)
            .execute()
        )
        files = []
        now = datetime.now(timezone.utc)
        for f in (resp.data or []):
            created = datetime.fromisoformat(f["created_at"].replace("Z", "+00:00"))
            processing_ms = int((now - created).total_seconds() * 1000)
            files.append({
                "id": f["id"],
                "filename": f.get("original_filename") or "unknown",
                "status": f["status"],
                "error_code": f.get("error_code"),
                "retry_count": f.get("retry_count", 0),
                "processing_time": processing_ms if f["status"] not in ("completed", "failed") else None,
                "created_at": f["created_at"],
                "updated_at": f["updated_at"],
            })

        return {"files": files}
    except Exception as e:
        logger.error("get_user_files_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to load files")


@router.get("/users/{user_id}/portfolios")
async def get_user_portfolios(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """List all portfolios for a user."""
    try:
        resp = (
            supabase_client.client.table("portfolios")
            .select("id, is_public, views_count, reactions_count, created_at, deleted_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        portfolios = []
        for idx, p in enumerate(resp.data or [], 1):
            portfolios.append({
                "id": p["id"],
                "title": f"Portfolio #{idx}",
                "status": "deleted" if p.get("deleted_at") else "active",
                "visibility": "public" if p.get("is_public") else "private",
                "views": p.get("views_count", 0),
                "likes": p.get("reactions_count", 0),
                "created_at": p["created_at"],
            })

        return {"portfolios": portfolios}
    except Exception as e:
        logger.error("get_user_portfolios_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to load portfolios")


@router.get("/users/{user_id}/stats")
async def get_user_stats(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """User stats summary for the stats tab."""
    try:
        # Count portfolios
        p_resp = (
            supabase_client.client.table("portfolios")
            .select("id, reactions_count", count="exact")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .execute()
        )
        total_portfolios = p_resp.count or 0
        total_likes_received = sum(p.get("reactions_count", 0) for p in (p_resp.data or []))

        # Count reviews
        o_resp = (
            supabase_client.client.table("reviews")
            .select("id", count="exact")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .execute()
        )
        total_opinions = o_resp.count or 0

        # Count reactions given
        r_resp = (
            supabase_client.client.table("reactions")
            .select("id", count="exact")
            .eq("user_id", user_id)
            .execute()
        )
        total_likes_given = r_resp.count or 0

        # Get user_stats row
        stats_resp = (
            supabase_client.client.table("user_stats")
            .select("total_points, tier")
            .eq("user_id", user_id)
            .execute()
        )
        stats_row = stats_resp.data[0] if stats_resp.data else {}

        # Get streak from profiles
        profile_resp = (
            supabase_client.client.table("profiles")
            .select("current_streak")
            .eq("id", user_id)
            .single()
            .execute()
        )
        streak = profile_resp.data.get("current_streak", 0) if profile_resp.data else 0

        return {
            "total_portfolios": total_portfolios,
            "total_opinions": total_opinions,
            "total_likes_given": total_likes_given,
            "total_likes_received": total_likes_received,
            "average_rating": 0,
            "rank": stats_row.get("tier", "Unranked"),
            "points": stats_row.get("total_points", 0),
            "streak": streak,
        }
    except Exception as e:
        logger.error("get_user_stats_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to load stats")


@router.get("/users/{user_id}/audit-log")
async def get_user_audit_log(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Per-user audit log of admin actions."""
    try:
        resp = (
            supabase_client.client.table("admin_action_log")
            .select("id, action, admin_id, reason, before_state, after_state, created_at")
            .eq("target_user_id", user_id)
            .order("created_at", desc=True)
            .limit(100)
            .execute()
        )

        # Get admin usernames
        admin_ids = list({r["admin_id"] for r in (resp.data or [])})
        admin_map = {}
        if admin_ids:
            admins_resp = (
                supabase_client.client.table("profiles")
                .select("id, username")
                .in_("id", admin_ids)
                .execute()
            )
            admin_map = {a["id"]: a.get("username", "—") for a in (admins_resp.data or [])}

        logs = []
        for r in (resp.data or []):
            logs.append({
                "id": r["id"],
                "action": r["action"],
                "admin_username": admin_map.get(r["admin_id"], "Unknown"),
                "reason": r["reason"],
                "details": {**(r.get("before_state") or {}), **(r.get("after_state") or {})},
                "created_at": r["created_at"],
            })

        return {"logs": logs}
    except Exception as e:
        logger.error("get_user_audit_log_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to load audit log")


@router.get("/files/stuck")
async def get_stuck_files(
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Global list of files stuck in processing (status in validating/scanning/parsing)."""
    try:
        resp = (
            supabase_client.client.table("portfolio_files")
            .select("id, user_id, original_filename, status, created_at, updated_at")
            .in_("status", ["validating", "scanning", "parsing"])
            .is_("deleted_at", "null")
            .order("created_at")
            .execute()
        )

        user_ids = list({f["user_id"] for f in (resp.data or [])})
        username_map = {}
        if user_ids:
            users_resp = (
                supabase_client.client.table("profiles")
                .select("id, username")
                .in_("id", user_ids)
                .execute()
            )
            username_map = {u["id"]: u.get("username", "—") for u in (users_resp.data or [])}

        now = datetime.now(timezone.utc)
        files = []
        for f in (resp.data or []):
            created = datetime.fromisoformat(f["created_at"].replace("Z", "+00:00"))
            processing_ms = int((now - created).total_seconds() * 1000)
            files.append({
                "id": f["id"],
                "filename": f.get("original_filename") or "unknown",
                "user_id": f["user_id"],
                "username": username_map.get(f["user_id"], "—"),
                "status": f["status"],
                "processing_time": processing_ms,
                "created_at": f["created_at"],
                "updated_at": f["updated_at"],
            })

        return {"files": files}
    except Exception as e:
        logger.error("get_stuck_files_error", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to load stuck files")


@router.get("/audit-log")
async def get_global_audit_log(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None),
    admin_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    admin: dict = Depends(require_admin),
):
    """Global audit log with pagination and filters."""
    try:
        offset = (page - 1) * per_page
        query = supabase_client.client.table("admin_action_log").select(
            "id, action, admin_id, target_user_id, reason, created_at",
            count="exact",
        )

        if action:
            query = query.eq("action", action)
        if admin_id:
            query = query.eq("admin_id", admin_id)
        if search:
            query = query.ilike("reason", f"%{search}%")

        query = query.order("created_at", desc=True).range(offset, offset + per_page - 1)
        resp = query.execute()
        total = resp.count or 0

        # Resolve admin and target usernames
        all_ids = set()
        for r in (resp.data or []):
            all_ids.add(r["admin_id"])
            if r.get("target_user_id"):
                all_ids.add(r["target_user_id"])

        username_map = {}
        if all_ids:
            names_resp = (
                supabase_client.client.table("profiles")
                .select("id, username")
                .in_("id", list(all_ids))
                .execute()
            )
            username_map = {u["id"]: u.get("username", "—") for u in (names_resp.data or [])}

        logs = []
        for r in (resp.data or []):
            logs.append({
                "id": r["id"],
                "action": r["action"],
                "admin_id": r["admin_id"],
                "admin_username": username_map.get(r["admin_id"], "Unknown"),
                "target_user_id": r.get("target_user_id"),
                "target_username": username_map.get(r.get("target_user_id", ""), None),
                "reason": r["reason"],
                "created_at": r["created_at"],
            })

        return {"logs": logs, "total": total, "page": page, "per_page": per_page}
    except Exception as e:
        logger.error("get_global_audit_log_error", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to load audit log")


# ---------------------------------------------------------------------------
# Write endpoints (mutations + audit logging)
# ---------------------------------------------------------------------------

@router.patch("/users/{user_id}/flags")
async def update_user_flags(
    user_id: str,
    body: FlagUpdateRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Toggle user flags: is_admin, is_banned, is_shadow_banned."""
    try:
        # Get before state
        profile_resp = (
            supabase_client.client.table("profiles")
            .select("is_admin, is_shadow_banned")
            .eq("id", user_id)
            .single()
            .execute()
        )
        if not profile_resp.data:
            raise HTTPException(status_code=404, detail="User not found")

        before = dict(profile_resp.data)

        if body.field == "is_banned":
            # Ban/unban = lock/unlock all sessions
            if body.value:
                supabase_client.client.table("auth_sessions").update({
                    "state": "locked",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }).eq("user_id", user_id).neq("state", "locked").execute()
            else:
                supabase_client.client.table("auth_sessions").update({
                    "state": "signed_out",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }).eq("user_id", user_id).eq("state", "locked").execute()

            after = {"is_banned": body.value}
        else:
            # Direct profile column update (is_admin or is_shadow_banned)
            supabase_client.client.table("profiles").update({
                body.field: body.value,
            }).eq("id", user_id).execute()
            after = {body.field: body.value}

        await log_admin_action(
            admin_id=admin["id"],
            action=f"flag_{body.field}",
            reason=body.reason,
            target_user_id=user_id,
            before_state=before,
            after_state=after,
            ip_address=_get_ip(request),
        )

        return {"status": "success", "message": f"{body.field} updated to {body.value}"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_user_flags_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to update flags")


@router.post("/users/{user_id}/sessions/{session_id}/advance")
async def advance_user_session(
    user_id: str,
    session_id: str,
    body: SessionAdvanceRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """
    Advance a stuck session to the next logical state.
    Updates profile flags as prerequisites before advancing the session.
    """
    try:
        # Load current session
        session_resp = (
            supabase_client.client.table("auth_sessions")
            .select("*")
            .eq("session_id", session_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not session_resp.data:
            raise HTTPException(status_code=404, detail="Session not found")

        current_state = session_resp.data["state"]
        before = {"state": current_state}

        # Determine next state and required profile flag updates
        profile_updates = {}
        if current_state == "username_selection":
            target_state = "needs_consent"
            profile_updates["username_confirmed"] = True
        elif current_state == "needs_consent":
            target_state = "active"
            profile_updates["privacy_consent_given"] = True
            profile_updates["onboarding_completed"] = True
        elif current_state == "portfolio_refresh_required":
            target_state = "active"
            # Extend portfolio_refresh_due_at by admin-selected days so DB trigger allows transition
            new_due = datetime.now(timezone.utc) + timedelta(days=body.extension_days)
            supabase_client.client.table("profiles").update({
                "portfolio_refresh_due_at": new_due.isoformat(),
            }).eq("id", user_id).execute()
            profile_updates["portfolio_refresh_due_at"] = new_due.isoformat()
        elif current_state == "unverified_email":
            target_state = "username_selection"
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot advance session from state '{current_state}'",
            )

        # Update profile flags first (DB trigger validates before session update)
        if profile_updates:
            supabase_client.client.table("profiles").update(
                profile_updates
            ).eq("id", user_id).execute()

        # Update session state
        supabase_client.client.table("auth_sessions").update({
            "state": target_state,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("session_id", session_id).execute()

        after = {"state": target_state, "profile_updates": profile_updates}

        await log_admin_action(
            admin_id=admin["id"],
            action="advance_session",
            reason=body.reason,
            target_user_id=user_id,
            before_state=before,
            after_state=after,
            ip_address=_get_ip(request),
        )

        return {"status": "success", "previous_state": current_state, "new_state": target_state}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("advance_session_error", error=str(e), user_id=user_id, session_id=session_id)
        raise HTTPException(status_code=500, detail=f"Failed to advance session: {str(e)}")


@router.post("/users/{user_id}/sessions/{session_id}/unlock")
async def unlock_user_session(
    user_id: str,
    session_id: str,
    body: AdminReasonRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Unlock a locked session (sets state to signed_out, user must re-login)."""
    try:
        session_resp = (
            supabase_client.client.table("auth_sessions")
            .select("state")
            .eq("session_id", session_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not session_resp.data:
            raise HTTPException(status_code=404, detail="Session not found")

        current_state = session_resp.data["state"]
        if current_state != "locked":
            raise HTTPException(status_code=400, detail=f"Session is not locked (current: {current_state})")

        supabase_client.client.table("auth_sessions").update({
            "state": "signed_out",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("session_id", session_id).execute()

        await log_admin_action(
            admin_id=admin["id"],
            action="unlock_session",
            reason=body.reason,
            target_user_id=user_id,
            before_state={"state": "locked"},
            after_state={"state": "signed_out"},
            ip_address=_get_ip(request),
        )

        return {"status": "success", "message": "Session unlocked"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("unlock_session_error", error=str(e), user_id=user_id, session_id=session_id)
        raise HTTPException(status_code=500, detail="Failed to unlock session")


@router.post("/users/{user_id}/files/{file_id}/retry")
async def admin_retry_file(
    user_id: str,
    file_id: str,
    body: AdminReasonRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Force retry a file (admin override — bypasses retry limit, resets count to 0)."""
    try:
        file_resp = (
            supabase_client.client.table("portfolio_files")
            .select("*")
            .eq("id", file_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not file_resp.data:
            raise HTTPException(status_code=404, detail="File not found")

        file_record = file_resp.data
        before = {"status": file_record["status"], "retry_count": file_record.get("retry_count", 0)}

        # Reset file for reprocessing
        supabase_client.client.table("portfolio_files").update({
            "status": "uploaded",
            "retry_count": 0,
            "error_code": None,
            "error_message": None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", file_id).execute()

        # Re-enqueue RQ job
        from app.services.jobs.tasks import parse_pdf_task
        from app.core.rq_app import pdf_parsing_queue
        from rq import Retry
        pdf_url = supabase_client.client.storage.from_(
            file_record.get("storage_bucket", "portfolio-pdfs")
        ).get_public_url(file_record["storage_path"])

        task = pdf_parsing_queue.enqueue(
            parse_pdf_task,
            pdf_url=pdf_url,
            pdf_hash=file_record.get("file_hash", ""),
            user_id=user_id,
            file_id=file_id,
            retry=Retry(max=5, interval=[10, 30, 60, 120, 300]),
            job_timeout=300,
        )

        # Update job id
        supabase_client.client.table("portfolio_files").update({
            "celery_task_id": task.id,
        }).eq("id", file_id).execute()

        after = {"status": "uploaded", "retry_count": 0, "celery_task_id": task.id}

        await log_admin_action(
            admin_id=admin["id"],
            action="force_retry_file",
            reason=body.reason,
            target_user_id=user_id,
            target_file_id=file_id,
            before_state=before,
            after_state=after,
            ip_address=_get_ip(request),
        )

        return {"status": "success", "task_id": task.id, "message": "File queued for reprocessing"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("admin_retry_file_error", error=str(e), file_id=file_id)
        raise HTTPException(status_code=500, detail="Failed to retry file")


@router.post("/users/{user_id}/files/{file_id}/clear")
async def admin_clear_file(
    user_id: str,
    file_id: str,
    body: AdminReasonRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Clear file state / soft-delete to unblock re-upload (hash collision fix)."""
    try:
        file_resp = (
            supabase_client.client.table("portfolio_files")
            .select("status, error_code, file_hash")
            .eq("id", file_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not file_resp.data:
            raise HTTPException(status_code=404, detail="File not found")

        before = dict(file_resp.data)

        supabase_client.client.table("portfolio_files").update({
            "deleted_at": datetime.now(timezone.utc).isoformat(),
            "error_message": f"Admin cleared: {body.reason[:100]}",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", file_id).execute()

        await log_admin_action(
            admin_id=admin["id"],
            action="clear_file",
            reason=body.reason,
            target_user_id=user_id,
            target_file_id=file_id,
            before_state=before,
            after_state={"deleted_at": "now", "cleared": True},
            ip_address=_get_ip(request),
        )

        return {"status": "success", "message": "File cleared — user can re-upload"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("admin_clear_file_error", error=str(e), file_id=file_id)
        raise HTTPException(status_code=500, detail="Failed to clear file")


@router.post("/users/{user_id}/stats/recalculate")
async def admin_recalculate_stats(
    user_id: str,
    body: AdminReasonRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Recalculate all derived stats for a user."""
    try:
        # Recalculate streak via DB function
        try:
            supabase_client.client.rpc("calculate_user_streak", {"p_user_id": user_id}).execute()
        except Exception as e:
            logger.warning("streak_recalc_failed", user_id=user_id, error=str(e))

        # Recount portfolio reaction/comment counts from source tables
        portfolios_resp = (
            supabase_client.client.table("portfolios")
            .select("id")
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .execute()
        )
        for p in (portfolios_resp.data or []):
            pid = p["id"]
            reactions_count_resp = (
                supabase_client.client.table("reactions")
                .select("id", count="exact")
                .eq("portfolio_id", pid)
                .execute()
            )
            reviews_count_resp = (
                supabase_client.client.table("reviews")
                .select("id", count="exact")
                .eq("portfolio_id", pid)
                .is_("deleted_at", "null")
                .execute()
            )
            supabase_client.client.table("portfolios").update({
                "reactions_count": reactions_count_resp.count or 0,
                "comments_count": reviews_count_resp.count or 0,
            }).eq("id", pid).execute()

        await log_admin_action(
            admin_id=admin["id"],
            action="recalculate_stats",
            reason=body.reason,
            target_user_id=user_id,
            ip_address=_get_ip(request),
        )

        return {"status": "success", "message": "Stats recalculated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("recalculate_stats_error", error=str(e), user_id=user_id)
        raise HTTPException(status_code=500, detail="Failed to recalculate stats")


@router.post("/files/batch-retry")
async def admin_batch_retry(
    body: BatchRetryRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Batch force-retry multiple stuck files."""
    try:
        results = []
        for file_id in body.file_ids:
            try:
                file_resp = (
                    supabase_client.client.table("portfolio_files")
                    .select("id, user_id, storage_path, storage_bucket, file_hash, status")
                    .eq("id", file_id)
                    .single()
                    .execute()
                )
                if not file_resp.data:
                    results.append({"file_id": file_id, "status": "not_found"})
                    continue

                f = file_resp.data

                supabase_client.client.table("portfolio_files").update({
                    "status": "uploaded",
                    "retry_count": 0,
                    "error_code": None,
                    "error_message": None,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", file_id).execute()

                from app.services.jobs.tasks import parse_pdf_task
                from app.core.rq_app import pdf_parsing_queue
                from rq import Retry
                pdf_url = supabase_client.client.storage.from_(
                    f.get("storage_bucket", "portfolio-pdfs")
                ).get_public_url(f["storage_path"])

                task = pdf_parsing_queue.enqueue(
                    parse_pdf_task,
                    pdf_url=pdf_url,
                    pdf_hash=f.get("file_hash", ""),
                    user_id=f["user_id"],
                    file_id=file_id,
                    retry=Retry(max=5, interval=[10, 30, 60, 120, 300]),
                    job_timeout=300,
                )

                supabase_client.client.table("portfolio_files").update({
                    "celery_task_id": task.id,
                }).eq("id", file_id).execute()

                results.append({"file_id": file_id, "status": "retried", "task_id": task.id})

                await log_admin_action(
                    admin_id=admin["id"],
                    action="batch_retry_file",
                    reason=body.reason,
                    target_user_id=f["user_id"],
                    target_file_id=file_id,
                    before_state={"status": f["status"]},
                    after_state={"status": "uploaded", "task_id": task.id},
                    ip_address=_get_ip(request),
                )
            except Exception as e:
                results.append({"file_id": file_id, "status": "error", "error": str(e)})

        return {"status": "success", "results": results}
    except Exception as e:
        logger.error("batch_retry_error", error=str(e))
        raise HTTPException(status_code=500, detail="Batch retry failed")
