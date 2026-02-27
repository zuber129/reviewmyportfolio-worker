"""Platform statistics endpoints."""

from typing import Any, Dict

import structlog
from app.infrastructure.redis_client import RedisClient
from app.infrastructure.supabase_client import supabase_client
from fastapi import APIRouter

logger = structlog.get_logger()
router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/platform", response_model=Dict[str, Any])
async def get_platform_stats() -> Dict[str, Any]:
    """
    Get platform-wide statistics.

    Returns:
        - total_users: Total active investors
        - total_portfolios: Total portfolios uploaded
        - total_value: Sum of all portfolio values
        - avg_xirr: Average XIRR across all portfolios

    Cached for 1 hour since these are marketing stats.
    """
    redis = RedisClient()
    cache_key = "platform:stats:v1"
    cache_ttl = 10 * 3600  # 10 hour cache

    # Try to get from cache
    try:
        await redis.connect()
        cached = await redis.get(cache_key)
        if cached:
            logger.info("platform_stats_cache_hit")
            return cached
    except Exception as e:
        logger.warning("redis_cache_miss", error=str(e))

    # Calculate stats from Supabase
    try:
        # Total users
        users_response = (
            supabase_client.table("profiles").select("id", count="exact").execute()  # type: ignore[attr-defined]
        )
        total_users = users_response.count or 0

        # Total portfolios
        portfolios_response = (
            supabase_client.table("portfolios").select("id", count="exact").execute()  # type: ignore[attr-defined]
        )
        total_portfolios = portfolios_response.count or 0

        # Get all portfolios with values for aggregation
        portfolios_data = (
            supabase_client.table("portfolios")  # type: ignore[attr-defined]
            .select("total_value,xirr")
            .not_.is_("total_value", "null")
            .execute()
        )

        # Calculate sum of portfolio values
        total_value = sum(p.get("total_value", 0) or 0 for p in portfolios_data.data)

        # Calculate average XIRR (only portfolios with XIRR)
        xirr_values = [
            p.get("xirr") for p in portfolios_data.data if p.get("xirr") is not None
        ]
        avg_xirr = sum(xirr_values) / len(xirr_values) if xirr_values else 0

        stats = {
            "total_users": int(total_users),
            "total_portfolios": int(total_portfolios),
            "total_value": float(total_value),
            "avg_xirr": round(float(avg_xirr), 2) if avg_xirr else 0,
        }

        # Cache the result
        try:
            await redis.set(cache_key, stats, expire=cache_ttl)
            logger.info("platform_stats_cached", stats=stats)
        except Exception as e:
            logger.warning("redis_cache_set_failed", error=str(e))

        return stats

    except Exception as e:
        logger.error("platform_stats_error", error=str(e))
        # Return zeros if error
        return {
            "total_users": 0,
            "total_portfolios": 0,
            "total_value": 0,
            "avg_xirr": 0,
        }
    finally:
        await redis.disconnect()
