"""Feed Cache Service - Redis-based portfolio feed caching with filters"""

from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from app.infrastructure.redis_client import redis_client

logger = structlog.get_logger()


class FeedCacheService:
    """Service for managing portfolio feed cache with Redis"""

    # Redis key patterns
    FEED_GLOBAL = "feed:global"
    FEED_FILTER_PREFIX = "feed:filter:"
    PORTFOLIO_PREFIX = "portfolio:"
    FEED_TOTAL_COUNT = "feed:total_count"
    FEED_LAST_UPDATE = "feed:last_update"

    @staticmethod
    def _get_filter_key(filter_name: str) -> str:
        """Get Redis key for filter hash"""
        return f"{FeedCacheService.FEED_FILTER_PREFIX}{filter_name}"

    @staticmethod
    def _get_portfolio_key(portfolio_id: str) -> str:
        """Get Redis key for portfolio data"""
        return f"{FeedCacheService.PORTFOLIO_PREFIX}{portfolio_id}"

    async def populate_feed_cache(
        self,
        portfolio_id: str,
        portfolio_data: Dict[str, Any],
        created_at: datetime,
    ) -> bool:
        """
        Populate Redis cache with portfolio data for feed.

        Args:
            portfolio_id: Portfolio UUID
            portfolio_data: Dict with keys: user_id, title, total_value, xirr,
                           risk_level, holding_count, is_public, etc.
            created_at: Portfolio creation timestamp

        Returns:
            True if successful, False otherwise
        """
        try:
            pipeline = redis_client.pipeline()
            if not pipeline:
                logger.warning("redis_pipeline_unavailable")
                return False

            timestamp = created_at.timestamp()

            # 1. Add to primary feed index (sorted by timestamp)
            pipeline.zadd(self.FEED_GLOBAL, {portfolio_id: timestamp})

            # 2. Populate filter metadata hashes
            # Portfolio size
            if "total_value" in portfolio_data:
                pipeline.hset(
                    self._get_filter_key("portfolio_size"),
                    portfolio_id,
                    float(portfolio_data["total_value"]),
                )

            # XIRR
            if "xirr" in portfolio_data and portfolio_data["xirr"] is not None:
                pipeline.hset(
                    self._get_filter_key("xirr"),
                    portfolio_id,
                    float(portfolio_data["xirr"]),
                )

            # Risk level
            if "risk_level" in portfolio_data:
                pipeline.hset(
                    self._get_filter_key("risk_level"),
                    portfolio_id,
                    portfolio_data["risk_level"],
                )

            # Holding count
            if "holding_count" in portfolio_data:
                pipeline.hset(
                    self._get_filter_key("holding_count"),
                    portfolio_id,
                    int(portfolio_data["holding_count"]),
                )

            # 3. Cache full portfolio data
            portfolio_cache_data = {
                "id": portfolio_id,
                "user_id": str(portfolio_data.get("user_id", "")),
                "title": portfolio_data.get("title", ""),
                "total_value": str(portfolio_data.get("total_value", 0)),
                "xirr": str(portfolio_data.get("xirr", 0)),
                "risk_level": portfolio_data.get("risk_level", ""),
                "holding_count": str(portfolio_data.get("holding_count", 0)),
                "created_at": created_at.isoformat(),
                "is_public": str(portfolio_data.get("is_public", False)),
            }
            pipeline.hset(
                self._get_portfolio_key(portfolio_id), mapping=portfolio_cache_data
            )

            # 4. Update feed metadata
            pipeline.incr(self.FEED_TOTAL_COUNT)
            pipeline.set(self.FEED_LAST_UPDATE, datetime.utcnow().timestamp())

            # Execute all Redis commands in one batch
            await pipeline.execute()

            logger.info(
                "feed_cache_populated", portfolio_id=portfolio_id, timestamp=timestamp
            )
            return True

        except Exception as e:
            logger.error(
                "feed_cache_populate_error", portfolio_id=portfolio_id, error=str(e)
            )
            return False

    async def get_feed(
        self,
        page: int = 1,
        page_size: int = 20,
        portfolio_size_min: Optional[float] = None,
        portfolio_size_max: Optional[float] = None,
        xirr_min: Optional[float] = None,
        xirr_max: Optional[float] = None,
        risk_level: Optional[List[str]] = None,
        holding_count_min: Optional[int] = None,
        holding_count_max: Optional[int] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Get filtered and sorted portfolio feed from cache.

        Returns:
            {
                "portfolios": [...],
                "pagination": {"page": 1, "page_size": 20, "total": 100, ...}
            }
        """
        try:
            # Step 1: Get base portfolio IDs
            over_fetch_multiplier = 3
            fetch_count = page * page_size * over_fetch_multiplier

            if sort_by == "created_at":
                # Use primary feed index (already sorted by timestamp)
                if sort_order == "desc":
                    base_portfolio_ids = await redis_client.zrevrange(
                        self.FEED_GLOBAL, 0, fetch_count - 1
                    )
                else:
                    base_portfolio_ids = await redis_client.zrange(
                        self.FEED_GLOBAL, 0, fetch_count - 1
                    )
            else:
                # For other sort fields, get all IDs first
                base_portfolio_ids = await redis_client.zrange(self.FEED_GLOBAL, 0, -1)

            if not base_portfolio_ids:
                return {
                    "portfolios": [],
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": 0,
                        "total_pages": 0,
                        "has_previous": False,
                        "has_next": False,
                    },
                }

            # Step 2: Apply filters
            filtered_portfolio_ids = await self._apply_filters(
                base_portfolio_ids,
                portfolio_size_min=portfolio_size_min,
                portfolio_size_max=portfolio_size_max,
                xirr_min=xirr_min,
                xirr_max=xirr_max,
                risk_level=risk_level,
                holding_count_min=holding_count_min,
                holding_count_max=holding_count_max,
            )

            # Step 3: Sort (if not by created_at)
            if sort_by != "created_at":
                filtered_portfolio_ids = await self._sort_portfolio_ids(
                    filtered_portfolio_ids,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )

            # Step 4: Paginate
            total_count = len(filtered_portfolio_ids)
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            page_portfolio_ids = filtered_portfolio_ids[start_idx:end_idx]

            # Step 5: Fetch full portfolio data
            portfolios = await self._fetch_portfolios_data(page_portfolio_ids)

            # Step 6: Return response
            return {
                "portfolios": portfolios,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_count,
                    "total_pages": (total_count + page_size - 1) // page_size,
                    "has_previous": page > 1,
                    "has_next": end_idx < total_count,
                },
            }

        except Exception as e:
            logger.error("feed_cache_get_error", error=str(e))
            return {
                "portfolios": [],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": 0,
                    "total_pages": 0,
                    "has_previous": False,
                    "has_next": False,
                },
            }

    async def _apply_filters(
        self,
        portfolio_ids: List[str],
        portfolio_size_min: Optional[float] = None,
        portfolio_size_max: Optional[float] = None,
        xirr_min: Optional[float] = None,
        xirr_max: Optional[float] = None,
        risk_level: Optional[List[str]] = None,
        holding_count_min: Optional[int] = None,
        holding_count_max: Optional[int] = None,
    ) -> List[str]:
        """Apply filters using Redis filter hashes"""

        # If no filters, return all IDs
        if not any(
            [
                portfolio_size_min,
                portfolio_size_max,
                xirr_min,
                xirr_max,
                risk_level,
                holding_count_min,
                holding_count_max,
            ]
        ):
            return portfolio_ids

        filtered_ids = set(portfolio_ids)

        # Filter by portfolio size (range)
        if portfolio_size_min is not None or portfolio_size_max is not None:
            size_values = await redis_client.hmget(
                self._get_filter_key("portfolio_size"), list(filtered_ids)
            )
            matching = set()
            for pid, value in zip(filtered_ids, size_values):
                if value is None:
                    continue
                try:
                    value = float(value)
                    if (portfolio_size_min is None or value >= portfolio_size_min) and (
                        portfolio_size_max is None or value <= portfolio_size_max
                    ):
                        matching.add(pid)
                except (ValueError, TypeError):
                    continue
            filtered_ids &= matching

        # Filter by XIRR (range)
        if xirr_min is not None or xirr_max is not None:
            xirr_values = await redis_client.hmget(
                self._get_filter_key("xirr"), list(filtered_ids)
            )
            matching = set()
            for pid, value in zip(filtered_ids, xirr_values):
                if value is None:
                    continue
                try:
                    value = float(value)
                    if (xirr_min is None or value >= xirr_min) and (
                        xirr_max is None or value <= xirr_max
                    ):
                        matching.add(pid)
                except (ValueError, TypeError):
                    continue
            filtered_ids &= matching

        # Filter by risk level (multi-select)
        if risk_level:
            risk_values = await redis_client.hmget(
                self._get_filter_key("risk_level"), list(filtered_ids)
            )
            matching = {
                pid
                for pid, value in zip(filtered_ids, risk_values)
                if value and value in risk_level
            }
            filtered_ids &= matching

        # Filter by holding count (range)
        if holding_count_min is not None or holding_count_max is not None:
            count_values = await redis_client.hmget(
                self._get_filter_key("holding_count"), list(filtered_ids)
            )
            matching = set()
            for pid, value in zip(filtered_ids, count_values):
                if value is None:
                    continue
                try:
                    value = int(value)
                    if (holding_count_min is None or value >= holding_count_min) and (
                        holding_count_max is None or value <= holding_count_max
                    ):
                        matching.add(pid)
                except (ValueError, TypeError):
                    continue
            filtered_ids &= matching

        return list(filtered_ids)

    async def _sort_portfolio_ids(
        self,
        portfolio_ids: List[str],
        sort_by: str,
        sort_order: str,
    ) -> List[str]:
        """Sort portfolio IDs by specified field"""

        # Fetch sort field values from Redis
        sort_values = await redis_client.hmget(
            self._get_filter_key(sort_by), portfolio_ids
        )

        # Build (portfolio_id, value) tuples
        id_value_pairs = []
        for pid, value in zip(portfolio_ids, sort_values):
            if value is not None:
                try:
                    # Convert to appropriate type
                    if sort_by in ["xirr", "portfolio_size"]:
                        value = float(value)
                    elif sort_by == "holding_count":
                        value = int(value)
                    id_value_pairs.append((pid, value))
                except (ValueError, TypeError):
                    continue

        # Sort by value
        id_value_pairs.sort(key=lambda x: x[1], reverse=(sort_order == "desc"))

        return [pid for pid, _ in id_value_pairs]

    async def _fetch_portfolios_data(
        self, portfolio_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """Fetch full portfolio data from cache"""

        if not portfolio_ids:
            return []

        portfolios = []
        pipeline = redis_client.pipeline()
        if not pipeline:
            return []

        # Batch fetch all portfolio data
        for pid in portfolio_ids:
            pipeline.hgetall(self._get_portfolio_key(pid))

        portfolio_data_list = await pipeline.execute()

        for portfolio_data in portfolio_data_list:
            if portfolio_data:
                portfolios.append(portfolio_data)

        return portfolios

    async def invalidate_portfolio(self, portfolio_id: str) -> bool:
        """
        Remove portfolio from feed cache (for delete/update operations).

        Args:
            portfolio_id: Portfolio UUID to remove

        Returns:
            True if successful, False otherwise
        """
        try:
            pipeline = redis_client.pipeline()
            if not pipeline:
                return False

            # Remove from primary feed index
            pipeline.zrem(self.FEED_GLOBAL, portfolio_id)

            # Remove from all filter hashes
            pipeline.hdel(self._get_filter_key("portfolio_size"), portfolio_id)
            pipeline.hdel(self._get_filter_key("xirr"), portfolio_id)
            pipeline.hdel(self._get_filter_key("risk_level"), portfolio_id)
            pipeline.hdel(self._get_filter_key("holding_count"), portfolio_id)

            # Remove full portfolio data
            pipeline.delete(self._get_portfolio_key(portfolio_id))

            # Update metadata
            pipeline.decr(self.FEED_TOTAL_COUNT)
            pipeline.set(self.FEED_LAST_UPDATE, datetime.utcnow().timestamp())

            await pipeline.execute()

            logger.info("feed_cache_invalidated", portfolio_id=portfolio_id)
            return True

        except Exception as e:
            logger.error(
                "feed_cache_invalidate_error", portfolio_id=portfolio_id, error=str(e)
            )
            return False

    async def get_total_count(self) -> int:
        """Get total number of portfolios in feed"""
        try:
            # Use direct Redis get for simple integer value (not JSON)
            if redis_client.redis:
                count = await redis_client.redis.get(self.FEED_TOTAL_COUNT)
                return int(count) if count else 0
            return 0
        except Exception:
            return await redis_client.zcard(self.FEED_GLOBAL)


# Singleton instance
feed_cache_service = FeedCacheService()
