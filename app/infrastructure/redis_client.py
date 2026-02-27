import json  # type: ignore[import-untyped]
from typing import Any, Optional

import structlog  # type: ignore[import-untyped]
from app.core.config import settings
from redis import asyncio as aioredis  # type: ignore[import-untyped]

logger = structlog.get_logger()


class RedisClient:
    def __init__(self):
        self.redis: Optional[Any] = None
        self.pool: Optional[Any] = None

    async def connect(self):
        try:
            # Create connection pool for better performance
            self.pool = aioredis.ConnectionPool.from_url(
                settings.redis_url,
                max_connections=10,
                encoding="utf-8",
                decode_responses=True,
                socket_keepalive=True,
            )
            self.redis = aioredis.Redis(connection_pool=self.pool)
            await self.redis.ping()
            logger.info("redis_connected", url=settings.redis_url, pool_size=10)
        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            self.redis = None

    async def disconnect(self):
        if self.redis:
            await self.redis.close()
        if self.pool:
            await self.pool.disconnect()
        logger.info("redis_disconnected")

    async def get(self, key: str) -> Optional[Any]:
        if not self.redis:
            return None

        try:
            value = await self.redis.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error("redis_get_error", key=key, error=str(e))
            return None

    async def set(self, key: str, value: Any, expire: int = 3600) -> bool:
        if not self.redis:
            return False

        try:
            serialized = json.dumps(value)
            await self.redis.set(key, serialized, ex=expire)
            return True
        except Exception as e:
            logger.error("redis_set_error", key=key, error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        if not self.redis:
            return False

        try:
            await self.redis.delete(key)
            return True
        except Exception as e:
            logger.error("redis_delete_error", key=key, error=str(e))
            return False

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        if not self.redis:
            return None

        try:
            return await self.redis.incr(key, amount)
        except Exception as e:
            logger.error("redis_incr_error", key=key, error=str(e))
            return None

    async def expire(self, key: str, seconds: int) -> bool:
        if not self.redis:
            return False

        try:
            return await self.redis.expire(key, seconds)
        except Exception as e:
            logger.error("redis_expire_error", key=key, error=str(e))
            return False

    async def ttl(self, key: str) -> Optional[int]:
        """Get time to live for a key"""
        if not self.redis:
            return None

        try:
            ttl_value = await self.redis.ttl(key)
            return ttl_value if ttl_value >= 0 else None
        except Exception as e:
            logger.error("redis_ttl_error", key=key, error=str(e))
            return None

    # ============ SORTED SET OPERATIONS (for feed index) ============

    async def zadd(self, key: str, mapping: dict) -> Optional[int]:
        """Add members to sorted set with scores"""
        if not self.redis:
            return None
        try:
            return await self.redis.zadd(key, mapping)
        except Exception as e:
            logger.error("redis_zadd_error", key=key, error=str(e))
            return None

    async def zrange(self, key: str, start: int, end: int) -> list:
        """Get range from sorted set (ascending order)"""
        if not self.redis:
            return []
        try:
            return await self.redis.zrange(key, start, end)
        except Exception as e:
            logger.error("redis_zrange_error", key=key, error=str(e))
            return []

    async def zrevrange(self, key: str, start: int, end: int) -> list:
        """Get range from sorted set (descending order)"""
        if not self.redis:
            return []
        try:
            return await self.redis.zrevrange(key, start, end)
        except Exception as e:
            logger.error("redis_zrevrange_error", key=key, error=str(e))
            return []

    async def zrem(self, key: str, *members) -> Optional[int]:
        """Remove members from sorted set"""
        if not self.redis:
            return None
        try:
            return await self.redis.zrem(key, *members)
        except Exception as e:
            logger.error("redis_zrem_error", key=key, error=str(e))
            return None

    async def zcard(self, key: str) -> int:
        """Get cardinality (count) of sorted set"""
        if not self.redis:
            return 0
        try:
            return await self.redis.zcard(key)
        except Exception as e:
            logger.error("redis_zcard_error", key=key, error=str(e))
            return 0

    # ============ HASH OPERATIONS (for filter metadata) ============

    async def hset(
        self,
        key: str,
        field: Optional[str] = None,
        value: Any = None,
        mapping: Optional[dict] = None,
    ) -> Optional[int]:
        """Set hash field(s). Supports both single field or mapping."""
        if not self.redis:
            return None
        try:
            if mapping:
                return await self.redis.hset(key, mapping=mapping)
            elif field and value is not None:
                return await self.redis.hset(key, field, value)
            return None
        except Exception as e:
            logger.error("redis_hset_error", key=key, error=str(e))
            return None

    async def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value"""
        if not self.redis:
            return None
        try:
            return await self.redis.hget(key, field)
        except Exception as e:
            logger.error("redis_hget_error", key=key, field=field, error=str(e))
            return None

    async def hgetall(self, key: str) -> dict:
        """Get all fields and values from hash"""
        if not self.redis:
            return {}
        try:
            return await self.redis.hgetall(key)
        except Exception as e:
            logger.error("redis_hgetall_error", key=key, error=str(e))
            return {}

    async def hmget(self, key: str, fields: list) -> list:
        """Get multiple hash field values"""
        if not self.redis:
            return []
        try:
            return await self.redis.hmget(key, fields)
        except Exception as e:
            logger.error("redis_hmget_error", key=key, error=str(e))
            return []

    async def hdel(self, key: str, *fields) -> Optional[int]:
        """Delete hash fields"""
        if not self.redis:
            return None
        try:
            return await self.redis.hdel(key, *fields)
        except Exception as e:
            logger.error("redis_hdel_error", key=key, error=str(e))
            return None

    # ============ PIPELINE (for batch operations) ============

    def pipeline(self):
        """Create a pipeline for batch operations"""
        if not self.redis:
            return None
        return self.redis.pipeline()

    # ============ KEY PATTERN OPERATIONS ============

    async def keys(self, pattern: str) -> list:
        """Get keys matching pattern (use sparingly in production)"""
        if not self.redis:
            return []
        try:
            return await self.redis.keys(pattern)
        except Exception as e:
            logger.error("redis_keys_error", pattern=pattern, error=str(e))
            return []


redis_client = RedisClient()
