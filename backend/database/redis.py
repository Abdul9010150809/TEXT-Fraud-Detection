import redis.asyncio as redis
import logging
from backend.config import Config

logger = logging.getLogger(__name__)

class RedisConnection:
    def __init__(self):
        self.client: redis.Redis = None

    async def connect(self):
        try:
            self.client = redis.Redis.from_url(
                Config.REDIS_URL,
                db=Config.REDIS_DB,
                password=Config.REDIS_PASSWORD,
                max_connections=Config.REDIS_MAX_CONNECTIONS,
                decode_responses=True
            )
            # Test the connection
            await self.client.ping()
            logger.info("Connected to Redis successfully")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def close(self):
        if self.client:
            await self.client.aclose()
            logger.info("Redis connection closed")

    def get_client(self) -> redis.Redis:
        if not self.client:
            raise RuntimeError("Redis client not initialized. Call connect() first.")
        return self.client

    async def set_with_ttl(self, key: str, value: str, ttl: int = None):
        """Set a key with TTL (Time To Live)"""
        if ttl is None:
            ttl = Config.CACHE_TTL
        await self.client.setex(key, ttl, value)

    async def get(self, key: str) -> str:
        """Get value by key"""
        return await self.client.get(key)

    async def delete(self, key: str):
        """Delete a key"""
        await self.client.delete(key)

# Global instance
redis_conn = RedisConnection()