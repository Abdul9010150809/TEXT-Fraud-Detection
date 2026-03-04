import logging
from typing import Any

logger = logging.getLogger(__name__)


class MongoDBConnection:
    def __init__(self):
        self.client = None
        self.db = None

    async def connect(self):
        try:
            # Lazy import to avoid requiring motor at static-check time
            import motor.motor_asyncio as motor
            from backend.config import Config

            self.client = motor.AsyncIOMotorClient(Config.MONGODB_URL, maxPoolSize=Config.MONGODB_MAX_POOL_SIZE)
            self.db = self.client[Config.MONGODB_DATABASE]
            logger.info("Connected to MongoDB")
        except Exception as e:
            logger.warning(f"MongoDB client not available or failed to connect: {e}")

    async def close(self):
        try:
            if self.client:
                self.client.close()
                logger.info("MongoDB connection closed")
        except Exception:
            pass


# global instance
mongodb_conn = MongoDBConnection()
